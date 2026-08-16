"""Bounded, no-follow reads for untrusted repository files."""

from __future__ import annotations

import ctypes
import os
import stat
from pathlib import Path
from typing import Any, Protocol

from agentsec.models import Diagnostic, DiagnosticKind

_READ_CHUNK_SIZE = 64 * 1024
_MAX_SAFE_FILE_BYTES = 4_000_000


class _UnsafeFileError(OSError):
    pass


class _SymlinkedFileError(_UnsafeFileError):
    def __init__(self, path: Path) -> None:
        self.path = path
        super().__init__(f"symlinked file path: {path}")


class _WindowsFileApi(Protocol):
    def open_directory(self, path: Path) -> int: ...

    def validate_directory(self, handle: int, path: Path) -> None: ...

    def open_file(self, path: Path) -> int: ...

    def validate_file(self, handle: int, path: Path) -> None: ...

    def size(self, handle: int) -> int: ...

    def snapshot(self, handle: int) -> tuple[int, int, int, int]: ...

    def read(self, handle: int, size: int) -> bytes: ...

    def close(self, handle: int) -> None: ...


def safe_read_regular_file(
    path: Path, max_bytes: int
) -> tuple[bytes | None, tuple[Diagnostic, ...]]:
    """Read one regular file once, bounded and without following links."""
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < 0:
        return None, (_error(path, "Invalid safe read byte limit"),)
    effective_limit = min(max_bytes, _MAX_SAFE_FILE_BYTES)
    try:
        content = (
            _read_windows(path, effective_limit)
            if _is_windows()
            else _read_posix(path, effective_limit)
        )
    except _SymlinkedFileError as error:
        return None, (_error(error.path, "Refusing to follow symlinked file path"),)
    except (OSError, OverflowError, UnicodeError, ValueError):
        return None, (_error(path, "Unable to read file safely"),)
    return content, ()


def _is_windows() -> bool:
    return os.name == "nt"


def _read_posix(path: Path, max_bytes: int) -> bytes:
    if not _supports_anchored_no_follow():
        raise _UnsafeFileError("anchored no-follow reads are unavailable")

    parent_descriptor: int | None = None
    descriptor: int | None = None
    content: bytes | None = None
    primary_error: OSError | OverflowError | ValueError | None = None
    try:
        parent_descriptor, filename = _open_parent_directory(path)
        path_before = _stat_at(parent_descriptor, filename)
        _require_regular_path(path_before, path)
        _require_within_limit(path_before.st_size, max_bytes)

        descriptor = _open_file_at(parent_descriptor, filename)
        opened = os.fstat(descriptor)
        _require_regular_file(opened)
        _require_same_identity(path_before, opened)
        _require_unchanged(path_before, opened)
        _require_within_limit(opened.st_size, max_bytes)

        content = _read_bounded(descriptor, max_bytes)

        file_after = os.fstat(descriptor)
        path_after = _stat_at(parent_descriptor, filename)
        _require_regular_file(file_after)
        _require_regular_path(path_after, path)
        _require_same_identity(opened, file_after)
        _require_same_identity(opened, path_after)
        _require_unchanged(opened, file_after)
        _require_unchanged(file_after, path_after)
        _require_within_limit(file_after.st_size, max_bytes)
        if len(content) != file_after.st_size:
            raise _UnsafeFileError("file size changed while reading")
        _verify_parent_path(path, parent_descriptor, filename)
    except (OSError, OverflowError, ValueError) as error:
        primary_error = error
    finally:
        cleanup_errors = _close_descriptors(descriptor, parent_descriptor)

    if cleanup_errors:
        raise _UnsafeFileError("safe read failed")
    if primary_error is not None:
        raise primary_error
    if content is None:
        raise _UnsafeFileError("safe read returned no content")
    return content


def _supports_anchored_no_follow() -> bool:
    return (
        os.name == "posix"
        and bool(getattr(os, "O_NOFOLLOW", 0))
        and bool(getattr(os, "O_DIRECTORY", 0))
        and os.open in os.supports_dir_fd
        and os.stat in os.supports_dir_fd
    )


def _open_parent_directory(path: Path) -> tuple[int, str]:
    anchor, components = _path_components(path)
    if not components:
        raise _UnsafeFileError("file path has no file component")

    current: int | None = os.open(anchor, _directory_open_flags())
    current_path = Path(anchor)
    try:
        if current is None:
            raise _UnsafeFileError("file parent descriptor was not opened")
        _require_directory_file(os.fstat(current))
        for component in components[:-1]:
            current_path /= component
            path_before = _stat_at(current, component)
            _require_directory_path(path_before, current_path)
            following = os.open(component, _directory_open_flags(), dir_fd=current)
            try:
                opened = os.fstat(following)
                _require_directory_file(opened)
                _require_same_identity(path_before, opened)
                _require_unchanged(path_before, opened)
            except BaseException:
                _close_descriptors(following)
                raise
            previous = current
            current = following
            try:
                os.close(previous)
            except BaseException:
                _close_descriptors(previous, current)
                current = None
                raise
    except BaseException:
        _close_descriptors(current)
        raise
    if current is None:
        raise _UnsafeFileError("file parent descriptor was not retained")
    return current, components[-1]


def _path_components(path: Path) -> tuple[str, tuple[str, ...]]:
    parts = path.parts
    components = parts[1:] if path.is_absolute() else parts
    if any(component in {"", ".", ".."} for component in components):
        raise _UnsafeFileError("unsafe file path component")
    return (path.anchor if path.is_absolute() else "."), components


def _file_open_flags() -> int:
    return (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )


def _directory_open_flags() -> int:
    return _file_open_flags() | int(getattr(os, "O_DIRECTORY", 0))


def _open_file_at(parent: int, filename: str) -> int:
    return os.open(filename, _file_open_flags(), dir_fd=parent)


def _stat_at(parent: int, component: str) -> os.stat_result:
    return os.stat(component, dir_fd=parent, follow_symlinks=False)


def _read_bounded(descriptor: int, max_bytes: int) -> bytes:
    result = bytearray()
    while len(result) < max_bytes:
        read_size = min(_READ_CHUNK_SIZE, max_bytes - len(result))
        chunk = os.read(descriptor, read_size)
        if not chunk:
            return bytes(result)
        result.extend(chunk)
    return bytes(result)


def _verify_parent_path(path: Path, original_parent: int, filename: str) -> None:
    verification_parent, verification_filename = _open_parent_directory(path)
    try:
        if verification_filename != filename:
            raise _UnsafeFileError("filename changed while reading")
        _require_same_identity(os.fstat(original_parent), os.fstat(verification_parent))
    finally:
        os.close(verification_parent)


def _close_descriptors(*descriptors: int | None) -> tuple[OSError, ...]:
    errors: list[OSError] = []
    for descriptor in descriptors:
        if descriptor is None:
            continue
        try:
            os.close(descriptor)
        except OSError as error:
            errors.append(error)
    return tuple(errors)


def _require_regular_path(file_stat: os.stat_result, path: Path) -> None:
    if _is_link_or_reparse(file_stat):
        raise _SymlinkedFileError(path)
    if not stat.S_ISREG(file_stat.st_mode):
        raise _UnsafeFileError("file path is not regular")


def _require_regular_file(file_stat: os.stat_result) -> None:
    if _is_link_or_reparse(file_stat) or not stat.S_ISREG(file_stat.st_mode):
        raise _UnsafeFileError("opened file is not regular")


def _require_directory_path(file_stat: os.stat_result, path: Path) -> None:
    if _is_link_or_reparse(file_stat):
        raise _SymlinkedFileError(path)
    if not stat.S_ISDIR(file_stat.st_mode):
        raise _UnsafeFileError("file parent is not a directory")


def _require_directory_file(file_stat: os.stat_result) -> None:
    if _is_link_or_reparse(file_stat) or not stat.S_ISDIR(file_stat.st_mode):
        raise _UnsafeFileError("opened file parent is not a directory")


def _is_link_or_reparse(file_stat: os.stat_result) -> bool:
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return stat.S_ISLNK(file_stat.st_mode) or bool(
        getattr(file_stat, "st_file_attributes", 0) & reparse_flag
    )


def _require_within_limit(size: int, max_bytes: int) -> None:
    if size < 0 or size > max_bytes:
        raise _UnsafeFileError("file exceeds byte limit")


def _require_same_identity(first: os.stat_result, second: os.stat_result) -> None:
    first_identity = _stable_identity(first)
    second_identity = _stable_identity(second)
    if (
        first_identity is not None
        and second_identity is not None
        and first_identity != second_identity
    ):
        raise _UnsafeFileError("file identity changed")


def _stable_identity(file_stat: os.stat_result) -> tuple[int, int] | None:
    device = getattr(file_stat, "st_dev", None)
    inode = getattr(file_stat, "st_ino", None)
    if not isinstance(device, int) or not isinstance(inode, int) or inode == 0:
        return None
    return device, inode


def _require_unchanged(before: os.stat_result, after: os.stat_result) -> None:
    before_snapshot = (
        stat.S_IFMT(before.st_mode),
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )
    after_snapshot = (
        stat.S_IFMT(after.st_mode),
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )
    if before_snapshot != after_snapshot:
        raise _UnsafeFileError("file changed while reading")


def _read_windows(path: Path, max_bytes: int) -> bytes:
    if not path.is_absolute():
        raise _UnsafeFileError("Windows safe read path must be absolute")
    api = _windows_file_api()
    handles: list[int] = []
    try:
        parent_handles: list[tuple[int, Path, tuple[int, int, int, int]]] = []
        for parent in reversed(path.parents):
            handle = api.open_directory(parent)
            handles.append(handle)
            api.validate_directory(handle, parent)
            parent_handles.append((handle, parent, api.snapshot(handle)))

        file_handle = api.open_file(path)
        handles.append(file_handle)
        api.validate_file(file_handle, path)
        initial_snapshot = api.snapshot(file_handle)
        initial_size = initial_snapshot[1]
        _require_within_limit(initial_size, max_bytes)
        raw = _read_windows_bounded(api, file_handle, max_bytes)
        api.validate_file(file_handle, path)
        if api.snapshot(file_handle) != initial_snapshot or len(raw) != initial_size:
            raise _UnsafeFileError("Windows file changed while reading")

        verification_file = api.open_file(path)
        handles.append(verification_file)
        api.validate_file(verification_file, path)
        if api.snapshot(verification_file) != initial_snapshot:
            raise _UnsafeFileError("Windows file binding changed")
        for handle, parent, initial_parent_snapshot in parent_handles:
            api.validate_directory(handle, parent)
            if api.snapshot(handle) != initial_parent_snapshot:
                raise _UnsafeFileError("Windows file parent changed")
            verification_parent = api.open_directory(parent)
            handles.append(verification_parent)
            api.validate_directory(verification_parent, parent)
            if api.snapshot(verification_parent) != initial_parent_snapshot:
                raise _UnsafeFileError("Windows file parent binding changed")
        return raw
    finally:
        errors: list[OSError] = []
        for handle in reversed(handles):
            try:
                api.close(handle)
            except OSError as error:
                errors.append(error)
        if errors:
            raise _UnsafeFileError("Unable to close Windows file handles") from errors[0]


def _read_windows_bounded(api: _WindowsFileApi, handle: int, max_bytes: int) -> bytes:
    result = bytearray()
    while len(result) < max_bytes:
        read_size = min(_READ_CHUNK_SIZE, max_bytes - len(result))
        chunk = api.read(handle, read_size)
        if not chunk:
            return bytes(result)
        result.extend(chunk)
    return bytes(result)


def _windows_file_api() -> _WindowsFileApi:
    return _CtypesWindowsFileApi()


class _FileAttributeTagInfo(ctypes.Structure):
    _fields_ = [
        ("file_attributes", ctypes.c_uint32),
        ("reparse_tag", ctypes.c_uint32),
    ]


class _FileTime(ctypes.Structure):
    _fields_ = [("low", ctypes.c_uint32), ("high", ctypes.c_uint32)]


class _ByHandleFileInformation(ctypes.Structure):
    _fields_ = [
        ("file_attributes", ctypes.c_uint32),
        ("creation_time", _FileTime),
        ("last_access_time", _FileTime),
        ("last_write_time", _FileTime),
        ("volume_serial_number", ctypes.c_uint32),
        ("file_size_high", ctypes.c_uint32),
        ("file_size_low", ctypes.c_uint32),
        ("number_of_links", ctypes.c_uint32),
        ("file_index_high", ctypes.c_uint32),
        ("file_index_low", ctypes.c_uint32),
    ]


class _CtypesWindowsFileApi:
    _FILE_ATTRIBUTE_DIRECTORY = 0x00000010
    _FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
    _FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
    _FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
    _FILE_FLAG_SEQUENTIAL_SCAN = 0x08000000
    _FILE_READ_ATTRIBUTES = 0x00000080
    _GENERIC_READ = 0x80000000
    _FILE_SHARE_READ = 0x00000001
    _OPEN_EXISTING = 3
    _FILE_TYPE_DISK = 1
    _FILE_ATTRIBUTE_TAG_INFO_CLASS = 9

    def __init__(self) -> None:
        loader = getattr(ctypes, "WinDLL", None)
        if loader is None:
            raise _UnsafeFileError("Windows file APIs are unavailable")
        self._ctypes = ctypes
        self._kernel32: Any = loader("kernel32", use_last_error=True)
        self._create_file: Any = self._kernel32.CreateFileW
        self._create_file.argtypes = [
            ctypes.c_wchar_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
        ]
        self._create_file.restype = ctypes.c_void_p
        self._get_file_type: Any = self._kernel32.GetFileType
        self._get_file_type.argtypes = [ctypes.c_void_p]
        self._get_file_type.restype = ctypes.c_uint32
        self._get_info: Any = self._kernel32.GetFileInformationByHandleEx
        self._get_info.argtypes = [
            ctypes.c_void_p,
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.c_uint32,
        ]
        self._get_info.restype = ctypes.c_int
        self._get_basic_info: Any = self._kernel32.GetFileInformationByHandle
        self._get_basic_info.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(_ByHandleFileInformation),
        ]
        self._get_basic_info.restype = ctypes.c_int
        self._get_size: Any = self._kernel32.GetFileSizeEx
        self._get_size.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_longlong)]
        self._get_size.restype = ctypes.c_int
        self._read_file: Any = self._kernel32.ReadFile
        self._read_file.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint32),
            ctypes.c_void_p,
        ]
        self._read_file.restype = ctypes.c_int
        self._close_handle: Any = self._kernel32.CloseHandle
        self._close_handle.argtypes = [ctypes.c_void_p]
        self._close_handle.restype = ctypes.c_int

    def open_directory(self, path: Path) -> int:
        return self._open(
            path,
            self._FILE_READ_ATTRIBUTES,
            self._FILE_FLAG_OPEN_REPARSE_POINT | self._FILE_FLAG_BACKUP_SEMANTICS,
        )

    def open_file(self, path: Path) -> int:
        return self._open(
            path,
            self._GENERIC_READ,
            self._FILE_FLAG_OPEN_REPARSE_POINT | self._FILE_FLAG_SEQUENTIAL_SCAN,
        )

    def _open(self, path: Path, access: int, flags: int) -> int:
        handle = self._create_file(
            str(path),
            access,
            self._FILE_SHARE_READ,
            None,
            self._OPEN_EXISTING,
            flags,
            None,
        )
        invalid = self._ctypes.c_void_p(-1).value
        if handle in {None, invalid}:
            raise _UnsafeFileError("Unable to open Windows file safely")
        return int(handle)

    def validate_directory(self, handle: int, path: Path) -> None:
        attributes = self._attributes(handle)
        if (
            attributes & self._FILE_ATTRIBUTE_REPARSE_POINT
            or not attributes & self._FILE_ATTRIBUTE_DIRECTORY
            or self._get_file_type(handle) != self._FILE_TYPE_DISK
        ):
            raise _SymlinkedFileError(path)

    def validate_file(self, handle: int, path: Path) -> None:
        attributes = self._attributes(handle)
        if (
            attributes & self._FILE_ATTRIBUTE_REPARSE_POINT
            or attributes & self._FILE_ATTRIBUTE_DIRECTORY
            or self._get_file_type(handle) != self._FILE_TYPE_DISK
        ):
            raise _SymlinkedFileError(path)

    def _attributes(self, handle: int) -> int:
        info = _FileAttributeTagInfo()
        if not self._get_info(
            handle,
            self._FILE_ATTRIBUTE_TAG_INFO_CLASS,
            self._ctypes.byref(info),
            self._ctypes.sizeof(info),
        ):
            raise _UnsafeFileError("Unable to inspect Windows file path")
        return int(info.file_attributes)

    def size(self, handle: int) -> int:
        value = self._ctypes.c_longlong()
        if not self._get_size(handle, self._ctypes.byref(value)):
            raise _UnsafeFileError("Unable to size Windows file")
        return int(value.value)

    def snapshot(self, handle: int) -> tuple[int, int, int, int]:
        info = _ByHandleFileInformation()
        if not self._get_basic_info(handle, self._ctypes.byref(info)):
            raise _UnsafeFileError("Unable to snapshot Windows file path")
        identity = (
            int(info.volume_serial_number) << 64
            | int(info.file_index_high) << 32
            | int(info.file_index_low)
        )
        size = int(info.file_size_high) << 32 | int(info.file_size_low)
        modified = int(info.last_write_time.high) << 32 | int(info.last_write_time.low)
        created = int(info.creation_time.high) << 32 | int(info.creation_time.low)
        return identity, size, modified, created

    def read(self, handle: int, size: int) -> bytes:
        buffer = self._ctypes.create_string_buffer(size)
        count = self._ctypes.c_uint32()
        if not self._read_file(handle, buffer, size, self._ctypes.byref(count), None):
            raise _UnsafeFileError("Unable to read Windows file")
        return bytes(buffer.raw[: count.value])

    def close(self, handle: int) -> None:
        if not self._close_handle(handle):
            raise OSError("Unable to close Windows file handle")


def _error(path: Path, message: str) -> Diagnostic:
    return Diagnostic(DiagnosticKind.ERROR, path, message)

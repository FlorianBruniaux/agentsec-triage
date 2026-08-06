from __future__ import annotations

import ctypes
import json
import os
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, cast

from agentsec.models import Diagnostic, DiagnosticKind

_MAX_STARTUP_CONFIG_BYTES = 1_000_000
_READ_CHUNK_SIZE = 64 * 1024
_CLAUDE_STARTUP_EVENTS = (
    "SessionStart",
    "Setup",
    "InstructionsLoaded",
    "DirectoryAdded",
)


@dataclass(frozen=True, slots=True)
class StartupHook:
    kind: str
    event: str
    command: str
    path: Path


class _StartupConfigError(ValueError):
    pass


class _SymlinkedConfigError(OSError):
    def __init__(self, path: Path) -> None:
        self.path = path
        super().__init__(f"symlinked startup configuration path: {path}")


class _UnsafeConfigError(OSError):
    pass


class _WindowsFileApi(Protocol):
    def open_directory(self, path: Path) -> int: ...

    def validate_directory(self, handle: int, path: Path) -> None: ...

    def open_file(self, path: Path) -> int: ...

    def validate_file(self, handle: int, path: Path) -> None: ...

    def size(self, handle: int) -> int: ...

    def read(self, handle: int, size: int) -> bytes: ...

    def close(self, handle: int) -> None: ...


def inspect_startup_config(
    path: Path,
) -> tuple[tuple[StartupHook, ...], tuple[Diagnostic, ...]]:
    """Read startup configuration as data without executing repository content."""
    is_claude = path.parent.name == ".claude" and path.name in {
        "settings.json",
        "settings.local.json",
    }
    is_vscode = path.parent.name == ".vscode" and path.name == "tasks.json"
    if not is_claude and not is_vscode:
        return (), (_error(path, "Unable to parse startup configuration"),)

    try:
        text = _read_text_without_following_links(path)
    except _SymlinkedConfigError as exc:
        return (), (_error(exc.path, "Refusing to follow symlinked config path"),)
    except (OSError, UnicodeError, ValueError):
        return (), (_error(path, "Unable to read startup configuration"),)

    try:
        if is_claude:
            document = _load_json(text)
            hooks = _extract_claude_hooks(document, path)
        else:
            document = _load_json(_strip_jsonc(text))
            hooks = _extract_vscode_hooks(document, path)
    except (ValueError, RecursionError):
        return (), (_error(path, "Unable to parse startup configuration"),)

    return hooks, ()


def _read_text_without_following_links(path: Path) -> str:
    if _is_windows():
        return _read_text_windows(path)
    if not _supports_anchored_no_follow():
        raise _UnsafeConfigError("safe startup configuration opening is unavailable")
    return _read_text_anchored(path)


def _is_windows() -> bool:
    return os.name == "nt"


def _read_text_windows(path: Path) -> str:
    if not path.is_absolute():
        raise _UnsafeConfigError("Windows startup configuration path must be absolute")
    api = _windows_file_api()
    handles: list[int] = []
    try:
        parent_handles: list[tuple[int, Path]] = []
        for parent in reversed(path.parents):
            handle = api.open_directory(parent)
            handles.append(handle)
            api.validate_directory(handle, parent)
            parent_handles.append((handle, parent))

        file_handle = api.open_file(path)
        handles.append(file_handle)
        api.validate_file(file_handle, path)
        initial_size = api.size(file_handle)
        _require_within_limit(initial_size)
        raw = _read_windows_bounded(api, file_handle)
        api.validate_file(file_handle, path)
        if api.size(file_handle) != initial_size or len(raw) != initial_size:
            raise _UnsafeConfigError("Windows startup configuration changed while reading")
        for handle, parent in parent_handles:
            api.validate_directory(handle, parent)
        return raw.decode("utf-8", errors="strict")
    finally:
        errors: list[OSError] = []
        for handle in reversed(handles):
            try:
                api.close(handle)
            except OSError as exc:
                errors.append(exc)
        if errors:
            raise _UnsafeConfigError("Unable to close Windows startup handles") from errors[0]


def _read_windows_bounded(api: _WindowsFileApi, handle: int) -> bytes:
    result = bytearray()
    while True:
        read_size = min(_READ_CHUNK_SIZE, _MAX_STARTUP_CONFIG_BYTES - len(result) + 1)
        chunk = api.read(handle, read_size)
        if not chunk:
            return bytes(result)
        result.extend(chunk)
        if len(result) > _MAX_STARTUP_CONFIG_BYTES:
            raise _UnsafeConfigError("startup configuration exceeds byte limit")


def _windows_file_api() -> _WindowsFileApi:
    return _CtypesWindowsFileApi()


class _FileAttributeTagInfo(ctypes.Structure):
    _fields_ = [
        ("file_attributes", ctypes.c_uint32),
        ("reparse_tag", ctypes.c_uint32),
    ]


class _CtypesWindowsFileApi:
    _FILE_ATTRIBUTE_DIRECTORY = 0x00000010
    _FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
    _FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
    _FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
    _FILE_FLAG_SEQUENTIAL_SCAN = 0x08000000
    _FILE_READ_ATTRIBUTES = 0x00000080
    _GENERIC_READ = 0x80000000
    _FILE_SHARE_ALL = 0x00000007
    _OPEN_EXISTING = 3
    _FILE_TYPE_DISK = 1
    _FILE_ATTRIBUTE_TAG_INFO_CLASS = 9

    def __init__(self) -> None:
        import ctypes

        loader = getattr(ctypes, "WinDLL", None)
        if loader is None:
            raise _UnsafeConfigError("Windows file APIs are unavailable")
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
            self._FILE_SHARE_ALL,
            None,
            self._OPEN_EXISTING,
            flags,
            None,
        )
        invalid = self._ctypes.c_void_p(-1).value
        if handle in {None, invalid}:
            raise _UnsafeConfigError("Unable to open Windows startup path safely")
        return int(handle)

    def validate_directory(self, handle: int, path: Path) -> None:
        attributes = self._attributes(handle)
        if (
            attributes & self._FILE_ATTRIBUTE_REPARSE_POINT
            or not attributes & self._FILE_ATTRIBUTE_DIRECTORY
            or self._get_file_type(handle) != self._FILE_TYPE_DISK
        ):
            raise _SymlinkedConfigError(path)

    def validate_file(self, handle: int, path: Path) -> None:
        attributes = self._attributes(handle)
        if (
            attributes & self._FILE_ATTRIBUTE_REPARSE_POINT
            or attributes & self._FILE_ATTRIBUTE_DIRECTORY
            or self._get_file_type(handle) != self._FILE_TYPE_DISK
        ):
            raise _SymlinkedConfigError(path)

    def _attributes(self, handle: int) -> int:
        info = _FileAttributeTagInfo()
        if not self._get_info(
            handle,
            self._FILE_ATTRIBUTE_TAG_INFO_CLASS,
            self._ctypes.byref(info),
            self._ctypes.sizeof(info),
        ):
            raise _UnsafeConfigError("Unable to inspect Windows startup path")
        return int(info.file_attributes)

    def size(self, handle: int) -> int:
        value = self._ctypes.c_longlong()
        if not self._get_size(handle, self._ctypes.byref(value)):
            raise _UnsafeConfigError("Unable to size Windows startup configuration")
        return int(value.value)

    def read(self, handle: int, size: int) -> bytes:
        buffer = self._ctypes.create_string_buffer(size)
        count = self._ctypes.c_uint32()
        if not self._read_file(handle, buffer, size, self._ctypes.byref(count), None):
            raise _UnsafeConfigError("Unable to read Windows startup configuration")
        return bytes(buffer.raw[: count.value])

    def close(self, handle: int) -> None:
        if not self._close_handle(handle):
            raise OSError("Unable to close Windows startup handle")


def _supports_anchored_no_follow() -> bool:
    return (
        os.name == "posix"
        and bool(getattr(os, "O_DIRECTORY", 0))
        and bool(getattr(os, "O_NOFOLLOW", 0))
        and os.open in os.supports_dir_fd
        and os.stat in os.supports_dir_fd
    )


def _read_text_anchored(path: Path) -> str:
    parent_fd, filename = _open_parent_directory(path)
    try:
        path_before = _stat_at(parent_fd, filename)
        _require_regular_path(path_before, path)
        _require_within_limit(path_before.st_size)

        file_fd = os.open(filename, _file_open_flags(), dir_fd=parent_fd)
        try:
            opened = os.fstat(file_fd)
            _require_regular_file(opened)
            _require_same_identity(path_before, opened)
            _require_unchanged(path_before, opened)
            _require_within_limit(opened.st_size)
            raw = _read_bounded(file_fd)

            file_after = os.fstat(file_fd)
            path_after = _stat_at(parent_fd, filename)
            _require_regular_file(file_after)
            _require_regular_path(path_after, path)
            _require_same_identity(opened, file_after)
            _require_same_identity(opened, path_after)
            _require_unchanged(opened, file_after)
            _require_unchanged(file_after, path_after)
            if len(raw) != file_after.st_size:
                raise _UnsafeConfigError("startup configuration changed while reading")
            _verify_parent_path(path, parent_fd, filename)
            return raw.decode("utf-8", errors="strict")
        finally:
            os.close(file_fd)
    finally:
        os.close(parent_fd)


def _open_parent_directory(path: Path) -> tuple[int, str]:
    anchor, components = _path_components(path)
    if not components:
        raise _UnsafeConfigError("startup configuration path has no file component")

    current = os.open(anchor, _directory_open_flags())
    current_path = Path(anchor)
    try:
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
            except BaseException:
                os.close(following)
                raise
            os.close(current)
            current = following
    except BaseException:
        os.close(current)
        raise
    return current, components[-1]


def _path_components(path: Path) -> tuple[str, tuple[str, ...]]:
    parts = path.parts
    components = parts[1:] if path.is_absolute() else parts
    if any(component in {"", ".", ".."} for component in components):
        raise _UnsafeConfigError("unsafe startup configuration path component")
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
    return _file_open_flags() | os.O_DIRECTORY


def _stat_at(parent_fd: int, component: str) -> os.stat_result:
    return os.stat(component, dir_fd=parent_fd, follow_symlinks=False)


def _read_bounded(file_fd: int) -> bytes:
    result = bytearray()
    while True:
        read_size = min(_READ_CHUNK_SIZE, _MAX_STARTUP_CONFIG_BYTES - len(result) + 1)
        chunk = os.read(file_fd, read_size)
        if not chunk:
            return bytes(result)
        result.extend(chunk)
        if len(result) > _MAX_STARTUP_CONFIG_BYTES:
            raise _UnsafeConfigError("startup configuration exceeds byte limit")


def _verify_parent_path(path: Path, original_parent: int, filename: str) -> None:
    verification_parent, verification_filename = _open_parent_directory(path)
    try:
        if verification_filename != filename:
            raise _UnsafeConfigError("startup configuration filename changed")
        _require_same_identity(os.fstat(original_parent), os.fstat(verification_parent))
    finally:
        os.close(verification_parent)


def _require_regular_path(file_stat: os.stat_result, path: Path) -> None:
    if stat.S_ISLNK(file_stat.st_mode):
        raise _SymlinkedConfigError(path)
    if not stat.S_ISREG(file_stat.st_mode):
        raise _UnsafeConfigError("startup configuration is not a regular file")


def _require_regular_file(file_stat: os.stat_result) -> None:
    if not stat.S_ISREG(file_stat.st_mode):
        raise _UnsafeConfigError("opened startup configuration is not a regular file")


def _require_directory_path(file_stat: os.stat_result, path: Path) -> None:
    if stat.S_ISLNK(file_stat.st_mode):
        raise _SymlinkedConfigError(path)
    if not stat.S_ISDIR(file_stat.st_mode):
        raise _UnsafeConfigError("startup configuration parent is not a directory")


def _require_directory_file(file_stat: os.stat_result) -> None:
    if not stat.S_ISDIR(file_stat.st_mode):
        raise _UnsafeConfigError("opened startup configuration parent is not a directory")


def _require_within_limit(size: int) -> None:
    if size < 0 or size > _MAX_STARTUP_CONFIG_BYTES:
        raise _UnsafeConfigError("startup configuration exceeds byte limit")


def _require_same_identity(first: os.stat_result, second: os.stat_result) -> None:
    if (first.st_dev, first.st_ino) != (second.st_dev, second.st_ino):
        raise _UnsafeConfigError("startup configuration identity changed")


def _require_unchanged(before: os.stat_result, after: os.stat_result) -> None:
    if (
        stat.S_IFMT(before.st_mode),
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    ) != (
        stat.S_IFMT(after.st_mode),
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    ):
        raise _UnsafeConfigError("startup configuration changed while reading")


def _load_json(text: str) -> Mapping[str, object]:
    document = json.loads(
        text,
        object_pairs_hook=_reject_duplicate_keys,
        parse_constant=_reject_nonstandard_constant,
    )
    return _as_object(document, "startup configuration root")


def _extract_claude_hooks(document: Mapping[str, object], path: Path) -> tuple[StartupHook, ...]:
    raw_hooks = document.get("hooks", {})
    hooks = _as_object(raw_hooks, "hooks")
    result: list[StartupHook] = []

    for event in _CLAUDE_STARTUP_EVENTS:
        if event not in hooks:
            continue
        groups = _as_array(hooks[event], f"hooks.{event}")
        for group_index, raw_group in enumerate(groups):
            group = _as_object(raw_group, f"hooks.{event}[{group_index}]")
            entries = _as_array(group.get("hooks"), f"hooks.{event}[{group_index}].hooks")
            for hook_index, raw_hook in enumerate(entries):
                hook = _as_object(
                    raw_hook,
                    f"hooks.{event}[{group_index}].hooks[{hook_index}]",
                )
                if hook.get("type") != "command":
                    continue
                command = hook.get("command")
                if not isinstance(command, str) or not command:
                    raise _StartupConfigError("Claude command hook must contain a command")
                result.append(StartupHook("claude", event, command, path))

    return tuple(result)


def _extract_vscode_hooks(document: Mapping[str, object], path: Path) -> tuple[StartupHook, ...]:
    if "tasks" not in document:
        return ()
    tasks = _as_array(document["tasks"], "tasks")
    result: list[StartupHook] = []

    for index, raw_task in enumerate(tasks):
        task = _as_object(raw_task, f"tasks[{index}]")
        if "runOptions" not in task:
            continue
        run_options = _as_object(task["runOptions"], f"tasks[{index}].runOptions")
        if run_options.get("runOn") != "folderOpen":
            continue
        command = task.get("command")
        if not isinstance(command, str) or not command:
            raise _StartupConfigError("folderOpen task must contain a command")
        result.append(StartupHook("vscode", "folderOpen", command, path))

    return tuple(result)


def _strip_jsonc(text: str) -> str:
    return _strip_trailing_commas(_strip_comments(text))


def _strip_comments(text: str) -> str:
    result: list[str] = []
    index = 0
    in_string = False
    escaped = False
    in_line_comment = False
    in_block_comment = False

    while index < len(text):
        char = text[index]
        next_char = text[index + 1] if index + 1 < len(text) else ""

        if in_line_comment:
            if char in "\r\n":
                in_line_comment = False
                result.append(char)
            else:
                result.append(" ")
            index += 1
            continue

        if in_block_comment:
            if char == "*" and next_char == "/":
                result.extend((" ", " "))
                in_block_comment = False
                index += 2
            else:
                result.append(char if char in "\r\n" else " ")
                index += 1
            continue

        if in_string:
            result.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            index += 1
            continue

        if char == '"':
            in_string = True
            result.append(char)
            index += 1
        elif char == "/" and next_char == "/":
            result.extend((" ", " "))
            in_line_comment = True
            index += 2
        elif char == "/" and next_char == "*":
            result.extend((" ", " "))
            in_block_comment = True
            index += 2
        else:
            result.append(char)
            index += 1

    if in_block_comment:
        raise _StartupConfigError("unterminated JSONC block comment")
    return "".join(result)


def _strip_trailing_commas(text: str) -> str:
    result: list[str] = []
    in_string = False
    escaped = False

    for index, char in enumerate(text):
        if in_string:
            result.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue

        if char == '"':
            in_string = True
            result.append(char)
            continue

        if char == ",":
            lookahead = index + 1
            while lookahead < len(text) and text[lookahead].isspace():
                lookahead += 1
            if lookahead < len(text) and text[lookahead] in "]}":
                continue
        result.append(char)

    return "".join(result)


def _as_object(value: object, context: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise _StartupConfigError(f"{context} must be an object")
    return cast(Mapping[str, object], value)


def _as_array(value: object, context: str) -> list[object]:
    if not isinstance(value, list):
        raise _StartupConfigError(f"{context} must be an array")
    return cast(list[object], value)


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _StartupConfigError("duplicate JSON object key")
        result[key] = value
    return result


def _reject_nonstandard_constant(value: str) -> object:
    raise _StartupConfigError(f"non-standard JSON constant: {value}")


def _error(path: Path, message: str) -> Diagnostic:
    return Diagnostic(DiagnosticKind.ERROR, path, message)

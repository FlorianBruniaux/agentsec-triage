from __future__ import annotations

import os
import stat
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

from agentsec.models import Diagnostic, DiagnosticKind

_FILE_ATTRIBUTE_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_MAX_SAFE_RECURSION_DEPTH = 256


@dataclass(frozen=True, slots=True)
class DiscoveryLimits:
    max_file_bytes: int
    max_files: int
    max_diagnostics: int
    max_depth: int = 64
    max_entries: int = 100_000
    max_directories: int = 10_000

    def __post_init__(self) -> None:
        for name, value in (
            ("max_file_bytes", self.max_file_bytes),
            ("max_files", self.max_files),
            ("max_diagnostics", self.max_diagnostics),
            ("max_depth", self.max_depth),
            ("max_entries", self.max_entries),
            ("max_directories", self.max_directories),
        ):
            if value < 0:
                raise ValueError(f"{name} must be non-negative")
        if self.max_depth > _MAX_SAFE_RECURSION_DEPTH:
            raise ValueError(
                f"max_depth must not exceed {_MAX_SAFE_RECURSION_DEPTH}"
            )


@dataclass(frozen=True, slots=True)
class DiscoveredFile:
    relative_path: Path
    absolute_path: Path
    size: int
    symlink: bool


@dataclass(slots=True)
class _DiagnosticBuffer:
    root: Path
    limit: int
    items: list[Diagnostic] = field(default_factory=list)
    truncated: bool = False

    def add(self, path: Path, message: str) -> None:
        diagnostic = Diagnostic(DiagnosticKind.ERROR, path, message)
        if len(self.items) < self.limit:
            self.items.append(diagnostic)
        else:
            self.truncated = True

    def finish(self) -> tuple[Diagnostic, ...]:
        diagnostics = sorted(
            self.items,
            key=lambda diagnostic: (
                diagnostic.kind,
                diagnostic.path.as_posix(),
                diagnostic.message,
            ),
        )
        if self.truncated:
            diagnostics.append(
                Diagnostic(
                    DiagnosticKind.ERROR,
                    self.root,
                    f"diagnostics truncated at max_diagnostics={self.limit}; discovery incomplete",
                )
            )
        return tuple(diagnostics)


@dataclass(frozen=True, slots=True)
class _OpenedDirectory:
    file_descriptor: int | None
    entries: tuple[_DirectoryEntry, ...]


@dataclass(frozen=True, slots=True)
class _DirectoryEntry:
    name: str
    listed_as_directory: bool


@dataclass(slots=True)
class _TraversalState:
    entries_seen: int = 0
    directories_opened: int = 0
    stopped: bool = False


def discover(
    root: Path, limits: DiscoveryLimits
) -> tuple[tuple[DiscoveredFile, ...], tuple[Diagnostic, ...]]:
    diagnostics = _DiagnosticBuffer(root=root, limit=limits.max_diagnostics)
    try:
        scan_root = root.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        diagnostics.add(root, f"cannot access scan root: {_error_message(error)}")
        return (), diagnostics.finish()

    if not scan_root.is_dir():
        diagnostics.add(root, "scan root is not a directory")
        return (), diagnostics.finish()

    root_stat = _safe_lstat(scan_root, diagnostics)
    if root_stat is None or not stat.S_ISDIR(root_stat.st_mode):
        diagnostics.add(root, "scan root cannot be safely inspected as a directory")
        return (), diagnostics.finish()

    discovered: list[DiscoveredFile] = []
    state = _TraversalState()
    _scan_directory(
        scan_root,
        root_stat,
        scan_root=scan_root,
        parent_fd=None,
        entry_name=None,
        limits=limits,
        discovered=discovered,
        diagnostics=diagnostics,
        depth=0,
        state=state,
    )

    return (
        tuple(sorted(discovered, key=lambda item: item.relative_path.as_posix())),
        diagnostics.finish(),
    )


def _scan_directory(
    path: Path,
    expected_stat: os.stat_result,
    *,
    scan_root: Path,
    parent_fd: int | None,
    entry_name: str | None,
    limits: DiscoveryLimits,
    discovered: list[DiscoveredFile],
    diagnostics: _DiagnosticBuffer,
    depth: int,
    state: _TraversalState,
) -> bool:
    if depth > limits.max_depth:
        diagnostics.add(
            path,
            f"directory traversal stopped at max_depth={limits.max_depth}; subtree skipped",
        )
        return False
    if state.directories_opened >= limits.max_directories:
        diagnostics.add(
            path,
            "directory traversal stopped at "
            f"max_directories={limits.max_directories}; discovery incomplete",
        )
        state.stopped = True
        return True
    opened = _open_directory(
        path,
        expected_stat,
        scan_root=scan_root,
        parent_fd=parent_fd,
        entry_name=entry_name,
        diagnostics=diagnostics,
        limits=limits,
        state=state,
    )
    if opened is None:
        return state.stopped
    if not _directory_path_matches(path, expected_stat, diagnostics):
        if opened.file_descriptor is not None:
            os.close(opened.file_descriptor)
        return False
    state.directories_opened += 1

    try:
        for directory_entry in opened.entries:
            name = directory_entry.name
            if name == ".git":
                continue
            candidate = path / name
            if opened.file_descriptor is None and not _path_fallback_parent_is_safe(
                path,
                expected_stat,
                scan_root,
                diagnostics,
            ):
                return False
            if (
                not directory_entry.listed_as_directory
                and len(discovered) >= limits.max_files
            ):
                diagnostics.add(
                    scan_root,
                    f"file discovery stopped at max_files={limits.max_files}; discovery incomplete",
                )
                return True
            entry_stat = _safe_entry_lstat(
                candidate,
                name,
                opened.file_descriptor,
                diagnostics,
            )
            if opened.file_descriptor is None and not _path_fallback_parent_is_safe(
                path,
                expected_stat,
                scan_root,
                diagnostics,
            ):
                return False
            if entry_stat is None:
                continue
            if stat.S_ISDIR(entry_stat.st_mode) and not _is_link_like(entry_stat):
                if _scan_directory(
                    candidate,
                    entry_stat,
                    scan_root=scan_root,
                    parent_fd=opened.file_descriptor,
                    entry_name=name,
                    limits=limits,
                    discovered=discovered,
                    diagnostics=diagnostics,
                    depth=depth + 1,
                    state=state,
                ):
                    return True
                continue
            if not _is_link_like(entry_stat) and not stat.S_ISREG(entry_stat.st_mode):
                diagnostics.add(
                    candidate,
                    "special file type is not analyzable; coverage incomplete",
                )
                continue
            if len(discovered) >= limits.max_files:
                diagnostics.add(
                    scan_root,
                    f"file discovery stopped at max_files={limits.max_files}; discovery incomplete",
                )
                return True
            discovered.append(
                DiscoveredFile(
                    relative_path=candidate.relative_to(scan_root),
                    absolute_path=candidate,
                    size=entry_stat.st_size,
                    symlink=_is_link_like(entry_stat),
                )
            )
    finally:
        if opened.file_descriptor is not None:
            os.close(opened.file_descriptor)
    return False


def _open_directory(
    path: Path,
    expected_stat: os.stat_result,
    *,
    scan_root: Path,
    parent_fd: int | None,
    entry_name: str | None,
    diagnostics: _DiagnosticBuffer,
    limits: DiscoveryLimits,
    state: _TraversalState,
) -> _OpenedDirectory | None:
    current_stat = _safe_lstat(path, diagnostics)
    if current_stat is None:
        return None
    if _is_link_like(current_stat) or not stat.S_ISDIR(current_stat.st_mode):
        diagnostics.add(path, "directory changed type before opening; subtree skipped")
        return None
    if _file_identity(current_stat) != _file_identity(expected_stat):
        diagnostics.add(path, "directory identity changed before opening; subtree skipped")
        return None

    if _supports_fd_traversal():
        return _open_directory_by_fd(
            path,
            expected_stat,
            parent_fd=parent_fd,
            entry_name=entry_name,
            diagnostics=diagnostics,
            limits=limits,
            state=state,
        )
    return _open_directory_by_path(
        path,
        expected_stat,
        scan_root,
        diagnostics,
        limits,
        state,
    )


def _open_directory_by_fd(
    path: Path,
    expected_stat: os.stat_result,
    *,
    parent_fd: int | None,
    entry_name: str | None,
    diagnostics: _DiagnosticBuffer,
    limits: DiscoveryLimits,
    state: _TraversalState,
) -> _OpenedDirectory | None:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    target: str | Path = path if parent_fd is None else entry_name or path.name
    try:
        file_descriptor = os.open(target, flags, dir_fd=parent_fd)
    except OSError as error:
        diagnostics.add(path, f"cannot safely open directory: {_error_message(error)}")
        return None

    try:
        keep_open = False
        opened_stat = os.fstat(file_descriptor)
        if (
            _is_link_like(opened_stat)
            or not stat.S_ISDIR(opened_stat.st_mode)
            or _file_identity(opened_stat) != _file_identity(expected_stat)
        ):
            diagnostics.add(path, "directory changed while opening; subtree skipped")
            return None
        entries = _read_directory_entries(
            file_descriptor,
            path,
            diagnostics,
            limits,
            state,
        )
        if entries is None:
            return None
        keep_open = True
        return _OpenedDirectory(file_descriptor=file_descriptor, entries=entries)
    finally:
        if not keep_open:
            os.close(file_descriptor)


def _open_directory_by_path(
    path: Path,
    expected_stat: os.stat_result,
    scan_root: Path,
    diagnostics: _DiagnosticBuffer,
    limits: DiscoveryLimits,
    state: _TraversalState,
) -> _OpenedDirectory | None:
    if not _path_is_confined(path, scan_root, diagnostics):
        return None
    try:
        iterator = os.scandir(path)
    except OSError as error:
        diagnostics.add(path, f"cannot open directory: {_error_message(error)}")
        return None

    with iterator:
        current_stat = _safe_lstat(path, diagnostics)
        if current_stat is None:
            return None
        if (
            _is_link_like(current_stat)
            or not stat.S_ISDIR(current_stat.st_mode)
            or _file_identity(current_stat) != _file_identity(expected_stat)
            or not _path_is_confined(path, scan_root, diagnostics)
        ):
            diagnostics.add(path, "directory changed while opening; subtree skipped")
            return None
        try:
            entries = _bounded_directory_entries(iterator, path, diagnostics, limits, state)
        except OSError as error:
            diagnostics.add(path, f"cannot read directory: {_error_message(error)}")
            return None
        if entries is None:
            return None
    return _OpenedDirectory(file_descriptor=None, entries=entries)


def _read_directory_entries(
    file_descriptor: int,
    path: Path,
    diagnostics: _DiagnosticBuffer,
    limits: DiscoveryLimits,
    state: _TraversalState,
) -> tuple[_DirectoryEntry, ...] | None:
    try:
        with os.scandir(file_descriptor) as iterator:
            return _bounded_directory_entries(iterator, path, diagnostics, limits, state)
    except OSError as error:
        diagnostics.add(path, f"cannot read directory: {_error_message(error)}")
        return None


def _bounded_directory_entries(
    iterator: Iterator[os.DirEntry[str]],
    path: Path,
    diagnostics: _DiagnosticBuffer,
    limits: DiscoveryLimits,
    state: _TraversalState,
) -> tuple[_DirectoryEntry, ...] | None:
    remaining = limits.max_entries - state.entries_seen
    entries: list[_DirectoryEntry] = []
    for entry in iterator:
        if len(entries) >= remaining:
            state.entries_seen += len(entries)
            state.stopped = True
            diagnostics.add(
                path,
                "directory traversal stopped at "
                f"max_entries={limits.max_entries}; discovery incomplete",
            )
            return None
        entries.append(
            _DirectoryEntry(
                name=entry.name,
                listed_as_directory=entry.is_dir(follow_symlinks=False),
            )
        )
    state.entries_seen += len(entries)
    return tuple(sorted(entries, key=lambda entry: entry.name))


def _path_is_confined(path: Path, scan_root: Path, diagnostics: _DiagnosticBuffer) -> bool:
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(scan_root)
    except (OSError, RuntimeError, ValueError) as error:
        diagnostics.add(path, f"directory escaped scan root: {_error_message(error)}")
        return False
    if os.path.normcase(os.path.abspath(resolved)) != os.path.normcase(os.path.abspath(path)):
        diagnostics.add(path, "directory path contains a link or reparse point; subtree skipped")
        return False
    return True


def _supports_fd_traversal() -> bool:
    return (
        bool(getattr(os, "O_NOFOLLOW", 0))
        and os.open in os.supports_dir_fd
        and os.stat in os.supports_dir_fd
        and os.stat in os.supports_follow_symlinks
        and os.scandir in os.supports_fd
    )


def _file_identity(entry_stat: os.stat_result) -> tuple[int, int]:
    return entry_stat.st_dev, entry_stat.st_ino


def _safe_lstat(path: Path, diagnostics: _DiagnosticBuffer) -> os.stat_result | None:
    try:
        return path.lstat()
    except OSError as error:
        diagnostics.add(path, f"cannot inspect entry: {_error_message(error)}")
        return None


def _safe_entry_lstat(
    path: Path,
    name: str,
    parent_fd: int | None,
    diagnostics: _DiagnosticBuffer,
) -> os.stat_result | None:
    if parent_fd is None:
        return _safe_lstat(path, diagnostics)
    try:
        return os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError as error:
        diagnostics.add(path, f"cannot inspect entry: {_error_message(error)}")
        return None


def _directory_path_matches(
    path: Path, expected_stat: os.stat_result, diagnostics: _DiagnosticBuffer
) -> bool:
    current_stat = _safe_lstat(path, diagnostics)
    if current_stat is None:
        return False
    if (
        _is_link_like(current_stat)
        or not stat.S_ISDIR(current_stat.st_mode)
        or _file_identity(current_stat) != _file_identity(expected_stat)
    ):
        diagnostics.add(path, "directory changed after opening; subtree skipped")
        return False
    return True


def _path_fallback_parent_is_safe(
    path: Path,
    expected_stat: os.stat_result,
    scan_root: Path,
    diagnostics: _DiagnosticBuffer,
) -> bool:
    return _directory_path_matches(path, expected_stat, diagnostics) and _path_is_confined(
        path,
        scan_root,
        diagnostics,
    )


def _is_link_like(entry_stat: os.stat_result) -> bool:
    file_attributes = getattr(entry_stat, "st_file_attributes", 0)
    return stat.S_ISLNK(entry_stat.st_mode) or bool(
        file_attributes & _FILE_ATTRIBUTE_REPARSE_POINT
    )


def _error_message(error: OSError | RuntimeError | ValueError) -> str:
    if isinstance(error, OSError) and error.strerror:
        return error.strerror
    return str(error) or type(error).__name__

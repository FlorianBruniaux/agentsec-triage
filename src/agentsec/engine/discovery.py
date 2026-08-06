from __future__ import annotations

import os
import stat
from dataclasses import dataclass, field
from heapq import merge
from pathlib import Path

from agentsec.models import Diagnostic, DiagnosticKind


@dataclass(frozen=True, slots=True)
class DiscoveryLimits:
    max_file_bytes: int
    max_files: int
    max_diagnostics: int

    def __post_init__(self) -> None:
        for name, value in (
            ("max_file_bytes", self.max_file_bytes),
            ("max_files", self.max_files),
            ("max_diagnostics", self.max_diagnostics),
        ):
            if value < 0:
                raise ValueError(f"{name} must be non-negative")


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

    discovered: list[DiscoveredFile] = []
    limit_reached = False

    def report_walk_error(error: OSError) -> None:
        error_path = Path(error.filename) if error.filename else scan_root
        if not error_path.is_absolute():
            error_path = scan_root / error_path
        diagnostics.add(error_path, f"cannot traverse directory: {_error_message(error)}")

    for current, directory_names, file_names in os.walk(
        scan_root,
        topdown=True,
        onerror=report_walk_error,
        followlinks=False,
    ):
        current_path = Path(current)
        try:
            current_path.relative_to(scan_root)
        except ValueError:
            diagnostics.add(current_path, "walk escaped scan root; subtree skipped")
            directory_names.clear()
            continue

        traversable_directories: list[str] = []
        directory_entries = ((name, True) for name in sorted(directory_names))
        file_entries = ((name, False) for name in sorted(file_names))

        for name, listed_as_directory in merge(directory_entries, file_entries):
            if name == ".git":
                continue
            absolute_path = current_path / name
            if not listed_as_directory and len(discovered) >= limits.max_files:
                diagnostics.add(
                    scan_root,
                    f"file discovery stopped at max_files={limits.max_files}; discovery incomplete",
                )
                limit_reached = True
                break

            entry_stat = _safe_lstat(absolute_path, diagnostics)
            if entry_stat is None:
                continue
            if listed_as_directory and stat.S_ISDIR(entry_stat.st_mode):
                traversable_directories.append(name)
                continue
            if len(discovered) >= limits.max_files:
                diagnostics.add(
                    scan_root,
                    f"file discovery stopped at max_files={limits.max_files}; discovery incomplete",
                )
                limit_reached = True
                break
            discovered.append(
                DiscoveredFile(
                    relative_path=absolute_path.relative_to(scan_root),
                    absolute_path=absolute_path,
                    size=entry_stat.st_size,
                    symlink=stat.S_ISLNK(entry_stat.st_mode),
                )
            )
        directory_names[:] = traversable_directories

        if limit_reached:
            break

    return (
        tuple(sorted(discovered, key=lambda item: item.relative_path.as_posix())),
        diagnostics.finish(),
    )


def _safe_lstat(path: Path, diagnostics: _DiagnosticBuffer) -> os.stat_result | None:
    try:
        return path.lstat()
    except OSError as error:
        diagnostics.add(path, f"cannot inspect entry: {_error_message(error)}")
        return None


def _error_message(error: OSError | RuntimeError) -> str:
    if isinstance(error, OSError) and error.strerror:
        return error.strerror
    return str(error) or type(error).__name__

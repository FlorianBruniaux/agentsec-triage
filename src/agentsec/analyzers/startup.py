from __future__ import annotations

import json
import os
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import cast

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
    if not _supports_anchored_no_follow():
        raise _UnsafeConfigError("safe startup configuration opening is unavailable")
    return _read_text_anchored(path)


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

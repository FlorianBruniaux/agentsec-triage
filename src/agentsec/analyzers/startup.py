from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from agentsec.analyzers.safe_io import safe_read_regular_file
from agentsec.models import Diagnostic, DiagnosticKind

_MAX_STARTUP_CONFIG_BYTES = 1024 * 1024
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


def inspect_startup_config(
    path: Path,
) -> tuple[tuple[StartupHook, ...], tuple[Diagnostic, ...]]:
    """Safely read and parse repository startup configuration."""
    content, diagnostics = safe_read_regular_file(path, _MAX_STARTUP_CONFIG_BYTES)
    if content is None:
        return (), diagnostics
    return inspect_startup_config_content(content, path)


def inspect_startup_config_content(
    content: bytes,
    path: Path,
) -> tuple[tuple[StartupHook, ...], tuple[Diagnostic, ...]]:
    """Parse already-read startup configuration bytes without reopening the path."""
    if len(content) > _MAX_STARTUP_CONFIG_BYTES:
        return (), (_error(path, "Startup configuration exceeds 1 MiB parser limit"),)
    is_claude = path.parent.name == ".claude" and path.name in {
        "settings.json",
        "settings.local.json",
    }
    is_vscode = path.parent.name == ".vscode" and path.name == "tasks.json"
    if not is_claude and not is_vscode:
        return (), (_error(path, "Unable to parse startup configuration"),)

    try:
        text = content.decode("utf-8", errors="strict")
        if is_claude:
            hooks = _extract_claude_hooks(_load_json(text), path)
        else:
            hooks = _extract_vscode_hooks(_load_json(_strip_jsonc(text)), path)
    except (UnicodeError, ValueError, RecursionError):
        return (), (_error(path, "Unable to parse startup configuration"),)
    return hooks, ()


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

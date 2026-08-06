from __future__ import annotations

import re
from collections.abc import Mapping
from pathlib import Path

_SECRET_PATTERN = re.compile(
    r"gh[pousr]_[A-Za-z0-9_]{20,}|npm_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|sk-ant-[A-Za-z0-9_-]{20,}"
)
_USER_HOME_PATH_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_/])(?:/(?:Users|home)/[^/\s]+(?:/[^\s\"'<>]*)*|"
    r"[A-Za-z]:\\Users\\[^\\\s]+(?:\\[^\s\"'<>]*)*)"
)


def redact_result(payload: dict[str, object], root: Path) -> dict[str, object]:
    """Return a recursively redacted copy of a scan result payload."""
    return _redact_mapping(payload, str(root.absolute()))


def _redact_mapping(payload: Mapping[str, object], root: str) -> dict[str, object]:
    return {key: _redact_value(value, root) for key, value in payload.items()}


def _redact_value(value: object, root: str) -> object:
    if isinstance(value, Mapping):
        return _redact_mapping(value, root)
    if isinstance(value, list):
        return [_redact_value(item, root) for item in value]
    if isinstance(value, str):
        redacted = value.replace(root, "<SCAN_ROOT>")
        redacted = _USER_HOME_PATH_PATTERN.sub("<REDACTED_PATH>", redacted)
        return _SECRET_PATTERN.sub("<REDACTED_SECRET>", redacted)
    return value

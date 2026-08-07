from __future__ import annotations

import re
from collections.abc import Mapping
from pathlib import Path, PurePath

_SECRET_PATTERN = re.compile(
    r"gh[pousr]_[A-Za-z0-9_]{20,}|npm_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|sk-ant-[A-Za-z0-9_-]{20,}"
)
_USER_HOME_PATH_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_/])(?:/(?:Users|home)/[^\"'<>)]*?(?=[\"')]|$)|"
    r"[A-Za-z]:\\Users\\[^\"'<>)]*?(?=[\"')]|$))"
)


def redact_result(payload: dict[str, object], root: PurePath) -> dict[str, object]:
    """Return a recursively redacted copy of a scan result payload."""
    return _redact_mapping(payload, _root_forms(root))


def redact_text(text: str, root: PurePath | None = None) -> str:
    """Redact a user-facing message without requiring a scan result payload."""
    redacted = _redact_value(text, _root_forms(root) if root is not None else ())
    assert isinstance(redacted, str)
    return redacted


def _root_forms(root: PurePath) -> tuple[str, ...]:
    absolute_root: PurePath = root.absolute() if isinstance(root, Path) else root
    return tuple(dict.fromkeys((str(absolute_root), absolute_root.as_posix())))


def _redact_mapping(
    payload: Mapping[str, object], roots: tuple[str, ...]
) -> dict[str, object]:
    return {key: _redact_value(value, roots) for key, value in payload.items()}


def _redact_value(value: object, roots: tuple[str, ...]) -> object:
    if isinstance(value, Mapping):
        return _redact_mapping(value, roots)
    if isinstance(value, list):
        return [_redact_value(item, roots) for item in value]
    if isinstance(value, str):
        redacted = value
        for root in roots:
            if root:
                redacted = redacted.replace(root, "<SCAN_ROOT>")
        redacted = _USER_HOME_PATH_PATTERN.sub("<REDACTED_PATH>", redacted)
        return _SECRET_PATTERN.sub("<REDACTED_SECRET>", redacted)
    return value

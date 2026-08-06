from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from agentsec.models import Diagnostic, DiagnosticKind


@dataclass(frozen=True, slots=True)
class InstalledPackage:
    name: str
    version: str
    manifest: Path
    preinstall: str | None


class _ManifestError(ValueError):
    pass


def inspect_package_manifest(
    path: Path,
) -> tuple[InstalledPackage | None, tuple[Diagnostic, ...]]:
    """Extract exact installed-package evidence from a package manifest."""
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError, ValueError):
        return None, (_error(path, "Unable to read package manifest"),)

    try:
        document = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonstandard_constant,
        )
        root = _as_object(document, "package manifest root")
        name = _required_non_empty_string(root, "name")
        version = _required_non_empty_string(root, "version")
        preinstall = _preinstall(root)
    except (ValueError, RecursionError):
        return None, (_error(path, "Unable to parse package manifest"),)

    return InstalledPackage(name, version, path, preinstall), ()


def _preinstall(root: Mapping[object, object]) -> str | None:
    if "scripts" not in root:
        return None
    scripts = _as_object(root["scripts"], "scripts")
    if "preinstall" not in scripts:
        return None
    value = scripts["preinstall"]
    if not isinstance(value, str):
        raise _ManifestError("scripts.preinstall must be a string")
    return value


def _required_non_empty_string(document: Mapping[object, object], key: str) -> str:
    value = document.get(key)
    if not isinstance(value, str) or not value:
        raise _ManifestError(f"{key} must be a non-empty string")
    return value


def _as_object(value: object, context: str) -> Mapping[object, object]:
    if not isinstance(value, Mapping):
        raise _ManifestError(f"{context} must be an object")
    return value


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _ManifestError("duplicate JSON object key")
        result[key] = value
    return result


def _reject_nonstandard_constant(value: str) -> object:
    raise _ManifestError(f"non-standard JSON constant: {value}")


def _error(path: Path, message: str) -> Diagnostic:
    return Diagnostic(DiagnosticKind.ERROR, path, message)

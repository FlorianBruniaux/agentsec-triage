#!/usr/bin/env python3
"""Validate the inert competitive benchmark fixture corpus."""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import cast
from urllib.parse import urlparse

PROJECT_ROOT = Path(__file__).parents[1]
DEFAULT_MANIFEST = PROJECT_ROOT / "research" / "competitive-fixtures" / "manifest.yaml"

ROOT_FIELDS = frozenset({"schema_version", "fixtures"})
FIXTURE_FIELDS = frozenset(
    {
        "id",
        "directory",
        "kind",
        "technique",
        "expected_evidence",
        "source_url",
        "applicable_tool_classes",
        "inert",
        "control",
        "files",
    }
)
FILE_FIELDS = frozenset({"path", "type"})
KINDS = frozenset({"positive", "negative", "near_miss", "unsupported", "safety"})
TOOL_CLASSES = frozenset(
    {"repository", "campaign", "agent_config", "skill", "mcp", "ci", "package"}
)
FILE_TYPES = frozenset({"text", "binary_placeholder", "symlink"})
ARCHIVE_SUFFIXES = frozenset({".zip", ".tar", ".tgz", ".gz", ".bz2", ".xz", ".7z", ".rar"})
SLUG = re.compile(r"^[a-z0-9][a-z0-9-]*$")
SECRET_PATTERNS = (
    re.compile(rb"AKIA[0-9A-Z]{16}"),
    re.compile(rb"gh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(rb"xox[baprs]-[A-Za-z0-9-]{10,}"),
    re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
)
MAX_FIXTURE_FILE_BYTES = 1_000_000


def _load_manifest(path: Path) -> dict[str, object]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"fixture manifest: {error}") from error
    if not isinstance(payload, dict):
        raise ValueError("fixture manifest: expected a JSON object")
    return cast(dict[str, object], payload)


def _required_string(
    value: dict[str, object],
    field: str,
    label: str,
    errors: list[str],
) -> str | None:
    if field not in value:
        errors.append(f"{label}.{field}: missing required field")
        return None
    candidate = value[field]
    if not isinstance(candidate, str) or not candidate:
        errors.append(f"{label}.{field}: expected a non-empty string")
        return None
    return candidate


def _relative_path(value: str) -> Path | None:
    path = Path(value)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        return None
    return path


def _https_url(value: str) -> bool:
    parsed = urlparse(value)
    return (
        parsed.scheme == "https"
        and bool(parsed.hostname)
        and not parsed.username
        and not parsed.password
    )


def _string_list(
    value: object,
    label: str,
    errors: list[str],
    *,
    allowed: frozenset[str] | None = None,
) -> list[str]:
    if (
        not isinstance(value, list)
        or not value
        or not all(isinstance(item, str) and item for item in value)
    ):
        errors.append(f"{label}: expected a non-empty string array")
        return []
    items = cast(list[str], value)
    if len(set(items)) != len(items):
        errors.append(f"{label}: duplicate values are forbidden")
    if allowed is not None:
        for item in items:
            if item not in allowed:
                errors.append(f"{label}: unknown value '{item}'")
    return items


def _filesystem_entries(root: Path) -> dict[str, Path]:
    entries: dict[str, Path] = {}
    for current, directories, files in os.walk(root, followlinks=False):
        current_path = Path(current)
        for directory in list(directories):
            candidate = current_path / directory
            if candidate.is_symlink():
                entries[candidate.relative_to(root).as_posix()] = candidate
                directories.remove(directory)
        for filename in files:
            candidate = current_path / filename
            entries[candidate.relative_to(root).as_posix()] = candidate
    return entries


def _validate_content(path: Path, label: str, file_type: str, errors: list[str]) -> None:
    try:
        mode = path.lstat().st_mode
    except OSError as error:
        errors.append(f"{label}: unable to inspect file: {error}")
        return

    if file_type == "symlink":
        if not path.is_symlink():
            errors.append(f"{label}: expected a symbolic link")
        return

    if mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
        errors.append(f"{label}: executable permission bits are forbidden")

    if path.suffix.casefold() in ARCHIVE_SUFFIXES:
        errors.append(f"{label}: archive files are forbidden")

    if path.is_symlink():
        errors.append(f"{label}: undeclared symbolic link")
        return
    if not path.is_file():
        errors.append(f"{label}: expected a regular file")
        return

    try:
        size = path.stat().st_size
        content = path.read_bytes()
    except OSError as error:
        errors.append(f"{label}: unable to read file: {error}")
        return
    if size > MAX_FIXTURE_FILE_BYTES:
        errors.append(f"{label}: fixture file exceeds {MAX_FIXTURE_FILE_BYTES} bytes")
        return
    for pattern in SECRET_PATTERNS:
        if pattern.search(content):
            errors.append(f"{label}: secret-shaped content is forbidden")
            break
    if file_type == "text":
        try:
            content.decode("utf-8")
        except UnicodeDecodeError:
            errors.append(f"{label}: text fixture is not valid UTF-8")


def _validate_files(
    fixture: dict[str, object],
    fixture_root: Path,
    label: str,
    errors: list[str],
) -> None:
    files_value = fixture.get("files")
    if not isinstance(files_value, list) or not files_value:
        errors.append(f"{label}.files: expected a non-empty array")
        return

    declared: dict[str, str] = {}
    for index, raw_file in enumerate(files_value):
        file_label = f"{label}.files[{index}]"
        if not isinstance(raw_file, dict):
            errors.append(f"{file_label}: expected an object")
            continue
        file_entry = cast(dict[str, object], raw_file)
        for field in sorted(set(file_entry) - FILE_FIELDS):
            errors.append(f"{file_label}.{field}: unknown field")
        path_value = _required_string(file_entry, "path", file_label, errors)
        type_value = _required_string(file_entry, "type", file_label, errors)
        if path_value is None or type_value is None:
            continue
        relative = _relative_path(path_value)
        if relative is None:
            errors.append(f"{file_label}.path: expected a confined relative path")
            continue
        normalized = relative.as_posix()
        if normalized in declared:
            errors.append(f"{file_label}.path: duplicate value '{normalized}'")
            continue
        if type_value not in FILE_TYPES:
            errors.append(f"{file_label}.type: unknown value '{type_value}'")
            continue
        if type_value == "binary_placeholder" and normalized != "bun.lockb":
            errors.append(f"{file_label}: binary placeholder is allowed only for bun.lockb")
        declared[normalized] = type_value

    actual = _filesystem_entries(fixture_root) if fixture_root.is_dir() else {}
    if not fixture_root.is_dir():
        errors.append(f"{label}.directory: fixture directory does not exist")
    for path_value in sorted(set(actual) - set(declared)):
        errors.append(f"{label}.files: undeclared file '{path_value}'")
    for path_value in sorted(set(declared) - set(actual)):
        errors.append(f"{label}.files: declared file does not exist '{path_value}'")
    for path_value in sorted(set(actual) & set(declared)):
        _validate_content(
            actual[path_value], f"{label}.files[{path_value}]", declared[path_value], errors
        )


def validate_manifest(payload: dict[str, object], fixture_base: Path) -> list[str]:
    errors: list[str] = []
    for field in sorted(set(payload) - ROOT_FIELDS):
        errors.append(f"{field}: unknown field")
    if payload.get("schema_version") != "1":
        errors.append("schema_version: expected '1'")

    fixtures_value = payload.get("fixtures")
    if not isinstance(fixtures_value, list) or not fixtures_value:
        errors.append("fixtures: expected a non-empty array")
        return errors

    seen_ids: set[str] = set()
    controls: list[tuple[str, str]] = []
    for index, raw_fixture in enumerate(fixtures_value):
        label = f"fixtures[{index}]"
        if not isinstance(raw_fixture, dict):
            errors.append(f"{label}: expected an object")
            continue
        fixture = cast(dict[str, object], raw_fixture)
        for field in sorted(set(fixture) - FIXTURE_FIELDS):
            errors.append(f"{label}.{field}: unknown field")
        fixture_id = _required_string(fixture, "id", label, errors)
        directory = _required_string(fixture, "directory", label, errors)
        kind = _required_string(fixture, "kind", label, errors)
        _required_string(fixture, "technique", label, errors)
        source_url = _required_string(fixture, "source_url", label, errors)

        if fixture_id is not None:
            if not SLUG.fullmatch(fixture_id):
                errors.append(f"{label}.id: invalid slug '{fixture_id}'")
            if fixture_id in seen_ids:
                errors.append(f"{label}.id: duplicate value '{fixture_id}'")
            seen_ids.add(fixture_id)
        if directory is not None and directory != fixture_id:
            errors.append(f"{label}.directory: must equal fixture id")
        if kind is not None and kind not in KINDS:
            errors.append(f"{label}.kind: unknown value '{kind}'")
        if source_url is not None and not _https_url(source_url):
            errors.append(f"{label}.source_url: expected a credential-free HTTPS URL")

        _string_list(fixture.get("expected_evidence"), f"{label}.expected_evidence", errors)
        _string_list(
            fixture.get("applicable_tool_classes"),
            f"{label}.applicable_tool_classes",
            errors,
            allowed=TOOL_CLASSES,
        )
        if fixture.get("inert") is not True:
            errors.append(f"{label}.inert: expected true")

        control = fixture.get("control")
        if control is not None and not isinstance(control, str):
            errors.append(f"{label}.control: expected a fixture id or null")
        elif isinstance(control, str) and fixture_id is not None:
            controls.append((label, control))

        if directory is not None and _relative_path(directory) is not None:
            _validate_files(fixture, fixture_base / directory, label, errors)

    for label, control in controls:
        if control not in seen_ids:
            errors.append(f"{label}.control: unknown fixture id '{control}'")
    return errors


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    return parser


def main(arguments: Sequence[str] | None = None) -> int:
    options = _parser().parse_args(arguments)
    try:
        payload = _load_manifest(options.manifest)
    except ValueError as error:
        print(error, file=sys.stderr)
        return 1
    errors = validate_manifest(payload, options.manifest.resolve().parent)
    for validation_error in errors:
        print(f"competitive fixtures: {validation_error}", file=sys.stderr)
    if errors:
        return 1
    fixtures = cast(list[object], payload["fixtures"])
    label = "fixture" if len(fixtures) == 1 else "fixtures"
    print(f"Validated {len(fixtures)} inert competitive {label}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

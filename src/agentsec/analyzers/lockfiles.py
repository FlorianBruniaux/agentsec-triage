from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from agentsec.models import Diagnostic, DiagnosticKind


@dataclass(frozen=True, slots=True)
class ResolvedPackage:
    name: str
    version: str
    source: Path


class _LockfileParseError(ValueError):
    pass


def parse_lockfile(
    path: Path,
) -> tuple[tuple[ResolvedPackage, ...], tuple[Diagnostic, ...]]:
    """Extract resolved package versions from a supported lockfile."""
    if path.name == "bun.lockb":
        return (), (_error(path, "Unsupported binary Bun lockfile format"),)

    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return (), (_error(path, "Unable to read lockfile"),)

    try:
        if path.suffix == ".json":
            packages = _parse_npm(text, path)
        elif path.suffix in {".yaml", ".yml"}:
            packages = _parse_pnpm(text, path)
        elif path.name == "bun.lock":
            packages = _parse_bun(text, path)
        elif path.suffix == ".lock":
            packages = _parse_yarn(text, path)
        else:
            raise _LockfileParseError("Unsupported lockfile format")
    except (json.JSONDecodeError, RecursionError, _LockfileParseError):
        return (), (_error(path, "Unable to parse lockfile"),)

    return _finalize(packages), ()


def _parse_npm(text: str, source: Path) -> list[ResolvedPackage]:
    document = json.loads(text)
    if not isinstance(document, dict):
        raise _LockfileParseError("npm lockfile root must be an object")

    lockfile_version = document.get("lockfileVersion")
    if not isinstance(lockfile_version, int) or isinstance(lockfile_version, bool):
        raise _LockfileParseError("npm lockfileVersion must be an integer")
    if lockfile_version not in {1, 2, 3}:
        raise _LockfileParseError("unsupported npm lockfileVersion")

    if lockfile_version == 1:
        dependencies = _required_mapping(document, "dependencies")
        packages: list[ResolvedPackage] = []
        _collect_npm_dependencies(dependencies, source, packages)
        return packages

    package_entries = _required_mapping(document, "packages")
    packages = []
    for package_path, raw_metadata in package_entries.items():
        if not isinstance(package_path, str) or not package_path:
            continue
        if "node_modules/" not in package_path:
            continue
        metadata = _as_mapping(raw_metadata, "npm package metadata")
        version = _required_string(metadata, "version")
        name = package_path.rsplit("node_modules/", 1)[1]
        name, version = _normalize_npm_alias(name, version)
        packages.append(ResolvedPackage(name, version, source))
    return packages


def _parse_pnpm(text: str, source: Path) -> list[ResolvedPackage]:
    lockfile_version = _pnpm_lockfile_version(text)
    if lockfile_version not in range(5, 10):
        raise _LockfileParseError("unsupported pnpm lockfileVersion")

    package_keys = _yaml_section_keys(text, "packages")
    packages = []
    for package_key in package_keys:
        if lockfile_version == 5:
            name, version = _split_pnpm_v5_key(package_key)
        else:
            name, version = _split_name_version(package_key.lstrip("/"), "pnpm package key")
            version = version.partition("(")[0]
            if not version:
                raise _LockfileParseError("invalid pnpm package version")
        packages.append(ResolvedPackage(name, version, source))
    return packages


def _pnpm_lockfile_version(text: str) -> int:
    for line in text.splitlines():
        if line.startswith("lockfileVersion:"):
            raw_version = _unquote(line.partition(":")[2].strip())
            match = re.fullmatch(r"([0-9]+)(?:\.[0-9]+)?", raw_version)
            if match is None:
                raise _LockfileParseError("invalid pnpm lockfileVersion")
            return int(match.group(1))
    raise _LockfileParseError("missing pnpm lockfileVersion")


def _yaml_section_keys(text: str, section: str) -> tuple[str, ...]:
    in_section = False
    keys: list[str] = []
    for line in text.splitlines():
        if not in_section:
            if line == f"{section}:":
                in_section = True
            continue

        if line and not line.startswith((" ", "\t")):
            break
        if not line.startswith("  ") or line.startswith("    "):
            continue
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or not stripped.endswith(":"):
            raise _LockfileParseError(f"invalid {section} entry")
        key = _unquote(stripped[:-1].strip())
        if not key:
            raise _LockfileParseError(f"empty {section} entry")
        keys.append(key)

    if not in_section:
        raise _LockfileParseError(f"missing {section} section")
    return tuple(keys)


def _split_pnpm_v5_key(package_key: str) -> tuple[str, str]:
    value = package_key.lstrip("/")
    if value.startswith("@"):
        parts = value.split("/")
        if len(parts) != 3 or not all(parts):
            raise _LockfileParseError("invalid scoped pnpm v5 package key")
        name = "/".join(parts[:2])
        version = parts[2]
    else:
        name, separator, version = value.partition("/")
        if not separator or not name or not version:
            raise _LockfileParseError("invalid pnpm v5 package key")
    version = version.partition("_")[0]
    if not version:
        raise _LockfileParseError("invalid pnpm v5 package version")
    return name, version


def _unquote(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        return value[1:-1]
    return value


def _parse_yarn(text: str, source: Path) -> list[ResolvedPackage]:
    packages: list[ResolvedPackage] = []
    header: str | None = None
    version: str | None = None
    resolution: str | None = None

    def finish_block() -> None:
        nonlocal header, version, resolution
        if header is None or header == "__metadata":
            header = None
            version = None
            resolution = None
            return
        if version is None:
            raise _LockfileParseError("Yarn package block has no version")
        name = _yarn_name(header, resolution)
        packages.append(ResolvedPackage(name, version, source))
        header = None
        version = None
        resolution = None

    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line.startswith((" ", "\t")):
            finish_block()
            stripped = line.strip()
            if not stripped.endswith(":"):
                raise _LockfileParseError("invalid Yarn block header")
            header = stripped[:-1].strip()
            continue
        if header is None:
            raise _LockfileParseError("Yarn metadata outside package block")

        metadata = line.strip()
        if metadata.startswith("version "):
            version = _unquote(metadata.removeprefix("version ").strip())
        elif metadata.startswith("version:"):
            version = _unquote(metadata.partition(":")[2].strip())
        elif metadata.startswith("resolution:"):
            resolution = _unquote(metadata.partition(":")[2].strip())

    finish_block()
    return packages


def _yarn_name(header: str, resolution: str | None) -> str:
    if resolution is not None:
        resolved_name, separator, _ = resolution.rpartition("@npm:")
        if separator and resolved_name:
            return resolved_name

    first_descriptor = header.split(",", 1)[0].strip()
    first_descriptor = _unquote(first_descriptor)
    _, alias_separator, alias_target = first_descriptor.partition("@npm:")
    if alias_separator:
        name, _ = _split_name_version(alias_target, "Yarn npm alias")
        return name
    name, _ = _split_name_version(first_descriptor, "Yarn descriptor")
    return name


def _parse_bun(text: str, source: Path) -> list[ResolvedPackage]:
    document = json.loads(_normalize_jsonc(text))
    root = _as_mapping(document, "Bun lockfile root")
    package_entries = _required_mapping(root, "packages")
    packages = []
    for raw_name, raw_metadata in package_entries.items():
        if not isinstance(raw_name, str) or not raw_name:
            raise _LockfileParseError("Bun package name must be a non-empty string")
        if not isinstance(raw_metadata, list) or not raw_metadata:
            raise _LockfileParseError("Bun package metadata must be a non-empty array")
        descriptor = raw_metadata[0]
        if not isinstance(descriptor, str):
            raise _LockfileParseError("Bun package descriptor must be a string")
        name, version = _split_name_version(descriptor, "Bun package descriptor")
        packages.append(ResolvedPackage(name, version, source))
    return packages


def _normalize_jsonc(text: str) -> str:
    without_comments: list[str] = []
    index = 0
    in_string = False
    escaped = False
    while index < len(text):
        character = text[index]
        following = text[index + 1] if index + 1 < len(text) else ""
        if in_string:
            without_comments.append(character)
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            index += 1
            continue
        if character == '"':
            in_string = True
            without_comments.append(character)
            index += 1
            continue
        if character == "/" and following == "/":
            newline = text.find("\n", index + 2)
            index = len(text) if newline == -1 else newline
            continue
        if character == "/" and following == "*":
            end = text.find("*/", index + 2)
            if end == -1:
                raise _LockfileParseError("unterminated Bun lockfile comment")
            index = end + 2
            continue
        without_comments.append(character)
        index += 1

    normalized = "".join(without_comments)
    without_trailing_commas: list[str] = []
    in_string = False
    escaped = False
    for index, character in enumerate(normalized):
        if in_string:
            without_trailing_commas.append(character)
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
            without_trailing_commas.append(character)
            continue
        if character == ",":
            remainder = normalized[index + 1 :].lstrip()
            if remainder.startswith(("}", "]")):
                continue
        without_trailing_commas.append(character)
    return "".join(without_trailing_commas)


def _collect_npm_dependencies(
    dependencies: Mapping[object, object],
    source: Path,
    packages: list[ResolvedPackage],
) -> None:
    for raw_name, raw_metadata in dependencies.items():
        if not isinstance(raw_name, str) or not raw_name:
            raise _LockfileParseError("npm dependency name must be a non-empty string")
        metadata = _as_mapping(raw_metadata, "npm dependency metadata")
        version = _required_string(metadata, "version")
        name, version = _normalize_npm_alias(raw_name, version)
        packages.append(ResolvedPackage(name, version, source))

        nested = metadata.get("dependencies")
        if nested is not None:
            _collect_npm_dependencies(
                _as_mapping(nested, "nested npm dependencies"), source, packages
            )


def _normalize_npm_alias(name: str, version: str) -> tuple[str, str]:
    if not version.startswith("npm:"):
        return name, version
    return _split_name_version(version.removeprefix("npm:"), "npm alias")


def _split_name_version(value: str, context: str) -> tuple[str, str]:
    name, separator, version = value.rpartition("@")
    if not separator or not name or not version:
        raise _LockfileParseError(f"invalid {context}")
    return name, version


def _required_mapping(document: Mapping[object, object], key: str) -> Mapping[object, object]:
    if key not in document:
        raise _LockfileParseError(f"missing {key}")
    return _as_mapping(document[key], key)


def _as_mapping(value: object, context: str) -> Mapping[object, object]:
    if not isinstance(value, Mapping):
        raise _LockfileParseError(f"{context} must be an object")
    return value


def _required_string(document: Mapping[object, object], key: str) -> str:
    value = document.get(key)
    if not isinstance(value, str) or not value:
        raise _LockfileParseError(f"{key} must be a non-empty string")
    return value


def _finalize(packages: list[ResolvedPackage]) -> tuple[ResolvedPackage, ...]:
    return tuple(
        sorted(
            set(packages),
            key=lambda package: (package.name, package.version, str(package.source)),
        )
    )


def _error(path: Path, message: str) -> Diagnostic:
    return Diagnostic(DiagnosticKind.ERROR, path, message)

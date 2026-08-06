from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Protocol, TypedDict, cast

import yaml  # type: ignore[import-untyped]
from jsonschema import Draft202012Validator  # type: ignore[import-untyped]

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SOURCE = PROJECT_ROOT / "data" / "threat-db.yaml"
DEFAULT_SCHEMA = PROJECT_ROOT / "data" / "threat-db.schema.json"
DEFAULT_OUTPUT = PROJECT_ROOT / "src" / "agentsec" / "resources" / "threat-db.json"


class ThreatDatabaseBuildError(Exception):
    """Raised when authoring data cannot be loaded, validated, or normalized."""


class DuplicateYamlKeyError(ValueError):
    """Raised when YAML contains an ambiguous mapping."""


class DuplicateJsonKeyError(ValueError):
    """Raised when JSON contains an ambiguous object."""


class YamlNode(Protocol):
    tag: str


class MappingNode(YamlNode, Protocol):
    value: list[tuple[YamlNode, YamlNode]]


class SequenceNode(YamlNode, Protocol):
    value: list[YamlNode]


_YAML_MERGE_TAG = "tag:yaml.org,2002:merge"
_YAML_MAPPING_TAG = "tag:yaml.org,2002:map"
_YAML_SEQUENCE_TAG = "tag:yaml.org,2002:seq"
_YAML_MERGE_KEY = object()


class UniqueKeySafeLoader(yaml.SafeLoader):  # type: ignore[misc]
    """Safe YAML loader that rejects duplicate keys at every mapping depth."""

    def __init__(self, stream: object) -> None:
        super().__init__(stream)
        self._validated_mapping_node_ids: set[int] = set()

    def construct_mapping(
        self, node: MappingNode, deep: bool = False
    ) -> dict[object, object]:
        self._validate_mapping_node(node, deep=deep)
        return cast(dict[object, object], super().construct_mapping(node, deep=deep))

    def _validate_mapping_node(self, node: MappingNode, *, deep: bool) -> None:
        node_id = id(node)
        if node_id in self._validated_mapping_node_ids:
            return
        self._validated_mapping_node_ids.add(node_id)

        local_keys: dict[object, None] = {}
        for key_node, value_node in node.value:
            key = (
                _YAML_MERGE_KEY
                if key_node.tag == _YAML_MERGE_TAG
                else cast(object, self.construct_object(key_node, deep=deep))
            )
            try:
                duplicate = key in local_keys
            except TypeError as exc:
                raise TypeError("invalid YAML mapping key") from exc
            if duplicate:
                raise DuplicateYamlKeyError
            local_keys[key] = None
            if key_node.tag == _YAML_MERGE_TAG:
                self._validate_merge_sources(value_node, deep=deep)

    def _validate_merge_sources(self, node: YamlNode, *, deep: bool) -> None:
        if node.tag == _YAML_MAPPING_TAG:
            self._validate_mapping_node(cast(MappingNode, node), deep=deep)
            return
        if node.tag != _YAML_SEQUENCE_TAG:
            return
        for source in cast(SequenceNode, node).value:
            if source.tag == _YAML_MAPPING_TAG:
                self._validate_mapping_node(cast(MappingNode, source), deep=deep)


def _reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateJsonKeyError
        result[key] = value
    return result


class NormalizedPayload(TypedDict):
    commit_indicators: list[dict[str, str]]
    complete: bool
    domains: list[str]
    hashes: dict[str, str]
    package_versions: dict[str, list[str]]
    updated: str
    version: str
    wildcard_package_versions: dict[str, list[str]]


def _load_yaml(path: Path) -> dict[str, object]:
    try:
        loaded = cast(
            object,
            yaml.load(
                path.read_text(encoding="utf-8"),
                Loader=UniqueKeySafeLoader,
            ),
        )
    except DuplicateYamlKeyError as exc:
        raise ThreatDatabaseBuildError(
            "load failed: duplicate YAML mapping key"
        ) from exc
    except TypeError as exc:
        raise ThreatDatabaseBuildError("load failed: invalid YAML mapping key") from exc
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise ThreatDatabaseBuildError(f"load failed for {path}: {exc}") from exc
    if not isinstance(loaded, dict) or not all(isinstance(key, str) for key in loaded):
        raise ThreatDatabaseBuildError(f"load failed for {path}: root must be an object")
    return cast(dict[str, object], loaded)


def _load_schema(path: Path) -> dict[str, object]:
    try:
        loaded = cast(
            object,
            json.loads(
                path.read_text(encoding="utf-8"),
                object_pairs_hook=_reject_duplicate_json_keys,
            ),
        )
    except DuplicateJsonKeyError as exc:
        raise ThreatDatabaseBuildError(
            "schema load failed: duplicate JSON object key"
        ) from exc
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ThreatDatabaseBuildError(f"schema load failed for {path}: {exc}") from exc
    if not isinstance(loaded, dict) or not all(isinstance(key, str) for key in loaded):
        raise ThreatDatabaseBuildError(f"schema load failed for {path}: root must be an object")
    return cast(dict[str, object], loaded)


def _load_validated_document(source: Path, schema_path: Path) -> dict[str, object]:
    document = _load_yaml(source)
    schema = _load_schema(schema_path)
    try:
        Draft202012Validator.check_schema(schema)
    except Exception as exc:
        raise ThreatDatabaseBuildError(f"schema validation failed: {exc}") from exc
    errors = sorted(
        Draft202012Validator(schema).iter_errors(document),
        key=lambda error: (tuple(str(part) for part in error.absolute_path), error.message),
    )
    if errors:
        error = errors[0]
        raise ThreatDatabaseBuildError(
            f"validation failed at {error.json_path}: {error.message}"
        )
    return document


def _mapping(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise ThreatDatabaseBuildError(f"extraction failed: {label} must be an object")
    return cast(dict[str, object], value)


def _array(value: object, label: str) -> list[object]:
    if not isinstance(value, list):
        raise ThreatDatabaseBuildError(f"extraction failed: {label} must be an array")
    return cast(list[object], value)


def _string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ThreatDatabaseBuildError(f"extraction failed: {label} must be a string")
    return value


def _extract_packages(
    document: Mapping[str, object],
) -> tuple[dict[str, list[str]], dict[str, list[str]]]:
    exact: dict[str, set[str]] = {}
    wildcard: dict[str, set[str]] = {}
    skills = _array(document.get("malicious_skills"), "malicious_skills")
    for index, value in enumerate(skills):
        skill = _mapping(value, f"malicious_skills[{index}]")
        if skill.get("platform") != "npm" or "version" not in skill:
            continue
        name = _string(skill.get("name"), f"malicious_skills[{index}].name")
        version = _string(skill.get("version"), f"malicious_skills[{index}].version")
        if name.endswith("/*"):
            wildcard.setdefault(name[:-1], set()).add(version)
        else:
            exact.setdefault(name, set()).add(version)
    if not exact:
        raise ThreatDatabaseBuildError("extraction failed: no exact npm package versions found")
    return (
        {name: sorted(versions) for name, versions in sorted(exact.items())},
        {name: sorted(versions) for name, versions in sorted(wildcard.items())},
    )


def _extract_hashes(document: Mapping[str, object]) -> dict[str, str]:
    iocs = _mapping(document.get("iocs"), "iocs")
    entries = _array(iocs.get("malware_hashes"), "iocs.malware_hashes")
    hashes: dict[str, str] = {}
    for index, value in enumerate(entries):
        entry = _mapping(value, f"iocs.malware_hashes[{index}]")
        digest = _string(entry.get("hash"), f"iocs.malware_hashes[{index}].hash")
        if re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            continue
        description = _string(entry.get("type"), f"iocs.malware_hashes[{index}].type")
        previous = hashes.setdefault(digest, description)
        if previous != description:
            raise ThreatDatabaseBuildError(
                f"extraction failed: conflicting descriptions for SHA-256 {digest}"
            )
    if not hashes:
        raise ThreatDatabaseBuildError("extraction failed: no complete SHA-256 values found")
    return dict(sorted(hashes.items()))


def _extract_domains(document: Mapping[str, object]) -> list[str]:
    iocs = _mapping(document.get("iocs"), "iocs")
    entries = _array(iocs.get("malicious_domains"), "iocs.malicious_domains")
    domains = {
        _string(
            _mapping(value, f"iocs.malicious_domains[{index}]").get("domain"),
            f"iocs.malicious_domains[{index}].domain",
        )
        for index, value in enumerate(entries)
    }
    if not domains:
        raise ThreatDatabaseBuildError("extraction failed: no campaign domains found")
    return sorted(domains)


_COMMIT_DETAIL = re.compile(
    r"authored as ['\"](?P<author>[^'\"]+)['\"] with email "
    r"(?P<email>\S+) and the message ['\"](?P<message>[^'\"]+)['\"]"
)


def _extract_commit_indicators(document: Mapping[str, object]) -> list[dict[str, str]]:
    campaigns = _array(document.get("campaigns"), "campaigns")
    indicators: set[tuple[str, str, str]] = set()
    for index, value in enumerate(campaigns):
        campaign = _mapping(value, f"campaigns[{index}]")
        raw_impersonation = campaign.get("ai_agent_impersonation")
        if raw_impersonation is None:
            continue
        impersonation = _mapping(
            raw_impersonation, f"campaigns[{index}].ai_agent_impersonation"
        )
        detail = _string(
            impersonation.get("detail"),
            f"campaigns[{index}].ai_agent_impersonation.detail",
        )
        match = _COMMIT_DETAIL.search(detail)
        if match is None:
            raise ThreatDatabaseBuildError(
                "extraction failed: documented commit indicator has an unsupported format"
            )
        indicators.add((match["author"], match["email"], match["message"]))
    if not indicators:
        raise ThreatDatabaseBuildError("extraction failed: no commit indicators found")
    return [
        {"author": author, "email": email, "subject": message}
        for author, email, message in sorted(indicators)
    ]


def _normalize(document: Mapping[str, object]) -> NormalizedPayload:
    package_versions, wildcard_package_versions = _extract_packages(document)
    return {
        "commit_indicators": _extract_commit_indicators(document),
        "complete": True,
        "domains": _extract_domains(document),
        "hashes": _extract_hashes(document),
        "package_versions": package_versions,
        "updated": _string(document.get("updated"), "updated"),
        "version": _string(document.get("version"), "version"),
        "wildcard_package_versions": wildcard_package_versions,
    }


def _write_payload(output: Path, payload: Mapping[str, object]) -> None:
    temporary = output.with_name(f".{output.name}.tmp")
    try:
        output.parent.mkdir(parents=True, exist_ok=True)
        temporary.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        temporary.replace(output)
    except (OSError, UnicodeError, TypeError, ValueError) as exc:
        temporary.unlink(missing_ok=True)
        raise ThreatDatabaseBuildError(f"output failed for {output}: {exc}") from exc


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build the bundled AgentSec threat database")
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        document = _load_validated_document(args.source, args.schema)
        payload = _normalize(document)
        _write_payload(args.output, payload)
    except ThreatDatabaseBuildError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    package_count = sum(len(versions) for versions in payload["package_versions"].values())
    wildcard_count = sum(
        len(versions) for versions in payload["wildcard_package_versions"].values()
    )
    print(
        f"built threat database version={payload['version']} "
        f"packages={package_count} wildcards={wildcard_count} "
        f"hashes={len(payload['hashes'])} domains={len(payload['domains'])} "
        f"commit_indicators={len(payload['commit_indicators'])} output={args.output}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Build a deterministic review inventory for threat-database prose fields."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Protocol, cast
from urllib.parse import quote, unquote

import yaml  # type: ignore[import-untyped]

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SOURCE = PROJECT_ROOT / "data" / "threat-db.yaml"
DEFAULT_OUTPUT = PROJECT_ROOT / "docs" / "LICENSE-PROSE-INVENTORY.json"
PROSE_KEYS = frozenset({"notes", "description"})
SCHEMA_VERSION = "license-prose-inventory-v1"
UNKNOWN = "UNKNOWN"
UNREVIEWED = "UNREVIEWED"
LOCAL_PROVENANCE_VERIFIED = "LOCAL_PROVENANCE_VERIFIED"
HISTORICALLY_VERIFIED_PROSE = frozenset(
    {
        (
            "scanning_tools[name=AI-Infra-Guard (A.I.G)].notes",
            "b042d384c5cf7912b4c2054bfdc42b34c2fa498a21163cd7945a9f2339a3f132",
        ),
        (
            "scanning_tools[name=Aguara].notes",
            "2c10155615c99a2af03ac4019e449406d0544dc7dc5f3abb88182a7a81c49894",
        ),
        (
            "scanning_tools[name=AquilaX AI Agent Configuration Scanner].notes",
            "f412e44144900af37907cbf4c9a8ec1b05daebb12e2cbd47609514be63c9df65",
        ),
        (
            "scanning_tools[name=Cisco AI Agent Security Scanner for IDEs].notes",
            "00ab7da8001bd80377830609ff60e3045c12f13dee3c0f78d211686887887667",
        ),
        (
            "scanning_tools[name=Cisco DefenseClaw].notes",
            "0fecd298e102691be64d83a8da4b8b8fdb741ad417ae5792579fc8a4d9aed249",
        ),
        (
            "scanning_tools[name=ClawArmor].notes",
            "745998ce567676c7d0b73b6d6922d70d38d929f63206d1df2880a59cf5080bb2",
        ),
        (
            "scanning_tools[name=ClawNet].notes",
            "f37ec4a1d3bdb63febac81f8eb058de2c533e1b74a63b1fafd2fccebf3330f37",
        ),
        (
            "scanning_tools[name=ClawSec].notes",
            "e998581ce9ecbeddd473efa9d206f7d6d3c5f5b1eb1f6d714646680d07b9a13e",
        ),
        (
            "scanning_tools[name=ESET AI Skills Checker].notes",
            "f5c099f6b0b20351281ea855c0120f377697fd9655d06860a64fb15cd85ece29",
        ),
        (
            "scanning_tools[name=Ferrok].notes",
            "8d093ba27a32cefe587b35c681c534b78de430d807228e919b962eb513a40e07",
        ),
        (
            "scanning_tools[name=GitHub Security Lab Taskflow Agent].notes",
            "ba7e2bb3f7096d2a485a8f4354cffcacaf75deb6fed33777dfa78845281fe679",
        ),
        (
            "scanning_tools[name=Golf Scanner].notes",
            "ad467f118bbc42d2fa2225d5ad639d2b2edd1f2429735eb1adf6bb39232593eb",
        ),
        (
            "scanning_tools[name=Jozu Agent Guard].notes",
            "4ae5d650dc8dd5d3ffe73e970e1e3c4b5b89c819609d4b7b03515daa55818d9b",
        ),
        (
            "scanning_tools[name=MCP Sentinel].notes",
            "a8ef3e8fb5617010615fec7f701d9026b209c5386438d407cff3efb053964636",
        ),
        (
            "scanning_tools[name=Microsoft MDASH].notes",
            "ac724d29b3d16c612b6efb0e34b9beaace88b600babe56eb19a4a3c8b0e33bc9",
        ),
        (
            "scanning_tools[name=NVIDIA SkillSpector].notes",
            "a602040740824e5b7434f82a48489ae96f8c6fdf12765a8fb9736c5008e681e1",
        ),
        (
            "scanning_tools[name=OpenAI Codex Security].notes",
            "2a9f24ff1975a1ff153a1a5dd0ac3a4b914983d67564ac2259a1fd44a9820938",
        ),
        (
            "scanning_tools[name=SandyClaw].notes",
            "5784b9347c04ea29ca06f2828a1a7bd5db9e5916cc899e28e83a4135cb0b4762",
        ),
        (
            "scanning_tools[name=Semgrep MCP].notes",
            "7515151969f23652f100b932ac4c0ec6a2fdeccb6f871e94bb873aff1d910c08",
        ),
        (
            "scanning_tools[name=SkillDetonate].notes",
            "6591809cf5c5171a74327b38797f3e214113b2d86108797e6e182f0902e811d3",
        ),
        (
            "scanning_tools[name=SkillRisk].notes",
            "3b1381282cb24ff7b5e7ef1d4030b7a12326f44cb2175ab17ad03e38362206ca",
        ),
        (
            "scanning_tools[name=SkillScan Security].notes",
            "3681387e291b85ee79274e03009bba489f56eed21ee666ce82ffc598c67a2859",
        ),
        (
            "scanning_tools[name=Snyk Agent Scan].notes",
            "523bab9815c00d053ad5ffd066da35013747e613488c47ef36883ed03f15f901",
        ),
        (
            "scanning_tools[name=Straiker MCP Security Platform].notes",
            "cce37ef259c8ed3716933fe325fafbeab210f4ea86bda2bf9451df3c066a1416",
        ),
        (
            "scanning_tools[name=VIPER-MCP].notes",
            "039a66d5d46003925e2f826ff1a9d088a4236429842568d03559eb1ef5c805bf",
        ),
        (
            "scanning_tools[name=hackmyagent].notes",
            "6ca6a4bcd6fa15b84e7181f573fe4cb7aeacbc78f9feb0a7314ce92b2d6be4d9",
        ),
        (
            "scanning_tools[name=mcp-scan].notes",
            "e02ebb57fc41ad6a4b40759a24bcd901d0569a5d46c11e1ce040a9cc400fdab5",
        ),
        (
            "scanning_tools[name=mcp-spec-check].notes",
            "22bf48b0e41e9a359d4faacbf288f305b1b40350cec7fcd003efe330ffbcf04d",
        ),
    }
)
ACTION_WITH_SOURCE = (
    "Compare the cited source, document independent authorship or permission, "
    "then rewrite independently or remove."
)
ACTION_WITHOUT_SOURCE = (
    "No source locator is available. Record the source and rights evidence, "
    "then rewrite independently, obtain permission, or remove."
)


class ProseInventoryBuildError(Exception):
    """Raised when an inventory input cannot produce reliable evidence."""


class DuplicateYamlKeyError(ValueError):
    """Raised when YAML contains an ambiguous mapping."""


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

    def construct_mapping(self, node: MappingNode, deep: bool = False) -> dict[object, object]:
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


def _mapping(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise ProseInventoryBuildError(f"{label} must be an object")
    return cast(dict[str, object], value)


def _sequence(value: object, label: str) -> list[object]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise ProseInventoryBuildError(f"{label} must be an array")
    return list(value)


def _load_yaml(path: Path) -> tuple[dict[str, object], bytes]:
    try:
        raw = path.read_bytes()
        loaded = cast(
            object,
            yaml.load(raw.decode("utf-8"), Loader=UniqueKeySafeLoader),
        )
    except DuplicateYamlKeyError as exc:
        raise ProseInventoryBuildError("duplicate YAML mapping key") from exc
    except TypeError as exc:
        raise ProseInventoryBuildError("invalid YAML mapping key") from exc
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise ProseInventoryBuildError("cannot read threat database YAML") from exc
    return _mapping(loaded, "threat database"), raw


def _source_locators(document: Mapping[str, object]) -> dict[str, str]:
    locators: dict[str, str] = {}
    for index, value in enumerate(_sequence(document.get("sources"), "sources")):
        source = _mapping(value, f"sources[{index}]")
        name = source.get("name")
        url = source.get("url")
        if not isinstance(name, str) or not name or not isinstance(url, str) or not url:
            continue
        if name in locators:
            raise ProseInventoryBuildError("source names must be unique")
        locators[name] = url
    return locators


def _structural_selector(value: object) -> str:
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ProseInventoryBuildError("cannot build structural field locator") from exc
    return f"sha256={hashlib.sha256(encoded).hexdigest()[:16]}"


def _sequence_selector(values: Sequence[object], index: int) -> str:
    item = values[index]
    if not isinstance(item, Mapping):
        return _structural_selector(item)
    for key in ("id", "name", "pattern", "domain", "hash", "ip", "url", "repo"):
        candidate = item.get(key)
        if not isinstance(candidate, str) or not candidate:
            continue
        if sum(isinstance(other, Mapping) and other.get(key) == candidate for other in values) == 1:
            return f"{key}={quote(candidate, safe='-._~')}"
    return _structural_selector(item)


def _source_locators_for(record: Mapping[str, object], locators: Mapping[str, str]) -> list[str]:
    found: set[str] = set()
    url = record.get("url")
    if isinstance(url, str) and url.startswith(("https://", "http://")):
        found.add(url)
    sources = record.get("sources")
    if sources is not None:
        for index, source_value in enumerate(_sequence(sources, "sources")):
            if not isinstance(source_value, str) or not source_value:
                raise ProseInventoryBuildError(f"sources[{index}] must be a non-empty string")
            if source_value.startswith(("https://", "http://")):
                found.add(source_value)
            else:
                found.add(locators.get(source_value, source_value))
    source = record.get("source")
    if isinstance(source, str) and source:
        if source.startswith(("https://", "http://")):
            found.add(source)
        elif source in locators:
            found.add(locators[source])
    return sorted(found)


def _review_state(field_path: str, value_sha256: str) -> str:
    prefix = "scanning_tools[name="
    suffix = "].notes"
    historical_path = field_path
    if field_path.startswith(prefix) and field_path.endswith(suffix):
        historical_path = f"{prefix}{unquote(field_path[len(prefix) : -len(suffix)])}{suffix}"
    if (historical_path, value_sha256) in HISTORICALLY_VERIFIED_PROSE:
        return LOCAL_PROVENANCE_VERIFIED
    return UNREVIEWED


def _collect_entries(
    value: object,
    path: str,
    locators: Mapping[str, str],
    entries: list[dict[str, object]],
) -> None:
    if isinstance(value, Mapping):
        record = _mapping(value, path or "threat database")
        source_locators = [] if not path else _source_locators_for(record, locators)
        for key, child in record.items():
            child_path = f"{path}.{key}" if path else key
            if key in PROSE_KEYS and isinstance(child, str):
                value_sha256 = hashlib.sha256(child.encode("utf-8")).hexdigest()
                entries.append(
                    {
                        "classification": UNKNOWN,
                        "field_path": child_path,
                        "required_action": (
                            ACTION_WITH_SOURCE if source_locators else ACTION_WITHOUT_SOURCE
                        ),
                        "review_state": _review_state(child_path, value_sha256),
                        "source_locators": source_locators,
                        "value_sha256": value_sha256,
                    }
                )
            else:
                _collect_entries(child, child_path, locators, entries)
        return
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        values = list(value)
        for index, child in enumerate(values):
            child_path = f"{path}[{_sequence_selector(values, index)}]"
            _collect_entries(child, child_path, locators, entries)


def build_inventory(document: Mapping[str, object], raw_source: bytes) -> dict[str, object]:
    entries: list[dict[str, object]] = []
    _collect_entries(document, "", _source_locators(document), entries)
    entries.sort(key=lambda entry: cast(str, entry["field_path"]))
    if len({cast(str, entry["field_path"]) for entry in entries}) != len(entries):
        raise ProseInventoryBuildError("field path collision")
    return {
        "entries": entries,
        "field_count": len(entries),
        "schema_version": SCHEMA_VERSION,
        "source_sha256": hashlib.sha256(raw_source).hexdigest(),
    }


def _render_json(payload: Mapping[str, object]) -> bytes:
    return (json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode(
        "utf-8"
    )


def _write_json(path: Path, payload: Mapping[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_bytes(_render_json(payload))
    temporary.replace(path)


def _check_json(path: Path, payload: Mapping[str, object]) -> None:
    try:
        current = path.read_bytes()
    except OSError as exc:
        raise ProseInventoryBuildError("license prose inventory is stale") from exc
    if current != _render_json(payload):
        raise ProseInventoryBuildError("license prose inventory is stale")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build a deterministic license prose review inventory."
    )
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--check", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    try:
        document, raw_source = _load_yaml(arguments.source)
        inventory = build_inventory(document, raw_source)
        if arguments.check:
            _check_json(arguments.output, inventory)
        else:
            _write_json(arguments.output, inventory)
    except ProseInventoryBuildError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    action = "checked" if arguments.check else "built"
    print(
        f"{action} license prose inventory fields={inventory['field_count']} "
        f"output={arguments.output}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, cast

import yaml  # type: ignore[import-untyped]
from jsonschema import (  # type: ignore[import-untyped]
    Draft202012Validator,
    FormatChecker,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SOURCES = PROJECT_ROOT / "data" / "intelligence" / "sources.yaml"
DEFAULT_EVENTS = PROJECT_ROOT / "data" / "intelligence" / "events.yaml"
DEFAULT_SCHEMA = PROJECT_ROOT / "data" / "intelligence" / "intelligence.schema.json"
DEFAULT_SOURCES_OUTPUT = PROJECT_ROOT / "docs" / "SECURITY-INTELLIGENCE.md"
DEFAULT_TIMELINE_OUTPUT = PROJECT_ROOT / "docs" / "SECURITY-TIMELINE.md"
DEFAULT_JSON_OUTPUT = (
    PROJECT_ROOT / "src" / "agentsec" / "resources" / "security-intelligence.json"
)


class IntelligenceBuildError(Exception):
    """Raised when intelligence data cannot be validated or rendered."""


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


@dataclass(frozen=True, slots=True)
class IntelligenceCorpus:
    schema_version: str
    updated: str
    sources: tuple[dict[str, object], ...]
    events: tuple[dict[str, object], ...]


def _reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateJsonKeyError
        result[key] = value
    return result


def _load_yaml(path: Path) -> dict[str, object]:
    try:
        loaded = cast(
            object,
            yaml.load(path.read_text(encoding="utf-8"), Loader=UniqueKeySafeLoader),
        )
    except DuplicateYamlKeyError as exc:
        raise IntelligenceBuildError(
            "load failed: duplicate YAML mapping key"
        ) from exc
    except TypeError as exc:
        raise IntelligenceBuildError("load failed: invalid YAML mapping key") from exc
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise IntelligenceBuildError("load failed: unreadable YAML document") from exc
    if not isinstance(loaded, dict) or not all(isinstance(key, str) for key in loaded):
        raise IntelligenceBuildError("load failed: YAML root must be an object")
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
        raise IntelligenceBuildError(
            "schema load failed: duplicate JSON object key"
        ) from exc
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise IntelligenceBuildError("schema load failed: unreadable JSON schema") from exc
    if not isinstance(loaded, dict) or not all(isinstance(key, str) for key in loaded):
        raise IntelligenceBuildError("schema load failed: root must be an object")
    return cast(dict[str, object], loaded)


def _mapping(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise IntelligenceBuildError(f"extraction failed: {label} must be an object")
    return cast(dict[str, object], value)


def _records(document: Mapping[str, object], key: str) -> tuple[dict[str, object], ...]:
    value = document.get(key)
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise IntelligenceBuildError(f"extraction failed: {key} must be an array")
    return tuple(_mapping(item, f"{key} entry") for item in value)


def _string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise IntelligenceBuildError(f"extraction failed: {label} must be a string")
    return value


def _strings(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise IntelligenceBuildError(f"extraction failed: {label} must be an array")
    if not all(isinstance(item, str) and item for item in value):
        raise IntelligenceBuildError(f"extraction failed: {label} must contain strings")
    return tuple(cast(Sequence[str], value))


def _validate_document(
    document: Mapping[str, object],
    schema: Mapping[str, object],
    expected_kind: str,
) -> None:
    try:
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema, format_checker=FormatChecker())
    except Exception as exc:
        raise IntelligenceBuildError("schema validation failed: invalid schema") from exc
    errors = sorted(
        validator.iter_errors(document),
        key=lambda error: tuple(str(part) for part in error.absolute_path),
    )
    if errors:
        raise IntelligenceBuildError(f"validation failed: {expected_kind} document")
    if document.get("kind") != expected_kind:
        raise IntelligenceBuildError(f"validation failed: expected {expected_kind} document")


def _require_unique_ids(records: Sequence[Mapping[str, object]], label: str) -> set[str]:
    identifiers: set[str] = set()
    for record in records:
        identifier = _string(record.get("id"), f"{label} id")
        if identifier in identifiers:
            raise IntelligenceBuildError(f"cross-reference failed: duplicate {label} id")
        identifiers.add(identifier)
    return identifiers


def _validate_cross_references(
    sources: Sequence[Mapping[str, object]],
    events: Sequence[Mapping[str, object]],
) -> None:
    source_ids = _require_unique_ids(sources, "source")
    event_ids = _require_unique_ids(events, "event")
    for event in events:
        event_id = _string(event.get("id"), "event id")
        for source_id in _strings(event.get("source_ids"), "event source_ids"):
            if source_id not in source_ids:
                raise IntelligenceBuildError(
                    "cross-reference failed: unresolved source id"
                )
        affected_event_ids = event.get("affected_event_ids")
        if affected_event_ids is not None:
            for affected_event_id in _strings(
                affected_event_ids, "affected event ids"
            ):
                if affected_event_id == event_id:
                    raise IntelligenceBuildError(
                        "cross-reference failed: event cannot affect itself"
                    )
                if affected_event_id not in event_ids:
                    raise IntelligenceBuildError(
                        "cross-reference failed: unresolved affected event id"
                    )
        status = _string(event.get("status"), "event status")
        confidence = _string(event.get("confidence"), "event confidence")
        if (status == "contested") != (confidence == "contested"):
            raise IntelligenceBuildError(
                "cross-reference failed: contested status and confidence must agree"
            )


def load_intelligence(
    sources_path: Path,
    events_path: Path,
    schema_path: Path,
) -> IntelligenceCorpus:
    sources_document = _load_yaml(sources_path)
    events_document = _load_yaml(events_path)
    schema = _load_schema(schema_path)
    _validate_document(sources_document, schema, "sources")
    _validate_document(events_document, schema, "events")

    sources = _records(sources_document, "sources")
    events = _records(events_document, "events")
    _validate_cross_references(sources, events)

    source_version = _string(sources_document.get("schema_version"), "schema version")
    event_version = _string(events_document.get("schema_version"), "schema version")
    if source_version != event_version:
        raise IntelligenceBuildError("cross-reference failed: schema version mismatch")
    updated = max(
        _string(sources_document.get("updated"), "sources updated"),
        _string(events_document.get("updated"), "events updated"),
    )
    return IntelligenceCorpus(
        schema_version=source_version,
        updated=updated,
        sources=sources,
        events=events,
    )


def _source_sort_key(source: Mapping[str, object]) -> tuple[str, str, str]:
    return (
        _string(source.get("publisher"), "source publisher").casefold(),
        _string(source.get("title"), "source title").casefold(),
        _string(source.get("id"), "source id"),
    )


def _event_date(event: Mapping[str, object]) -> str:
    for key in ("updated_date", "disclosed_date", "occurred_date"):
        value = event.get(key)
        if isinstance(value, str) and value:
            return value
    raise IntelligenceBuildError("render failed: event has no date")


def _sorted_events(
    events: Sequence[dict[str, object]],
) -> tuple[dict[str, object], ...]:
    by_id = sorted(events, key=lambda event: _string(event.get("id"), "event id"))
    return tuple(sorted(by_id, key=_event_date, reverse=True))


def _markdown(value: str) -> str:
    return " ".join(value.split()).replace("\\", "\\\\").replace("|", "\\|")


def _optional_date(record: Mapping[str, object], key: str) -> str:
    value = record.get(key)
    return value if isinstance(value, str) else "not recorded"


def render_sources_markdown(corpus: IntelligenceCorpus) -> str:
    sources = sorted(corpus.sources, key=_source_sort_key)
    lines = [
        "# Security Intelligence",
        "",
        "> Generated from `data/intelligence/sources.yaml`. Do not edit this file directly.",
        "",
        (
            f"Schema version `{corpus.schema_version}` · Updated `{corpus.updated}` · "
            f"{len(sources)} reviewed sources."
        ),
        "",
        "Listing a source records the specific claim reviewed by AgentSec. It is not an",
        "endorsement of every statement in that source.",
        "",
        "## Source catalogue",
        "",
        "| Publisher | Source | Type | Status | Published | Reviewed | Topics |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for source in sources:
        title = _markdown(_string(source.get("title"), "source title"))
        url = _string(source.get("url"), "source URL")
        topics = ", ".join(_strings(source.get("topics"), "source topics"))
        lines.append(
            "| "
            + " | ".join(
                (
                    _markdown(_string(source.get("publisher"), "source publisher")),
                    f"[{title}]({url})",
                    _markdown(_string(source.get("source_type"), "source type")),
                    _markdown(_string(source.get("status"), "source status").upper()),
                    _optional_date(source, "published_date"),
                    _string(source.get("reviewed_date"), "source reviewed date"),
                    _markdown(topics),
                )
            )
            + " |"
        )

    lines.extend(("", "## Reviewed claim scope", ""))
    for source in sources:
        lines.extend(
            (
                f"### {_markdown(_string(source.get('title'), 'source title'))}",
                "",
                f"- ID: `{_string(source.get('id'), 'source id')}`",
                f"- Publisher: {_markdown(_string(source.get('publisher'), 'publisher'))}",
                f"- URL: <{_string(source.get('url'), 'source URL')}>",
                "- Supports:",
            )
        )
        for claim in _strings(source.get("supports"), "source supports"):
            lines.append(f"  - {_markdown(claim)}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _source_by_id(corpus: IntelligenceCorpus) -> dict[str, dict[str, object]]:
    return {
        _string(source.get("id"), "source id"): source for source in corpus.sources
    }


def render_timeline_markdown(corpus: IntelligenceCorpus) -> str:
    events = _sorted_events(corpus.events)
    sources = _source_by_id(corpus)
    lines = [
        "# Security Timeline",
        "",
        "> Generated from `data/intelligence/events.yaml`. Do not edit this file directly.",
        "",
        (
            f"Schema version `{corpus.schema_version}` · Updated `{corpus.updated}` · "
            f"{len(events)} events tracked by AgentSec."
        ),
        "",
        "This is a reviewed project ledger, not a complete history of all security",
        "vulnerabilities. Occurrence, disclosure, and update dates remain distinct.",
        "",
        "## Chronology",
        "",
        "| Date | Status | Type | Event | Detector coverage |",
        "| --- | --- | --- | --- | --- |",
    ]
    for event in events:
        coverage = _mapping(event.get("detector_coverage"), "detector coverage")
        lines.append(
            "| "
            + " | ".join(
                (
                    _event_date(event),
                    _string(event.get("status"), "event status").upper(),
                    _markdown(_string(event.get("event_type"), "event type")),
                    _markdown(_string(event.get("title"), "event title")),
                    _markdown(_string(coverage.get("status"), "coverage status")),
                )
            )
            + " |"
        )

    lines.extend(("", "## Event details", ""))
    for event in events:
        coverage = _mapping(event.get("detector_coverage"), "detector coverage")
        related = _mapping(event.get("related"), "related IDs")
        event_id = _string(event.get("id"), "event id")
        lines.extend(
            (
                f"### {_event_date(event)}: {_markdown(_string(event.get('title'), 'title'))}",
                "",
                f"- ID: `{event_id}`",
                (
                    f"- Status: **{_string(event.get('status'), 'status').upper()}** · "
                    f"Confidence: **{_string(event.get('confidence'), 'confidence').upper()}**"
                ),
                f"- Type: `{_string(event.get('event_type'), 'event type')}`",
                f"- Ecosystems: {', '.join(_strings(event.get('ecosystems'), 'ecosystems'))}",
                (
                    f"- Dates: occurred `{_optional_date(event, 'occurred_date')}`, "
                    f"disclosed `{_optional_date(event, 'disclosed_date')}`, "
                    f"updated `{_optional_date(event, 'updated_date')}`"
                ),
                (
                    f"- Detector coverage: `{_string(coverage.get('status'), 'coverage')}`: "
                    f"{_markdown(_string(coverage.get('notes'), 'coverage notes'))}"
                ),
                "",
                _markdown(_string(event.get("summary"), "event summary")),
                "",
                "Sources:",
            )
        )
        for source_id in _strings(event.get("source_ids"), "event source IDs"):
            source = sources[source_id]
            lines.append(
                "- "
                f"[{_markdown(_string(source.get('publisher'), 'publisher'))}: "
                f"{_markdown(_string(source.get('title'), 'title'))}]"
                f"({_string(source.get('url'), 'source URL')}) (`{source_id}`)"
            )
        affected_event_ids = event.get("affected_event_ids")
        if affected_event_ids is not None:
            affected = ", ".join(
                f"`{value}`"
                for value in _strings(affected_event_ids, "affected event IDs")
            )
            lines.extend(("", f"Affects events: {affected}"))
        related_parts: list[str] = []
        for label, key in (
            ("campaigns", "campaign_ids"),
            ("CVEs", "cve_ids"),
            ("techniques", "technique_ids"),
        ):
            values = _strings(related.get(key), f"related {key}")
            if values:
                related_parts.append(f"{label}: {', '.join(f'`{value}`' for value in values)}")
        if related_parts:
            lines.extend(("", "Related: " + "; ".join(related_parts)))
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def render_json(corpus: IntelligenceCorpus) -> str:
    payload = {
        "schema_version": corpus.schema_version,
        "updated": corpus.updated,
        "sources": [dict(source) for source in sorted(corpus.sources, key=_source_sort_key)],
        "events": [dict(event) for event in _sorted_events(corpus.events)],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(content, encoding="utf-8", newline="\n")
    temporary.replace(path)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate and generate AgentSec security intelligence artifacts."
    )
    parser.add_argument("--sources", type=Path, default=DEFAULT_SOURCES)
    parser.add_argument("--events", type=Path, default=DEFAULT_EVENTS)
    parser.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA)
    parser.add_argument("--sources-output", type=Path, default=DEFAULT_SOURCES_OUTPUT)
    parser.add_argument("--timeline-output", type=Path, default=DEFAULT_TIMELINE_OUTPUT)
    parser.add_argument("--json-output", type=Path, default=DEFAULT_JSON_OUTPUT)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    try:
        corpus = load_intelligence(arguments.sources, arguments.events, arguments.schema)
        _write_text(arguments.sources_output, render_sources_markdown(corpus))
        _write_text(arguments.timeline_output, render_timeline_markdown(corpus))
        _write_text(arguments.json_output, render_json(corpus))
    except IntelligenceBuildError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(
        "built security intelligence "
        f"version={corpus.schema_version} sources={len(corpus.sources)} "
        f"events={len(corpus.events)} updated={corpus.updated}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

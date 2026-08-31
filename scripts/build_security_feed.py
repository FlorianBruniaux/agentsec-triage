from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tomllib
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import cast

import yaml  # type: ignore[import-untyped]
from jsonschema import Draft202012Validator, FormatChecker  # type: ignore[import-untyped]

from agentsec.detectors.registry import get_detectors

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_THREAT_DATABASE = PROJECT_ROOT / "data" / "threat-db.yaml"
DEFAULT_INTELLIGENCE = (
    PROJECT_ROOT / "src" / "agentsec" / "resources" / "security-intelligence.json"
)
DEFAULT_PROJECT = PROJECT_ROOT / "pyproject.toml"
DEFAULT_SCHEMA = PROJECT_ROOT / "schemas" / "security-feed-v1.schema.json"
DEFAULT_OUTPUT = PROJECT_ROOT / "exports" / "security-feed.v1.json"


class SecurityFeedBuildError(Exception):
    """Raised when public feed inputs or output violate the contract."""


def _read_bytes(path: Path, label: str) -> bytes:
    try:
        return path.read_bytes()
    except OSError as exc:
        raise SecurityFeedBuildError(f"cannot read {label}") from exc


def _text_digest(raw: bytes) -> str:
    """Hash text inputs independently of Git's platform line-ending checkout."""
    normalized = raw.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    return hashlib.sha256(normalized).hexdigest()


def _mapping(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise SecurityFeedBuildError(f"{label} must be an object")
    return cast(dict[str, object], value)


def _sequence(value: object, label: str) -> list[object]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise SecurityFeedBuildError(f"{label} must be an array")
    return list(value)


def _string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise SecurityFeedBuildError(f"{label} must be a non-empty string")
    return value


def _load_yaml(path: Path) -> tuple[dict[str, object], bytes]:
    raw = _read_bytes(path, "threat database")
    try:
        loaded = cast(object, yaml.safe_load(raw))
    except yaml.YAMLError as exc:
        raise SecurityFeedBuildError("invalid threat database YAML") from exc
    return _mapping(loaded, "threat database"), raw


def _load_json(path: Path, label: str) -> tuple[dict[str, object], bytes]:
    raw = _read_bytes(path, label)
    try:
        loaded = cast(object, json.loads(raw))
    except json.JSONDecodeError as exc:
        raise SecurityFeedBuildError(f"invalid {label} JSON") from exc
    return _mapping(loaded, label), raw


def _load_project_version(path: Path) -> str:
    try:
        project = tomllib.loads(_read_bytes(path, "project metadata").decode("utf-8"))
    except (UnicodeError, tomllib.TOMLDecodeError) as exc:
        raise SecurityFeedBuildError("invalid project metadata") from exc
    return _string(_mapping(project.get("project"), "project metadata").get("version"), "version")


def _number_occurrences(value: object, key: str) -> list[int | float]:
    found: list[int | float] = []
    if isinstance(value, Mapping):
        for child_key, child in value.items():
            if child_key == key and isinstance(child, (int, float)) and not isinstance(child, bool):
                found.append(child)
            found.extend(_number_occurrences(child, key))
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        for child in value:
            found.extend(_number_occurrences(child, key))
    return found


def _unique_metric(database: Mapping[str, object], key: str) -> int | float:
    values = _number_occurrences(database, key)
    if len(values) != 1:
        raise SecurityFeedBuildError(
            f"landing metric {key} must occur exactly once, found {len(values)}"
        )
    return values[0]


def _records(database: Mapping[str, object], key: str) -> list[object]:
    return _sequence(database.get(key), f"threat database {key}")


def _project_source(source: object) -> dict[str, object]:
    item = _mapping(source, "intelligence source")
    projected = {
        key: item[key]
        for key in (
            "id",
            "title",
            "publisher",
            "url",
            "source_type",
            "status",
            "reviewed_date",
        )
    }
    if "published_date" in item:
        projected["published_date"] = item["published_date"]
    return projected


def _event_date(event: Mapping[str, object]) -> tuple[str, str]:
    for kind, key in (
        ("updated", "updated_date"),
        ("disclosed", "disclosed_date"),
        ("occurred", "occurred_date"),
    ):
        value = event.get(key)
        if isinstance(value, str) and value:
            return kind, value
    raise SecurityFeedBuildError("intelligence event has no date")


def _project_event(event: object) -> dict[str, object]:
    item = _mapping(event, "intelligence event")
    coverage = _mapping(item.get("detector_coverage"), "detector coverage")
    date_kind, date = _event_date(item)
    projected = {
        "id": item["id"],
        "event_type": item["event_type"],
        "title": item["title"],
        "summary": item["summary"],
        "date": date,
        "date_kind": date_kind,
        "ecosystems": item["ecosystems"],
        "status": item["status"],
        "confidence": item["confidence"],
        "source_ids": item["source_ids"],
        "related": item["related"],
        "detector_coverage": {
            "status": coverage["status"],
            "detector_ids": coverage["detector_ids"],
            "summary": coverage["notes"],
        },
    }
    if "affected_event_ids" in item:
        projected["affected_event_ids"] = item["affected_event_ids"]
    return projected


def _project_detectors() -> list[dict[str, object]]:
    projected: list[dict[str, object]] = []
    for detector in sorted(get_detectors(), key=lambda item: item.id):
        metadata = detector.metadata
        if metadata.remediation_url is None:
            raise SecurityFeedBuildError(f"detector {detector.id} has no remediation URL")
        projected.append(
            {
                "id": detector.id,
                "version": detector.version,
                "description": metadata.description,
                "supported_inputs": list(metadata.supported_inputs),
                "campaign_ids": list(metadata.campaign_ids),
                "technique_ids": list(metadata.technique_ids),
                "source_references": list(metadata.source_references),
                "limitations": list(metadata.limitations),
                "remediation_url": metadata.remediation_url,
                "not_scanned": list(metadata.not_scanned),
            }
        )
    return projected


def build_feed(
    database: Mapping[str, object],
    intelligence: Mapping[str, object],
    *,
    project_version: str,
    database_raw: bytes,
    intelligence_raw: bytes,
) -> dict[str, object]:
    sources = sorted(
        (_project_source(item) for item in _sequence(intelligence.get("sources"), "sources")),
        key=lambda item: cast(str, item["id"]),
    )
    events = sorted(
        (_project_event(item) for item in _sequence(intelligence.get("events"), "events")),
        key=lambda item: (cast(str, item["date"]), cast(str, item["id"])),
        reverse=True,
    )
    return {
        "schema_version": "1",
        "content_license": "CC-BY-SA-4.0",
        "agentsec": {
            "name": "AgentSec Triage",
            "version": project_version,
            "status": "alpha",
            "repository_url": "https://github.com/FlorianBruniaux/agentsec-triage",
            "documentation_url": "https://github.com/FlorianBruniaux/agentsec-triage#readme",
            "installation_url": "https://github.com/FlorianBruniaux/agentsec-triage/blob/main/docs/installation.md",
            "scan_command": "agentsec scan /path/to/repository --format json --redact",
        },
        "database": {
            "version": _string(database.get("version"), "database version"),
            "updated": _string(database.get("updated"), "database updated date"),
            "record_counts": {
                "attack_techniques": len(_records(database, "attack_techniques")),
                "campaigns": len(_records(database, "campaigns")),
                "cves": len(_records(database, "cve_database")),
                "malicious_skill_records": len(_records(database, "malicious_skills")),
            },
        },
        "landing_metrics": {
            "critical_risk_skills": _unique_metric(database, "critical_risk"),
            "exposed_servers": _unique_metric(database, "exposed_servers"),
            "flawed_skills_percent": _unique_metric(database, "flawed_percentage"),
            "malicious_payloads": _unique_metric(database, "malicious_payloads"),
            "skills_scanned": _unique_metric(database, "skills_scanned"),
        },
        "intelligence": {
            "schema_version": _string(intelligence.get("schema_version"), "intelligence schema"),
            "updated": _string(intelligence.get("updated"), "intelligence updated date"),
            "sources": sources,
            "events": events,
        },
        "detectors": _project_detectors(),
        "input_digests": {
            "intelligence_sha256": _text_digest(intelligence_raw),
            "threat_database_sha256": _text_digest(database_raw),
        },
    }


def _validate_feed(feed: Mapping[str, object], schema: Mapping[str, object]) -> None:
    try:
        Draft202012Validator.check_schema(schema)
        errors = sorted(
            Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(feed),
            key=lambda error: tuple(str(part) for part in error.absolute_path),
        )
    except Exception as exc:
        raise SecurityFeedBuildError("invalid security feed schema") from exc
    if errors:
        path = "/".join(str(part) for part in errors[0].absolute_path) or "<root>"
        raise SecurityFeedBuildError(f"security feed validation failed at {path}")


def _write_json(path: Path, payload: Mapping[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    temporary.replace(path)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build the AgentSec public security feed.")
    parser.add_argument("--threat-database", type=Path, default=DEFAULT_THREAT_DATABASE)
    parser.add_argument("--intelligence", type=Path, default=DEFAULT_INTELLIGENCE)
    parser.add_argument("--project", type=Path, default=DEFAULT_PROJECT)
    parser.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    try:
        database, database_raw = _load_yaml(arguments.threat_database)
        intelligence, intelligence_raw = _load_json(arguments.intelligence, "intelligence")
        schema, _ = _load_json(arguments.schema, "security feed schema")
        feed = build_feed(
            database,
            intelligence,
            project_version=_load_project_version(arguments.project),
            database_raw=database_raw,
            intelligence_raw=intelligence_raw,
        )
        _validate_feed(feed, schema)
        _write_json(arguments.output, feed)
    except SecurityFeedBuildError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    database_feed = cast(Mapping[str, object], feed["database"])
    intelligence_feed = cast(Mapping[str, object], feed["intelligence"])
    print(
        "built public security feed "
        f"schema={feed['schema_version']} database={database_feed['version']} "
        f"events={len(cast(Sequence[object], intelligence_feed['events']))} "
        f"output={arguments.output}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

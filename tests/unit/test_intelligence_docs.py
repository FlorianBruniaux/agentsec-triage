import json
import runpy
from collections.abc import Callable
from copy import deepcopy
from pathlib import Path
from typing import cast

import yaml
from jsonschema import Draft202012Validator

PROJECT_ROOT = Path(__file__).parents[2]
INTELLIGENCE_ROOT = PROJECT_ROOT / "data" / "intelligence"
BUILDER = runpy.run_path(str(PROJECT_ROOT / "scripts" / "build_intelligence_docs.py"))
IntelligenceBuildError = cast(type[Exception], BUILDER["IntelligenceBuildError"])
load_intelligence = cast(Callable[[Path, Path, Path], object], BUILDER["load_intelligence"])
render_json = cast(Callable[[object], str], BUILDER["render_json"])
render_sources_markdown = cast(
    Callable[[object], str], BUILDER["render_sources_markdown"]
)
render_timeline_markdown = cast(
    Callable[[object], str], BUILDER["render_timeline_markdown"]
)


def _load_yaml(name: str) -> dict[str, object]:
    loaded = yaml.safe_load((INTELLIGENCE_ROOT / name).read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    return cast(dict[str, object], loaded)


def test_authoring_documents_validate_against_shared_schema() -> None:
    schema_path = INTELLIGENCE_ROOT / "intelligence.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)

    for name in ("sources.yaml", "events.yaml"):
        validator.validate(_load_yaml(name))


def test_initial_records_have_unique_ids_and_resolved_sources() -> None:
    source_document = _load_yaml("sources.yaml")
    event_document = _load_yaml("events.yaml")
    sources = cast(list[dict[str, object]], source_document["sources"])
    events = cast(list[dict[str, object]], event_document["events"])

    source_ids = [cast(str, source["id"]) for source in sources]
    event_ids = [cast(str, event["id"]) for event in events]
    assert len(source_ids) == len(set(source_ids))
    assert len(event_ids) == len(set(event_ids))

    known_sources = set(source_ids)
    for event in events:
        assert set(cast(list[str], event["source_ids"])) <= known_sources


def test_initial_intelligence_separates_confirmed_and_contested_keyv_claims() -> None:
    source_document = _load_yaml("sources.yaml")
    event_document = _load_yaml("events.yaml")
    sources = cast(list[dict[str, object]], source_document["sources"])
    events = cast(list[dict[str, object]], event_document["events"])

    assert any("keyv" in cast(str, source["id"]) for source in sources)
    by_id = {cast(str, event["id"]): event for event in events}

    confirmed = by_id["evt-2026-08-keyv-campaign-disclosure"]
    assert confirmed["status"] == "confirmed"
    assert confirmed["confidence"] == "confirmed"
    assert cast(dict[str, object], confirmed["detector_coverage"])["status"] == "partial"

    contested = by_id["evt-2026-08-keyv-contested-scope"]
    assert contested["status"] == "contested"
    assert contested["confidence"] == "contested"


def test_claude_code_webfetch_cve_is_sourced_and_explicitly_not_detected() -> None:
    source_document = _load_yaml("sources.yaml")
    event_document = _load_yaml("events.yaml")
    threat_document = yaml.safe_load(
        (PROJECT_ROOT / "data" / "threat-db.yaml").read_text(encoding="utf-8")
    )
    assert isinstance(threat_document, dict)

    sources = {
        cast(str, source["id"]): source
        for source in cast(list[dict[str, object]], source_document["sources"])
    }
    events = {
        cast(str, event["id"]): event
        for event in cast(list[dict[str, object]], event_document["events"])
    }

    advisory = sources["anthropic-ghsa-fg94-h982-f3mm"]
    assert advisory["source_type"] == "advisory"
    assert advisory["publisher"] == "Anthropic"

    event = events["evt-2026-06-claude-code-webfetch-exfiltration"]
    assert event["status"] == "confirmed"
    assert event["confidence"] == "confirmed"
    assert cast(dict[str, object], event["related"])["cve_ids"] == [
        "CVE-2026-54316"
    ]
    assert cast(dict[str, object], event["detector_coverage"])["status"] == (
        "not_detected"
    )
    assert threat_document["version"] == "2.27.0"


def _write_documents(
    tmp_path: Path,
    source_document: dict[str, object],
    event_document: dict[str, object],
) -> tuple[Path, Path]:
    sources_path = tmp_path / "sources.yaml"
    events_path = tmp_path / "events.yaml"
    sources_path.write_text(yaml.safe_dump(source_document, sort_keys=False), encoding="utf-8")
    events_path.write_text(yaml.safe_dump(event_document, sort_keys=False), encoding="utf-8")
    return sources_path, events_path


def test_loader_rejects_duplicate_yaml_keys_before_validation(tmp_path: Path) -> None:
    sources_path = tmp_path / "sources.yaml"
    sources_path.write_text(
        'schema_version: "1"\n'
        "kind: sources\n"
        'updated: "2026-08-07"\n'
        "sources:\n"
        "  - id: first\n"
        "    id: do-not-leak\n",
        encoding="utf-8",
    )

    try:
        load_intelligence(
            sources_path,
            INTELLIGENCE_ROOT / "events.yaml",
            INTELLIGENCE_ROOT / "intelligence.schema.json",
        )
    except IntelligenceBuildError as exc:
        assert str(exc) == "load failed: duplicate YAML mapping key"
        assert "do-not-leak" not in str(exc)
    else:
        raise AssertionError("duplicate YAML key was accepted")


def test_loader_rejects_duplicate_stable_ids(tmp_path: Path) -> None:
    sources = deepcopy(_load_yaml("sources.yaml"))
    events = deepcopy(_load_yaml("events.yaml"))
    source_records = cast(list[dict[str, object]], sources["sources"])
    source_records.append(deepcopy(source_records[0]))
    source_path, event_path = _write_documents(tmp_path, sources, events)

    try:
        load_intelligence(
            source_path,
            event_path,
            INTELLIGENCE_ROOT / "intelligence.schema.json",
        )
    except IntelligenceBuildError as exc:
        assert str(exc) == "cross-reference failed: duplicate source id"
    else:
        raise AssertionError("duplicate source id was accepted")


def test_loader_rejects_unresolved_event_source_reference(tmp_path: Path) -> None:
    sources = deepcopy(_load_yaml("sources.yaml"))
    events = deepcopy(_load_yaml("events.yaml"))
    event_records = cast(list[dict[str, object]], events["events"])
    event_records[0]["source_ids"] = ["missing-source"]
    source_path, event_path = _write_documents(tmp_path, sources, events)

    try:
        load_intelligence(
            source_path,
            event_path,
            INTELLIGENCE_ROOT / "intelligence.schema.json",
        )
    except IntelligenceBuildError as exc:
        assert str(exc) == "cross-reference failed: unresolved source id"
    else:
        raise AssertionError("unresolved source id was accepted")


def test_renderers_are_deterministic_and_expose_contested_status() -> None:
    corpus = load_intelligence(
        INTELLIGENCE_ROOT / "sources.yaml",
        INTELLIGENCE_ROOT / "events.yaml",
        INTELLIGENCE_ROOT / "intelligence.schema.json",
    )

    sources = render_sources_markdown(corpus)
    assert sources == render_sources_markdown(corpus)
    timeline = render_timeline_markdown(corpus)
    assert timeline == render_timeline_markdown(corpus)
    assert "CONTESTED" in timeline
    assert "events tracked by AgentSec" in timeline
    assert chr(0x2014) not in sources
    assert chr(0x2014) not in timeline
    assert "not recorded" in timeline

    rendered_json = render_json(corpus)
    assert rendered_json == render_json(corpus)
    payload = json.loads(rendered_json)
    assert "generated_at" not in payload
    assert payload["schema_version"] == "1"


def test_timeline_orders_events_by_best_available_date_descending(tmp_path: Path) -> None:
    sources = deepcopy(_load_yaml("sources.yaml"))
    events = deepcopy(_load_yaml("events.yaml"))
    event_records = cast(list[dict[str, object]], events["events"])
    event_records[1]["updated_date"] = "2026-08-07"
    source_path, event_path = _write_documents(tmp_path, sources, events)
    corpus = load_intelligence(
        source_path,
        event_path,
        INTELLIGENCE_ROOT / "intelligence.schema.json",
    )

    timeline = render_timeline_markdown(corpus)
    assert timeline.index("evt-2026-08-keyv-contested-scope") < timeline.index(
        "evt-2026-08-keyv-campaign-disclosure"
    )


def test_loader_accepts_distinct_occurrence_and_disclosure_dates(tmp_path: Path) -> None:
    sources = deepcopy(_load_yaml("sources.yaml"))
    events = deepcopy(_load_yaml("events.yaml"))
    event_records = cast(list[dict[str, object]], events["events"])
    event_records[0]["occurred_date"] = "2026-08-04"
    source_path, event_path = _write_documents(tmp_path, sources, events)

    corpus = load_intelligence(
        source_path,
        event_path,
        INTELLIGENCE_ROOT / "intelligence.schema.json",
    )

    assert corpus is not None


def test_loader_rejects_nonexistent_calendar_date(tmp_path: Path) -> None:
    sources = deepcopy(_load_yaml("sources.yaml"))
    events = deepcopy(_load_yaml("events.yaml"))
    source_records = cast(list[dict[str, object]], sources["sources"])
    source_records[0]["reviewed_date"] = "2026-99-99"
    source_path, event_path = _write_documents(tmp_path, sources, events)

    try:
        load_intelligence(
            source_path,
            event_path,
            INTELLIGENCE_ROOT / "intelligence.schema.json",
        )
    except IntelligenceBuildError as exc:
        assert str(exc) == "validation failed: sources document"
    else:
        raise AssertionError("nonexistent calendar date was accepted")


def _correction_event(target_id: str) -> dict[str, object]:
    return {
        "id": "evt-2026-08-example-correction",
        "event_type": "correction",
        "title": "Example event corrected",
        "summary": "A later primary source corrected one claim in the earlier event.",
        "ecosystems": ["developer-tools"],
        "updated_date": "2026-08-31",
        "status": "corrected",
        "confidence": "confirmed",
        "source_ids": ["varonis-cosnitch-2026"],
        "affected_event_ids": [target_id],
        "related": {
            "campaign_ids": [],
            "cve_ids": [],
            "technique_ids": [],
        },
        "detector_coverage": {
            "status": "not_applicable",
            "detector_ids": [],
            "notes": "The correction changes intelligence, not repository coverage.",
        },
    }


def _retraction_event(target_id: str) -> dict[str, object]:
    event = _correction_event(target_id)
    event["id"] = "evt-2026-08-example-retraction"
    event["event_type"] = "retraction"
    event["title"] = "Example event retracted"
    event["status"] = "retracted"
    return event


def _load_error(
    tmp_path: Path,
    sources: dict[str, object],
    events: dict[str, object],
) -> str:
    source_path, event_path = _write_documents(tmp_path, sources, events)
    try:
        load_intelligence(
            source_path,
            event_path,
            INTELLIGENCE_ROOT / "intelligence.schema.json",
        )
    except IntelligenceBuildError as exc:
        return str(exc)
    raise AssertionError("invalid intelligence documents were accepted")


def test_loader_accepts_correction_that_preserves_and_references_prior_event(
    tmp_path: Path,
) -> None:
    sources = deepcopy(_load_yaml("sources.yaml"))
    events = deepcopy(_load_yaml("events.yaml"))
    event_records = cast(list[dict[str, object]], events["events"])
    target_id = cast(str, event_records[0]["id"])
    event_records.append(_correction_event(target_id))
    source_path, event_path = _write_documents(tmp_path, sources, events)

    corpus = load_intelligence(
        source_path,
        event_path,
        INTELLIGENCE_ROOT / "intelligence.schema.json",
    )

    timeline = render_timeline_markdown(corpus)
    assert f"Affects events: `{target_id}`" in timeline
    payload = json.loads(render_json(corpus))
    correction = next(
        item
        for item in cast(list[dict[str, object]], payload["events"])
        if item["id"] == "evt-2026-08-example-correction"
    )
    assert correction["affected_event_ids"] == [target_id]
    assert any(
        item["id"] == target_id
        for item in cast(list[dict[str, object]], payload["events"])
    )


def test_loader_rejects_correction_without_affected_event_ids(tmp_path: Path) -> None:
    sources = deepcopy(_load_yaml("sources.yaml"))
    events = deepcopy(_load_yaml("events.yaml"))
    event_records = cast(list[dict[str, object]], events["events"])
    correction = _correction_event(cast(str, event_records[0]["id"]))
    correction.pop("affected_event_ids")
    event_records.append(correction)

    assert _load_error(tmp_path, sources, events) == (
        "validation failed: events document"
    )


def test_loader_rejects_unresolved_correction_target(tmp_path: Path) -> None:
    sources = deepcopy(_load_yaml("sources.yaml"))
    events = deepcopy(_load_yaml("events.yaml"))
    event_records = cast(list[dict[str, object]], events["events"])
    event_records.append(_correction_event("evt-missing"))

    assert _load_error(tmp_path, sources, events) == (
        "cross-reference failed: unresolved affected event id"
    )


def test_loader_rejects_self_referencing_correction(tmp_path: Path) -> None:
    sources = deepcopy(_load_yaml("sources.yaml"))
    events = deepcopy(_load_yaml("events.yaml"))
    event_records = cast(list[dict[str, object]], events["events"])
    event_records.append(_correction_event("evt-2026-08-example-correction"))

    assert _load_error(tmp_path, sources, events) == (
        "cross-reference failed: event cannot affect itself"
    )


def test_loader_rejects_correction_with_non_correction_status(tmp_path: Path) -> None:
    sources = deepcopy(_load_yaml("sources.yaml"))
    events = deepcopy(_load_yaml("events.yaml"))
    event_records = cast(list[dict[str, object]], events["events"])
    correction = _correction_event(cast(str, event_records[0]["id"]))
    correction["status"] = "confirmed"
    event_records.append(correction)

    assert _load_error(tmp_path, sources, events) == (
        "validation failed: events document"
    )


def test_loader_requires_correction_update_date(tmp_path: Path) -> None:
    sources = deepcopy(_load_yaml("sources.yaml"))
    events = deepcopy(_load_yaml("events.yaml"))
    event_records = cast(list[dict[str, object]], events["events"])
    correction = _correction_event(cast(str, event_records[0]["id"]))
    correction.pop("updated_date")
    correction["disclosed_date"] = "2026-08-31"
    event_records.append(correction)

    assert _load_error(tmp_path, sources, events) == (
        "validation failed: events document"
    )


def test_loader_rejects_retraction_without_affected_event_ids(tmp_path: Path) -> None:
    sources = deepcopy(_load_yaml("sources.yaml"))
    events = deepcopy(_load_yaml("events.yaml"))
    event_records = cast(list[dict[str, object]], events["events"])
    retraction = _retraction_event(cast(str, event_records[0]["id"]))
    retraction.pop("affected_event_ids")
    event_records.append(retraction)

    assert _load_error(tmp_path, sources, events) == (
        "validation failed: events document"
    )


def test_loader_rejects_retraction_with_non_retracted_status(tmp_path: Path) -> None:
    sources = deepcopy(_load_yaml("sources.yaml"))
    events = deepcopy(_load_yaml("events.yaml"))
    event_records = cast(list[dict[str, object]], events["events"])
    retraction = _retraction_event(cast(str, event_records[0]["id"]))
    retraction["status"] = "corrected"
    event_records.append(retraction)

    assert _load_error(tmp_path, sources, events) == (
        "validation failed: events document"
    )


def test_loader_rejects_affected_event_ids_on_ordinary_event(tmp_path: Path) -> None:
    sources = deepcopy(_load_yaml("sources.yaml"))
    events = deepcopy(_load_yaml("events.yaml"))
    event_records = cast(list[dict[str, object]], events["events"])
    event_records[0]["affected_event_ids"] = [event_records[1]["id"]]

    assert _load_error(tmp_path, sources, events) == (
        "validation failed: events document"
    )

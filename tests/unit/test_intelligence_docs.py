import json
from pathlib import Path
from typing import cast

import yaml
from jsonschema import Draft202012Validator

PROJECT_ROOT = Path(__file__).parents[2]
INTELLIGENCE_ROOT = PROJECT_ROOT / "data" / "intelligence"


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


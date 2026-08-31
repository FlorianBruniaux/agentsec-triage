from __future__ import annotations

import json
import runpy
from collections.abc import Callable, Mapping
from copy import deepcopy
from pathlib import Path
from typing import cast

import pytest
from jsonschema import Draft202012Validator

from agentsec.detectors.registry import get_detectors

PROJECT_ROOT = Path(__file__).parents[2]
SOURCE = PROJECT_ROOT / "data" / "response-playbooks.json"
SCHEMA = PROJECT_ROOT / "schemas" / "response-playbooks-v1.schema.json"
RESOURCE = PROJECT_ROOT / "src" / "agentsec" / "resources" / "response-playbooks.json"
DOCS_ROOT = PROJECT_ROOT / "docs" / "response-playbooks"
BUILDER_PATH = PROJECT_ROOT / "scripts" / "build_response_playbooks.py"


def _builder() -> dict[str, object]:
    return runpy.run_path(str(BUILDER_PATH))


def _document() -> dict[str, object]:
    loaded = json.loads(SOURCE.read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    return cast(dict[str, object], loaded)


def _detector_rules() -> dict[str, frozenset[str]]:
    return {
        detector.id: frozenset(detector.rule_ids)
        for detector in get_detectors()
    }


def test_authoring_playbooks_validate_against_public_schema() -> None:
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(_document())


def test_every_active_detector_rule_has_exactly_one_versioned_playbook() -> None:
    namespace = _builder()
    validate = cast(
        Callable[[Mapping[str, object], Mapping[str, frozenset[str]]], None],
        namespace["validate_rule_coverage"],
    )
    document = _document()

    validate(document, _detector_rules())

    mapped: dict[tuple[str, str], int] = {}
    for playbook in cast(list[dict[str, object]], document["playbooks"]):
        for rule_id in cast(list[str], playbook["rule_ids"]):
            key = (cast(str, playbook["detector_id"]), rule_id)
            mapped[key] = mapped.get(key, 0) + 1
    expected = {
        (detector_id, rule_id)
        for detector_id, rule_ids in _detector_rules().items()
        for rule_id in rule_ids
    }
    assert set(mapped) == expected
    assert set(mapped.values()) == {1}


def test_playbooks_keep_confidence_states_manual_phases_and_scope_limits() -> None:
    for playbook in cast(list[dict[str, object]], _document()["playbooks"]):
        assert set(cast(dict[str, str], playbook["confidence_guidance"])) == {
            "confirmed",
            "contested",
            "high",
            "review",
        }
        automation = cast(dict[str, str], playbook["automation"])
        assert automation == {
            "destructive_actions": "forbidden",
            "execution": "manual-only",
        }
        phases = cast(list[dict[str, object]], playbook["phases"])
        assert [phase["id"] for phase in phases] == [
            "evidence-collection",
            "manual-containment",
            "remediation",
            "verification",
        ]
        assert all(phase["mode"] == "manual" for phase in phases)
        assert all(cast(list[str], phase["actions"]) for phase in phases)
        assert cast(list[str], playbook["out_of_scope"])
        assert cast(list[dict[str, str]], playbook["sources"])


def test_builder_rejects_missing_or_unknown_active_rule_mapping(tmp_path: Path) -> None:
    namespace = _builder()
    validate = cast(
        Callable[[Mapping[str, object], Mapping[str, frozenset[str]]], None],
        namespace["validate_rule_coverage"],
    )
    error = cast(type[Exception], namespace["ResponsePlaybookBuildError"])
    document = deepcopy(_document())
    playbooks = cast(list[dict[str, object]], document["playbooks"])
    rules = cast(list[str], playbooks[0]["rule_ids"])
    rules.pop()

    with pytest.raises(error, match="active detector rule coverage mismatch"):
        validate(document, _detector_rules())

    document = deepcopy(_document())
    playbooks = cast(list[dict[str, object]], document["playbooks"])
    cast(list[str], playbooks[0]["rule_ids"]).append("unknown-rule")
    with pytest.raises(error, match="active detector rule coverage mismatch"):
        validate(document, _detector_rules())


def test_builder_outputs_are_deterministic_and_public_paths_resolve() -> None:
    namespace = _builder()
    render_resource = cast(
        Callable[[Mapping[str, object]], str], namespace["render_resource"]
    )
    render_index = cast(
        Callable[[Mapping[str, object]], str], namespace["render_index"]
    )
    render_playbook = cast(
        Callable[[Mapping[str, object]], str], namespace["render_playbook"]
    )
    document = _document()

    assert RESOURCE.read_text(encoding="utf-8") == render_resource(document)
    assert (DOCS_ROOT / "README.md").read_text(encoding="utf-8") == render_index(
        document
    )
    for playbook in cast(list[dict[str, object]], document["playbooks"]):
        path = PROJECT_ROOT / cast(str, playbook["document_path"])
        assert path.is_file()
        assert path.read_text(encoding="utf-8") == render_playbook(playbook)


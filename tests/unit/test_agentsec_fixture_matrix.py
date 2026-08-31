from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).parents[2]
SCRIPT_PATH = PROJECT_ROOT / "scripts" / "run_agentsec_fixture_matrix.py"
SPEC = importlib.util.spec_from_file_location("agentsec_fixture_matrix", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def _payload(*, elapsed_ms: int = 1) -> dict[str, object]:
    return {
        "complete": True,
        "database_version": "test-db",
        "detectors": [
            {
                "applicability": "applicable",
                "bytes_inspected": 10,
                "detector_id": "test-detector",
                "files_inspected": 1,
                "files_seen": 1,
                "not_scanned": ["git.history"],
            }
        ],
        "diagnostics": [],
        "discovery": {
            "directories_opened": 1,
            "entries_seen": 1,
            "exclusions": [],
            "files_selected": 1,
        },
        "elapsed_ms": elapsed_ms,
        "findings": [],
        "not_scanned": ["git.history"],
        "root": "<SCAN_ROOT>",
        "schema_version": "2",
        "scope": "repository",
        "tool_version": "test-tool",
    }


def test_normalization_removes_only_runtime_duration() -> None:
    first = MODULE._normalized_payload(_payload(elapsed_ms=1))
    second = MODULE._normalized_payload(_payload(elapsed_ms=99))

    assert "elapsed_ms" not in first
    assert MODULE._digest(first) == MODULE._digest(second)


def test_normalization_rejects_unredacted_root() -> None:
    payload = _payload()
    payload["root"] = "/private/repository"

    with pytest.raises(MODULE.BaselineError, match="root is not redacted"):
        MODULE._normalized_payload(payload)


def test_summary_requires_three_deterministic_runs() -> None:
    fixture = {"id": "clean-control", "kind": "negative"}
    runs = [(0, _payload(elapsed_ms=value)) for value in (1, 2, 3)]

    summary = MODULE._summarize_fixture(fixture, runs)

    assert summary["applicability"] == "applicable"
    assert summary["complete"] is True
    assert summary["exit_code"] == 0
    assert summary["repeat_count"] == 3


def test_summary_rejects_semantic_drift_between_runs() -> None:
    fixture = {"id": "clean-control", "kind": "negative"}
    changed = _payload()
    changed["complete"] = False
    runs = [(0, _payload()), (0, changed), (0, _payload())]

    with pytest.raises(MODULE.BaselineError, match="not deterministic"):
        MODULE._summarize_fixture(fixture, runs)


def test_output_must_stay_under_ignored_local_directory(tmp_path: Path) -> None:
    with pytest.raises(MODULE.BaselineError, match="ignored local run directory"):
        MODULE._validated_output_path(tmp_path / "baseline.json")


def test_fixture_directory_must_stay_under_fixture_root(tmp_path: Path) -> None:
    fixture_root = tmp_path / "fixtures"
    fixture_root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()

    with pytest.raises(MODULE.BaselineError, match="outside fixture root"):
        MODULE._resolved_fixture_root(fixture_root, "../outside")

from __future__ import annotations

from pathlib import Path

import pytest

from agentsec.detectors.base import DetectorMetadata, ScanContext
from agentsec.detectors.registry import get_detectors
from agentsec.engine.discovery import DiscoveryLimits
from agentsec.engine.runner import run_scan
from agentsec.models import (
    Applicability,
    Coverage,
    DetectorResult,
    ThreatDatabase,
)
from agentsec.scopes import ScanScope

LIMITS = DiscoveryLimits(max_file_bytes=4_000_000, max_files=1000, max_diagnostics=100)


class NeverAppliesDetector:
    id = "never"
    version = "1"
    metadata = DetectorMetadata(
        description="never applies",
        supported_inputs=(),
        campaign_ids=(),
        technique_ids=(),
        source_references=(),
        limitations=(),
        remediation_url=None,
        not_scanned=("detector.never",),
    )

    def applies(self, context: ScanContext) -> bool:
        return False

    def run(self, context: ScanContext) -> DetectorResult:
        raise AssertionError("run must not be called when not applicable")


class ExplodingDetector:
    id = "explode"
    version = "1"
    metadata = NeverAppliesDetector.metadata

    def applies(self, context: ScanContext) -> bool:
        return True

    def run(self, context: ScanContext) -> DetectorResult:
        raise RuntimeError("boom")


@pytest.fixture
def empty_database() -> ThreatDatabase:
    return ThreatDatabase(
        version="test",
        updated="2026-08-06",
        package_versions={},
        wildcard_package_versions={},
        hashes={},
        domains=frozenset(),
        commit_indicators=(),
    )


def test_not_applicable_detector_does_not_make_scan_incomplete(
    tmp_path: Path, empty_database: ThreatDatabase
) -> None:
    result = run_scan(tmp_path, [NeverAppliesDetector()], empty_database, LIMITS)

    assert result.complete is True
    assert result.exit_code() == 0
    assert result.detector_results[0].applicability is Applicability.NOT_APPLICABLE
    assert result.not_scanned == (
        "container.filesystems",
        "detector.never",
        "host.caches",
        "host.credentials",
        "host.global_config",
        "host.processes",
        "remediation.automatic",
        "remote.ci",
        "remote.repositories",
    )


def test_detector_exception_becomes_error_not_clean_result(
    tmp_path: Path, empty_database: ThreatDatabase
) -> None:
    result = run_scan(tmp_path, [ExplodingDetector()], empty_database, LIMITS)

    assert result.complete is False
    assert result.exit_code() == 2
    assert "detector failed" in result.diagnostics[0].message


def test_runner_sorts_detectors_and_shares_one_resolved_context(
    tmp_path: Path, empty_database: ThreatDatabase
) -> None:
    seen_contexts: list[ScanContext] = []

    class RecordingDetector:
        version = "1"

        def __init__(self, identifier: str) -> None:
            self.id = identifier

        def applies(self, context: ScanContext) -> bool:
            seen_contexts.append(context)
            return True

        def run(self, context: ScanContext) -> DetectorResult:
            seen_contexts.append(context)
            return DetectorResult(
                detector_id=self.id,
                applicability=Applicability.APPLICABLE,
                findings=(),
                diagnostics=(),
                coverage=Coverage(),
            )

    result = run_scan(
        tmp_path / ".",
        [RecordingDetector("z"), RecordingDetector("a")],
        empty_database,
        LIMITS,
    )

    assert [item.detector_id for item in result.detector_results] == ["a", "z"]
    assert len(seen_contexts) == 4
    assert all(context is seen_contexts[0] for context in seen_contexts)
    assert seen_contexts[0].root == tmp_path.resolve()
    assert seen_contexts[0].files == ()


def test_runner_records_scope_and_discovery_once_for_multiple_detectors(
    tmp_path: Path, empty_database: ThreatDatabase
) -> None:
    (tmp_path / "input.txt").write_text("evidence")

    class CountingDetector:
        version = "1"

        def __init__(self, identifier: str) -> None:
            self.id = identifier
            self.metadata = DetectorMetadata(
                description=identifier,
                supported_inputs=("regular files",),
                campaign_ids=(),
                technique_ids=(),
                source_references=(),
                limitations=(),
                remediation_url=None,
                not_scanned=(f"{identifier}.outside",),
            )

        def applies(self, context: ScanContext) -> bool:
            assert context.scope is ScanScope.REPOSITORY
            return True

        def run(self, context: ScanContext) -> DetectorResult:
            return DetectorResult(
                detector_id=self.id,
                applicability=Applicability.APPLICABLE,
                findings=(),
                diagnostics=(),
                coverage=Coverage(
                    files_seen=len(context.files),
                    files_inspected=len(context.files),
                    bytes_inspected=sum(item.size for item in context.files),
                ),
            )

    result = run_scan(
        tmp_path,
        [CountingDetector("z"), CountingDetector("a")],
        empty_database,
        LIMITS,
        scope=ScanScope.REPOSITORY,
    )

    payload = result.to_dict()
    assert payload["scope"] == "repository"
    assert payload["discovery"] == {
        "entries_seen": 1,
        "directories_opened": 1,
        "files_selected": 1,
        "exclusions": [],
    }
    assert [item["detector_id"] for item in payload["detectors"]] == ["a", "z"]
    assert [item["files_seen"] for item in payload["detectors"]] == [1, 1]
    assert payload["detectors"][0]["not_scanned"] == ["a.outside"]
    assert "coverage" not in payload


def test_discovery_error_keeps_scan_incomplete(
    tmp_path: Path, empty_database: ThreatDatabase
) -> None:
    result = run_scan(tmp_path / "missing", (), empty_database, LIMITS)

    assert result.complete is False
    assert result.exit_code() == 2


def test_root_resolution_error_becomes_an_incomplete_scan(
    tmp_path: Path, empty_database: ThreatDatabase, monkeypatch: pytest.MonkeyPatch
) -> None:
    def failing_resolve(path: Path, *, strict: bool = False) -> Path:
        raise OSError("root resolution denied")

    monkeypatch.setattr(Path, "resolve", failing_resolve)

    result = run_scan(tmp_path, (), empty_database, LIMITS)

    assert result.complete is False
    assert result.exit_code() == 2
    assert "cannot access scan root" in result.diagnostics[0].message


def test_root_validation_error_becomes_an_incomplete_scan(
    tmp_path: Path, empty_database: ThreatDatabase, monkeypatch: pytest.MonkeyPatch
) -> None:
    def failing_is_dir(path: Path) -> bool:
        raise OSError("root validation denied")

    monkeypatch.setattr(Path, "is_dir", failing_is_dir)

    result = run_scan(tmp_path, (), empty_database, LIMITS)

    assert result.complete is False
    assert result.exit_code() == 2
    assert "cannot inspect scan root" in result.diagnostics[0].message


def test_root_lstat_error_becomes_an_incomplete_scan(
    tmp_path: Path, empty_database: ThreatDatabase, monkeypatch: pytest.MonkeyPatch
) -> None:
    def failing_lstat(path: Path) -> object:
        raise OSError("root metadata denied")

    monkeypatch.setattr(Path, "lstat", failing_lstat)

    result = run_scan(tmp_path, (), empty_database, LIMITS)

    assert result.complete is False
    assert result.exit_code() == 2
    assert result.diagnostics[0].path == tmp_path
    assert "cannot inspect entry" in result.diagnostics[0].message


def test_detector_errors_share_a_bounded_diagnostic_buffer(
    tmp_path: Path, empty_database: ThreatDatabase
) -> None:
    limits = DiscoveryLimits(max_file_bytes=4_000_000, max_files=1000, max_diagnostics=1)

    result = run_scan(
        tmp_path,
        [ExplodingDetector(), ExplodingDetector(), ExplodingDetector()],
        empty_database,
        limits,
    )

    assert result.complete is False
    assert len(result.diagnostics) == 2
    assert "detector failed" in result.diagnostics[0].message
    assert "truncated" in result.diagnostics[1].message


def test_explicit_registry_contains_shai_hulud_detector() -> None:
    detectors = get_detectors()

    assert [detector.id for detector in detectors] == ["shai-hulud-keyv"]
    assert get_detectors(["shai-hulud-keyv"]) == detectors
    with pytest.raises(ValueError, match="unknown detector IDs: missing"):
        get_detectors(["missing"])

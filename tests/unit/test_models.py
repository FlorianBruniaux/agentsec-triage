from pathlib import Path

import pytest

from agentsec.models import (
    Applicability,
    Confidence,
    Coverage,
    DetectorResult,
    Diagnostic,
    DiagnosticKind,
    Finding,
    ScanResult,
    Severity,
    ThreatDatabase,
)


def test_incomplete_scan_cannot_return_clean_exit_code():
    result = ScanResult(
        tool_version="0.1.0a0",
        database_version="2.26.0",
        root=Path("/repo"),
        detector_results=(),
        diagnostics=(Diagnostic(DiagnosticKind.ERROR, Path("/repo"), "unreadable"),),
        elapsed_ms=1,
    )
    assert result.complete is False
    assert result.exit_code() == 2


def test_findings_return_one_and_serialize_in_stable_order():
    finding = Finding(
        detector_id="shai-hulud-keyv",
        rule_id="compromised-package-version",
        severity=Severity.CRITICAL,
        confidence=Confidence.CONFIRMED,
        path=Path("package-lock.json"),
        evidence="keyv@6.0.0",
        campaign_ids=("shai-hulud-keyv-2026-08",),
    )
    detector = DetectorResult(
        detector_id="shai-hulud-keyv",
        applicability=Applicability.APPLICABLE,
        findings=(finding,),
        diagnostics=(),
        coverage=Coverage(files_seen=1, files_inspected=1, bytes_inspected=10),
    )
    result = ScanResult(
        tool_version="0.1.0a0",
        database_version="2.26.0",
        root=Path("/repo"),
        detector_results=(detector,),
        diagnostics=(),
        elapsed_ms=2,
    )
    assert result.complete is True
    assert result.exit_code() == 1
    assert result.to_dict()["findings"][0]["evidence"] == "keyv@6.0.0"


def test_threat_database_copies_and_freezes_nested_mappings():
    package_versions = {"keyv": {"6.0.0"}}
    wildcard_package_versions = {"keyv": {"6.*"}}
    hashes = {"package-lock.json": "abc"}
    commit_indicators = [{"repository": "owner/repository"}]
    database = ThreatDatabase(
        version="2.26.0",
        updated="2026-08-06",
        package_versions=package_versions,
        wildcard_package_versions=wildcard_package_versions,
        hashes=hashes,
        domains=frozenset({"example.test"}),
        commit_indicators=tuple(commit_indicators),
    )

    package_versions["keyv"].add("6.0.1")
    wildcard_package_versions["keyv"].add("7.*")
    hashes["package-lock.json"] = "changed"
    commit_indicators[0]["repository"] = "changed/repository"

    assert database.package_versions["keyv"] == frozenset({"6.0.0"})
    assert database.wildcard_package_versions["keyv"] == frozenset({"6.*"})
    assert database.hashes["package-lock.json"] == "abc"
    assert database.commit_indicators[0]["repository"] == "owner/repository"
    with pytest.raises(TypeError):
        database.commit_indicators[0]["repository"] = "mutated/repository"


def test_serialization_aggregates_and_sorts_mixed_detector_results():
    detector_b = DetectorResult(
        detector_id="detector-b",
        applicability=Applicability.APPLICABLE,
        findings=(
            Finding(
                "detector-b",
                "high-rule",
                Severity.HIGH,
                Confidence.HIGH,
                Path("b.lock"),
                "high",
            ),
            Finding(
                "detector-b",
                "critical-rule",
                Severity.CRITICAL,
                Confidence.CONFIRMED,
                Path("b.lock"),
                "critical",
            ),
        ),
        diagnostics=(Diagnostic(DiagnosticKind.WARNING, Path("b"), "b-warning"),),
        coverage=Coverage(3, 2, 30, ("network", "git")),
    )
    detector_a = DetectorResult(
        detector_id="detector-a",
        applicability=Applicability.APPLICABLE,
        findings=(
            Finding(
                "detector-a",
                "medium-rule",
                Severity.MEDIUM,
                Confidence.REVIEW,
                Path("a.lock"),
                "medium",
            ),
        ),
        diagnostics=(Diagnostic(DiagnosticKind.ERROR, Path("a"), "a-error"),),
        coverage=Coverage(1, 1, 10, ("git", "container")),
    )
    result = ScanResult(
        tool_version="0.1.0a0",
        database_version="2.26.0",
        root=Path("/repo"),
        detector_results=(detector_b, detector_a),
        diagnostics=(Diagnostic(DiagnosticKind.WARNING, Path("z"), "aggregate-warning"),),
        elapsed_ms=2,
    )

    payload = result.to_dict()

    assert [finding["evidence"] for finding in payload["findings"]] == [
        "critical",
        "high",
        "medium",
    ]
    assert [diagnostic["message"] for diagnostic in payload["diagnostics"]] == [
        "a-error",
        "b-warning",
        "aggregate-warning",
    ]
    assert payload["coverage"] == {
        "files_seen": 4,
        "files_inspected": 3,
        "bytes_inspected": 40,
    }
    assert payload["not_scanned"] == ["container", "git", "network"]

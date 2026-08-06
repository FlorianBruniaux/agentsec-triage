from pathlib import Path

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

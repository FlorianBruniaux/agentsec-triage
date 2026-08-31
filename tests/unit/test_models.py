from pathlib import Path, PureWindowsPath

import pytest

from agentsec.models import (
    Applicability,
    Confidence,
    Coverage,
    DetectorResult,
    Diagnostic,
    DiagnosticKind,
    DiscoveryCoverage,
    ExclusionCount,
    Finding,
    ScanResult,
    Severity,
    ThreatDatabase,
)
from agentsec.output.human import render_human
from agentsec.scopes import ExclusionReason


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


def test_discovery_coverage_sorts_and_freezes_exclusion_counts() -> None:
    coverage = DiscoveryCoverage(
        entries_seen=9,
        directories_opened=3,
        files_selected=4,
        exclusions=(
            ExclusionCount(ExclusionReason.GENERATED_OR_CACHE, paths=2, subtrees=1),
            ExclusionCount(ExclusionReason.BINARY_ASSET, paths=1, subtrees=0),
        ),
    )

    assert tuple(item.reason for item in coverage.exclusions) == (
        ExclusionReason.BINARY_ASSET,
        ExclusionReason.GENERATED_OR_CACHE,
    )


@pytest.mark.parametrize(
    "factory",
    (
        lambda: ExclusionCount(ExclusionReason.BINARY_ASSET, paths=-1, subtrees=0),
        lambda: ExclusionCount(ExclusionReason.BINARY_ASSET, paths=0, subtrees=-1),
        lambda: DiscoveryCoverage(
            entries_seen=-1,
            directories_opened=0,
            files_selected=0,
            exclusions=(),
        ),
    ),
)
def test_discovery_coverage_rejects_negative_counts(factory: object) -> None:
    with pytest.raises(ValueError, match="non-negative"):
        factory()  # type: ignore[operator]


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
    contested_package_versions = {"disputed": {"1.0.0"}}
    contested_wildcard_package_versions = {"@keyv/": {"6.0.0"}}
    package_version_sources = {
        "@keyv/": {"6.0.0": ["JFrog", "SafeDep"]},
    }
    hashes = {"package-lock.json": "abc"}
    commit_indicators = [{"repository": "owner/repository"}]
    database = ThreatDatabase(
        version="2.26.0",
        updated="2026-08-06",
        package_versions=package_versions,
        wildcard_package_versions=wildcard_package_versions,
        contested_package_versions=contested_package_versions,
        contested_wildcard_package_versions=contested_wildcard_package_versions,
        package_version_sources=package_version_sources,
        hashes=hashes,
        domains=frozenset({"example.test"}),
        commit_indicators=tuple(commit_indicators),
    )

    package_versions["keyv"].add("6.0.1")
    wildcard_package_versions["keyv"].add("7.*")
    contested_package_versions["disputed"].add("1.0.1")
    contested_wildcard_package_versions["@keyv/"].add("6.0.1")
    package_version_sources["@keyv/"]["6.0.0"].append("mutated")
    hashes["package-lock.json"] = "changed"
    commit_indicators[0]["repository"] = "changed/repository"

    assert database.package_versions["keyv"] == frozenset({"6.0.0"})
    assert database.wildcard_package_versions["keyv"] == frozenset({"6.*"})
    assert database.contested_package_versions["disputed"] == frozenset({"1.0.0"})
    assert database.contested_wildcard_package_versions["@keyv/"] == frozenset({"6.0.0"})
    assert database.package_version_sources["@keyv/"]["6.0.0"] == (
        "JFrog",
        "SafeDep",
    )
    assert database.hashes["package-lock.json"] == "abc"
    assert database.commit_indicators[0]["repository"] == "owner/repository"
    with pytest.raises(TypeError):
        database.commit_indicators[0]["repository"] = "mutated/repository"
    with pytest.raises(TypeError):
        database.package_version_sources["@keyv/"]["6.0.0"] = ("mutated",)


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


def test_serialization_and_human_output_use_forward_slashes_for_windows_paths():
    detector = DetectorResult(
        detector_id="detector",
        applicability=Applicability.APPLICABLE,
        findings=(
            Finding(
                "detector",
                "rule",
                Severity.HIGH,
                Confidence.HIGH,
                PureWindowsPath(r"nested\z.lock"),
                "z",
            ),
            Finding(
                "detector",
                "rule",
                Severity.HIGH,
                Confidence.HIGH,
                PureWindowsPath(r"nested\a.lock"),
                "a",
            ),
        ),
        diagnostics=(
            Diagnostic(
                DiagnosticKind.WARNING,
                PureWindowsPath(r"C:\repo\nested\warning.txt"),
                "warning",
            ),
        ),
        coverage=Coverage(files_seen=2, files_inspected=2, bytes_inspected=20),
    )
    result = ScanResult(
        tool_version="0.1.0a0",
        database_version="2.26.0",
        root=PureWindowsPath(r"C:\repo"),
        detector_results=(detector,),
        diagnostics=(),
        elapsed_ms=2,
    )

    payload = result.to_dict()

    assert payload["root"] == "C:/repo"
    assert [finding["path"] for finding in payload["findings"]] == [
        "nested/a.lock",
        "nested/z.lock",
    ]
    assert payload["diagnostics"][0]["path"] == "C:/repo/nested/warning.txt"
    human = render_human(result, redact=False)
    assert r"nested\a.lock" not in human
    assert "nested/a.lock" in human
    assert "C:/repo/nested/warning.txt" in human

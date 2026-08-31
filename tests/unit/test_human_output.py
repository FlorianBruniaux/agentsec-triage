from __future__ import annotations

from pathlib import PurePosixPath

from agentsec.models import (
    Applicability,
    Confidence,
    Coverage,
    DetectorResult,
    DiscoveryCoverage,
    ExclusionCount,
    Finding,
    ScanResult,
    Severity,
)
from agentsec.output.human import render_human
from agentsec.scopes import ExclusionReason, ScanScope

_ANSI_RESET = "\x1b[0m"


def _result_with_finding(*, remediation_url: str | None) -> ScanResult:
    detector = DetectorResult(
        detector_id="shai-hulud-keyv",
        applicability=Applicability.APPLICABLE,
        findings=(
            Finding(
                "shai-hulud-keyv",
                "startup-hook",
                Severity.MEDIUM,
                Confidence.REVIEW,
                PurePosixPath(".claude/settings.json"),
                "claude SessionStart hook",
                remediation_url=remediation_url,
            ),
        ),
        diagnostics=(),
        coverage=Coverage(files_seen=1, files_inspected=1, bytes_inspected=10),
    )
    return ScanResult(
        tool_version="0.1.0a0",
        database_version="2.27.0",
        root=PurePosixPath("/repo"),
        detector_results=(detector,),
        diagnostics=(),
        elapsed_ms=1,
    )


def test_render_human_surfaces_remediation_url_when_present() -> None:
    result = _result_with_finding(remediation_url="https://cc.bruniaux.com/security/")

    human = render_human(result, redact=False)

    assert "remediation: https://cc.bruniaux.com/security/" in human


def test_render_human_omits_remediation_suffix_when_absent() -> None:
    result = _result_with_finding(remediation_url=None)

    human = render_human(result, redact=False)

    assert "remediation:" not in human


def test_render_human_without_color_emits_no_ansi_codes() -> None:
    result = _result_with_finding(remediation_url=None)

    human = render_human(result, redact=False, color=False)

    assert "\x1b[" not in human


def test_render_human_with_color_wraps_each_severity_in_its_own_code() -> None:
    result = _result_with_finding(remediation_url=None)

    human = render_human(result, redact=False, color=True)

    assert f"\x1b[33mmedium{_ANSI_RESET}" in human
    assert f"\x1b[91mcritical{_ANSI_RESET}" in human
    assert f"\x1b[38;5;208mhigh{_ANSI_RESET}" in human
    assert f"\x1b[34mlow{_ANSI_RESET}" in human
    assert f"\x1b[35minfo{_ANSI_RESET}" in human


def test_render_human_with_color_still_contains_plain_evidence_text() -> None:
    result = _result_with_finding(remediation_url=None)

    human = render_human(result, redact=False, color=True)

    assert "shai-hulud-keyv/startup-hook" in human
    assert "claude SessionStart hook" in human


def test_render_human_separates_discovery_from_detector_coverage() -> None:
    result = _result_with_finding(remediation_url=None)
    result = ScanResult(
        tool_version=result.tool_version,
        database_version=result.database_version,
        root=result.root,
        detector_results=result.detector_results,
        diagnostics=result.diagnostics,
        elapsed_ms=result.elapsed_ms,
        scope=ScanScope.SOURCE,
        discovery=DiscoveryCoverage(
            entries_seen=12,
            directories_opened=3,
            files_selected=5,
            exclusions=(
                ExclusionCount(ExclusionReason.BINARY_ASSET, paths=2, subtrees=0),
            ),
        ),
    )

    human = render_human(result, redact=False)

    assert "Scope: source" in human
    assert "Discovery: entries_seen=12 directories_opened=3 files_selected=5" in human
    assert "binary_asset: paths=2 subtrees=0" in human
    assert "Detector coverage:" in human
    assert (
        "shai-hulud-keyv [applicable]: files_seen=1 files_inspected=1 "
        "bytes_inspected=10"
    ) in human
    assert "Coverage:" not in human

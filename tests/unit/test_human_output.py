from __future__ import annotations

from pathlib import PurePosixPath

from agentsec.models import (
    Applicability,
    Confidence,
    Coverage,
    DetectorResult,
    Finding,
    ScanResult,
    Severity,
)
from agentsec.output.human import render_human

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

"""Deterministic human-readable scan output."""

from __future__ import annotations

from collections.abc import Mapping
from typing import cast

from agentsec.models import Applicability, ScanResult, Severity
from agentsec.redaction import redact_result

_SEVERITIES = (
    Severity.CRITICAL.value,
    Severity.HIGH.value,
    Severity.MEDIUM.value,
    Severity.LOW.value,
    Severity.INFO.value,
)

_RESET = "\x1b[0m"

_SEVERITY_COLOR = {
    Severity.CRITICAL.value: "\x1b[91m",  # red
    Severity.HIGH.value: "\x1b[38;5;208m",  # orange
    Severity.MEDIUM.value: "\x1b[33m",  # yellow
    Severity.LOW.value: "\x1b[34m",  # blue
    Severity.INFO.value: "\x1b[35m",  # purple
}


def render_human(result: ScanResult, *, redact: bool, color: bool = False) -> str:
    """Render scan results in a stable order without calling an incomplete scan clean."""
    payload = result.to_dict()
    if redact:
        payload = redact_result(payload, result.root)

    discovery = cast(Mapping[str, object], payload["discovery"])
    exclusions = cast(list[Mapping[str, object]], discovery["exclusions"])
    detectors = cast(list[Mapping[str, object]], payload["detectors"])
    findings = cast(list[Mapping[str, object]], payload["findings"])
    diagnostics = cast(list[Mapping[str, object]], payload["diagnostics"])
    not_scanned = cast(list[str], payload["not_scanned"])
    complete = cast(bool, payload["complete"])

    lines = [
        f"AgentSec {payload['tool_version']} | threat database {payload['database_version']}",
        f"Scope: {payload['scope']}",
        f"Complete: {'yes' if complete else 'no'}",
        "Discovery: "
        f"entries_seen={discovery['entries_seen']} "
        f"directories_opened={discovery['directories_opened']} "
        f"files_selected={discovery['files_selected']}",
    ]
    if exclusions:
        lines.append("Exclusions:")
        lines.extend(
            f"  {item['reason']}: paths={item['paths']} subtrees={item['subtrees']}"
            for item in exclusions
        )
    else:
        lines.append("Exclusions: none")
    if detectors:
        lines.append("Detector coverage:")
        lines.extend(
            f"  {item['detector_id']} [{item['applicability']}]: "
            f"files_seen={item['files_seen']} "
            f"files_inspected={item['files_inspected']} "
            f"bytes_inspected={item['bytes_inspected']}"
            for item in detectors
        )
    else:
        lines.append("Detector coverage: none")
    if complete and all(
        item.applicability is Applicability.NOT_APPLICABLE
        for item in result.detector_results
    ):
        lines.append("No applicable detectors; no indicators found in completed checks.")
    elif complete and not findings:
        lines.append("No indicators found in completed checks.")
    elif not complete and not findings:
        lines.append("No findings reported because checks are incomplete.")

    lines.append("Findings:")
    for severity in _SEVERITIES:
        label = _colorize(severity, severity, color=color)
        items = [item for item in findings if item["severity"] == severity]
        if not items:
            lines.append(f"  {label}: none")
            continue
        lines.extend(f"  {label}: {_format_finding(item)}" for item in items)

    if diagnostics:
        lines.append("Diagnostics:")
        lines.extend(
            f"  {item['kind']}: {item['path']}: {item['message']}" for item in diagnostics
        )
    else:
        lines.append("Diagnostics: none")
    if not_scanned:
        lines.append("Not scanned:")
        lines.extend(f"  {item}" for item in not_scanned)
    else:
        lines.append("Not scanned: none")
    return "\n".join(lines) + "\n"


def _format_finding(finding: Mapping[str, object]) -> str:
    location = str(finding["path"])
    if finding["line"] is not None:
        location = f"{location}:{finding['line']}"
    text = (
        f"{finding['detector_id']}/{finding['rule_id']} "
        f"[{finding['confidence']}] {location}: {finding['evidence']}"
    )
    remediation_url = finding.get("remediation_url")
    if remediation_url:
        text = f"{text} (remediation: {remediation_url})"
    return text


def _colorize(severity: str, text: str, *, color: bool) -> str:
    if not color:
        return text
    return f"{_SEVERITY_COLOR[severity]}{text}{_RESET}"

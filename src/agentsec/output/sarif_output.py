"""Deterministic SARIF 2.1.0 rendering for repository scans."""

from __future__ import annotations

import json
from collections import defaultdict
from typing import cast
from urllib.parse import quote

from agentsec.models import ScanResult
from agentsec.output.json_output import scan_payload

_SARIF_SCHEMA = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/"
    "sarif-schema-2.1.0.json"
)
_SEVERITY_LEVELS = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def render_sarif(result: ScanResult, *, redact: bool) -> str:
    """Render one scan result as deterministic SARIF 2.1.0 JSON."""
    payload = scan_payload(result, redact=redact)
    findings = cast(list[dict[str, object]], payload["findings"])
    diagnostics = cast(list[dict[str, object]], payload["diagnostics"])
    discovery = cast(dict[str, object], payload["discovery"])
    sarif: dict[str, object] = {
        "$schema": _SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "AgentSec Triage",
                        "informationUri": (
                            "https://github.com/FlorianBruniaux/agentsec-triage"
                        ),
                        "semanticVersion": result.tool_version,
                        "rules": _rules(findings),
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": result.complete,
                        "exitCode": result.exit_code(),
                        "toolExecutionNotifications": [
                            _notification(item) for item in diagnostics
                        ],
                    }
                ],
                "results": [_finding(item) for item in findings],
                "properties": {
                    "agentsec.complete": result.complete,
                    "agentsec.databaseVersion": result.database_version,
                    "agentsec.detectors": [
                        _detector_coverage(item)
                        for item in cast(
                            list[dict[str, object]], payload["detectors"]
                        )
                    ],
                    "agentsec.diagnostics": diagnostics,
                    "agentsec.discovery": {
                        "entriesSeen": discovery["entries_seen"],
                        "directoriesOpened": discovery["directories_opened"],
                        "filesSelected": discovery["files_selected"],
                    },
                    "agentsec.discoveryExclusions": discovery["exclusions"],
                    "agentsec.elapsedMs": result.elapsed_ms,
                    "agentsec.notScanned": payload["not_scanned"],
                    "agentsec.scope": result.scope.value,
                },
            }
        ],
    }
    return json.dumps(sarif, indent=2, sort_keys=True) + "\n"


def _rules(findings: list[dict[str, object]]) -> list[dict[str, object]]:
    grouped: dict[str, list[dict[str, object]]] = defaultdict(list)
    for finding in findings:
        grouped[_sarif_rule_id(finding)].append(finding)

    rules: list[dict[str, object]] = []
    for rule_id in sorted(grouped):
        matches = grouped[rule_id]
        first = matches[0]
        detector_id = cast(str, first["detector_id"])
        original_rule_id = cast(str, first["rule_id"])
        tags = sorted(
            {
                cast(str, tag)
                for finding in matches
                for key in ("campaign_ids", "technique_ids")
                for tag in cast(list[object], finding[key])
            }
        )
        rule: dict[str, object] = {
            "id": rule_id,
            "name": original_rule_id,
            "shortDescription": {
                "text": f"{original_rule_id} reported by {detector_id}"
            },
            "properties": {
                "agentsec.detectorId": detector_id,
                "tags": tags,
            },
        }
        remediation_urls = {
            cast(str, finding["remediation_url"])
            for finding in matches
            if finding["remediation_url"] is not None
        }
        if len(remediation_urls) == 1:
            rule["helpUri"] = remediation_urls.pop()
        rules.append(rule)
    return rules


def _finding(finding: dict[str, object]) -> dict[str, object]:
    path = cast(str, finding["path"])
    line = cast(int | None, finding["line"])
    physical_location: dict[str, object] = {
        "artifactLocation": {
            "uri": quote(path, safe="/:@-._~"),
            "uriBaseId": "%SRCROOT%",
        }
    }
    if line is not None:
        physical_location["region"] = {"startLine": line}

    properties: dict[str, object] = {
        "agentsec.campaignIds": finding["campaign_ids"],
        "agentsec.confidence": finding["confidence"],
        "agentsec.detectorId": finding["detector_id"],
        "agentsec.originalSeverity": finding["severity"],
        "agentsec.techniqueIds": finding["technique_ids"],
    }
    if finding["remediation_url"] is not None:
        properties["agentsec.remediationUrl"] = finding["remediation_url"]

    severity = cast(str, finding["severity"])
    return {
        "ruleId": _sarif_rule_id(finding),
        "level": _SEVERITY_LEVELS[severity],
        "message": {"text": finding["evidence"]},
        "locations": [{"physicalLocation": physical_location}],
        "properties": properties,
    }


def _notification(diagnostic: dict[str, object]) -> dict[str, object]:
    kind = cast(str, diagnostic["kind"])
    return {
        "level": "error" if kind == "error" else "warning",
        "message": {"text": f"{diagnostic['path']}: {diagnostic['message']}"},
        "properties": {"agentsec.kind": kind},
    }


def _detector_coverage(detector: dict[str, object]) -> dict[str, object]:
    return {
        "detectorId": detector["detector_id"],
        "applicability": detector["applicability"],
        "filesSeen": detector["files_seen"],
        "filesInspected": detector["files_inspected"],
        "bytesInspected": detector["bytes_inspected"],
        "notScanned": detector["not_scanned"],
    }


def _sarif_rule_id(finding: dict[str, object]) -> str:
    return f"{finding['detector_id']}/{finding['rule_id']}"

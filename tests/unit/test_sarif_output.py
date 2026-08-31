from __future__ import annotations

import json
from pathlib import Path

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
)
from agentsec.output.sarif_output import render_sarif
from agentsec.scopes import ExclusionReason


def _result(*, findings: tuple[Finding, ...]) -> ScanResult:
    detector = DetectorResult(
        detector_id="shai-hulud-keyv",
        applicability=Applicability.APPLICABLE,
        findings=findings,
        diagnostics=(
            Diagnostic(
                DiagnosticKind.ERROR,
                Path("/repo/package-lock.json"),
                "Unable to inspect authoritative lockfile",
            ),
        ),
        coverage=Coverage(
            files_seen=3,
            files_inspected=2,
            bytes_inspected=512,
            not_scanned=("remote.ci", "git.history"),
        ),
    )
    return ScanResult(
        tool_version="0.1.0a0",
        database_version="2.27.0",
        root=Path("/repo"),
        detector_results=(detector,),
        diagnostics=(
            Diagnostic(
                DiagnosticKind.WARNING,
                Path("/repo/.git"),
                "VCS metadata excluded",
            ),
        ),
        elapsed_ms=12,
        discovery=DiscoveryCoverage(
            entries_seen=7,
            directories_opened=2,
            files_selected=3,
            exclusions=(
                ExclusionCount(ExclusionReason.VCS_METADATA, paths=1, subtrees=1),
                ExclusionCount(ExclusionReason.BINARY_ASSET, paths=2, subtrees=0),
            ),
        ),
        global_not_scanned=("host.credentials",),
    )


def test_sarif_preserves_incomplete_scan_metadata_deterministically() -> None:
    result = _result(findings=())

    first = render_sarif(result, redact=False)
    second = render_sarif(result, redact=False)
    payload = json.loads(first)

    assert first == second
    assert payload["version"] == "2.1.0"
    assert payload["$schema"] == (
        "https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/"
        "sarif-schema-2.1.0.json"
    )
    run = payload["runs"][0]
    assert run["invocations"] == [
        {
            "executionSuccessful": False,
            "exitCode": 2,
            "toolExecutionNotifications": [
                {
                    "level": "error",
                    "message": {
                        "text": (
                            "/repo/package-lock.json: "
                            "Unable to inspect authoritative lockfile"
                        )
                    },
                    "properties": {"agentsec.kind": "error"},
                },
                {
                    "level": "warning",
                    "message": {"text": "/repo/.git: VCS metadata excluded"},
                    "properties": {"agentsec.kind": "warning"},
                },
            ],
        }
    ]
    assert run["properties"] == {
        "agentsec.complete": False,
        "agentsec.databaseVersion": "2.27.0",
        "agentsec.detectors": [
            {
                "applicability": "applicable",
                "bytesInspected": 512,
                "detectorId": "shai-hulud-keyv",
                "filesInspected": 2,
                "filesSeen": 3,
                "notScanned": ["git.history", "remote.ci"],
            }
        ],
        "agentsec.diagnostics": [
            {
                "kind": "error",
                "message": "Unable to inspect authoritative lockfile",
                "path": "/repo/package-lock.json",
            },
            {
                "kind": "warning",
                "message": "VCS metadata excluded",
                "path": "/repo/.git",
            },
        ],
        "agentsec.discovery": {
            "directoriesOpened": 2,
            "entriesSeen": 7,
            "filesSelected": 3,
        },
        "agentsec.discoveryExclusions": [
            {"paths": 2, "reason": "binary_asset", "subtrees": 0},
            {"paths": 1, "reason": "vcs_metadata", "subtrees": 1},
        ],
        "agentsec.elapsedMs": 12,
        "agentsec.notScanned": ["git.history", "host.credentials", "remote.ci"],
        "agentsec.scope": "source",
    }


@pytest.mark.parametrize(
    ("severity", "level"),
    (
        (Severity.CRITICAL, "error"),
        (Severity.HIGH, "error"),
        (Severity.MEDIUM, "warning"),
        (Severity.LOW, "note"),
        (Severity.INFO, "note"),
    ),
)
def test_sarif_maps_severity_rule_and_location(
    severity: Severity,
    level: str,
) -> None:
    finding = Finding(
        detector_id="shai-hulud-keyv",
        rule_id="compromised-lockfile-version",
        severity=severity,
        confidence=Confidence.CONFIRMED,
        path=Path("nested/package lock.json"),
        evidence="keyv@6.0.0",
        campaign_ids=("shai-hulud-keyv-2026-08",),
        technique_ids=("npm.compromised-version",),
        line=7,
        remediation_url="https://cc.bruniaux.com/security/",
    )

    run = json.loads(render_sarif(_result(findings=(finding,)), redact=False))["runs"][0]

    assert run["tool"]["driver"]["rules"] == [
        {
            "helpUri": "https://cc.bruniaux.com/security/",
            "id": "shai-hulud-keyv/compromised-lockfile-version",
            "name": "compromised-lockfile-version",
            "properties": {
                "agentsec.detectorId": "shai-hulud-keyv",
                "tags": [
                    "npm.compromised-version",
                    "shai-hulud-keyv-2026-08",
                ],
            },
            "shortDescription": {
                "text": (
                    "compromised-lockfile-version reported by "
                    "shai-hulud-keyv"
                )
            },
        }
    ]
    assert run["results"] == [
        {
            "level": level,
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": "nested/package%20lock.json",
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {"startLine": 7},
                    }
                }
            ],
            "message": {"text": "keyv@6.0.0"},
            "properties": {
                "agentsec.campaignIds": ["shai-hulud-keyv-2026-08"],
                "agentsec.confidence": "confirmed",
                "agentsec.detectorId": "shai-hulud-keyv",
                "agentsec.originalSeverity": severity.value,
                "agentsec.remediationUrl": "https://cc.bruniaux.com/security/",
                "agentsec.techniqueIds": ["npm.compromised-version"],
            },
            "ruleId": "shai-hulud-keyv/compromised-lockfile-version",
        }
    ]


def test_sarif_redaction_hides_root_paths_and_secret_shaped_evidence() -> None:
    finding = Finding(
        detector_id="shai-hulud-keyv",
        rule_id="startup-hook",
        severity=Severity.MEDIUM,
        confidence=Confidence.REVIEW,
        path=Path("ghp_abcdefghijklmnopqrstuvwxyz0123456789/settings.json"),
        evidence="token ghp_abcdefghijklmnopqrstuvwxyz0123456789",
    )

    rendered = render_sarif(_result(findings=(finding,)), redact=True)

    assert "/repo" not in rendered
    assert "ghp_abcdefghijklmnopqrstuvwxyz0123456789" not in rendered
    assert "<SCAN_ROOT>" in rendered
    assert "<REDACTED_SECRET>" in rendered
    assert "%3CREDACTED_SECRET%3E/settings.json" in rendered

"""Deterministic detector coverage documents and renderers."""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import cast

from agentsec import __version__
from agentsec.detectors.base import Detector, DetectorRuleMetadata
from agentsec.models import AuthoringCoverage, ThreatDatabase

_PROJECTION_FIELDS = (
    ("attack_techniques", "attack_techniques_total", "attack_techniques_projected"),
    ("campaigns", "campaigns_total", "commit_indicators_projected"),
    ("cves", "cves_total", "cves_projected"),
    ("domains", "domains_total", "domains_projected"),
    ("malicious_skills", "malicious_skills_total", "malicious_skills_projected"),
    ("malware_hashes", "malware_hashes_total", "malware_hashes_projected"),
)


def build_detector_explanation(
    detector: Detector,
    database: ThreatDatabase,
) -> dict[str, object]:
    """Project canonical detector and database metadata into schema v1."""

    coverage = database.authoring_coverage
    if coverage is None:
        raise ValueError("threat database projection coverage unavailable")
    metadata = detector.metadata
    _validate_rule_contract(metadata.technique_ids, metadata.rules)
    rules = [
        {
            "id": rule.id,
            "state": "active",
            "campaign_ids": sorted(set(metadata.campaign_ids)),
            "technique_ids": sorted(set(rule.technique_ids)),
        }
        for rule in sorted(metadata.rules, key=lambda item: item.id)
    ]
    sources = [
        {"reference": reference, "state": "active"}
        for reference in sorted(set(metadata.source_references))
    ]
    not_scanned = [
        {"id": capability, "state": "not_scanned"}
        for capability in sorted(set(metadata.not_scanned))
    ]
    return {
        "schema_version": "1",
        "tool_version": __version__,
        "database": {
            "version": database.version,
            "updated": database.updated,
        },
        "detector": {
            "id": detector.id,
            "version": detector.version,
            "description": metadata.description,
            "applicability": metadata.applicability,
            "supported_inputs": sorted(set(metadata.supported_inputs)),
            "campaign_ids": sorted(set(metadata.campaign_ids)),
            "technique_ids": sorted(set(metadata.technique_ids)),
            "rules": rules,
            "sources": sources,
            "limitations": sorted(set(metadata.limitations)),
            "remediation_url": metadata.remediation_url,
            "not_scanned": not_scanned,
        },
        "counters": {
            "active_rules": len(rules),
            "active_sources": len(sources),
            "limitations": len(set(metadata.limitations)),
            "not_scanned": len(not_scanned),
            "supported_inputs": len(set(metadata.supported_inputs)),
        },
        "intelligence_projection": _intelligence_projection(coverage),
    }


def render_detector_explanation_json(payload: Mapping[str, object]) -> str:
    """Render stable machine output with a final newline."""

    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def render_detector_explanation_human(payload: Mapping[str, object]) -> str:
    """Render the same coverage document for an operator."""

    database = cast(Mapping[str, object], payload["database"])
    detector = cast(Mapping[str, object], payload["detector"])
    rules = cast(list[Mapping[str, object]], detector["rules"])
    sources = cast(list[Mapping[str, object]], detector["sources"])
    capabilities = cast(list[Mapping[str, object]], detector["not_scanned"])
    projections = cast(list[Mapping[str, object]], payload["intelligence_projection"])
    lines = [
        str(detector["id"]),
        f"version: {detector['version']}",
        f"description: {detector['description']}",
        f"applicability: {detector['applicability']}",
        f"supported_inputs: {_join_strings(detector['supported_inputs'])}",
        f"campaign_ids: {_join_strings(detector['campaign_ids'])}",
        f"technique_ids: {_join_strings(detector['technique_ids'])}",
        "rules: " + ", ".join(str(item["id"]) for item in rules),
        "source_references: "
        + ", ".join(str(item["reference"]) for item in sources),
        f"limitations: {_join_strings(detector['limitations'], separator='; ')}",
        f"remediation_url: {detector['remediation_url'] or 'none'}",
        "not_scanned: " + ", ".join(str(item["id"]) for item in capabilities),
        f"threat_database: {database['version']} (updated {database['updated']})",
        "intelligence_projection:",
    ]
    lines.extend(
        "  "
        f"{item['id']}: {item['state']} "
        f"active={item['active_count']} documented={item['documented_count']} "
        f"documented_only={item['documented_only_count']}"
        for item in projections
    )
    return "\n".join(lines) + "\n"


def _intelligence_projection(
    coverage: AuthoringCoverage,
) -> list[dict[str, object]]:
    entries: list[dict[str, object]] = []
    for identifier, documented_field, active_field in _PROJECTION_FIELDS:
        documented = cast(int, getattr(coverage, documented_field))
        active = cast(int, getattr(coverage, active_field))
        if active == 0:
            state = "documented_only"
        elif active == documented:
            state = "active"
        else:
            state = "partial"
        entries.append(
            {
                "id": identifier,
                "state": state,
                "documented_count": documented,
                "active_count": active,
                "documented_only_count": documented - active,
            }
        )
    return entries


def _validate_rule_contract(
    detector_techniques: tuple[str, ...],
    rules: tuple[DetectorRuleMetadata, ...],
) -> None:
    rule_ids = [rule.id for rule in rules]
    if len(rule_ids) != len(set(rule_ids)):
        raise ValueError("detector metadata contains duplicate rule IDs")
    declared = set(detector_techniques)
    for rule in rules:
        undeclared = set(rule.technique_ids) - declared
        if undeclared:
            raise ValueError(
                "detector rule contains undeclared technique IDs: "
                + ", ".join(sorted(undeclared))
            )


def _join_strings(value: object, *, separator: str = ", ") -> str:
    strings = cast(list[str], value)
    return separator.join(strings) or "none"

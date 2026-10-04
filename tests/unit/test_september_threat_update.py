"""Evidence and coverage boundaries for the September 2026 intelligence review."""

from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).parents[2]


def test_dynamodb_cdk_advisory_keeps_deployment_condition_and_no_detection() -> None:
    database = yaml.safe_load((ROOT / "data/threat-db.yaml").read_text(encoding="utf-8"))
    events = yaml.safe_load((ROOT / "data/intelligence/events.yaml").read_text(encoding="utf-8"))
    cve = next(c for c in database["cve_database"] if c["id"] == "CVE-2026-85654")
    assert cve["affected"] == "awslabs.dynamodb-mcp-server >= 2.0.10, <= 2.1.5"
    assert cve["fixed_in"] == "2.1.6"
    assert "deploy" in cve["description"]
    event = next(e for e in events["events"] if "CVE-2026-85654" in e["related"]["cve_ids"])
    assert event["detector_coverage"]["status"] == "not_detected"
    assert event["detector_coverage"]["detector_ids"] == []


@pytest.mark.parametrize("identifier", [
    "CVE-2026-59971", "CVE-2026-59973", "CVE-2026-72718",
    "CVE-2026-81376", "CVE-2026-78462", "CVE-2026-81378",
    "CVE-2026-81357", "CVE-2026-81377", "CVE-2026-81380",
    "CVE-2026-81381", "CVE-2026-81383", "CVE-2026-81379",
    "CVE-2026-70334", "ADVISORY-CC-2026-003",
])
def test_reviewed_advisories_resolve_primary_evidence_without_claiming_detection(
    identifier: str,
) -> None:
    database = yaml.safe_load((ROOT / "data/threat-db.yaml").read_text(encoding="utf-8"))
    sources = yaml.safe_load((ROOT / "data/intelligence/sources.yaml").read_text(encoding="utf-8"))
    events = yaml.safe_load((ROOT / "data/intelligence/events.yaml").read_text(encoding="utf-8"))
    cve = next(c for c in database["cve_database"] if c["id"] == identifier)
    source_ids = {s["id"] for s in sources["sources"] if s["url"] == cve["source"]}
    if identifier == "ADVISORY-CC-2026-003":
        # A rolling changelog also supports later events; retain this review's source.
        source_ids = {"anthropic-changelog-september-2026"}
    assert source_ids
    fiches = [e for e in events["events"] if source_ids.intersection(e["source_ids"])]
    assert fiches
    assert all(e["detector_coverage"]["status"] == "not_detected" for e in fiches)
    assert all(e["detector_coverage"]["detector_ids"] == [] for e in fiches)
    assert all(e["updated_date"] == "2026-09-12" for e in fiches)
    if cve["component"].startswith("Visual Studio Code"):
        assert cve["fixed_in"] == "1.136.2"
    if identifier == "CVE-2026-59971":
        assert "stdio" in cve["description"] and "unaffected" in cve["description"]
        assert fiches[0]["disclosed_date"] == "2026-06-21"
    if identifier == "CVE-2026-59973":
        assert "mcp-from-openapi >= 2.3.0, < 2.5.0" in cve["affected"]
        assert "frontmcp and @frontmcp/adapters >= 1.2.1, < 1.5.0" in cve["affected"]
        assert database["minimum_safe_versions"]["mcp-from-openapi"] == "2.5.0"
    if identifier == "ADVISORY-CC-2026-003":
        assert fiches[0]["related"]["cve_ids"] == []
        assert "not a CVE" in cve["notes"]


def test_gitspawn_monitoring_preserves_delivery_and_patch_status_limits() -> None:
    sources = yaml.safe_load((ROOT / "data/intelligence/sources.yaml").read_text(encoding="utf-8"))
    events = yaml.safe_load((ROOT / "data/intelligence/events.yaml").read_text(encoding="utf-8"))
    source = next(s for s in sources["sources"] if s["id"] == "manifold-gitspawn-2026-09")
    fiche = next(e for e in events["events"] if e["id"] == "evt-2026-09-gitspawn-monitoring")
    assert "ordinary clone, fetch and pull do not copy" in " ".join(source["supports"])
    assert fiche["status"] == "monitoring"
    assert fiche["confidence"] == "review"
    assert fiche["detector_coverage"]["status"] == "not_detected"
    assert "no current fixed floor is inferred" in fiche["summary"]

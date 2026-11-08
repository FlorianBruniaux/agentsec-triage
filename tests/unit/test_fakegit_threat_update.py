"""Guard the November 5 FakeGit intelligence: counts, defanging, confidence, no IOC leak."""

from __future__ import annotations

import json
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).parents[2]
CAMPAIGN_ID = "fakegit-smartloader-2025-03"


def _yaml(path: str) -> dict[str, object]:
    return yaml.safe_load((ROOT / path).read_text(encoding="utf-8"))


def test_gist_repositories_are_defanged_with_status_and_zip_path() -> None:
    repos = [
        item
        for item in _yaml("data/threat-db.yaml")["iocs"]["github_repos"]  # type: ignore[index]
        if item.get("campaign_id") == CAMPAIGN_ID
    ]

    assert len(repos) == 73
    assert len({item["repo"] for item in repos}) == 73
    assert sum(item["status"] == "live" for item in repos) == 51
    assert sum(item["status"] == "gone" for item in repos) == 22
    assert all(item["status_checked"] == "2026-11-04" for item in repos)
    assert all(re.fullmatch(r"hxxps://github\[\.\]com/[^/]+/[^/]+", item["repo"]) for item in repos)
    assert all(item["committed_zip"].endswith(".zip") for item in repos)
    assert {item["committed_zip"] for item in repos} >= {
        ".claude/hooks/config/supercharged-claude-skills-v2.0.zip",
        "packages/pypi/anywhere_agents/composer/.claude/commands/anywhere_agents_v3.4.zip",
    }


def test_hash_confidence_is_preserved_and_projection_is_conservative() -> None:
    hashes = {
        item["hash"]: item
        for item in _yaml("data/threat-db.yaml")["iocs"]["malware_hashes"]  # type: ignore[index]
        if item.get("campaign_id") == CAMPAIGN_ID
    }

    assert len(hashes) == 10
    projected = {
        digest
        for digest, item in hashes.items()
        if item["detector_projection"] == "exact-hash"
    }
    assert projected == {
        "53039bdeb3e155236dce324281f59846c2da7518a54859c409286aaff86d61a2",
        "bd2a6bff153d95ab3d94d7db4525c49c31f5c6f32ddbf8e7c466732b0a6eb071",
        "4f5c5ad522d8dba60e89c443e07d65c3ce373ef1a617d220d3b69a185c11dae2",
        "2a7afb187157a4052e5b9797d1d1c7ee807b2edeffef076a08b20b12e3dcf317",
    }
    assert all(hashes[digest]["confidence"] == "confirmed" for digest in projected)
    sample_two = [item for item in hashes.values() if item["confidence"] == "review"]
    assert len(sample_two) == 3
    assert all(item["detector_projection"] == "none" for item in sample_two)


def test_events_reference_declared_sources_and_state_partial_coverage() -> None:
    sources = {item["id"] for item in _yaml("data/intelligence/sources.yaml")["sources"]}  # type: ignore[index]
    events = [
        item
        for item in _yaml("data/intelligence/events.yaml")["events"]  # type: ignore[index]
        if CAMPAIGN_ID in item["related"]["campaign_ids"]
    ]

    assert len(events) == 3
    for event in events:
        assert set(event["source_ids"]) <= sources
        assert event["detector_coverage"]["status"] == "partial"
        assert event["detector_coverage"]["detector_ids"] == ["fakegit-archive-lure"]
    by_id = {event["id"]: event for event in events}
    resurgence = by_id["evt-2026-10-fakegit-resurgence"]
    assert resurgence["status"] == "monitoring"
    assert resurgence["confidence"] == "review"


def test_public_feed_and_ledger_carry_no_fakegit_ioc() -> None:
    forbidden = [
        "53039bdeb3e155236dce324281f59846c2da7518a54859c409286aaff86d61a2",
        "217.119.129",
        "213.176.72",
        "hxxps://github[.]com",
        "7d7757",
    ]
    for path in (
        "exports/security-feed.v1.json",
        "docs/SECURITY-TIMELINE.md",
        "docs/SECURITY-INTELLIGENCE.md",
        "src/agentsec/resources/security-intelligence.json",
    ):
        text = (ROOT / path).read_text(encoding="utf-8")
        assert not [item for item in forbidden if item in text], path
    feed = json.loads((ROOT / "exports/security-feed.v1.json").read_text(encoding="utf-8"))
    assert "fakegit-archive-lure" in {item["id"] for item in feed["detectors"]}

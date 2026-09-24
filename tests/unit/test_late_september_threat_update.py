"""Preserve reviewed version, evidence and detection boundaries for the September batch."""

from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).parents[2]


@pytest.mark.parametrize(
    "identifier, affected, fixed, disclosed",
    [
        ("CVE-2026-77258", "mcp-atlassian < 0.22.0", "0.22.0", "2026-07-10"),
        ("CVE-2026-77250", "mcp-atlassian < 0.22.0", "0.22.0", "2026-07-10"),
        ("CVE-2026-77249", "mcp-atlassian < 0.22.0", "0.22.0", "2026-07-10"),
        ("CVE-2026-77247", "mcp-atlassian < 0.22.0", "0.22.0", "2026-07-10"),
        ("CVE-2026-77244", "mcp-atlassian < 0.22.0", "0.22.0", "2026-07-10"),
        ("CVE-2026-77274", "mcp-atlassian < 0.22.0", "0.22.0", "2026-07-10"),
        ("CVE-2026-77271", "mcp-atlassian < 0.22.0", "0.22.0", "2026-07-10"),
        ("CVE-2026-77267", "mcp-atlassian < 0.22.0", "0.22.0", "2026-07-10"),
        ("CVE-2026-77272", "mcp-atlassian < 0.22.0", "0.22.0", "2026-07-10"),
        ("CVE-2026-77262", "mcp-atlassian < 0.22.0", "0.22.0", "2026-07-10"),
        ("CVE-2026-77268", "mcp-atlassian < 0.22.0", "0.22.0", "2026-07-10"),
        ("CVE-2026-77259", "mcp-atlassian < 0.22.0", "0.22.0", "2026-07-10"),
        ("CVE-2026-77261", "mcp-atlassian < 0.22.0", "0.22.0", "2026-07-10"),
        ("CVE-2026-77270", "mcp-atlassian < 0.22.0", "0.22.0", "2026-07-10"),
        ("CVE-2026-77265", "mcp-atlassian < 0.22.0", "0.22.0", "2026-07-10"),
        ("CVE-2026-77266", "mcp-atlassian < 0.22.0", "0.22.0", "2026-07-10"),
        ("CVE-2026-77269", "mcp-atlassian < 0.22.0", "0.22.0", "2026-07-10"),
        ("CVE-2026-77260", "mcp-atlassian < 0.22.0", "0.22.0", "2026-07-10"),
        ("CVE-2026-77257", "mcp-atlassian < 0.22.0", "0.22.0", "2026-07-10"),
        ("CVE-2026-77243", "mcp-atlassian < 0.22.0", "0.22.0", "2026-07-10"),
        ("CVE-2026-77255", "mcp-atlassian < 0.22.0", "0.22.0", "2026-07-10"),
        ("CVE-2026-77253", "mcp-atlassian < 0.22.0", "0.22.0", "2026-07-10"),
        ("CVE-2026-77251", "mcp-atlassian < 0.22.0", "0.22.0", "2026-07-10"),
        ("CVE-2026-77246", "mcp-atlassian < 0.22.0", "0.22.0", "2026-07-10"),
        ("CVE-2026-77248", "mcp-atlassian < 0.22.0", "0.22.0", "2026-07-10"),
        ("CVE-2026-61612", "@aborruso/ckan-mcp-server <= 0.4.107", "0.4.108", "2026-06-22"),
        ("CVE-2026-61647", "@roomi-fields/notebooklm-mcp >= 1.6.0, < 2.0.3", "2.0.3", "2026-06-23"),
        ("GHSA-jgh3-fggc-mcpm", "github.com/obot-platform/obot < 0.23.0", "0.23.0", "2026-06-22"),
        ("GHSA-pr6h-vr44-xq8j", "github.com/obot-platform/obot < 0.23.0", "0.23.0", "2026-06-22"),
        ("GHSA-xwmw-prc4-v3cr", "github.com/obot-platform/obot < 0.23.0", "0.23.0", "2026-06-22"),
        (
            "CVE-2026-77339",
            "github.com/f1bonacc1/process-compose < 1.120.0",
            "1.120.0",
            "2026-08-16",
        ),
        (
            "CVE-2026-58197",
            "ToolHive CLI < 0.30.1; ToolHive Studio < 0.38.0",
            "CLI 0.30.1; Studio 0.38.0",
            "2026-07-28",
        ),
        ("CVE-2026-61560", "@zereight/mcp-gitlab < 2.1.27", "2.1.27", "2026-06-22"),
        ("CVE-2026-61559", "@zereight/mcp-gitlab >= 0.0.1, < 2.1.27", "2.1.27", "2026-07-01"),
        ("CVE-2026-61568", "@zereight/mcp-gitlab < 2.1.30", "2.1.30", "2026-07-03"),
        ("GHSA-5648-rgj9-v224", "@zereight/mcp-gitlab < 2.1.30", "2.1.30", "2026-07-05"),
        (
            "ADVISORY-CC-2026-004",
            "Issue-specific introduction versions are not stated; "
            "fixes reviewed in 2.1.271 through 2.1.281",
            "2.1.281 includes the reviewed fixes",
            "2026-09-23",
        ),
        (
            "ADVISORY-CODEX-2026-001",
            "Codex CLI before 0.149.0; introduction version not stated",
            "0.149.0",
            "2026-09-15",
        ),
        (
            "ADVISORY-CODEX-2026-002",
            "Codex Desktop builds before 26.818.21641 with the affected helper; "
            "introduction build not stated",
            "26.818.21641",
            "2026-09-15",
        ),
        (
            "ADVISORY-PLUGIN4SHELL-2026-001",
            "Researcher-tested plugin installers; introduction versions not published",
            "Claude Code 2.1.179; Codex 0.146.0; no Copilot or Gemini floor established",
            "2026-09-17",
        ),
        (
            "CVE-2026-90999",
            "Automatic Seer handoff of attacker-controlled telemetry to a privileged "
            "coding agent; no numeric range published",
            None,
            "2026-09-16",
        ),
    ],
    ids=[
        "CVE-2026-77258",
        "CVE-2026-77250",
        "CVE-2026-77249",
        "CVE-2026-77247",
        "CVE-2026-77244",
        "CVE-2026-77274",
        "CVE-2026-77271",
        "CVE-2026-77267",
        "CVE-2026-77272",
        "CVE-2026-77262",
        "CVE-2026-77268",
        "CVE-2026-77259",
        "CVE-2026-77261",
        "CVE-2026-77270",
        "CVE-2026-77265",
        "CVE-2026-77266",
        "CVE-2026-77269",
        "CVE-2026-77260",
        "CVE-2026-77257",
        "CVE-2026-77243",
        "CVE-2026-77255",
        "CVE-2026-77253",
        "CVE-2026-77251",
        "CVE-2026-77246",
        "CVE-2026-77248",
        "CVE-2026-61612",
        "CVE-2026-61647",
        "GHSA-jgh3-fggc-mcpm",
        "GHSA-pr6h-vr44-xq8j",
        "GHSA-xwmw-prc4-v3cr",
        "CVE-2026-77339",
        "CVE-2026-58197",
        "CVE-2026-61560",
        "CVE-2026-61559",
        "CVE-2026-61568",
        "GHSA-5648-rgj9-v224",
        "ADVISORY-CC-2026-004",
        "ADVISORY-CODEX-2026-001",
        "ADVISORY-CODEX-2026-002",
        "ADVISORY-PLUGIN4SHELL-2026-001",
        "CVE-2026-90999",
    ],
)
def test_reviewed_record(identifier: str, affected: str, fixed: str | None, disclosed: str) -> None:
    database = yaml.safe_load((ROOT / "data/threat-db.yaml").read_text())
    evidence = yaml.safe_load((ROOT / "data/intelligence/sources.yaml").read_text())
    ledger = yaml.safe_load((ROOT / "data/intelligence/events.yaml").read_text())
    records = [r for r in database["cve_database"] if r["id"] == identifier]
    assert len(records) == 1, f"missing or duplicate reviewed record: {identifier}"
    record = records[0]
    assert record["affected"] == affected
    assert record.get("fixed_in") == fixed
    event = next(e for e in ledger["events"] if e["id"] == "evt-2026-09-" + identifier.lower())
    sources = {s["id"]: s for s in evidence["sources"]}
    assert any(sources[s]["url"] == record["source"] for s in event["source_ids"])
    assert event["disclosed_date"] == disclosed
    assert event["updated_date"] == "2026-09-24"
    assert event["detector_coverage"]["status"] == "not_detected"
    assert event["detector_coverage"]["detector_ids"] == []
    assert event["related"]["cve_ids"] == ([identifier] if identifier.startswith("CVE-") else [])
    if identifier == "CVE-2026-61647":
        assert "NOTEBOOKLM_VAULT_ROOT" in record["mitigation"]
        assert "unset" in record["description"]
    if identifier == "CVE-2026-61568":
        assert "still require a token" in record["description"]
    if identifier == "CVE-2026-77243":
        assert "READ_ONLY_MODE retains" in record["description"]
    if identifier == "CVE-2026-90999":
        assert "sentry-seer" not in database["minimum_safe_versions"]
        assert "no vendor patch information" in record["notes"]
    if identifier == "ADVISORY-PLUGIN4SHELL-2026-001":
        assert "no Copilot or Gemini floor established" in record["fixed_in"]
    if identifier.startswith("ADVISORY-CODEX-"):
        assert (
            "different components" in record["notes"]
            or "Desktop-installed helpers" in record["notes"]
        )

"""Guard the MCP coverage-gap batch reviewed on November 3, 2026.

Candidates came from the mcp-security-project/mcp-cve-project index. Each record must
cite the maintainer or GitHub advisory, not the index.
"""

from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).parents[2]
REVIEWED = "2026-11-03"


def _load():
    database = yaml.safe_load((ROOT / "data/threat-db.yaml").read_text(encoding="utf-8"))
    sources = yaml.safe_load((ROOT / "data/intelligence/sources.yaml").read_text(encoding="utf-8"))[
        "sources"
    ]
    events = yaml.safe_load((ROOT / "data/intelligence/events.yaml").read_text(encoding="utf-8"))[
        "events"
    ]
    return database, sources, events


@pytest.mark.parametrize(
    "identifier,ghsa,affected,fixed,disclosed,url",
    [
        (
            "CVE-2025-6514",
            "GHSA-6xpm-ggf7-wc3p",
            "mcp-remote >= 0.0.5, < 0.1.16",
            "0.1.16",
            "2025-07-09",
            "https://github.com/advisories/GHSA-6xpm-ggf7-wc3p",
        ),
        (
            "CVE-2026-47751",
            "GHSA-8q5r-mmjf-575q",
            "anthropics/claude-code-action < 1.0.74",
            "1.0.74",
            "2026-06-10",
            "https://github.com/anthropics/claude-code-action/security/advisories/GHSA-8q5r-mmjf-575q",
        ),
        (
            "CVE-2025-61260",
            "GHSA-xrxf-jgv3-qmrm",
            "@openai/codex <= 0.23.0",
            None,
            "2026-04-14",
            "https://github.com/advisories/GHSA-xrxf-jgv3-qmrm",
        ),
        (
            "CVE-2026-29783",
            "GHSA-g8r9-g2v8-jv6f",
            "@github/copilot <= 0.0.422",
            "0.0.423",
            "2026-03-06",
            "https://github.com/github/copilot-cli/security/advisories/GHSA-g8r9-g2v8-jv6f",
        ),
        (
            "CVE-2025-59944",
            "GHSA-xcwh-rrwj-gxc7",
            "Cursor < 1.6.23 (advisory range)",
            "1.7",
            "2025-10-02",
            "https://github.com/cursor/cursor/security/advisories/GHSA-xcwh-rrwj-gxc7",
        ),
        (
            "CVE-2025-61590",
            "GHSA-xg6w-rmh5-r77r",
            "Cursor < 1.7",
            "1.7",
            "2025-10-02",
            "https://github.com/cursor/cursor/security/advisories/GHSA-xg6w-rmh5-r77r",
        ),
        (
            "CVE-2025-61591",
            "GHSA-wj33-264c-j9cq",
            "Cursor CLI < 2025.09.17-25b418f",
            "2025.09.17-25b418f",
            "2025-10-02",
            "https://github.com/cursor/cursor/security/advisories/GHSA-wj33-264c-j9cq",
        ),
        (
            "CVE-2025-64106",
            "GHSA-4575-fh42-7848",
            "Cursor 1.7.28 (advisory range)",
            "2.0",
            "2025-11-03",
            "https://github.com/cursor/cursor/security/advisories/GHSA-4575-fh42-7848",
        ),
        (
            "CVE-2025-64109",
            "GHSA-4hwr-97q3-37w2",
            "Cursor CLI (Beta) < 2025.09.17-25b418f",
            "2025.09.17-25b418f",
            "2025-11-03",
            "https://github.com/cursor/cursor/security/advisories/GHSA-4hwr-97q3-37w2",
        ),
        (
            "CVE-2025-68433",
            "GHSA-cv6g-cmxc-vw8j",
            "Zed < v0.218.2-pre (including stable v0.217.2)",
            "v0.218.2-pre",
            "2025-12-17",
            "https://github.com/zed-industries/zed/security/advisories/GHSA-cv6g-cmxc-vw8j",
        ),
        (
            "CVE-2025-53365",
            "GHSA-j975-95f5-7wqh",
            "mcp < 1.10.0",
            "1.10.0",
            "2025-07-04",
            "https://github.com/modelcontextprotocol/python-sdk/security/advisories/GHSA-j975-95f5-7wqh",
        ),
        (
            "CVE-2025-53366",
            "GHSA-3qhf-m339-9g5v",
            "mcp < 1.9.4",
            "1.9.4",
            "2025-07-04",
            "https://github.com/modelcontextprotocol/python-sdk/security/advisories/GHSA-3qhf-m339-9g5v",
        ),
        (
            "CVE-2025-66414",
            "GHSA-w48q-cv73-mx4w",
            "@modelcontextprotocol/sdk < 1.24.0",
            "1.24.0",
            "2025-12-02",
            "https://github.com/modelcontextprotocol/typescript-sdk/security/advisories/GHSA-w48q-cv73-mx4w",
        ),
        (
            "CVE-2026-27896",
            "GHSA-wvj2-96wp-fq3f",
            "github.com/modelcontextprotocol/go-sdk < 1.3.1",
            "1.3.1",
            "2026-02-26",
            "https://github.com/modelcontextprotocol/go-sdk/security/advisories/GHSA-wvj2-96wp-fq3f",
        ),
        (
            "CVE-2026-34237",
            "GHSA-hv2w-8mjj-jw22",
            "io.modelcontextprotocol.sdk:mcp-core < 0.18.3; = 1.0.0; = 1.1.0",
            "0.x: 0.18.3; 1.0.x: 1.0.1; 1.1.x: 1.1.1",
            "2026-03-30",
            "https://github.com/modelcontextprotocol/java-sdk/security/advisories/GHSA-hv2w-8mjj-jw22",
        ),
        (
            "CVE-2025-58444",
            "GHSA-g9hg-qhmf-q45m",
            "@modelcontextprotocol/inspector < 0.16.6",
            "0.16.6",
            "2025-09-08",
            "https://github.com/modelcontextprotocol/inspector/security/advisories/GHSA-g9hg-qhmf-q45m",
        ),
        (
            "CVE-2025-62800",
            "GHSA-mxxr-jv3v-6pgc",
            "fastmcp < 2.13.0",
            "2.13.0",
            "2025-10-29",
            "https://github.com/PrefectHQ/fastmcp/security/advisories/GHSA-mxxr-jv3v-6pgc",
        ),
        (
            "CVE-2025-62801",
            "GHSA-rj5c-58rq-j5g5",
            "fastmcp < 2.13.0",
            "2.13.0",
            "2025-10-29",
            "https://github.com/PrefectHQ/fastmcp/security/advisories/GHSA-rj5c-58rq-j5g5",
        ),
        (
            "CVE-2025-69196",
            "GHSA-5h2m-4q8j-pqpj",
            "fastmcp < 2.14.2",
            "2.14.2",
            "2026-03-16",
            "https://github.com/PrefectHQ/fastmcp/security/advisories/GHSA-5h2m-4q8j-pqpj",
        ),
        (
            "CVE-2025-64340",
            "GHSA-m8x7-r2rg-vh5g",
            "fastmcp < 3.2.0",
            "3.2.0",
            "2026-03-31",
            "https://github.com/PrefectHQ/fastmcp/security/advisories/GHSA-m8x7-r2rg-vh5g",
        ),
        (
            "CVE-2026-47427",
            "GHSA-w4q6-qw23-4rg7",
            "github.com/github/github-mcp-server < 1.1.0",
            "1.1.0",
            "2026-07-28",
            "https://github.com/github/github-mcp-server/security/advisories/GHSA-w4q6-qw23-4rg7",
        ),
        (
            "CVE-2026-44427",
            "GHSA-v8vw-gw5j-w7m6",
            "github.com/modelcontextprotocol/registry >= 1.1.0, < 1.7.5",
            "1.7.5",
            "2026-05-08",
            "https://github.com/modelcontextprotocol/registry/security/advisories/GHSA-v8vw-gw5j-w7m6",
        ),
    ],
)
def test_reviewed_coverage_gap_record(identifier, ghsa, affected, fixed, disclosed, url):
    database, sources, events = _load()
    records = [item for item in database["cve_database"] if item["id"] == identifier]
    assert len(records) == 1, f"missing or duplicate reviewed record: {identifier}"
    record = records[0]
    assert record["affected"] == affected
    assert record.get("fixed_in") == fixed
    assert record["source"] == url
    assert "mcp-cve-project" not in record["source"]
    assert f"Alias: {ghsa}." in record["notes"]
    assert f"Reviewed {REVIEWED}" in record["notes"]
    assert "no executable AgentSec" in record["notes"]
    assert sum(r["source"] == url for r in database["cve_database"]) == 1
    matching = [event for event in events if event["id"] == "evt-2026-11-" + identifier.lower()]
    assert len(matching) == 1
    event = matching[0]
    assert event["disclosed_date"] == disclosed
    assert event["updated_date"] == REVIEWED
    assert event["status"] == "confirmed"
    assert event["confidence"] == "confirmed"
    assert event["detector_coverage"]["status"] == "not_detected"
    assert event["detector_coverage"]["detector_ids"] == []
    assert event["related"]["cve_ids"] == [identifier]
    assert any(s["url"] == url and s["id"] in event["source_ids"] for s in sources)


@pytest.mark.parametrize(
    "identifier,url",
    [
        ("CVE-2025-34072", "https://github.com/advisories/GHSA-gmx5-crwh-6vxg"),
        ("CVE-2026-19591", "https://github.com/advisories/GHSA-2frj-4qr5-m2rf"),
    ],
)
def test_unreviewed_advisories_stay_monitoring_without_fixed_versions(identifier, url):
    database, sources, events = _load()
    records = [item for item in database["cve_database"] if item["id"] == identifier]
    assert len(records) == 1
    assert records[0]["source"] == url
    assert "fixed_in" not in records[0]
    assert records[0]["notes"].startswith("Monitoring: unreviewed GitHub advisory")
    event = next(event for event in events if event["id"] == "evt-2026-11-" + identifier.lower())
    assert event["status"] == "monitoring"
    assert event["confidence"] == "review"
    assert event["detector_coverage"]["status"] == "not_detected"
    assert any(s["url"] == url and s["id"] in event["source_ids"] for s in sources)


def test_primary_advisory_overrides_index_values():
    database, _sources, _events = _load()
    action = next(item for item in database["cve_database"] if item["id"] == "CVE-2026-47751")
    assert action["fixed_in"] == "1.0.74"
    assert action["severity"] == "medium"


def test_coverage_gap_floors_rise_without_lowering_or_inventing():
    database, _sources, _events = _load()
    floors = database["minimum_safe_versions"]
    assert floors["mcp-inspector"] == "0.16.6"
    assert floors["mcp-java-sdk"] == "1.1.1"
    assert floors["github-mcp-server"] == "1.1.0"
    assert floors["mcp-registry"] == "1.7.5"
    assert floors["copilot-cli"] == "0.0.423"
    assert floors["claude-code-action"] == "1.0.94"
    assert floors["cursor"] == "3.0.0"
    assert floors["go-mcp-sdk"] == "1.4.0"
    assert "mcp-remote" not in floors
    assert "zed" not in floors


def test_deferred_vscode_report_is_not_recorded():
    database, _sources, events = _load()
    assert not [item for item in database["cve_database"] if item["id"] == "CVE-2026-21518"]
    assert not [event for event in events if "cve-2026-21518" in event["id"]]

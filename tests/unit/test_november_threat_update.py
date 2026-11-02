"""Guard reviewed November ranges, aliases, campaigns and coverage boundaries."""

import json
from pathlib import Path

import pytest
import yaml

from agentsec.detectors.shai_hulud import ShaiHuludDetector
from agentsec.engine.discovery import DiscoveryLimits
from agentsec.engine.runner import run_scan
from agentsec.models import Confidence, Severity
from agentsec.scopes import ScanScope
from agentsec.threat_db import load_bundled_database

ROOT = Path(__file__).parents[2]
LIMITS = DiscoveryLimits(max_file_bytes=1_000_000, max_files=1_000, max_diagnostics=100)


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
    "identifier,affected,fixed,disclosed,url,confidence",
    [
        (
            "CVE-2026-103435",
            "@anthropic-ai/claude-code < 2.1.129",
            "2.1.129",
            "2026-10-05",
            "https://github.com/anthropics/claude-code/security/advisories/GHSA-5j29-h97v-84ch",
            "confirmed",
        ),
        (
            "CVE-2026-86063",
            "@anthropic-ai/claude-code < 2.1.179",
            "2.1.179",
            "2026-10-09",
            "https://github.com/anthropics/claude-code/security/advisories/GHSA-pq7j-f95f-qfcv",
            "confirmed",
        ),
        (
            "CVE-2026-88066",
            "Claude Desktop < 1.8089.0",
            "1.8089.0",
            "2026-10-13",
            "https://github.com/anthropics/claude-code/security/advisories/GHSA-4p2j-qj3c-6x84",
            "confirmed",
        ),
        (
            "CVE-2026-88968",
            "@anthropic-ai/claude-code < 2.1.251",
            "2.1.251",
            "2026-10-26",
            "https://github.com/anthropics/claude-code/security/advisories/GHSA-5xjx-9qx6-jcrv",
            "confirmed",
        ),
        (
            "CVE-2026-96620",
            "claude-agent-sdk < 0.2.121",
            "0.2.121",
            "2026-09-12",
            "https://github.com/anthropics/claude-agent-sdk-python/security/advisories/GHSA-h4mw-j7qp-8mwm",
            "confirmed",
        ),
        (
            "CVE-2026-116684",
            "mcp >= 1.10.0, < 1.30.0; >= 2.0.0, < 2.2.0",
            "1.x: 1.30.0; 2.x: 2.2.0",
            "2026-10-05",
            "https://github.com/modelcontextprotocol/python-sdk/security/advisories/GHSA-w4fh-qvv9-3v23",
            "confirmed",
        ),
        (
            "GHSA-f897-62hf-6gxq",
            "@modelcontextprotocol/sdk >= 1.10.0, < 1.30.1; "
            "@modelcontextprotocol/server >= 2.0.0, < 2.1.0; "
            "@modelcontextprotocol/node >= 2.0.0, < 2.1.0; "
            "@modelcontextprotocol/hono >= 2.0.0, < 2.0.1",
            "sdk 1.x: 1.30.1; server and node 2.x: 2.1.0; hono: 2.0.1",
            "2026-10-15",
            "https://github.com/modelcontextprotocol/typescript-sdk/security/advisories/GHSA-f897-62hf-6gxq",
            "confirmed",
        ),
        (
            "CVE-2026-111770",
            "@modelcontextprotocol/server >= 2.0.0, < 2.3.0",
            "2.3.0",
            "2026-10-15",
            "https://github.com/modelcontextprotocol/typescript-sdk/security/advisories/GHSA-jm63-cq47-j5jp",
            "confirmed",
        ),
        (
            "CVE-2026-111768",
            "@modelcontextprotocol/sdk >= 1.3.0, < 1.32.0; "
            "@modelcontextprotocol/server >= 2.0.0, < 2.3.0",
            "sdk 1.x: 1.32.0; server 2.x: 2.3.0",
            "2026-10-15",
            "https://github.com/modelcontextprotocol/typescript-sdk/security/advisories/GHSA-46jr-4wx8-v453",
            "confirmed",
        ),
        (
            "CVE-2026-111771",
            "@modelcontextprotocol/sdk >= 1.6.0, < 1.32.0; "
            "@modelcontextprotocol/server >= 2.0.0, < 2.3.0; "
            "@modelcontextprotocol/express >= 2.0.0, < 2.0.2; "
            "@modelcontextprotocol/server-legacy >= 2.0.0, < 2.3.1",
            "sdk 1.x: 1.32.0; server 2.x: 2.3.0; express: 2.0.2; server-legacy: 2.3.1",
            "2026-10-05",
            "https://github.com/modelcontextprotocol/typescript-sdk/security/advisories/GHSA-rvq5-wwqv-78pq",
            "confirmed",
        ),
        (
            "GHSA-7xgj-8392-5q4r",
            "fastmcp and fastmcp-slim >= 3.0.0, < 3.4.10; >= 4.0.0, < 4.1.2",
            "3.x: 3.4.10; 4.x: 4.1.2",
            "2026-10-20",
            "https://github.com/PrefectHQ/fastmcp/security/advisories/GHSA-7xgj-8392-5q4r",
            "confirmed",
        ),
        (
            "GHSA-vqqp-x5qm-5qp4",
            "fastmcp and fastmcp-slim >= 4.0.0a1, < 4.1.2",
            "4.1.2",
            "2026-10-20",
            "https://github.com/PrefectHQ/fastmcp/security/advisories/GHSA-vqqp-x5qm-5qp4",
            "confirmed",
        ),
        (
            "CVE-2026-62264",
            "@sylphx/pdf-reader-mcp >= 2.2.0, < 3.0.1",
            "3.0.1",
            "2026-06-25",
            "https://github.com/SylphxAI/anymd/security/advisories/GHSA-q344-5v34-gm84",
            "confirmed",
        ),
        (
            "GHSA-4mfg-r38w-w8fg",
            "mcp-sanitizer < 1.4.0",
            "1.4.0",
            "2026-06-25",
            "https://github.com/starman69/mcp-sanitizer/security/advisories/GHSA-4mfg-r38w-w8fg",
            "confirmed",
        ),
        (
            "GHSA-7w82-6f9j-v9jp",
            "mcp-sanitizer < 1.4.0",
            "1.4.0",
            "2026-06-25",
            "https://github.com/starman69/mcp-sanitizer/security/advisories/GHSA-7w82-6f9j-v9jp",
            "confirmed",
        ),
        (
            "CVE-2026-60083",
            "SiYuan kernel before commit 3542530c505f (v3.8.0)",
            "3.8.0",
            "2026-08-08",
            "https://github.com/siyuan-note/siyuan/security/advisories/GHSA-c8r8-95hg-mp34",
            "confirmed",
        ),
        (
            "GHSA-953h-535j-jg2v",
            "github.com/envoyproxy/ai-gateway >= 0.4.0-rc1, < 1.2.0-rc1",
            "1.2.0-rc1",
            "2026-10-07",
            "https://github.com/theagentrouter/agent-router/security/advisories/GHSA-953h-535j-jg2v",
            "confirmed",
        ),
        (
            "CVE-2026-76894",
            "@aborruso/ckan-mcp-server < 0.4.112",
            "0.4.112",
            "2026-07-09",
            "https://github.com/ondata/ckan-mcp-server/security/advisories/GHSA-vqff-r82h-9crc",
            "confirmed",
        ),
        (
            "CVE-2026-84360",
            "nginx-ui before v2.4.1 (Go pseudo-version 1.9.10-0.20260703131214-23d1934099b0)",
            "2.4.1",
            "2026-07-17",
            "https://github.com/0xJacky/nginx-ui/security/advisories/GHSA-vc32-4gwf-77xp",
            "confirmed",
        ),
        (
            "CVE-2026-84318",
            "nginx-ui from Go pseudo-version 1.9.10-0.20250506154222-1330888280a2 before v2.4.1",
            "2.4.1",
            "2026-07-17",
            "https://github.com/0xJacky/nginx-ui/security/advisories/GHSA-9jww-cxg5-rj9m",
            "confirmed",
        ),
        (
            "CVE-2026-84317",
            "nginx-ui before v2.4.1 (Go pseudo-version 1.9.10-0.20260703131214-23d1934099b0)",
            "2.4.1",
            "2026-07-17",
            "https://github.com/0xJacky/nginx-ui/security/advisories/GHSA-76pm-mq2q-9gcr",
            "confirmed",
        ),
        (
            "CVE-2026-84319",
            "nginx-ui before v2.4.1 (Go pseudo-version 1.9.10-0.20260703131214-23d1934099b0)",
            "2.4.1",
            "2026-07-17",
            "https://github.com/0xJacky/nginx-ui/security/advisories/GHSA-5r62-gj48-897x",
            "confirmed",
        ),
        (
            "CVE-2026-105697",
            "langflow >= 1.1.2, < 1.10.3; langflow-base >= 0.1.2, < 0.10.3; lfx < 1.10.3",
            "langflow 1.10.3; langflow-base 0.10.3; lfx 1.10.3",
            "2026-09-28",
            "https://github.com/langflow-ai/langflow/security/advisories/GHSA-w794-rj3p-xv45",
            "confirmed",
        ),
        (
            "CVE-2026-105699",
            "langflow >= 1.6.8, <= 1.9.0",
            "1.9.1",
            "2026-09-22",
            "https://github.com/langflow-ai/langflow/security/advisories/GHSA-4hmc-cfm3-w43c",
            "confirmed",
        ),
        (
            "CVE-2026-61427",
            "praisonai <= 4.6.77",
            "4.6.78",
            "2026-06-25",
            "https://github.com/MervinPraison/PraisonAI/security/advisories/GHSA-hc5v-gxvj-58wh",
            "confirmed",
        ),
        (
            "CVE-2026-105806",
            "@payloadcms/plugin-mcp >= 3.61.0, < 3.88.0",
            "3.88.0",
            "2026-09-22",
            "https://github.com/payloadcms/payload/security/advisories/GHSA-2q76-m6w6-qgc6",
            "confirmed",
        ),
        (
            "CVE-2026-115477",
            "obsidian-tc >= 1.13.0, <= 1.31.3",
            "1.31.4",
            "2026-09-26",
            "https://github.com/The-40-Thieves/obsidian-tc/security/advisories/GHSA-737x-cwfr-5vvc",
            "confirmed",
        ),
        (
            "CVE-2026-113731",
            "djust >= 0.9.0, <= 1.0.9; >= 1.1.0, <= 1.1.6; >= 1.2.0.dev0, <= 1.2.3; "
            ">= 1.3.0.dev0, <= 1.3.0rc7",
            "1.0.10; 1.1.7; 1.2.4; 1.3.0rc8",
            "2026-10-15",
            "https://github.com/djust-org/djust/security/advisories/GHSA-r57g-mc79-8hj2",
            "confirmed",
        ),
        (
            "CVE-2026-94486",
            "next >= 16.0.0, < 16.3.8",
            "16.3.8",
            "2026-09-30",
            "https://github.com/vercel/next.js/security/advisories/GHSA-39w2-rjm5-chcv",
            "confirmed",
        ),
        (
            "CVE-2026-106484",
            "chrome-devtools-mcp >= 1.1.0, <= 1.4.0",
            "1.5.0",
            "2026-10-22",
            "https://github.com/ChromeDevTools/chrome-devtools-mcp/security/advisories/GHSA-5hw5-4q87-m6x9",
            "confirmed",
        ),
        (
            "CVE-2026-111091",
            "Junie CLI < 26.8.3",
            "26.8.3",
            "2026-10-15",
            "https://www.cve.org/CVERecord?id=CVE-2026-111091",
            "high",
        ),
    ],
)
def test_reviewed_november_record(identifier, affected, fixed, disclosed, url, confidence):
    database, sources, events = _load()
    records = [item for item in database["cve_database"] if item["id"] == identifier]
    assert len(records) == 1, f"missing or duplicate reviewed record: {identifier}"
    record = records[0]
    assert record["affected"] == affected
    assert record.get("fixed_in") == fixed
    assert record["source"] == url
    assert "Reviewed 2026-11-02" in record["notes"]
    assert "no executable AgentSec" in record["notes"]
    assert sum(r["source"] == url for r in database["cve_database"]) == 1
    matching = [event for event in events if event["id"] == "evt-2026-11-" + identifier.lower()]
    assert len(matching) == 1
    event = matching[0]
    assert event["disclosed_date"] == disclosed
    assert event["updated_date"] == "2026-11-02"
    assert event["status"] == "confirmed"
    assert event["confidence"] == confidence
    assert event["detector_coverage"]["status"] == "not_detected"
    assert event["detector_coverage"]["detector_ids"] == []
    assert event["related"]["cve_ids"] == ([identifier] if identifier.startswith("CVE-") else [])
    assert any(s["url"] == url and s["id"] in event["source_ids"] for s in sources)


@pytest.mark.parametrize(
    "identifier,url",
    [
        ("CVE-2026-88755", "https://nvd.nist.gov/vuln/detail/CVE-2026-88755"),
        ("CVE-2026-108714", "https://nvd.nist.gov/vuln/detail/CVE-2026-108714"),
        ("CVE-2026-108859", "https://nvd.nist.gov/vuln/detail/CVE-2026-108859"),
        ("CVE-2026-108716", "https://nvd.nist.gov/vuln/detail/CVE-2026-108716"),
    ],
)
def test_unconfirmed_november_reports_stay_monitoring_without_floors(identifier, url):
    database, sources, events = _load()
    records = [item for item in database["cve_database"] if item["id"] == identifier]
    assert len(records) == 1, "monitoring CVEs stay searchable in the catalogue"
    assert records[0]["source"] == url
    assert "fixed_in" not in records[0]
    assert records[0]["notes"].startswith("Monitoring: CVE record only")
    floors = database["minimum_safe_versions"]
    assert not {"zcode", "mcp-kotlin-sdk", "mcp-go", "mcp-remote"} & set(floors)
    matching = [event for event in events if event["id"] == "evt-2026-11-" + identifier.lower()]
    assert len(matching) == 1
    event = matching[0]
    assert event["status"] == "monitoring"
    assert event["confidence"] == "review"
    assert event["detector_coverage"]["status"] == "not_detected"
    assert event["related"]["cve_ids"] == [identifier]
    assert any(s["url"] == url and s["id"] in event["source_ids"] for s in sources)


def test_october_ghsa_records_gain_cve_aliases_without_rewriting_events():
    database, _sources, events = _load()
    aliases = {
        "GHSA-5h93-6whr-6q8j": "CVE-2026-116685",
        "GHSA-rwrf-2pqf-9j8j": "CVE-2026-116686",
        "GHSA-6prh-2h8m-c8cw": "CVE-2026-111769",
        "GHSA-22jm-h49p-29qw": "CVE-2026-111767",
    }
    for ghsa, cve in aliases.items():
        record = next(item for item in database["cve_database"] if item["id"] == ghsa)
        assert f"CVE alias: {cve}" in record["notes"]
        original = next(event for event in events if event["id"] == "evt-2026-10-" + ghsa.lower())
        assert original["related"]["cve_ids"] == []
        assert not [item for item in database["cve_database"] if item["id"] == cve]
    update = next(event for event in events if event["id"] == "evt-2026-11-mcp-sdk-cve-aliases")
    assert update["event_type"] == "intelligence_update"
    assert update["related"]["cve_ids"] == []
    assert all(f"{ghsa} is {cve}" in update["summary"] for ghsa, cve in aliases.items())
    assert "affected_event_ids" not in update


def test_november_campaign_events_keep_iocs_out_and_state_coverage():
    _database, sources, events = _load()
    by_id = {event["id"]: event for event in events}
    cursor = by_id["evt-2026-10-cursor-marketplace-claude-code-extension"]
    assert cursor["event_type"] == "campaign"
    assert cursor["occurred_date"] == "2026-10-29"
    assert cursor["detector_coverage"]["status"] == "not_detected"
    hooks = by_id["evt-2026-10-testmetest-agent-startup-hooks"]
    assert hooks["detector_coverage"]["status"] == "partial"
    assert hooks["detector_coverage"]["detector_ids"] == ["shai-hulud-keyv"]
    for event in (cursor, hooks):
        text = json.dumps(event)
        assert "134.209" not in text
        assert "svc-telemetry" not in text
        assert "0x96" not in text
    urls = {source["url"] for source in sources}
    assert "https://cursor.com/blog/claude-code-extension-security-notice" in urls
    assert "https://research.jfrog.com/post/beyond-testmetest-42-hijacked-github-repos/" in urls


def test_testmetest_claude_and_vscode_hooks_are_review_findings_only(tmp_path: Path):
    command = "node .github/init.js || bun .github/init.js"
    claude = tmp_path / ".claude" / "settings.json"
    claude.parent.mkdir()
    claude.write_text(
        json.dumps(
            {
                "hooks": {
                    "SessionStart": [
                        {"matcher": "*", "hooks": [{"type": "command", "command": command}]}
                    ]
                }
            }
        ),
        encoding="utf-8",
    )
    vscode = tmp_path / ".vscode" / "tasks.json"
    vscode.parent.mkdir()
    vscode.write_text(
        json.dumps(
            {
                "version": "2.0.0",
                "tasks": [
                    {
                        "label": "setup",
                        "type": "shell",
                        "command": command,
                        "runOptions": {"runOn": "folderOpen"},
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    gemini = tmp_path / ".gemini" / "settings.json"
    gemini.parent.mkdir()
    gemini.write_text(json.dumps({"hooks": {"SessionStart": [command]}}), encoding="utf-8")

    result = run_scan(
        tmp_path,
        [ShaiHuludDetector()],
        load_bundled_database(),
        LIMITS,
        scope=ScanScope.REPOSITORY,
    )

    startup = sorted(
        (item.rule_id, str(item.path), item.severity, item.confidence)
        for item in result.findings
        if "startup-hook" in item.rule_id
    )
    assert startup == [
        ("startup-hook", ".claude/settings.json", Severity.MEDIUM, Confidence.REVIEW),
        ("startup-hook", ".vscode/tasks.json", Severity.MEDIUM, Confidence.REVIEW),
    ]


def test_november_version_floors_add_branches_without_downgrades():
    database, _sources, _events = _load()
    floors = database["minimum_safe_versions"]
    expected = {
        "@modelcontextprotocol/server": "2.3.0",
        "@modelcontextprotocol/node": "2.1.0",
        "@modelcontextprotocol/hono": "2.0.1",
        "@modelcontextprotocol/express": "2.0.2",
        "@modelcontextprotocol/server-legacy": "2.3.1",
        "claude-agent-sdk-python": "0.2.121",
        "fastmcp-3": "3.4.10",
        "fastmcp-4": "4.1.2",
        "@sylphx/pdf-reader-mcp": "3.0.1",
        "mcp-sanitizer": "1.4.0",
        "chrome-devtools-mcp": "1.5.0",
        "junie-cli": "26.8.3",
        "@payloadcms/plugin-mcp": "3.88.0",
        "langflow": "1.10.3",
        "praisonai": "4.6.78",
        "obsidian-tc": "1.31.4",
        "@aborruso/ckan-mcp-server": "0.4.112",
        "nginx-ui": "2.4.1",
    }
    for name, version in expected.items():
        assert floors[name] == version
    assert floors["claude-code"] == "2.1.281"
    assert floors["claude-desktop"] == "1.15962.0"
    assert floors["@modelcontextprotocol/sdk"] == "1.32.0"
    assert floors["siyuan"] == "3.8.1"
    assert floors["fastmcp"] == "check upstream — CVE-2026-27124 patched version"

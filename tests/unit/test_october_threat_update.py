"""Guard reviewed October ranges, branch floors, aliases and coverage boundaries."""

from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).parents[2]


@pytest.mark.parametrize(
    "identifier,affected,fixed,disclosed,url",
    [
        (
            "GHSA-v234-4jrq-mgg6",
            "Claude Desktop >= 1.1.3918, < 1.15962.0",
            "1.15962.0",
            "2026-09-25",
            "https://github.com/anthropics/claude-code/security/advisories/GHSA-v234-4jrq-mgg6",
        ),
        (
            "CVE-2026-103012",
            "Enterprise >= 2.0.68, < 2.1.260; Team >= 2.1.38, < 2.1.260",
            "2.1.260",
            "2026-09-29",
            "https://github.com/anthropics/claude-code/security/advisories/GHSA-gfvf-j8jh-jxxw",
        ),
        (
            "GHSA-rwrf-2pqf-9j8j",
            "mcp >= 1.10.0, < 1.30.0; >= 2.0.0, < 2.2.0",
            "1.x: 1.30.0; 2.x: 2.2.0",
            "2026-09-28",
            "https://github.com/modelcontextprotocol/python-sdk/security/advisories/GHSA-rwrf-2pqf-9j8j",
        ),
        (
            "GHSA-qx49-fqc8-xw99",
            "mcp >= 1.9.1, < 1.30.0; >= 2.0.0a1, < 2.2.0",
            "1.x: 1.30.0; 2.x: 2.2.0",
            "2026-09-28",
            "https://github.com/modelcontextprotocol/python-sdk/security/advisories/GHSA-qx49-fqc8-xw99",
        ),
        (
            "CVE-2026-59951",
            "mcp >= 1.8.0, < 1.30.0; >= 2.0.0, < 2.2.0",
            "1.x: 1.30.0; 2.x: 2.2.0",
            "2026-09-30",
            "https://github.com/modelcontextprotocol/python-sdk/security/advisories/GHSA-84m7-p3x7-pcfv",
        ),
        (
            "GHSA-fmmv-w9g8-j3gc",
            "mcp < 1.29.1; >= 2.0.0, < 2.1.0",
            "1.x: 1.29.1; 2.x: 2.1.0",
            "2026-09-30",
            "https://github.com/modelcontextprotocol/python-sdk/security/advisories/GHSA-fmmv-w9g8-j3gc",
        ),
        (
            "GHSA-5h93-6whr-6q8j",
            "mcp >= 1.8.0, < 1.30.0; >= 2.0.0, < 2.2.0",
            "1.x: 1.30.0; 2.x: 2.2.0",
            "2026-10-02",
            "https://github.com/modelcontextprotocol/python-sdk/security/advisories/GHSA-5h93-6whr-6q8j",
        ),
        (
            "CVE-2026-97662",
            "awslabs.security-agent-mcp-server >= 0.1.1, < 0.2.0",
            "0.2.0",
            "2026-10-01",
            "https://github.com/awslabs/mcp/security/advisories/GHSA-8g28-rj54-p5p2",
        ),
        (
            "CVE-2026-104850",
            "@modelcontextprotocol/sdk >= 1.12.0, < 1.31.0; "
            "@modelcontextprotocol/client >= 2.0.0, < 2.2.0",
            "sdk 1.x: 1.31.0; client 2.x: 2.2.0",
            "2026-09-30",
            "https://github.com/modelcontextprotocol/typescript-sdk/security/advisories/GHSA-6qxp-vccf-f47h",
        ),
        (
            "GHSA-22jm-h49p-29qw",
            "@modelcontextprotocol/sdk >= 1.24.0, < 1.32.0",
            "1.32.0",
            "2026-10-02",
            "https://github.com/modelcontextprotocol/typescript-sdk/security/advisories/GHSA-22jm-h49p-29qw",
        ),
        (
            "GHSA-6prh-2h8m-c8cw",
            "@modelcontextprotocol/sdk < 1.32.0; @modelcontextprotocol/client >= 2.0.0, < 2.3.0",
            "sdk 1.x: 1.32.0; client 2.x: 2.3.0",
            "2026-10-02",
            "https://github.com/modelcontextprotocol/typescript-sdk/security/advisories/GHSA-6prh-2h8m-c8cw",
        ),
        (
            "CVE-2026-59723",
            "cline <= 3.0.24",
            None,
            "2026-06-23",
            "https://github.com/cline/cline/security/advisories/GHSA-3cj3-hqcr-g934",
        ),
    ],
)
def test_reviewed_october_record(identifier, affected, fixed, disclosed, url):
    database = yaml.safe_load((ROOT / "data/threat-db.yaml").read_text())
    sources = yaml.safe_load((ROOT / "data/intelligence/sources.yaml").read_text())["sources"]
    events = yaml.safe_load((ROOT / "data/intelligence/events.yaml").read_text())["events"]
    records = [item for item in database["cve_database"] if item["id"] == identifier]
    assert len(records) == 1, f"missing or duplicate reviewed record: {identifier}"
    record = records[0]
    assert record["affected"] == affected
    assert record.get("fixed_in") == fixed
    assert record["source"] == url
    matching = [event for event in events if event["id"] == "evt-2026-10-" + identifier.lower()]
    assert len(matching) == 1
    event = matching[0]
    assert event["disclosed_date"] == disclosed
    assert event["updated_date"] == "2026-10-04"
    assert event["status"] == event["confidence"] == "confirmed"
    assert event["detector_coverage"]["status"] == "not_detected"
    assert event["detector_coverage"]["detector_ids"] == []
    assert event["related"]["cve_ids"] == ([identifier] if identifier.startswith("CVE-") else [])
    assert any(s["url"] == url and s["id"] in event["source_ids"] for s in sources)
    assert sum(r["source"] == url for r in database["cve_database"]) == 1
    if identifier == "GHSA-qx49-fqc8-xw99":
        assert "issuer=" in record["mitigation"]
        assert "unbound" in record["mitigation"]
    if identifier == "CVE-2026-104850":
        assert "expectedIssuer" in record["mitigation"]
        assert "skipIssuerMetadataValidation" in record["mitigation"]
    if identifier in {"GHSA-5h93-6whr-6q8j", "GHSA-6prh-2h8m-c8cw"}:
        assert "Authorization" in record["description"]
    if identifier == "CVE-2026-103012":
        assert "endpoint-managed" in record["description"]
    if identifier == "GHSA-v234-4jrq-mgg6":
        assert "1.11847.5" in record["mitigation"]
        assert "user-interaction" in record["description"]
    if identifier == "CVE-2026-59723":
        assert "cline" not in database["minimum_safe_versions"]
        assert "no patched version" in record["mitigation"]


def test_october_version_floors_keep_branches_and_do_not_downgrade_claude():
    database = yaml.safe_load((ROOT / "data/threat-db.yaml").read_text())
    floors = database["minimum_safe_versions"]
    assert floors["mcp-python-sdk"] == "1.30.0"
    assert floors["mcp-python-sdk-2"] == "2.2.0"
    assert floors["@modelcontextprotocol/sdk"] == "1.32.0"
    assert floors["@modelcontextprotocol/client"] == "2.3.0"
    assert floors["@modelcontextprotocol/core"] == "2.2.0"
    assert floors["claude-code"] == "2.1.281"
    assert floors["claude-desktop"] == "1.15962.0"
    assert floors["awslabs.security-agent-mcp-server"] == "0.2.0"

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from jsonschema import validate

PROJECT_ROOT = Path(__file__).parents[2]
BUILDER = PROJECT_ROOT / "scripts" / "build_security_feed.py"
SCHEMA = PROJECT_ROOT / "schemas" / "security-feed-v1.schema.json"


def _build(
    output: Path,
    threat_database: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    command = [sys.executable, str(BUILDER), "--output", str(output)]
    if threat_database is not None:
        command.extend(["--threat-database", str(threat_database)])
    return subprocess.run(
        command,
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )


def test_builder_emits_deterministic_valid_public_feed_without_gated_iocs(
    tmp_path: Path,
) -> None:
    first_path = tmp_path / "first.json"
    second_path = tmp_path / "second.json"

    first = _build(first_path)
    second = _build(second_path)

    assert first.returncode == 0, first.stderr
    assert second.returncode == 0, second.stderr
    assert first_path.read_bytes() == second_path.read_bytes()

    payload = json.loads(first_path.read_text(encoding="utf-8"))
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    validate(payload, schema)

    assert payload["schema_version"] == "1"
    assert payload["agentsec"]["version"] == "0.1.0a0"
    assert payload["database"] == {
        "version": "2.27.0",
        "updated": "2026-08-17",
        "record_counts": {
            "attack_techniques": 40,
            "campaigns": 17,
            "cves": 114,
            "malicious_skill_records": 93,
        },
    }
    assert payload["landing_metrics"] == {
        "critical_risk_skills": 534,
        "exposed_servers": 1000,
        "flawed_skills_percent": 36.82,
        "malicious_payloads": 76,
        "skills_scanned": 3984,
    }
    assert payload["intelligence"]["updated"] == "2026-08-24"
    assert len(payload["intelligence"]["events"]) == 10
    assert len(payload["intelligence"]["sources"]) == 20
    assert [item["id"] for item in payload["detectors"]] == ["shai-hulud-keyv"]

    forbidden_keys = {
        "domains",
        "hashes",
        "iocs",
        "malicious_skills",
        "minimum_safe_versions",
        "package_versions",
        "supports",
    }

    def visit(value: object) -> None:
        if isinstance(value, dict):
            assert forbidden_keys.isdisjoint(value)
            for child in value.values():
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)

    visit(payload)


def test_builder_normalizes_input_line_endings_for_cross_platform_digests(
    tmp_path: Path,
) -> None:
    source = PROJECT_ROOT / "data" / "threat-db.yaml"
    crlf_database = tmp_path / "threat-db-crlf.yaml"
    canonical_database = source.read_bytes().replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    crlf_database.write_bytes(canonical_database.replace(b"\n", b"\r\n"))
    lf_output = tmp_path / "lf.json"
    crlf_output = tmp_path / "crlf.json"

    lf_result = _build(lf_output, source)
    crlf_result = _build(crlf_output, crlf_database)

    assert lf_result.returncode == 0, lf_result.stderr
    assert crlf_result.returncode == 0, crlf_result.stderr
    assert lf_output.read_bytes() == crlf_output.read_bytes()

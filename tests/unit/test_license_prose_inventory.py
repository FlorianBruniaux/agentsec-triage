from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parents[2]
SCRIPT = PROJECT_ROOT / "scripts" / "build_license_prose_inventory.py"


def _run(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *arguments],
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )


def test_extractor_records_every_prose_field_with_local_source_locator(tmp_path: Path) -> None:
    source = tmp_path / "threat-db.yaml"
    output = tmp_path / "inventory.json"
    source.write_text(
        "sources:\n"
        "  - name: Example advisory\n"
        "    url: https://example.test/advisory\n"
        "records:\n"
        "  - name: alpha\n"
        "    source: Example advisory\n"
        "    notes: Original local summary\n"
        "  - id: CVE-2099-0001\n"
        "    description: Independent description\n",
        encoding="utf-8",
    )

    result = _run("--source", str(source), "--output", str(output))

    assert result.returncode == 0, result.stderr
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["schema_version"] == "license-prose-inventory-v1"
    assert payload["field_count"] == 2
    assert payload["entries"] == [
        {
            "classification": "UNKNOWN",
            "field_path": "records[id=CVE-2099-0001].description",
            "required_action": (
                "No source locator is available. Record the source and rights evidence, "
                "then rewrite independently, obtain permission, or remove."
            ),
            "review_state": "UNREVIEWED",
            "source_locators": [],
            "value_sha256": hashlib.sha256(b"Independent description").hexdigest(),
        },
        {
            "classification": "UNKNOWN",
            "field_path": "records[name=alpha].notes",
            "required_action": (
                "Compare the cited source, document independent authorship or permission, "
                "then rewrite independently or remove."
            ),
            "review_state": "UNREVIEWED",
            "source_locators": ["https://example.test/advisory"],
            "value_sha256": hashlib.sha256(b"Original local summary").hexdigest(),
        },
    ]


def test_extractor_does_not_mark_new_scanning_tool_prose_as_historically_verified(
    tmp_path: Path,
) -> None:
    source = tmp_path / "threat-db.yaml"
    output = tmp_path / "inventory.json"
    source.write_text(
        "sources: []\n"
        "scanning_tools:\n"
        "  - name: unreviewed-tool\n"
        "    url: https://example.test/unreviewed-tool\n"
        "    notes: A new note without a local provenance review\n",
        encoding="utf-8",
    )

    result = _run("--source", str(source), "--output", str(output))

    assert result.returncode == 0, result.stderr
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["entries"][0]["review_state"] == "UNREVIEWED"
    assert payload["entries"][0]["source_locators"] == ["https://example.test/unreviewed-tool"]


def test_extractor_rejects_duplicate_yaml_keys_without_writing_an_inventory(tmp_path: Path) -> None:
    source = tmp_path / "threat-db.yaml"
    output = tmp_path / "inventory.json"
    source.write_text(
        "sources: []\n"
        "records:\n"
        "  - name: duplicate-note\n"
        "    notes: first value\n"
        "    notes: second value\n",
        encoding="utf-8",
    )

    result = _run("--source", str(source), "--output", str(output))

    assert result.returncode == 1
    assert result.stderr == "error: duplicate YAML mapping key\n"
    assert not output.exists()


def test_extractor_rejects_non_textual_prose_without_writing_an_inventory(
    tmp_path: Path,
) -> None:
    source = tmp_path / "threat-db.yaml"
    output = tmp_path / "inventory.json"
    source.write_text(
        "sources: []\n"
        "records:\n"
        "  - id: numeric-note\n"
        "    notes: 42\n",
        encoding="utf-8",
    )

    result = _run("--source", str(source), "--output", str(output))

    assert result.returncode == 1
    assert result.stderr == "error: records[id=numeric-note].notes must be text\n"
    assert not output.exists()


def test_extractor_rejects_yaml_merge_keys_without_writing_an_inventory(tmp_path: Path) -> None:
    source = tmp_path / "threat-db.yaml"
    output = tmp_path / "inventory.json"
    source.write_text(
        "sources: []\n"
        "defaults: &defaults\n"
        "  notes: inherited value\n"
        "records:\n"
        "  - id: merged-note\n"
        "    <<: *defaults\n"
        "    notes: local value\n",
        encoding="utf-8",
    )

    result = _run("--source", str(source), "--output", str(output))

    assert result.returncode == 1
    assert result.stderr == "error: YAML merge keys are not supported\n"
    assert not output.exists()


def test_extractor_preserves_all_sibling_source_locators_in_stable_order(tmp_path: Path) -> None:
    source = tmp_path / "threat-db.yaml"
    output = tmp_path / "inventory.json"
    source.write_text(
        "sources: []\n"
        "campaigns:\n"
        "  - id: campaign-1\n"
        "    sources:\n"
        "      - https://example.test/second\n"
        "      - https://example.test/first\n"
        "      - https://example.test/second\n"
        "    notes: Multiple cited sources\n",
        encoding="utf-8",
    )

    result = _run("--source", str(source), "--output", str(output))

    assert result.returncode == 0, result.stderr
    entry = json.loads(output.read_text(encoding="utf-8"))["entries"][0]
    assert entry["source_locators"] == [
        "https://example.test/first",
        "https://example.test/second",
    ]
    assert entry["required_action"].startswith("Compare the cited source")


def test_extractor_uses_escaped_stable_selectors(tmp_path: Path) -> None:
    source = tmp_path / "threat-db.yaml"
    output = tmp_path / "inventory.json"
    source.write_text(
        "sources: []\n"
        "records:\n"
        "  - name: alpha] beta=gamma\\delta\n"
        "    notes: Escaped selector\n"
        "c2_ips:\n"
        "  - ip: 203.0.113.10\n"
        "    notes: Stable IP selector\n"
        "exfil_urls:\n"
        "  - url: https://example.test/path?q=1\n"
        "    notes: Stable URL selector\n"
        "github_repos:\n"
        "  - repo: example/repo\n"
        "    notes: Stable repo selector\n",
        encoding="utf-8",
    )

    result = _run("--source", str(source), "--output", str(output))

    assert result.returncode == 0, result.stderr
    paths = [
        entry["field_path"] for entry in json.loads(output.read_text(encoding="utf-8"))["entries"]
    ]
    assert paths == [
        "c2_ips[ip=203.0.113.10].notes",
        "exfil_urls[url=https%3A%2F%2Fexample.test%2Fpath%3Fq%3D1].notes",
        "github_repos[repo=example%2Frepo].notes",
        "records[name=alpha%5D%20beta%3Dgamma%5Cdelta].notes",
    ]
    assert not any(re.search(r"\[\d+\]", path) for path in paths)


def test_extractor_rejects_structural_field_path_collisions(tmp_path: Path) -> None:
    collision_source = tmp_path / "collision.yaml"
    collision_output = tmp_path / "collision.json"
    collision_source.write_text(
        "sources: []\n"
        "records:\n"
        "  - notes: Duplicate structural record\n"
        "  - notes: Duplicate structural record\n",
        encoding="utf-8",
    )

    collision = _run("--source", str(collision_source), "--output", str(collision_output))

    assert collision.returncode == 1
    assert collision.stderr == "error: field path collision\n"
    assert not collision_output.exists()


def test_check_mode_rejects_a_byte_drift_with_unchanged_field_count(tmp_path: Path) -> None:
    source = tmp_path / "threat-db.yaml"
    output = tmp_path / "inventory.json"
    source.write_text(
        "sources: []\nrecords:\n  - id: evidence-1\n    notes: Original evidence\n",
        encoding="utf-8",
    )

    assert _run("--source", str(source), "--output", str(output)).returncode == 0
    stale = json.loads(output.read_text(encoding="utf-8"))
    stale["entries"][0]["value_sha256"] = "0" * 64
    output.write_text(json.dumps(stale, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    stale_result = _run("--source", str(source), "--output", str(output), "--check")
    assert stale_result.returncode == 1
    assert stale_result.stderr == "error: license prose inventory is stale\n"

    assert _run("--source", str(source), "--output", str(output)).returncode == 0
    assert _run("--source", str(source), "--output", str(output), "--check").returncode == 0


def test_extractor_is_deterministic_and_reconciles_the_current_database(tmp_path: Path) -> None:
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"

    first_result = _run("--output", str(first))
    second_result = _run("--output", str(second))

    assert first_result.returncode == 0, first_result.stderr
    assert second_result.returncode == 0, second_result.stderr
    assert first.read_bytes() == second.read_bytes()

    payload = json.loads(first.read_text(encoding="utf-8"))
    entries = payload["entries"]
    assert payload["field_count"] == 430
    assert len(entries) == payload["field_count"]
    assert entries == sorted(entries, key=lambda entry: entry["field_path"])
    assert {entry["classification"] for entry in entries} == {"UNKNOWN"}
    reviewed = [entry for entry in entries if entry["review_state"] == "LOCAL_PROVENANCE_VERIFIED"]
    assert len(reviewed) == 28
    assert all(entry["field_path"].startswith("scanning_tools[") for entry in reviewed)
    assert all(entry["field_path"].endswith(".notes") for entry in reviewed)
    assert sum(entry["review_state"] == "UNREVIEWED" for entry in entries) == 402
    assert all(len(entry["value_sha256"]) == 64 for entry in entries)

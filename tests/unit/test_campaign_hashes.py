"""Campaign-attributed hash projection stays separate from the shared hash map."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from agentsec.models import ThreatDatabase
from agentsec.threat_db import load_bundled_database

ROOT = Path(__file__).parents[2]
FAKEGIT_CAMPAIGN_ID = "fakegit-smartloader-2025-03"
FAKEGIT_ZIP_SHA256 = (
    "53039bdeb3e155236dce324281f59846c2da7518a54859c409286aaff86d61a2",
    "bd2a6bff153d95ab3d94d7db4525c49c31f5c6f32ddbf8e7c466732b0a6eb071",
)


def test_threat_database_defaults_to_no_campaign_hashes() -> None:
    database = ThreatDatabase(
        version="test",
        updated="2026-11-05",
        package_versions={},
        wildcard_package_versions={},
        hashes={},
        domains=frozenset(),
        commit_indicators=(),
    )

    assert dict(database.campaign_hashes) == {}


def test_bundled_database_projects_fakegit_zip_hashes_by_campaign() -> None:
    database = load_bundled_database()

    projected = database.campaign_hashes[FAKEGIT_CAMPAIGN_ID]
    for digest in FAKEGIT_ZIP_SHA256:
        assert digest in projected
        assert digest not in database.hashes


def test_shared_hash_map_keeps_only_unattributed_hashes() -> None:
    database = load_bundled_database()
    attributed = {
        digest for hashes in database.campaign_hashes.values() for digest in hashes
    }

    assert len(database.hashes) == 3
    assert attributed.isdisjoint(database.hashes)


def _build(document: dict[str, object], tmp_path: Path) -> subprocess.CompletedProcess[str]:
    source = tmp_path / "threat-db.yaml"
    source.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
    return subprocess.run(
        [
            sys.executable,
            "scripts/build_threat_db.py",
            "--source",
            str(source),
            "--output",
            str(tmp_path / "threat-db.json"),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


def _document() -> dict[str, object]:
    return yaml.safe_load((ROOT / "data/threat-db.yaml").read_text(encoding="utf-8"))


def test_builder_rejects_campaign_hash_without_projection_decision(tmp_path: Path) -> None:
    document = _document()
    hashes = document["iocs"]["malware_hashes"]  # type: ignore[index]
    entry = next(item for item in hashes if item.get("campaign_id") == FAKEGIT_CAMPAIGN_ID)
    del entry["detector_projection"]

    result = _build(document, tmp_path)

    assert result.returncode != 0
    assert "detector_projection" in result.stderr


def test_builder_keeps_withheld_campaign_hashes_out_of_every_runtime_map(
    tmp_path: Path,
) -> None:
    document = _document()
    withheld = [
        item
        for item in document["iocs"]["malware_hashes"]  # type: ignore[index]
        if item.get("detector_projection") == "none"
    ]
    assert withheld, "authoring data must record at least one withheld campaign hash"

    result = _build(document, tmp_path)

    assert result.returncode == 0, result.stderr
    payload = json.loads((tmp_path / "threat-db.json").read_text(encoding="utf-8"))
    projected = {
        digest for hashes in payload["campaign_hashes"].values() for digest in hashes
    }
    for item in withheld:
        assert item["hash"] not in payload["hashes"]
        assert item["hash"] not in projected


@pytest.mark.parametrize("bad", ["not-a-digest", "A" * 64])
def test_builder_rejects_campaign_hash_that_is_not_lowercase_sha256(
    bad: str, tmp_path: Path
) -> None:
    document = _document()
    entry = next(
        item
        for item in document["iocs"]["malware_hashes"]  # type: ignore[index]
        if item.get("detector_projection") == "exact-hash"
    )
    entry["hash"] = bad

    result = _build(document, tmp_path)

    assert result.returncode != 0
    assert "campaign" in result.stderr

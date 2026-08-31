from __future__ import annotations

import json
from pathlib import Path

from jsonschema import validate

from agentsec.batch import run_batch
from agentsec.detectors.shai_hulud import ShaiHuludDetector
from agentsec.engine.discovery import DiscoveryLimits
from agentsec.output.batch_output import render_batch_human, render_batch_json
from agentsec.scopes import ScanScope
from agentsec.threat_db import load_bundled_database

LIMITS = DiscoveryLimits(max_file_bytes=1_000_000, max_files=10_000, max_diagnostics=100)


def _batch(tmp_path: Path):
    roots = (tmp_path / "a", tmp_path / "b")
    for root in roots:
        root.mkdir()
    return run_batch(
        roots,
        [ShaiHuludDetector()],
        load_bundled_database(),
        LIMITS,
        scope=ScanScope.SOURCE,
    )


def test_batch_json_matches_schema_and_redacts_every_root(tmp_path: Path) -> None:
    result = _batch(tmp_path)
    payload = json.loads(render_batch_json(result, redact=True))
    batch_schema = json.loads(Path("schemas/batch-result-v1.schema.json").read_text())
    scan_schema = json.loads(Path("schemas/scan-result-v2.schema.json").read_text())
    batch_schema["$defs"] = {"scanResult": scan_schema}
    batch_schema["properties"]["results"]["items"] = {"$ref": "#/$defs/scanResult"}

    validate(payload, batch_schema)
    assert payload["schema_version"] == "1"
    assert str(tmp_path) not in json.dumps(payload)
    assert [item["root"] for item in payload["results"]] == [
        "<SCAN_ROOT_1>",
        "<SCAN_ROOT_2>",
    ]


def test_batch_human_has_one_compact_row_per_root(tmp_path: Path) -> None:
    result = _batch(tmp_path)

    text = render_batch_human(result, redact=False)

    assert "Repositories: 2" in text
    assert text.count("exit=0 complete=yes") == 2
    assert "Summary: exit_0=2 exit_1=0 exit_2=0" in text

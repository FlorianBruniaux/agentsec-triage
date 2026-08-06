import json
from pathlib import Path

from jsonschema import validate

from agentsec.models import ScanResult
from agentsec.output.json_output import render_json
from agentsec.redaction import redact_result


def test_redacted_json_hides_absolute_root(empty_scan_result: ScanResult):
    text = render_json(empty_scan_result, redact=True)

    assert str(empty_scan_result.root) not in text
    assert "<SCAN_ROOT>" in text


def test_redaction_replaces_known_secrets_recursively_without_mutating_payload(tmp_path: Path):
    root = tmp_path / "repository"
    payload = {
        "path": str(root / "package-lock.json"),
        "nested": [
            {"token": "ghp_abcdefghijklmnopqrstuvwxyz0123456789"},
            "npm_0123456789abcdefghij",
            "AKIA0123456789ABCDEF",
            "sk-ant-0123456789abcdefghi_jklmnop",
        ],
    }

    redacted = redact_result(payload, root)

    assert redacted == {
        "path": "<SCAN_ROOT>/package-lock.json",
        "nested": [
            {"token": "<REDACTED_SECRET>"},
            "<REDACTED_SECRET>",
            "<REDACTED_SECRET>",
            "<REDACTED_SECRET>",
        ],
    }
    assert payload["path"] == str(root / "package-lock.json")
    assert payload["nested"][0]["token"] != "<REDACTED_SECRET>"


def test_json_matches_public_schema(empty_scan_result: ScanResult):
    payload = json.loads(render_json(empty_scan_result, redact=False))
    schema = json.loads(Path("schemas/scan-result-v1.schema.json").read_text())

    validate(instance=payload, schema=schema)

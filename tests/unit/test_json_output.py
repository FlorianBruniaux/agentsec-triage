import json
from hashlib import sha256
from pathlib import Path, PureWindowsPath

from jsonschema import validate
from jsonschema.validators import Draft202012Validator

from agentsec.cli import _SCAN_RESULT_SCHEMA_SHA256
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


def test_redaction_hides_user_home_paths_in_evidence_and_diagnostics(tmp_path: Path):
    payload = {
        "findings": [
            {"evidence": "Credential file: /Users/alice/.ssh/config"},
            {"evidence": r"Credential file: C:\Users\alice\.ssh\config"},
        ],
        "diagnostics": [{"message": "Could not read /Users/alice/.ssh/config"}],
        "unchanged": "Repository metadata at /etc/agentsec/config",
    }

    redacted = redact_result(payload, tmp_path / "repository")

    assert redacted == {
        "findings": [
            {"evidence": "Credential file: <REDACTED_PATH>"},
            {"evidence": "Credential file: <REDACTED_PATH>"},
        ],
        "diagnostics": [{"message": "Could not read <REDACTED_PATH>"}],
        "unchanged": "Repository metadata at /etc/agentsec/config",
    }
    assert payload["findings"][0]["evidence"] == "Credential file: /Users/alice/.ssh/config"


def test_redaction_hides_user_home_paths_with_spaces_without_swallowing_context(
    tmp_path: Path,
):
    payload = {
        "posix": "Evidence: (/Users/alice/My Docs/report.txt).",
        "windows": 'Evidence: "C:\\Users\\alice\\My Docs\\report.txt".',
        "at_end": "Evidence: /Users/alice/My Docs/report.txt",
        "unchanged": "Repository metadata at /etc/agentsec/config",
    }

    redacted = redact_result(payload, tmp_path / "repository")

    assert redacted == {
        "posix": "Evidence: (<REDACTED_PATH>).",
        "windows": 'Evidence: "<REDACTED_PATH>".',
        "at_end": "Evidence: <REDACTED_PATH>",
        "unchanged": "Repository metadata at /etc/agentsec/config",
    }


def test_redaction_matches_serialized_and_native_windows_root_forms() -> None:
    payload = {
        "root": "C:/repo",
        "diagnostic": r"C:\repo\nested\warning.txt",
    }

    redacted = redact_result(payload, PureWindowsPath(r"C:\repo"))

    assert redacted == {
        "root": "<SCAN_ROOT>",
        "diagnostic": r"<SCAN_ROOT>\nested\warning.txt",
    }


def test_json_matches_public_schema(empty_scan_result: ScanResult):
    payload = json.loads(render_json(empty_scan_result, redact=False))
    schema = json.loads(Path("schemas/scan-result-v1.schema.json").read_text())

    validate(instance=payload, schema=schema)


def test_public_schema_is_meta_valid_and_matches_runtime_digest() -> None:
    raw_schema = Path("schemas/scan-result-v1.schema.json").read_bytes()
    schema = json.loads(raw_schema)

    Draft202012Validator.check_schema(schema)

    assert sha256(raw_schema).hexdigest() == _SCAN_RESULT_SCHEMA_SHA256


def test_public_schema_accepts_contested_confidence() -> None:
    schema = json.loads(Path("schemas/scan-result-v1.schema.json").read_text())
    confidence = schema["properties"]["findings"]["items"]["properties"]["confidence"]

    assert "contested" in confidence["enum"]

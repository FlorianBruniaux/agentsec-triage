from __future__ import annotations

import subprocess
import sys
from hashlib import sha256
from pathlib import Path

PROJECT_ROOT = Path(__file__).parents[2]


def _run(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "scripts/build_scan_schema_digest.py", *arguments],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


def test_digest_builder_generates_exact_schema_digest(tmp_path: Path) -> None:
    schema = tmp_path / "schema.json"
    output = tmp_path / "schema.sha256"
    schema.write_bytes(b'{"type":"object"}\n')

    result = _run("--schema", str(schema), "--output", str(output))

    assert result.returncode == 0
    assert result.stderr == ""
    assert output.read_text(encoding="ascii") == f"{sha256(schema.read_bytes()).hexdigest()}\n"


def test_digest_builder_check_detects_drift_without_writing(tmp_path: Path) -> None:
    schema = tmp_path / "schema.json"
    output = tmp_path / "schema.sha256"
    schema.write_bytes(b'{"type":"object"}\n')
    output.write_text(f"{'0' * 64}\n", encoding="ascii")

    result = _run("--schema", str(schema), "--output", str(output), "--check")

    assert result.returncode == 1
    assert result.stderr == "error: schema digest is stale\n"
    assert output.read_text(encoding="ascii") == f"{'0' * 64}\n"


def test_digest_builder_normalizes_schema_line_endings(tmp_path: Path) -> None:
    lf_schema = tmp_path / "schema-lf.json"
    crlf_schema = tmp_path / "schema-crlf.json"
    lf_output = tmp_path / "schema-lf.sha256"
    crlf_output = tmp_path / "schema-crlf.sha256"
    lf_bytes = b'{\n  "type": "object"\n}\n'
    lf_schema.write_bytes(lf_bytes)
    crlf_schema.write_bytes(lf_bytes.replace(b"\n", b"\r\n"))

    lf_result = _run("--schema", str(lf_schema), "--output", str(lf_output))
    crlf_result = _run(
        "--schema", str(crlf_schema), "--output", str(crlf_output)
    )

    assert lf_result.returncode == 0
    assert crlf_result.returncode == 0
    expected = f"{sha256(lf_bytes).hexdigest()}\n"
    assert lf_output.read_text(encoding="ascii") == expected
    assert crlf_output.read_text(encoding="ascii") == expected


def test_default_check_validates_all_public_schema_digests() -> None:
    result = _run("--check")

    assert result.returncode == 0
    assert "scan-result-v1.schema.json" in result.stdout
    assert "scan-result-v2.schema.json" in result.stdout
    assert "batch-result-v1.schema.json" in result.stdout
    assert "detector-explain-v1.schema.json" in result.stdout

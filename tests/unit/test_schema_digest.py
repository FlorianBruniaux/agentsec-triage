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

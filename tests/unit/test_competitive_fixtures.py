from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parents[2]
VALIDATOR = PROJECT_ROOT / "scripts" / "check_competitive_fixtures.py"
MANIFEST = PROJECT_ROOT / "research" / "competitive-fixtures" / "manifest.yaml"
FIXTURE_ROOT = MANIFEST.parent


def _fixture() -> dict[str, object]:
    return {
        "id": "clean-control",
        "directory": "clean-control",
        "kind": "negative",
        "technique": "benign repository control",
        "expected_evidence": ["no campaign evidence"],
        "source_url": "https://example.com/security-advisory",
        "applicable_tool_classes": ["repository"],
        "inert": True,
        "control": None,
        "files": [{"path": "README.md", "type": "text"}],
    }


def _payload() -> dict[str, object]:
    return {"schema_version": "1", "fixtures": [_fixture()]}


def _validate(
    tmp_path: Path,
    payload: dict[str, object],
    *,
    content: str = "Synthetic inert fixture.\n",
    executable: bool = False,
) -> subprocess.CompletedProcess[str]:
    root = tmp_path / "fixtures"
    fixture_dir = root / "clean-control"
    fixture_dir.mkdir(parents=True)
    fixture_file = fixture_dir / "README.md"
    fixture_file.write_text(content, encoding="utf-8")
    if executable:
        fixture_file.chmod(0o755)
    manifest = root / "manifest.yaml"
    manifest.write_text(json.dumps(payload), encoding="utf-8")
    return subprocess.run(
        [sys.executable, str(VALIDATOR), "--manifest", str(manifest)],
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )


def test_valid_fixture_manifest_passes(tmp_path: Path) -> None:
    result = _validate(tmp_path, _payload())

    assert result.returncode == 0, result.stderr
    assert result.stdout == "Validated 1 inert competitive fixture\n"


def test_committed_manifest_contains_twelve_inert_fixture_classes() -> None:
    payload = json.loads(MANIFEST.read_text(encoding="utf-8"))

    result = subprocess.run(
        [sys.executable, str(VALIDATOR), "--manifest", str(MANIFEST)],
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    fixtures = payload["fixtures"]
    assert len(fixtures) == 12
    assert all(fixture["inert"] is True for fixture in fixtures)
    assert {fixture["kind"] for fixture in fixtures} >= {
        "positive",
        "negative",
        "near_miss",
        "unsupported",
        "safety",
    }


def test_missing_source_url_fails(tmp_path: Path) -> None:
    payload = _payload()
    fixture = payload["fixtures"][0]
    assert isinstance(fixture, dict)
    del fixture["source_url"]

    result = _validate(tmp_path, payload)

    assert result.returncode == 1
    assert "fixtures[0].source_url: missing required field" in result.stderr


def test_non_inert_fixture_fails(tmp_path: Path) -> None:
    payload = _payload()
    fixture = payload["fixtures"][0]
    assert isinstance(fixture, dict)
    fixture["inert"] = False

    result = _validate(tmp_path, payload)

    assert result.returncode == 1
    assert "fixtures[0].inert: expected true" in result.stderr


def test_secret_shaped_fixture_content_fails(tmp_path: Path) -> None:
    result = _validate(
        tmp_path, _payload(), content="token = ghp_abcdefghijklmnopqrstuvwxyz123456\n"
    )

    assert result.returncode == 1
    assert "secret-shaped content" in result.stderr


def test_executable_fixture_file_fails(tmp_path: Path) -> None:
    if os.name == "nt":
        return

    result = _validate(tmp_path, _payload(), executable=True)

    assert result.returncode == 1
    assert "executable permission bits are forbidden" in result.stderr


def test_archive_fixture_file_fails(tmp_path: Path) -> None:
    payload = _payload()
    fixture = payload["fixtures"][0]
    assert isinstance(fixture, dict)
    fixture["files"] = [{"path": "payload.zip", "type": "text"}]
    root = tmp_path / "fixtures"
    fixture_dir = root / "clean-control"
    fixture_dir.mkdir(parents=True)
    (fixture_dir / "payload.zip").write_text("not an archive", encoding="utf-8")
    manifest = root / "manifest.yaml"
    manifest.write_text(json.dumps(payload), encoding="utf-8")

    result = subprocess.run(
        [sys.executable, str(VALIDATOR), "--manifest", str(manifest)],
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    assert "archive files are forbidden" in result.stderr


def test_undeclared_fixture_file_fails(tmp_path: Path) -> None:
    root = tmp_path / "fixtures"
    fixture_dir = root / "clean-control"
    fixture_dir.mkdir(parents=True)
    (fixture_dir / "README.md").write_text("Synthetic inert fixture.\n", encoding="utf-8")
    (fixture_dir / "extra.txt").write_text("undeclared\n", encoding="utf-8")
    manifest = root / "manifest.yaml"
    manifest.write_text(json.dumps(_payload()), encoding="utf-8")

    result = subprocess.run(
        [sys.executable, str(VALIDATOR), "--manifest", str(manifest)],
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    assert "undeclared file" in result.stderr

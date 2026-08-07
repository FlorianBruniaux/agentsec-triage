from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parents[2]
FIXTURES = PROJECT_ROOT / "tests" / "fixtures" / "shai_hulud"
GOLDEN = PROJECT_ROOT / "tests" / "golden"


def _run(*arguments: str) -> subprocess.CompletedProcess[str]:
    environment = {**os.environ, "PYTHONPATH": str(PROJECT_ROOT / "src")}
    return subprocess.run(
        [sys.executable, "-m", "agentsec.cli", *arguments],
        cwd=PROJECT_ROOT,
        env=environment,
        check=False,
        shell=False,
        text=True,
        capture_output=True,
    )


def test_scan_missing_root_is_incomplete_json_and_exits_two(tmp_path: Path) -> None:
    completed = _run("scan", str(tmp_path / "missing"), "--format", "json")

    assert completed.returncode == 2
    assert completed.stderr == ""
    assert json.loads(completed.stdout)["complete"] is False

    human = _run("scan", str(tmp_path / "missing"), "--format", "human")

    assert human.returncode == 2
    assert "No indicators found in completed checks" not in human.stdout


def test_scan_non_applicable_repository_is_completed_not_clean(tmp_path: Path) -> None:
    completed = _run("scan", str(tmp_path), "--format", "human")

    assert completed.returncode == 0
    assert completed.stderr == ""
    assert completed.stdout == (GOLDEN / "clean.txt").read_text(encoding="utf-8")


def test_scan_positive_fixture_exits_one_and_names_exact_package_version(tmp_path: Path) -> None:
    root = tmp_path / "positive"
    shutil.copytree(FIXTURES / "positive", root)

    completed = _run("scan", str(root), "--format", "json")

    assert completed.returncode == 1
    payload = json.loads(completed.stdout)
    assert any(finding["evidence"] == "@keyv/mongo@6.0.0" for finding in payload["findings"])
    assert [finding["evidence"] for finding in payload["findings"]] == json.loads(
        (GOLDEN / "finding.json").read_text(encoding="utf-8")
    )


def test_scan_redaction_removes_temporary_absolute_root(tmp_path: Path) -> None:
    completed = _run("scan", str(tmp_path), "--format", "json", "--redact")

    assert completed.returncode == 0
    assert str(tmp_path) not in completed.stdout
    assert "<SCAN_ROOT>" in completed.stdout


def test_detectors_list_contains_built_in_detector() -> None:
    completed = _run("detectors", "list")

    assert completed.returncode == 0
    assert completed.stderr == ""
    assert "shai-hulud-keyv" in completed.stdout


def test_unknown_detector_has_concise_usage_error() -> None:
    completed = _run("detectors", "explain", "missing")

    assert completed.returncode == 2
    assert completed.stdout == ""
    assert "unknown detector ID: missing" in completed.stderr
    assert "usage:" not in completed.stderr.lower()


def test_db_info_reports_generated_database_version_and_ioc_counts() -> None:
    completed = _run("db", "info")

    assert completed.returncode == 0
    assert completed.stderr == ""
    assert "2.26.0" in completed.stdout
    assert "package_versions=" in completed.stdout
    assert "hashes=" in completed.stdout
    assert "domains=" in completed.stdout
    assert "commit_indicators=" in completed.stdout


def test_doctor_validates_local_resources_and_schema_without_network() -> None:
    completed = _run("doctor")

    assert completed.returncode == 0
    assert completed.stderr == ""
    assert "Python:" in completed.stdout
    assert "database: 2.26.0" in completed.stdout
    assert "resource: available" in completed.stdout
    assert "schema: valid" in completed.stdout

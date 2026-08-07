from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import venv
import zipfile
from email.parser import BytesParser
from pathlib import Path

import pytest

import agentsec.cli as cli
from agentsec.threat_db import ThreatDatabaseError, load_bundled_database

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


def test_scan_negative_fixture_completes_with_review_findings_and_no_critical(
    tmp_path: Path,
) -> None:
    root = tmp_path / "negative"
    shutil.copytree(FIXTURES / "negative", root)

    completed = _run("scan", str(root), "--format", "json")

    assert completed.returncode == 1
    payload = json.loads(completed.stdout)
    assert payload["complete"] is True
    assert payload["diagnostics"] == []
    assert payload["findings"]
    assert all(finding["severity"] != "critical" for finding in payload["findings"])


def test_self_scan_shape_keeps_findings_when_unsupported_fixture_makes_it_incomplete(
    tmp_path: Path,
) -> None:
    root = tmp_path / "self-scan"
    shutil.copytree(FIXTURES / "positive", root)
    shutil.copy2(PROJECT_ROOT / "tests" / "fixtures" / "lockfiles" / "bun.lockb", root)

    completed = _run("scan", str(root), "--format", "json")

    assert completed.returncode == 2
    payload = json.loads(completed.stdout)
    assert payload["complete"] is False
    assert any(finding["confidence"] == "confirmed" for finding in payload["findings"])
    assert any(
        diagnostic["path"].endswith("bun.lockb")
        and diagnostic["message"] == "Unsupported binary Bun lockfile format"
        for diagnostic in payload["diagnostics"]
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


def test_doctor_from_wheel_without_dependencies_validates_packaged_schema(tmp_path: Path) -> None:
    dist = tmp_path / "dist"
    environment = tmp_path / "no-deps"
    offline = {**os.environ, "PIP_NO_INDEX": "1"}
    _checked(
        [
            sys.executable,
            "-m",
            "build",
            "--no-isolation",
            "--wheel",
            "--outdir",
            str(dist),
        ],
        env=offline,
    )
    wheel = next(dist.glob("*.whl"))
    with zipfile.ZipFile(wheel) as archive:
        metadata_name = next(name for name in archive.namelist() if name.endswith("METADATA"))
        metadata = BytesParser().parsebytes(archive.read(metadata_name))
    assert metadata.get_all("License-File", []) == []

    venv.create(environment, with_pip=True)
    scripts = environment / ("Scripts" if os.name == "nt" else "bin")
    python = scripts / ("python.exe" if os.name == "nt" else "python")
    _checked(
        [str(python), "-m", "pip", "install", "--no-index", "--no-deps", str(wheel)],
        env=offline,
    )

    completed = subprocess.run(
        [str(scripts / ("agentsec.exe" if os.name == "nt" else "agentsec")), "doctor"],
        check=False,
        shell=False,
        text=True,
        capture_output=True,
    )

    assert completed.returncode == 0
    assert completed.stderr == ""
    assert "schema: valid" in completed.stdout


def test_redacted_scan_database_load_error_does_not_leak_root_or_secret(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    root = tmp_path / "repository"
    secret = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
    failure = ThreatDatabaseError(f"cannot read {root}/private-token: {secret}")
    monkeypatch.setattr(cli, "load_bundled_database", lambda: (_ for _ in ()).throw(failure))

    assert cli.main(["scan", str(root), "--format", "json", "--redact"]) == 2

    captured = capsys.readouterr()
    assert captured.out == ""
    assert str(root) not in captured.err
    assert secret not in captured.err
    assert "<REDACTED_SECRET>" in captured.err


@pytest.mark.parametrize("content", ("{", '{"$schema": 1}'))
def test_doctor_invalid_schema_returns_concise_error_without_traceback(
    content: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    class InvalidSchemaResource:
        def joinpath(self, *names: str) -> InvalidSchemaResource:
            return self

        def read_bytes(self) -> bytes:
            return content.encode("utf-8")

    database = load_bundled_database()
    monkeypatch.setattr(cli, "_load_database", lambda: database)
    monkeypatch.setattr(cli.resources, "files", lambda package: InvalidSchemaResource())

    assert cli.main(["doctor"]) == 2

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.startswith("agentsec: local schema validation failed:")
    assert "Traceback" not in captured.err


@pytest.mark.parametrize("mutation", ("invalid_type", "unexpected_but_valid_field"))
def test_doctor_rejects_schema_that_is_not_the_prevalidated_artifact(
    mutation: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    class MutatedSchemaResource:
        def joinpath(self, *names: str) -> MutatedSchemaResource:
            return self

        def read_bytes(self) -> bytes:
            schema = json.loads(
                (PROJECT_ROOT / "schemas" / "scan-result-v1.schema.json").read_text(
                    encoding="utf-8"
                )
            )
            if mutation == "invalid_type":
                schema["properties"]["root"]["type"] = "not-a-json-schema-type"
            else:
                schema["description"] = "valid-looking but not prevalidated"
            return json.dumps(schema).encode("utf-8")

    database = load_bundled_database()
    monkeypatch.setattr(cli, "_load_database", lambda: database)
    monkeypatch.setattr(cli.resources, "files", lambda package: MutatedSchemaResource())

    assert cli.main(["doctor"]) == 2

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.startswith("agentsec: local schema validation failed:")
    assert "Traceback" not in captured.err


def _checked(arguments: list[str], *, env: dict[str, str] | None = None) -> None:
    completed = subprocess.run(
        arguments,
        cwd=PROJECT_ROOT,
        check=False,
        shell=False,
        text=True,
        capture_output=True,
        env=env,
    )
    assert completed.returncode == 0, completed.stderr

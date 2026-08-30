from __future__ import annotations

import io
import json
import os
import shutil
import subprocess
import sys
import venv
import zipfile
from email.parser import BytesParser
from hashlib import sha256
from pathlib import Path

import pytest
from jsonschema import validate

import agentsec.cli as cli
from agentsec.threat_db import ThreatDatabaseError, load_bundled_database

PROJECT_ROOT = Path(__file__).parents[2]
FIXTURES = PROJECT_ROOT / "tests" / "fixtures" / "shai_hulud"
GOLDEN = PROJECT_ROOT / "tests" / "golden"


def _run(*arguments: str) -> subprocess.CompletedProcess[str]:
    return _run_module("agentsec.cli", *arguments)


def _run_module(module: str, *arguments: str) -> subprocess.CompletedProcess[str]:
    environment = {**os.environ, "PYTHONPATH": str(PROJECT_ROOT / "src")}
    return subprocess.run(
        [sys.executable, "-m", module, *arguments],
        cwd=PROJECT_ROOT,
        env=environment,
        check=False,
        shell=False,
        text=True,
        capture_output=True,
    )


def test_package_module_entrypoint_matches_cli_module() -> None:
    package = _run_module("agentsec", "--help")
    cli_module = _run_module("agentsec.cli", "--help")

    assert package.returncode == cli_module.returncode == 0
    assert package.stdout == cli_module.stdout
    assert package.stderr == cli_module.stderr == ""


def test_scan_help_documents_progress_verbosity_and_safe_limits() -> None:
    completed = _run("scan", "--help")

    assert completed.returncode == 0
    assert completed.stderr == ""
    for option in (
        "--progress [{auto,always,never}]",
        "-v, --verbose",
        "--max-file-bytes",
        "--max-total-bytes",
        "--max-files",
        "--max-git-commits",
        "--max-directories",
        "--max-entries",
    ):
        assert option in completed.stdout
    assert "Progress is written to stderr" in completed.stdout


def test_progress_always_uses_stderr_without_corrupting_json(tmp_path: Path) -> None:
    completed = _run(
        "scan",
        str(tmp_path),
        "--format",
        "json",
        "--progress=always",
    )

    assert completed.returncode == 0
    assert json.loads(completed.stdout)["complete"] is True
    assert "[1/5] Loading threat database" in completed.stderr
    assert "[1/5] Threat database ready:" in completed.stderr
    assert "version=2.27.0" in completed.stderr
    assert "updated=2026-08-17" in completed.stderr
    assert "resource=" in completed.stderr
    assert "threat-db.json" in completed.stderr
    assert "package_records=17" in completed.stderr
    assert "hashes=3" in completed.stderr
    assert "domains=7" in completed.stderr
    assert "commit_indicators=1" in completed.stderr
    assert "[2/5] Validating repository" in completed.stderr
    assert (
        f"[2/5] Repository validated: root={tmp_path.resolve()} "
        "type=directory scan_mode=read-only detectors=shai-hulud-keyv"
        in completed.stderr
    )
    assert "[2/5] Safety limits:" in completed.stderr
    assert "max_entries=1000000" in completed.stderr
    assert "max_directories=100000" in completed.stderr
    assert "[3/5] Discovering files" in completed.stderr
    assert (
        "[3/5] Discovery complete: files=0 directories=1 entries=0"
        in completed.stderr
    )
    assert "[4/5] Running detectors" in completed.stderr
    assert "[5/5] Building report" in completed.stderr
    assert "[1/5]" not in completed.stdout


def test_progress_redacts_repository_and_resource_paths(tmp_path: Path) -> None:
    completed = _run(
        "scan",
        str(tmp_path),
        "--format",
        "json",
        "--progress=always",
        "--redact",
    )

    assert completed.returncode == 0
    assert str(tmp_path) not in completed.stderr
    assert str(PROJECT_ROOT) not in completed.stderr
    assert "root=<SCAN_ROOT>" in completed.stderr
    assert "resource=<REDACTED_PATH>" in completed.stderr


def test_database_progress_redacts_resource_without_relying_on_home_path() -> None:
    summary = cli._database_progress_summary(
        load_bundled_database(),
        redact=True,
    )

    assert "resource=<REDACTED_PATH>" in summary
    assert str(PROJECT_ROOT) not in summary


def test_progress_confirms_repository_validation_failure(tmp_path: Path) -> None:
    missing = tmp_path / "missing"

    completed = _run(
        "scan",
        str(missing),
        "--format",
        "json",
        "--progress=always",
    )

    assert completed.returncode == 2
    assert (
        "[2/5] Repository validation failed: diagnostics=1" in completed.stderr
    )
    assert "[3/5] Discovering files" not in completed.stderr


def test_terminal_discovery_uses_indeterminate_bar_then_finishes_at_100(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class TerminalBuffer(io.StringIO):
        def isatty(self) -> bool:
            return True

    progress_state_type = getattr(cli, "ProgressState", None)
    assert progress_state_type is not None
    stream = TerminalBuffer()
    monkeypatch.setattr(cli.sys, "stderr", stream)
    arguments = cli.build_parser().parse_args(["scan", "."])
    reporter = cli._progress_reporter(arguments)
    assert reporter is not None

    reporter(
        3,
        "Discovery progress: files=1000 directories=20 entries=1500",
        True,
        progress_state_type(1000, 20, 1500, False),
    )

    ongoing = stream.getvalue()
    assert ongoing.startswith("\r[3/5] [")
    assert "files=1000 directories=20 entries=1500" in ongoing
    assert "%" not in ongoing

    reporter(
        3,
        "Discovery complete: files=1250 directories=24 entries=1800",
        False,
        progress_state_type(1250, 24, 1800, True),
    )

    output = stream.getvalue()
    assert "[============] 100%" in output
    assert "files=1250 directories=24 entries=1800" in output
    assert output.endswith("\n")


def test_verbose_progress_reports_bounded_live_counts(tmp_path: Path) -> None:
    for index in range(1001):
        (tmp_path / f"file-{index:04d}.txt").write_text("x")

    completed = _run("scan", str(tmp_path), "--format", "json", "--verbose")

    assert completed.returncode == 0
    assert json.loads(completed.stdout)["complete"] is True
    assert "Discovered 1000 paths" in completed.stderr
    assert "Discovered 1001 paths" in completed.stderr
    assert "Inspected 1000 files" in completed.stderr
    assert "Inspected 1001 files" in completed.stderr
    assert (
        f"root={tmp_path.resolve()} type=directory scan_mode=read-only"
        in completed.stderr
    )


def test_scan_exposes_a_directory_budget_override(tmp_path: Path) -> None:
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()

    completed = _run(
        "scan",
        str(tmp_path),
        "--format",
        "json",
        "--max-directories",
        "1",
    )

    assert completed.returncode == 2
    payload = json.loads(completed.stdout)
    assert any("max_directories=1" in item["message"] for item in payload["diagnostics"])


def test_scan_exposes_an_entry_budget_override(tmp_path: Path) -> None:
    (tmp_path / "a.txt").write_text("a")
    (tmp_path / "b.txt").write_text("b")

    completed = _run(
        "scan",
        str(tmp_path),
        "--format",
        "json",
        "--max-entries",
        "1",
    )

    assert completed.returncode == 2
    payload = json.loads(completed.stdout)
    assert any("max_entries=1" in item["message"] for item in payload["diagnostics"])


def test_scan_missing_root_is_incomplete_json_and_exits_two(tmp_path: Path) -> None:
    completed = _run("scan", str(tmp_path / "missing"), "--format", "json")

    assert completed.returncode == 2
    assert completed.stderr == ""
    assert json.loads(completed.stdout)["complete"] is False

    human = _run("scan", str(tmp_path / "missing"), "--format", "human")

    assert human.returncode == 2
    assert "No indicators found in completed checks" not in human.stdout


def test_scan_git_repository_reports_unscanned_history_and_exits_two(tmp_path: Path) -> None:
    (tmp_path / ".git").mkdir()

    completed = _run("scan", str(tmp_path), "--format", "json")

    assert completed.returncode == 2
    assert completed.stderr == ""
    payload = json.loads(completed.stdout)
    assert payload["complete"] is False
    assert payload["findings"] == []
    assert any(
        diagnostic["message"]
        == "Local Git history not scanned: strict metadata confinement unavailable"
        for diagnostic in payload["diagnostics"]
    )


def test_scan_non_applicable_repository_is_completed_not_clean(tmp_path: Path) -> None:
    completed = _run("scan", str(tmp_path), "--format", "human", "--color", "never")

    assert completed.returncode == 0
    assert completed.stderr == ""
    assert completed.stdout == (GOLDEN / "clean.txt").read_text(encoding="utf-8")


def test_scan_color_defaults_to_always_without_a_flag(tmp_path: Path) -> None:
    completed = _run("scan", str(tmp_path), "--format", "human")

    assert completed.returncode == 0
    assert "\x1b[91mcritical\x1b[0m: none" in completed.stdout
    assert "\x1b[38;5;208mhigh\x1b[0m: none" in completed.stdout
    assert "\x1b[33mmedium\x1b[0m: none" in completed.stdout
    assert "\x1b[34mlow\x1b[0m: none" in completed.stdout
    assert "\x1b[35minfo\x1b[0m: none" in completed.stdout


def test_scan_color_always_emits_ansi_severity_codes(tmp_path: Path) -> None:
    completed = _run("scan", str(tmp_path), "--format", "human", "--color", "always")

    assert completed.returncode == 0
    assert "\x1b[91mcritical\x1b[0m: none" in completed.stdout
    assert "\x1b[38;5;208mhigh\x1b[0m: none" in completed.stdout
    assert "\x1b[33mmedium\x1b[0m: none" in completed.stdout
    assert "\x1b[34mlow\x1b[0m: none" in completed.stdout
    assert "\x1b[35minfo\x1b[0m: none" in completed.stdout


def test_scan_color_auto_stays_plain_when_stdout_is_not_a_terminal(tmp_path: Path) -> None:
    completed = _run("scan", str(tmp_path), "--format", "human", "--color", "auto")

    assert completed.returncode == 0
    assert "\x1b[" not in completed.stdout


def test_scan_positive_fixture_exits_one_and_names_exact_package_version(tmp_path: Path) -> None:
    root = tmp_path / "positive"
    shutil.copytree(FIXTURES / "positive", root)

    completed = _run("scan", str(root), "--format", "json")

    assert completed.returncode == 1
    payload = json.loads(completed.stdout)
    assert any(
        finding["evidence"]
        == "@keyv/mongo@6.0.0 (contested intelligence; sources: JFrog, SafeDep)"
        and finding["severity"] == "high"
        and finding["confidence"] == "contested"
        for finding in payload["findings"]
    )
    assert any(
        finding["evidence"] == "keyv@6.0.0"
        and finding["severity"] == "critical"
        and finding["confidence"] == "confirmed"
        for finding in payload["findings"]
    )
    schema = json.loads((PROJECT_ROOT / "schemas" / "scan-result-v1.schema.json").read_text())
    validate(instance=payload, schema=schema)
    payload["root"] = "<SCAN_ROOT>"
    payload["elapsed_ms"] = 0
    assert payload == json.loads((GOLDEN / "finding.json").read_text(encoding="utf-8"))


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


def test_detectors_explain_is_deterministic_and_exposes_metadata() -> None:
    first = _run("detectors", "explain", "shai-hulud-keyv")
    second = _run("detectors", "explain", "shai-hulud-keyv")

    assert first.returncode == 0
    assert first.stderr == ""
    assert first.stdout == second.stdout
    assert "description:" in first.stdout
    assert "supported_inputs:" in first.stdout
    assert "campaign_ids: shai-hulud-keyv-2026-08" in first.stdout
    assert "technique_ids:" in first.stdout
    assert "https://safedep.io/keyv-npm-supply-chain-compromise/" in first.stdout
    assert "limitations:" in first.stdout
    assert "remediation_url: https://cc.bruniaux.com/security/" in first.stdout
    assert "not_scanned: git.history" in first.stdout


def test_scan_rejects_file_limit_above_safe_reader_cap(tmp_path: Path) -> None:
    completed = _run("scan", str(tmp_path), "--max-file-bytes", "4000001")

    assert completed.returncode == 2
    assert completed.stdout == ""
    assert "must not exceed 4000000 bytes" in completed.stderr


def test_scan_total_byte_limit_is_exposed_and_incomplete_when_reached(tmp_path: Path) -> None:
    (tmp_path / "payload.bin").write_bytes(b"xx")

    completed = _run("scan", str(tmp_path), "--max-total-bytes", "1", "--format", "json")

    assert completed.returncode == 2
    payload = json.loads(completed.stdout)
    assert payload["coverage"]["bytes_inspected"] == 0
    assert any("max_total_bytes=1" in item["message"] for item in payload["diagnostics"])


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
    assert "2.27.0" in completed.stdout
    assert "package_versions=" in completed.stdout
    assert "contested_package_versions=0" in completed.stdout
    assert "contested_wildcard_package_versions=1" in completed.stdout
    assert "package_version_sources=" in completed.stdout
    assert "hashes=" in completed.stdout
    assert "domains=" in completed.stdout
    assert "commit_indicators=" in completed.stdout
    assert "authoring_malicious_skills=93" in completed.stdout
    assert "projected_malicious_skills=17" in completed.stdout
    assert "ignored_missing_platform=64" in completed.stdout
    assert "ignored_unsupported_platform=9" in completed.stdout
    assert "ignored_missing_version=3" in completed.stdout
    assert "projected_cves=0/114" in completed.stdout
    assert "projected_attack_techniques=0/40" in completed.stdout
    assert "projected_campaign_indicators=1/17" in completed.stdout


def test_doctor_validates_local_resources_and_schema_without_network() -> None:
    completed = _run("doctor")

    assert completed.returncode == 0
    assert completed.stderr == ""
    assert "Python:" in completed.stdout
    assert "database: 2.27.0" in completed.stdout
    assert "resource: available" in completed.stdout
    assert "schema: valid" in completed.stdout


def test_doctor_accepts_crlf_schema_bytes(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    raw_schema = (PROJECT_ROOT / "schemas" / "scan-result-v1.schema.json").read_bytes()
    canonical_schema = raw_schema.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    crlf_schema = canonical_schema.replace(b"\n", b"\r\n")
    monkeypatch.setattr(cli, "_read_schema_bytes", lambda: crlf_schema)

    result = cli._doctor()

    assert result == 0
    assert "schema: valid" in capsys.readouterr().out


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
        assert "agentsec/resources/security-intelligence.json" in archive.namelist()
        assert "agentsec/resources/scan-result-v1.schema.sha256" in archive.namelist()
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

    module_completed = subprocess.run(
        [str(python), "-m", "agentsec", "doctor"],
        check=False,
        shell=False,
        text=True,
        capture_output=True,
    )
    assert module_completed.returncode == 0
    assert module_completed.stdout == completed.stdout
    assert module_completed.stderr == ""


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
    monkeypatch.setattr(
        cli,
        "_read_schema_digest",
        lambda: sha256(content.encode("utf-8")).hexdigest(),
    )

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
    monkeypatch.setattr(
        cli,
        "_read_schema_digest",
        lambda: (PROJECT_ROOT / "schemas" / "scan-result-v1.schema.sha256")
        .read_text(encoding="ascii")
        .strip(),
    )

    assert cli.main(["doctor"]) == 2

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.startswith("agentsec: local schema validation failed:")
    assert "Traceback" not in captured.err


def test_doctor_rejects_schema_digest_mismatch(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    database = load_bundled_database()
    schema = (PROJECT_ROOT / "schemas" / "scan-result-v1.schema.json").read_bytes()
    monkeypatch.setattr(cli, "_load_database", lambda: database)
    monkeypatch.setattr(cli, "_read_schema_bytes", lambda: schema)
    monkeypatch.setattr(cli, "_read_schema_digest", lambda: "0" * 64)

    assert cli.main(["doctor"]) == 2

    captured = capsys.readouterr()
    assert captured.out == ""
    assert "schema integrity digest mismatch" in captured.err
    assert "Traceback" not in captured.err


def test_schema_digest_reader_rejects_malformed_digest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class DigestResource:
        def joinpath(self, *names: str) -> DigestResource:
            return self

        def read_text(self, *, encoding: str) -> str:
            assert encoding == "ascii"
            return "not-a-sha256\n"

    monkeypatch.setattr(cli.resources, "files", lambda package: DigestResource())

    with pytest.raises(ValueError, match="schema integrity digest is invalid"):
        cli._read_schema_digest()


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

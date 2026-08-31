from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import yaml

PROJECT_ROOT = Path(__file__).parents[2]
FIXTURES = PROJECT_ROOT / "tests" / "fixtures" / "shai_hulud"


def _run_action(
    workspace: Path,
    runner_temp: Path,
    *,
    sarif_file: str = "",
    scope: str = "source",
    redact: str = "true",
    action_root: Path = PROJECT_ROOT,
) -> tuple[subprocess.CompletedProcess[str], Path, Path]:
    github_output = runner_temp / "github-output"
    environment = {
        **os.environ,
        "GITHUB_ACTION_PATH": str(action_root),
        "GITHUB_WORKSPACE": str(workspace),
        "GITHUB_OUTPUT": str(github_output),
        "RUNNER_TEMP": str(runner_temp),
        "AGENTSEC_PATH": ".",
        "AGENTSEC_SCOPE": scope,
        "AGENTSEC_SARIF_FILE": sarif_file,
        "AGENTSEC_REDACT": redact,
    }
    completed = subprocess.run(
        [sys.executable, "scripts/run_local_action.py"],
        cwd=PROJECT_ROOT,
        env=environment,
        check=False,
        shell=False,
        text=True,
        capture_output=True,
    )
    output_path = (
        workspace / sarif_file
        if sarif_file
        else runner_temp / "agentsec.sarif"
    )
    return completed, output_path, github_output


def test_local_action_writes_sarif_after_scan_and_returns_finding_exit(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    runner_temp = tmp_path / "runner-temp"
    shutil.copytree(FIXTURES / "positive", workspace)
    runner_temp.mkdir()

    completed, sarif_path, github_output = _run_action(
        workspace,
        runner_temp,
        sarif_file=str(runner_temp / "reports" / "agentsec.sarif"),
    )

    assert completed.returncode == 1
    assert completed.stdout == ""
    payload = json.loads(sarif_path.read_text(encoding="utf-8"))
    run = payload["runs"][0]
    assert run["properties"]["agentsec.complete"] is True
    assert run["properties"]["agentsec.discovery"]["filesSelected"] == 3
    assert any(result["level"] == "error" for result in run["results"])
    assert github_output.read_text(encoding="utf-8").splitlines() == [
        f"sarif-file={sarif_path.resolve()}",
        "exit-code=1",
    ]


def test_local_action_publishes_incomplete_sarif_and_returns_two(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    runner_temp = tmp_path / "runner-temp"
    workspace.mkdir()
    runner_temp.mkdir()
    (workspace / "package-lock.json").write_text("not-json", encoding="utf-8")

    completed, sarif_path, github_output = _run_action(workspace, runner_temp)

    assert completed.returncode == 2
    payload = json.loads(sarif_path.read_text(encoding="utf-8"))
    run = payload["runs"][0]
    assert run["properties"]["agentsec.complete"] is False
    assert run["properties"]["agentsec.diagnostics"]
    assert run["invocations"][0]["exitCode"] == 2
    assert github_output.read_text(encoding="utf-8").endswith("exit-code=2\n")


def test_local_action_returns_zero_for_completed_scan_without_findings(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    runner_temp = tmp_path / "runner-temp"
    workspace.mkdir()
    runner_temp.mkdir()
    (workspace / "README.txt").write_text("fixture", encoding="utf-8")

    completed, sarif_path, _ = _run_action(workspace, runner_temp)

    assert completed.returncode == 0
    run = json.loads(sarif_path.read_text(encoding="utf-8"))["runs"][0]
    assert run["properties"]["agentsec.complete"] is True
    assert run["results"] == []


def test_local_action_rejects_invalid_scope_without_publishing_sarif(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    runner_temp = tmp_path / "runner-temp"
    workspace.mkdir()
    runner_temp.mkdir()

    completed, sarif_path, github_output = _run_action(
        workspace,
        runner_temp,
        scope="source --format human",
    )

    assert completed.returncode == 2
    assert not sarif_path.exists()
    assert "invalid scope" in completed.stderr.lower()
    assert github_output.read_text(encoding="utf-8") == "exit-code=2\n"


def test_local_action_rejects_report_path_inside_scanned_repository(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    runner_temp = tmp_path / "runner-temp"
    workspace.mkdir()
    runner_temp.mkdir()

    completed, sarif_path, github_output = _run_action(
        workspace,
        runner_temp,
        sarif_file="reports/agentsec.sarif",
    )

    assert completed.returncode == 2
    assert not sarif_path.exists()
    assert "outside the scanned repository" in completed.stderr.lower()
    assert github_output.read_text(encoding="utf-8") == "exit-code=2\n"


def test_local_action_rejects_multiline_output_path_before_github_output_write(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    runner_temp = tmp_path / "runner-temp"
    workspace.mkdir()
    runner_temp.mkdir()

    completed, sarif_path, github_output = _run_action(
        workspace,
        runner_temp,
        sarif_file="report.sarif\nforged-output=value",
    )

    assert completed.returncode == 2
    assert not sarif_path.exists()
    assert "must stay on one line" in completed.stderr
    assert github_output.read_text(encoding="utf-8") == "exit-code=2\n"


def test_local_action_rejects_non_boolean_redaction_input(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    runner_temp = tmp_path / "runner-temp"
    workspace.mkdir()
    runner_temp.mkdir()

    completed, sarif_path, github_output = _run_action(
        workspace,
        runner_temp,
        redact="true --format human",
    )

    assert completed.returncode == 2
    assert not sarif_path.exists()
    assert "redact must be true or false" in completed.stderr
    assert github_output.read_text(encoding="utf-8") == "exit-code=2\n"


def test_local_action_rejects_malformed_scanner_output(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    runner_temp = tmp_path / "runner-temp"
    action_root = tmp_path / "fake-action"
    workspace.mkdir()
    runner_temp.mkdir()
    package = action_root / "src" / "agentsec"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "__main__.py").write_text("print('{}')\n", encoding="utf-8")

    completed, sarif_path, github_output = _run_action(
        workspace,
        runner_temp,
        action_root=action_root,
    )

    assert completed.returncode == 2
    assert not sarif_path.exists()
    assert "valid fail-closed sarif" in completed.stderr.lower()
    assert github_output.read_text(encoding="utf-8") == "exit-code=2\n"


def test_composite_action_delegates_inputs_to_the_tested_runner() -> None:
    manifest = yaml.safe_load((PROJECT_ROOT / "action.yml").read_text(encoding="utf-8"))

    assert manifest["runs"]["using"] == "composite"
    assert manifest["inputs"]["path"]["default"] == "."
    assert manifest["inputs"]["scope"]["default"] == "source"
    assert manifest["inputs"]["sarif-file"]["default"] == ""
    assert manifest["inputs"]["redact"]["default"] == "true"
    assert manifest["outputs"]["exit-code"]["value"] == (
        "${{ steps.scan.outputs.exit-code }}"
    )
    step = manifest["runs"]["steps"][0]
    assert "uses" not in step
    assert step["env"] == {
        "AGENTSEC_PATH": "${{ inputs.path }}",
        "AGENTSEC_REDACT": "${{ inputs.redact }}",
        "AGENTSEC_SARIF_FILE": "${{ inputs.sarif-file }}",
        "AGENTSEC_SCOPE": "${{ inputs.scope }}",
    }
    assert step["run"] == 'python "$GITHUB_ACTION_PATH/scripts/run_local_action.py"\n'


def test_consumer_example_pins_every_remote_action_to_verified_sha() -> None:
    workflow = yaml.safe_load(
        (PROJECT_ROOT / "docs" / "examples" / "agentsec-local-action.yml").read_text(
            encoding="utf-8"
        )
    )
    steps = workflow["jobs"]["agentsec"]["steps"]
    remote_uses = [
        step["uses"]
        for step in steps
        if "uses" in step and not step["uses"].startswith("./")
    ]

    assert remote_uses == [
        "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
        "actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97",
        "github/codeql-action/upload-sarif@cdf488f595d80d6e07e03d4674febd5ab45fa938",
    ]
    assert all(len(reference.rsplit("@", 1)[1]) == 40 for reference in remote_uses)

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

PROJECT_ROOT = Path(__file__).parents[2]
RUNNER_PATH = PROJECT_ROOT / "scripts" / "run_competitive_benchmark.py"


def _load_runner() -> ModuleType:
    spec = importlib.util.spec_from_file_location("competitive_runner", RUNNER_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _project_index(clone_name: str = "example-tool") -> dict[str, object]:
    return {
        "schema_version": "1",
        "projects": [
            {
                "id": "example-tool",
                "name": "Example Tool",
                "url": "https://github.com/example/example-tool",
                "local_directory": clone_name,
                "revision": "0123456789ab",
                "category": "pre_trust_repository",
                "evidence_status": "code_verified",
                "execution_tier": "offline_sandbox",
                "license": "MIT",
                "profile": "docs/competitive-analysis/profiles/example-tool.md",
            }
        ],
    }


def _fixture_manifest() -> dict[str, object]:
    return {
        "schema_version": "1",
        "fixtures": [
            {
                "id": "clean-control",
                "directory": "clean-control",
                "kind": "negative",
                "technique": "clean control",
                "expected_evidence": ["no finding"],
                "source_url": "https://example.com/advisory",
                "applicable_tool_classes": ["repository"],
                "inert": True,
                "control": None,
                "files": [{"path": "README.md", "type": "text"}],
            }
        ],
    }


def _plan(clone_root: Path, fixture_root: Path) -> dict[str, object]:
    return {
        "schema_version": "1",
        "project_id": "example-tool",
        "revision": "0123456789ab",
        "fixture_id": "clean-control",
        "image": "example-tool@sha256:" + "a" * 64,
        "source_path": str(clone_root / "example-tool"),
        "fixture_path": str(fixture_root / "clean-control"),
        "source_mount": "ro",
        "fixture_mount": "ro",
        "command": ["/tool/bin/scanner", "scan", "/fixture"],
        "network": {"mode": "none", "allowlist": [], "approved": False},
        "timeout_seconds": 30,
        "memory_mb": 512,
        "pids_limit": 64,
        "cpus": 1.0,
        "output_limit_bytes": 1000000,
    }


def _write_inputs(tmp_path: Path) -> tuple[Path, Path, Path, Path, Path]:
    clone_root = tmp_path / "clones"
    source = clone_root / "example-tool"
    source.mkdir(parents=True)
    fixture_root = tmp_path / "fixtures"
    fixture = fixture_root / "clean-control"
    fixture.mkdir(parents=True)
    (fixture / "README.md").write_text("inert\n", encoding="utf-8")
    project_index = tmp_path / "projects.json"
    project_index.write_text(json.dumps(_project_index()), encoding="utf-8")
    fixture_manifest = fixture_root / "manifest.yaml"
    fixture_manifest.write_text(json.dumps(_fixture_manifest()), encoding="utf-8")
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(json.dumps(_plan(clone_root, fixture_root)), encoding="utf-8")
    return plan_path, project_index, fixture_manifest, clone_root, fixture_root


def _validate(tmp_path: Path, mutate: object | None = None) -> subprocess.CompletedProcess[str]:
    plan_path, project_index, fixture_manifest, clone_root, fixture_root = _write_inputs(tmp_path)
    if callable(mutate):
        payload = json.loads(plan_path.read_text(encoding="utf-8"))
        mutate(payload)
        plan_path.write_text(json.dumps(payload), encoding="utf-8")
    return subprocess.run(
        [
            sys.executable,
            str(RUNNER_PATH),
            "validate",
            "--plan",
            str(plan_path),
            "--project-index",
            str(project_index),
            "--fixture-manifest",
            str(fixture_manifest),
            "--clone-root",
            str(clone_root),
            "--fixture-root",
            str(fixture_root),
        ],
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )


def test_valid_plan_returns_approval_digest_and_docker_preview(tmp_path: Path) -> None:
    result = _validate(tmp_path)

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert len(payload["approval_digest"]) == 64
    command = payload["docker_argv"]
    assert command[:2] == ["docker", "run"]
    assert "--network" in command
    assert "none" in command
    assert "--read-only" in command
    assert "--cap-drop" in command
    assert "ALL" in command
    assert any(value.endswith(":/competitor:ro") for value in command)
    assert any(value.endswith(":/fixture:ro") for value in command)


def test_local_immutable_image_id_is_accepted(tmp_path: Path) -> None:
    result = _validate(
        tmp_path, lambda payload: payload.__setitem__("image", "sha256:" + "b" * 64)
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["docker_argv"][-4] == "sha256:" + "b" * 64


def test_shell_command_string_is_rejected(tmp_path: Path) -> None:
    result = _validate(tmp_path, lambda payload: payload.__setitem__("command", "scan /fixture"))

    assert result.returncode == 1
    assert "command: expected a non-empty argument array" in result.stderr


def test_unpinned_revision_is_rejected(tmp_path: Path) -> None:
    result = _validate(tmp_path, lambda payload: payload.__setitem__("revision", "000000000000"))

    assert result.returncode == 1
    assert "revision: does not match pinned project revision" in result.stderr


def test_unpinned_image_is_rejected(tmp_path: Path) -> None:
    result = _validate(
        tmp_path, lambda payload: payload.__setitem__("image", "example-tool:latest")
    )

    assert result.returncode == 1
    assert "image: expected a registry digest or local sha256 image ID" in result.stderr


def test_home_mount_is_rejected(tmp_path: Path) -> None:
    result = _validate(
        tmp_path, lambda payload: payload.__setitem__("source_path", str(Path.home()))
    )

    assert result.returncode == 1
    assert "source_path: expected the pinned clone directory" in result.stderr


def test_writable_fixture_mount_is_rejected(tmp_path: Path) -> None:
    result = _validate(tmp_path, lambda payload: payload.__setitem__("fixture_mount", "rw"))

    assert result.returncode == 1
    assert "fixture_mount: expected 'ro'" in result.stderr


def test_missing_timeout_is_rejected(tmp_path: Path) -> None:
    def remove_timeout(payload: dict[str, object]) -> None:
        del payload["timeout_seconds"]

    result = _validate(tmp_path, remove_timeout)

    assert result.returncode == 1
    assert "timeout_seconds: missing required field" in result.stderr


def test_unapproved_network_is_rejected(tmp_path: Path) -> None:
    def enable_network(payload: dict[str, object]) -> None:
        payload["network"] = {
            "mode": "allowlist",
            "allowlist": ["api.example.com:443"],
            "approved": False,
        }

    result = _validate(tmp_path, enable_network)

    assert result.returncode == 1
    assert "network: non-disabled network requires explicit approval" in result.stderr


def test_approval_digest_normalizes_equivalent_resource_numbers(tmp_path: Path) -> None:
    runner = _load_runner()
    plan_path, _, _, _, _ = _write_inputs(tmp_path)
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    equivalent = dict(plan)
    equivalent["timeout_seconds"] = 30.0
    equivalent["memory_mb"] = 512.0
    equivalent["pids_limit"] = 64.0
    equivalent["cpus"] = 1
    equivalent["output_limit_bytes"] = 1_000_000.0

    assert runner.normalize_plan(plan) == runner.normalize_plan(equivalent)
    assert runner.approval_digest(plan) == runner.approval_digest(equivalent)


def test_approval_digest_is_stable_when_plan_keys_are_reordered(tmp_path: Path) -> None:
    runner = _load_runner()
    plan_path, _, _, _, _ = _write_inputs(tmp_path)
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    reordered = {key: plan[key] for key in reversed(plan)}

    assert runner.approval_digest(plan) == runner.approval_digest(reordered)


def test_execute_rejects_unapproved_output_root_before_docker_lookup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    plan_path, project_index, fixture_manifest, clone_root, fixture_root = _write_inputs(tmp_path)
    runner = _load_runner()
    digest = runner.approval_digest(json.loads(plan_path.read_text(encoding="utf-8")))
    options = runner._parser().parse_args(
        [
            "execute",
            "--plan",
            str(plan_path),
            "--project-index",
            str(project_index),
            "--fixture-manifest",
            str(fixture_manifest),
            "--clone-root",
            str(clone_root),
            "--fixture-root",
            str(fixture_root),
            "--approval-digest",
            digest,
            "--output-root",
            str(tmp_path / "outside-local-boundary"),
        ]
    )
    monkeypatch.setattr(
        runner.shutil,
        "which",
        lambda _: pytest.fail("output-root rejection must not look up Docker"),
    )

    assert runner._execute_command(options) == 1
    assert "output root must be the ignored local directory" in capsys.readouterr().err


def test_execute_refuses_a_missing_approval_digest(tmp_path: Path) -> None:
    plan_path, project_index, fixture_manifest, clone_root, fixture_root = _write_inputs(tmp_path)

    result = subprocess.run(
        [
            sys.executable,
            str(RUNNER_PATH),
            "execute",
            "--plan",
            str(plan_path),
            "--project-index",
            str(project_index),
            "--fixture-manifest",
            str(fixture_manifest),
            "--clone-root",
            str(clone_root),
            "--fixture-root",
            str(fixture_root),
        ],
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 2
    assert "--approval-digest" in result.stderr


def test_redaction_removes_absolute_paths_and_secret_shapes(tmp_path: Path) -> None:
    runner = _load_runner()
    sensitive = tmp_path / "private-repository"
    raw = f"read {sensitive}/file.txt token ghp_abcdefghijklmnopqrstuvwxyz123456"

    redacted = runner.redact_output(raw, [sensitive])

    assert str(sensitive) not in redacted
    assert "ghp_" not in redacted
    assert "[REDACTED_PATH]" in redacted
    assert "[REDACTED_SECRET]" in redacted


def test_result_envelope_contains_required_evidence_fields() -> None:
    runner = _load_runner()

    envelope = runner.build_result_envelope(
        project_id="example-tool",
        revision="0123456789ab",
        fixture_id="clean-control",
        argument_vector=["/tool/bin/scanner", "scan", "/fixture"],
        image="example-tool@sha256:" + "a" * 64,
        network_policy={"mode": "none", "allowlist": [], "approved": False},
        exit_code=0,
        timed_out=False,
        duration_seconds=0.5,
        maximum_rss_kb=None,
        stdout=b"ok\n",
        stderr=b"",
        stdout_truncated=False,
        stderr_truncated=False,
        files_written=[],
    )

    assert envelope["schema_version"] == "1"
    assert envelope["stdout_sha256"]
    assert envelope["stderr_sha256"]
    assert envelope["network_attempts"] is None
    assert envelope["network_observation"] == "blocked_not_observed"
    assert envelope["normalized_findings"] == []
    assert "stdout" not in envelope
    assert "stderr" not in envelope


def test_self_test_proves_bounded_capture_and_redaction() -> None:
    result = subprocess.run(
        [sys.executable, str(RUNNER_PATH), "self-test"],
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "passed"
    assert payload["shell"] is False
    assert payload["network_policy"] == "none"
    assert payload["redaction"] is True
    assert payload["bounded_capture"] is True

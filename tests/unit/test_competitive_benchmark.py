from __future__ import annotations

import importlib.util
import json
import math
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
        "scratch_mb": 64,
    }


def _approval_receipt(digest: str) -> dict[str, object]:
    return {
        "schema_version": "1",
        "decision": "approved",
        "approver": "benchmark-owner",
        "approved_at": "2026-08-31T12:00:00+00:00",
        "scope": "execute",
        "plan_digest": digest,
        "statement": (
            "I approve execution of the exact benchmark plan with SHA-256 digest "
            f"{digest}."
        ),
    }


def _write_inputs(tmp_path: Path) -> tuple[Path, Path, Path, Path, Path]:
    clone_root = tmp_path / "clones"
    source = clone_root / "example-tool"
    full_commit = _git_commit(source)
    fixture_root = tmp_path / "fixtures"
    fixture = fixture_root / "clean-control"
    fixture.mkdir(parents=True)
    (fixture / "README.md").write_text("inert\n", encoding="utf-8")
    project_index = tmp_path / "projects.json"
    index = _project_index()
    assert isinstance(index["projects"], list)
    index["projects"][0]["revision"] = full_commit[:12]
    project_index.write_text(json.dumps(index), encoding="utf-8")
    fixture_manifest = fixture_root / "manifest.yaml"
    fixture_manifest.write_text(json.dumps(_fixture_manifest()), encoding="utf-8")
    plan_path = tmp_path / "plan.json"
    plan = _plan(clone_root, fixture_root)
    runner = _load_runner()
    plan.update(
        {
            "schema_version": "2",
            "revision": full_commit[:12],
            "source_commit": full_commit,
            "source_tree": runner.build_committed_source_evidence(source, full_commit),
            "fixture_tree": runner.build_tree_evidence(fixture),
        }
    )
    plan_path.write_text(json.dumps(plan), encoding="utf-8")
    return plan_path, project_index, fixture_manifest, clone_root, fixture_root


def _git_commit(repository: Path, filename: str = "source.txt", content: str = "source\n") -> str:
    repository.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-q", str(repository)], check=True)
    subprocess.run(
        ["git", "-C", str(repository), "config", "user.email", "test@example.test"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(repository), "config", "user.name", "Test"], check=True
    )
    (repository / filename).write_text(content, encoding="utf-8")
    subprocess.run(["git", "-C", str(repository), "add", filename], check=True)
    subprocess.run(["git", "-C", str(repository), "commit", "-qm", "fixture"], check=True)
    return subprocess.run(
        ["git", "-C", str(repository), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


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
    assert "approval_receipt" not in payload
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


@pytest.mark.parametrize("value", [math.nan, math.inf, -math.inf])
def test_non_finite_resource_number_is_rejected(tmp_path: Path, value: float) -> None:
    result = _validate(
        tmp_path,
        lambda payload: payload.__setitem__("timeout_seconds", value),
    )

    assert result.returncode == 1
    assert "timeout_seconds: expected a finite number" in result.stderr


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


def test_approval_digest_uses_tree_evidence_instead_of_host_specific_paths(
    tmp_path: Path,
) -> None:
    runner = _load_runner()
    plan_path, _, _, _, _ = _write_inputs(tmp_path)
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    relocated = dict(plan)
    relocated["source_path"] = "/different-host/clones/example-tool"
    relocated["fixture_path"] = "/different-checkout/fixtures/clean-control"
    changed_content = dict(plan)
    changed_content["fixture_tree"] = {
        **plan["fixture_tree"],
        "sha256": "f" * 64,
    }

    assert runner.approval_digest(plan) == runner.approval_digest(relocated)
    assert runner.approval_digest(plan) != runner.approval_digest(changed_content)


def test_tree_evidence_binds_content_modes_and_symlink_targets(tmp_path: Path) -> None:
    runner = _load_runner()
    root = tmp_path / "tree"
    root.mkdir()
    script = root / "scan.sh"
    script.write_bytes(b"echo inert\n")
    script.chmod(0o644)
    (root / "link").symlink_to("scan.sh")

    original = runner.build_tree_evidence(root)
    script.chmod(0o755)
    executable = runner.build_tree_evidence(root)
    (root / "link").unlink()
    (root / "link").symlink_to("other.txt")
    retargeted = runner.build_tree_evidence(root)

    assert original["file_count"] == 2
    assert original["total_bytes"] == len(b"echo inert\n")
    if sys.platform != "win32":
        assert original["sha256"] != executable["sha256"]
    assert executable["sha256"] != retargeted["sha256"]


def test_tree_evidence_hashes_files_streaming_and_enforces_file_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner = _load_runner()
    root = tmp_path / "tree"
    root.mkdir()
    oversized = root / "large.bin"
    oversized.write_bytes(b"x" * 32)
    monkeypatch.setattr(runner, "MAX_TREE_FILE_BYTES", 16)
    monkeypatch.setattr(
        runner.Path,
        "read_bytes",
        lambda _self: pytest.fail("tree hashing must stream file content"),
    )

    with pytest.raises(runner.TreeEvidenceError, match="per-file byte limit"):
        runner.build_tree_evidence(root)


def test_generate_reconstructs_digest_bound_plan_without_absolute_blueprint_paths(
    tmp_path: Path,
) -> None:
    clone_root = tmp_path / "clones"
    source = clone_root / "example-tool"
    full_commit = _git_commit(source)
    fixture_root = tmp_path / "fixtures"
    fixture = fixture_root / "clean-control"
    fixture.mkdir(parents=True)
    (fixture / "README.md").write_text("inert\n", encoding="utf-8")
    project_index = tmp_path / "projects.json"
    index = _project_index()
    assert isinstance(index["projects"], list)
    index["projects"][0]["revision"] = full_commit[:12]
    project_index.write_text(json.dumps(index), encoding="utf-8")
    fixture_manifest = fixture_root / "manifest.yaml"
    fixture_manifest.write_text(json.dumps(_fixture_manifest()), encoding="utf-8")
    blueprints = tmp_path / "blueprints.json"
    blueprint_payload = {
        "schema_version": "1",
        "plans": [
            {
                "project_id": "example-tool",
                "fixture_id": "clean-control",
                "image": "sha256:" + "a" * 64,
                "command": ["/tool/bin/scanner", "scan", "/fixture"],
                "network": {"mode": "none", "allowlist": [], "approved": False},
                "timeout_seconds": 30,
                "memory_mb": 512,
                "pids_limit": 64,
                "cpus": 1,
                "output_limit_bytes": 1_000_000,
                "scratch_mb": 64,
            }
        ],
    }
    blueprints.write_text(json.dumps(blueprint_payload), encoding="utf-8")
    assert str(tmp_path) not in blueprints.read_text(encoding="utf-8")
    output = tmp_path / "local" / "plans"

    result = subprocess.run(
        [
            sys.executable,
            str(RUNNER_PATH),
            "generate",
            "--blueprints",
            str(blueprints),
            "--project-index",
            str(project_index),
            "--fixture-manifest",
            str(fixture_manifest),
            "--clone-root",
            str(clone_root),
            "--fixture-root",
            str(fixture_root),
            "--output-root",
            str(output),
        ],
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    plan_path = output / "example-tool-clean-control.json"
    first = plan_path.read_bytes()
    plan = json.loads(first)
    assert plan["schema_version"] == "2"
    assert plan["source_commit"] == full_commit
    assert len(plan["source_tree"]["sha256"]) == 64
    assert len(plan["fixture_tree"]["sha256"]) == 64
    assert plan["source_path"] == str(source)
    assert plan["fixture_path"] == str(fixture)
    assert subprocess.run(
        [
            sys.executable,
            str(RUNNER_PATH),
            "generate",
            "--blueprints",
            str(blueprints),
            "--project-index",
            str(project_index),
            "--fixture-manifest",
            str(fixture_manifest),
            "--clone-root",
            str(clone_root),
            "--fixture-root",
            str(fixture_root),
            "--output-root",
            str(output),
        ],
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
    ).returncode == 0
    assert plan_path.read_bytes() == first


def test_validate_rejects_fixture_content_changed_after_plan_generation(tmp_path: Path) -> None:
    runner = _load_runner()
    clone_root = tmp_path / "clones"
    source = clone_root / "example-tool"
    full_commit = _git_commit(source)
    fixture_root = tmp_path / "fixtures"
    fixture = fixture_root / "clean-control"
    fixture.mkdir(parents=True)
    marker = fixture / "README.md"
    marker.write_text("inert\n", encoding="utf-8")
    index = _project_index()
    assert isinstance(index["projects"], list)
    index["projects"][0]["revision"] = full_commit[:12]
    plan = _plan(clone_root, fixture_root)
    plan.update(
        {
            "schema_version": "2",
            "revision": full_commit[:12],
            "source_commit": full_commit,
            "source_tree": runner.build_committed_source_evidence(source, full_commit),
            "fixture_tree": runner.build_tree_evidence(fixture),
        }
    )
    marker.write_text("changed\n", encoding="utf-8")

    errors = runner.validate_plan(
        plan,
        index,
        _fixture_manifest(),
        clone_root,
        fixture_root,
    )

    assert "fixture_tree: content does not match the approved plan" in errors


def test_execute_rejects_unapproved_output_root_before_docker_lookup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    plan_path, project_index, fixture_manifest, clone_root, fixture_root = _write_inputs(tmp_path)
    runner = _load_runner()
    digest = runner.approval_digest(json.loads(plan_path.read_text(encoding="utf-8")))
    receipt_path = tmp_path / "receipt.json"
    receipt_path.write_text(json.dumps(_approval_receipt(digest)), encoding="utf-8")
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
            "--approval-receipt",
            str(receipt_path),
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


def test_execute_refuses_without_a_distinct_approval_receipt(tmp_path: Path) -> None:
    plan_path, project_index, fixture_manifest, clone_root, fixture_root = _write_inputs(tmp_path)
    runner = _load_runner()
    digest = runner.approval_digest(json.loads(plan_path.read_text(encoding="utf-8")))

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
            "--approval-digest",
            digest,
            "--output-root",
            str(tmp_path / "outside-local-boundary"),
        ],
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 2
    assert "--approval-receipt" in result.stderr


def test_execute_refuses_a_malformed_approval_receipt_before_docker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    plan_path, project_index, fixture_manifest, clone_root, fixture_root = _write_inputs(tmp_path)
    runner = _load_runner()
    digest = runner.approval_digest(json.loads(plan_path.read_text(encoding="utf-8")))
    receipt_path = tmp_path / "receipt.json"
    receipt_path.write_text("{", encoding="utf-8")
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
            "--approval-receipt",
            str(receipt_path),
            "--output-root",
            str(tmp_path / "outside-local-boundary"),
        ]
    )
    monkeypatch.setattr(
        runner.shutil,
        "which",
        lambda _: pytest.fail("invalid receipt must not look up Docker"),
    )

    assert runner._execute_command(options) == 1
    assert "approval receipt:" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("mutate", "expected_error"),
    [
        (
            lambda receipt: receipt.__setitem__("decision", "declined"),
            "decision: expected 'approved'",
        ),
        (
            lambda receipt: receipt.__setitem__("approver", ""),
            "approver: expected a non-empty declared identity",
        ),
        (
            lambda receipt: receipt.__setitem__("plan_digest", "b" * 64),
            "plan_digest: does not match exact plan",
        ),
        (
            lambda receipt: receipt.__setitem__("approved_at", "not-a-date"),
            "approved_at: expected an ISO 8601 timestamp with timezone",
        ),
        (
            lambda receipt: receipt.__setitem__("scope", "validate"),
            "scope: expected 'execute'",
        ),
        (
            lambda receipt: receipt.__setitem__("statement", "approved"),
            "statement: does not bind the exact digest",
        ),
    ],
)
def test_execute_refuses_an_invalid_approval_receipt_before_docker(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    mutate: object,
    expected_error: str,
) -> None:
    plan_path, project_index, fixture_manifest, clone_root, fixture_root = _write_inputs(tmp_path)
    runner = _load_runner()
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    digest = runner.approval_digest(plan)
    receipt = _approval_receipt(digest)
    assert callable(mutate)
    mutate(receipt)
    receipt_path = tmp_path / "receipt.json"
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
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
            "--approval-receipt",
            str(receipt_path),
            "--output-root",
            str(tmp_path / "outside-local-boundary"),
        ]
    )
    monkeypatch.setattr(
        runner.shutil,
        "which",
        lambda _: pytest.fail("invalid receipt must not look up Docker"),
    )

    assert runner._execute_command(options) == 1
    assert expected_error in capsys.readouterr().err


def test_execute_refuses_a_receipt_when_the_plan_changes_before_docker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    plan_path, project_index, fixture_manifest, clone_root, fixture_root = _write_inputs(tmp_path)
    runner = _load_runner()
    original = json.loads(plan_path.read_text(encoding="utf-8"))
    receipt_path = tmp_path / "receipt.json"
    receipt_path.write_text(
        json.dumps(_approval_receipt(runner.approval_digest(original))), encoding="utf-8"
    )
    changed = dict(original)
    changed["command"] = ["/tool/bin/scanner", "scan", "/fixture", "--changed"]
    plan_path.write_text(json.dumps(changed), encoding="utf-8")
    changed_digest = runner.approval_digest(changed)
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
            changed_digest,
            "--approval-receipt",
            str(receipt_path),
            "--output-root",
            str(tmp_path / "outside-local-boundary"),
        ]
    )
    monkeypatch.setattr(
        runner.shutil,
        "which",
        lambda _: pytest.fail("changed plan must not look up Docker"),
    )

    assert runner._execute_command(options) == 1
    assert "plan_digest: does not match exact plan" in capsys.readouterr().err


def test_valid_approval_receipt_reaches_the_existing_output_boundary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    plan_path, project_index, fixture_manifest, clone_root, fixture_root = _write_inputs(tmp_path)
    runner = _load_runner()
    digest = runner.approval_digest(json.loads(plan_path.read_text(encoding="utf-8")))
    receipt_path = tmp_path / "receipt.json"
    receipt_path.write_text(json.dumps(_approval_receipt(digest)), encoding="utf-8")
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
            "--approval-receipt",
            str(receipt_path),
            "--output-root",
            str(tmp_path / "outside-local-boundary"),
        ]
    )
    monkeypatch.setattr(
        runner.shutil,
        "which",
        lambda _: pytest.fail("output boundary must reject before Docker"),
    )

    assert runner._execute_command(options) == 1
    assert "output root must be the ignored local directory" in capsys.readouterr().err


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
        plan_digest="c" * 64,
        receipt_sha256="d" * 64,
        approval_metadata={
            "decision": "approved",
            "approver": "benchmark-owner",
            "approved_at": "2026-08-31T12:00:00+00:00",
            "scope": "execute",
        },
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
    assert envelope["plan_digest"] == "c" * 64
    assert envelope["receipt_sha256"] == "d" * 64
    assert envelope["approval"] == {
        "decision": "approved",
        "approver": "benchmark-owner",
        "approved_at": "2026-08-31T12:00:00+00:00",
        "scope": "execute",
    }
    assert envelope["stdout_sha256"]
    assert envelope["stderr_sha256"]
    assert envelope["network_attempts"] is None
    assert envelope["network_observation"] == "blocked_not_observed"
    assert envelope["normalized_findings"] == []
    assert "stdout" not in envelope
    assert "stderr" not in envelope


def test_docker_plan_uses_cidfile_and_bounded_tmpfs_scratch(tmp_path: Path) -> None:
    runner = _load_runner()
    plan = _plan(tmp_path / "clones", tmp_path / "fixtures")
    plan["scratch_mb"] = 64
    cidfile = tmp_path / "container.cid"

    argv = runner.build_docker_argv(
        plan,
        cidfile=cidfile,
        source_path=tmp_path / "staged-source",
        fixture_path=tmp_path / "staged-fixture",
    )

    assert "--rm" not in argv
    assert argv[argv.index("--cidfile") + 1] == str(cidfile)
    assert "/scratch:rw,noexec,nosuid,nodev,size=64m" in argv
    assert not any(value.endswith(":/scratch:rw") for value in argv)


def test_timeout_cleanup_kills_removes_and_verifies_container_in_order(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner = _load_runner()
    cidfile = tmp_path / "container.cid"
    cidfile.write_text("a" * 64 + "\n", encoding="ascii")
    calls: list[list[str]] = []

    def run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    monkeypatch.setattr(runner.subprocess, "run", run)

    runner._cleanup_container(cidfile, timed_out=True)

    assert [call[1] for call in calls] == ["kill", "rm", "container"]
    assert calls[-1] == [
        "docker",
        "container",
        "ls",
        "-a",
        "--no-trunc",
        "--filter",
        f"id={'a' * 64}",
        "--format",
        "{{.ID}}",
    ]


def test_timeout_cleanup_fails_closed_when_daemon_query_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner = _load_runner()
    cidfile = tmp_path / "container.cid"
    cidfile.write_text("e" * 64, encoding="ascii")

    def run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        if argv[1] == "container":
            return subprocess.CompletedProcess(argv, 1, b"", b"daemon unavailable")
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    monkeypatch.setattr(runner.subprocess, "run", run)

    with pytest.raises(runner.BenchmarkCleanupError, match="absence query failed"):
        runner._cleanup_container(cidfile, timed_out=True)


def test_timeout_cleanup_fails_closed_when_daemon_container_remains(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner = _load_runner()
    cidfile = tmp_path / "container.cid"
    cidfile.write_text("b" * 64, encoding="ascii")
    calls: list[list[str]] = []

    def run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        calls.append(argv)
        stdout = ("b" * 64 + "\n").encode("ascii") if argv[1] == "container" else b""
        return subprocess.CompletedProcess(argv, 0, stdout, b"")

    monkeypatch.setattr(runner.subprocess, "run", run)

    with pytest.raises(runner.BenchmarkCleanupError, match="still exists"):
        runner._cleanup_container(cidfile, timed_out=True)
    assert calls[-1][1:3] == ["container", "ls"]


def test_timeout_cleanup_still_removes_and_queries_after_kill_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner = _load_runner()
    cidfile = tmp_path / "container.cid"
    cidfile.write_text("c" * 64, encoding="ascii")
    calls: list[str] = []

    def run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        calls.append(argv[1])
        return subprocess.CompletedProcess(argv, 1 if argv[1] == "kill" else 0, b"", b"")

    monkeypatch.setattr(runner.subprocess, "run", run)

    runner._cleanup_container(cidfile, timed_out=True)

    assert calls == ["kill", "rm", "container"]


def test_timeout_cleanup_queries_after_remove_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner = _load_runner()
    cidfile = tmp_path / "container.cid"
    cidfile.write_text("d" * 64, encoding="ascii")
    calls: list[str] = []

    def run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        calls.append(argv[1])
        return subprocess.CompletedProcess(argv, 1 if argv[1] == "rm" else 0, b"", b"")

    monkeypatch.setattr(runner.subprocess, "run", run)

    with pytest.raises(runner.BenchmarkCleanupError, match="removal command failed"):
        runner._cleanup_container(cidfile, timed_out=True)

    assert calls == ["kill", "rm", "container"]


def test_timeout_cleanup_fails_closed_when_cidfile_is_missing(tmp_path: Path) -> None:
    runner = _load_runner()

    with pytest.raises(runner.BenchmarkCleanupError, match="container ID"):
        runner._cleanup_container(tmp_path / "missing.cid", timed_out=True)


def test_write_inventory_enforces_total_byte_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner = _load_runner()
    (tmp_path / "first.bin").write_bytes(b"a" * 8)
    (tmp_path / "second.bin").write_bytes(b"b" * 8)
    monkeypatch.setattr(runner, "MAX_TREE_TOTAL_BYTES", 10)

    with pytest.raises(runner.TreeEvidenceError, match="total byte limit"):
        runner._inventory_files(tmp_path)


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

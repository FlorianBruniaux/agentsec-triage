#!/usr/bin/env python3
"""Validate and run an approved competitor benchmark inside a locked container."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import BinaryIO, cast

PROJECT_ROOT = Path(__file__).parents[1]
DEFAULT_PROJECT_INDEX = PROJECT_ROOT / "data" / "competitive-projects.yaml"
DEFAULT_FIXTURE_MANIFEST = PROJECT_ROOT / "research" / "competitive-fixtures" / "manifest.yaml"
DEFAULT_CLONE_ROOT = Path("/Users/florianbruniaux/Sites/divers-test/agent-security-ecosystem")
DEFAULT_FIXTURE_ROOT = DEFAULT_FIXTURE_MANIFEST.parent
DEFAULT_OUTPUT_ROOT = PROJECT_ROOT / "research" / "competitive-runs" / "local"

PLAN_FIELDS = frozenset(
    {
        "schema_version",
        "project_id",
        "revision",
        "fixture_id",
        "image",
        "source_path",
        "fixture_path",
        "source_mount",
        "fixture_mount",
        "command",
        "network",
        "timeout_seconds",
        "memory_mb",
        "pids_limit",
        "cpus",
        "output_limit_bytes",
    }
)
NETWORK_FIELDS = frozenset({"mode", "allowlist", "approved"})
REGISTRY_IMAGE_DIGEST = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._/-]*@sha256:[0-9a-f]{64}$"
)
LOCAL_IMAGE_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
REVISION = re.compile(r"^[0-9a-f]{12}$")
DESTINATION = re.compile(r"^[A-Za-z0-9.-]+:[1-9][0-9]{0,4}$")
SECRET_PATTERNS = (
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
)
MAX_TIMEOUT_SECONDS = 300
MAX_OUTPUT_LIMIT_BYTES = 10_000_000


def _load_json(path: Path, label: str) -> dict[str, object]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"{label}: {error}") from error
    if not isinstance(payload, dict):
        raise ValueError(f"{label}: expected a JSON object")
    return cast(dict[str, object], payload)


def _required_string(plan: dict[str, object], field: str, errors: list[str]) -> str | None:
    if field not in plan:
        errors.append(f"{field}: missing required field")
        return None
    value = plan[field]
    if not isinstance(value, str) or not value:
        errors.append(f"{field}: expected a non-empty string")
        return None
    return value


def _required_number(
    plan: dict[str, object],
    field: str,
    errors: list[str],
    *,
    minimum: float,
    maximum: float,
) -> float | None:
    if field not in plan:
        errors.append(f"{field}: missing required field")
        return None
    value = plan[field]
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        errors.append(f"{field}: expected a number")
        return None
    result = float(value)
    if result < minimum or result > maximum:
        errors.append(f"{field}: expected a value from {minimum:g} to {maximum:g}")
        return None
    return result


def _indexed_by_id(payload: dict[str, object], field: str) -> dict[str, dict[str, object]]:
    values = payload.get(field)
    if not isinstance(values, list):
        return {}
    result: dict[str, dict[str, object]] = {}
    for value in values:
        if isinstance(value, dict) and isinstance(value.get("id"), str):
            item = cast(dict[str, object], value)
            result[cast(str, item["id"])] = item
    return result


def _validate_network(value: object, errors: list[str]) -> dict[str, object] | None:
    if not isinstance(value, dict):
        errors.append("network: expected an object")
        return None
    network = cast(dict[str, object], value)
    for field in sorted(set(network) - NETWORK_FIELDS):
        errors.append(f"network.{field}: unknown field")
    if set(network) != NETWORK_FIELDS:
        for field in sorted(NETWORK_FIELDS - set(network)):
            errors.append(f"network.{field}: missing required field")
        return network

    mode = network.get("mode")
    allowlist = network.get("allowlist")
    approved = network.get("approved")
    if mode not in {"none", "allowlist"}:
        errors.append("network.mode: expected 'none' or 'allowlist'")
    if not isinstance(allowlist, list) or not all(
        isinstance(item, str) and DESTINATION.fullmatch(item) for item in allowlist
    ):
        errors.append("network.allowlist: expected host:port strings")
    if not isinstance(approved, bool):
        errors.append("network.approved: expected a boolean")
    if mode == "none" and allowlist:
        errors.append("network: disabled network cannot have an allowlist")
    if mode == "allowlist" and approved is not True:
        errors.append("network: non-disabled network requires explicit approval")
    if mode == "allowlist" and approved is True:
        errors.append("network: allowlist enforcement backend is not implemented")
    return network


def validate_plan(
    plan: dict[str, object],
    project_index: dict[str, object],
    fixture_manifest: dict[str, object],
    clone_root: Path,
    fixture_root: Path,
) -> list[str]:
    errors: list[str] = []
    for field in sorted(set(plan) - PLAN_FIELDS):
        errors.append(f"{field}: unknown field")
    if plan.get("schema_version") != "1":
        errors.append("schema_version: expected '1'")

    project_id = _required_string(plan, "project_id", errors)
    revision = _required_string(plan, "revision", errors)
    fixture_id = _required_string(plan, "fixture_id", errors)
    image = _required_string(plan, "image", errors)
    source_path = _required_string(plan, "source_path", errors)
    fixture_path = _required_string(plan, "fixture_path", errors)

    projects = _indexed_by_id(project_index, "projects")
    project = projects.get(project_id or "")
    if project_id is not None and project is None:
        errors.append(f"project_id: unknown project '{project_id}'")
    if revision is not None:
        if not REVISION.fullmatch(revision):
            errors.append("revision: expected 12 lowercase hexadecimal characters")
        elif project is not None and revision != project.get("revision"):
            errors.append("revision: does not match pinned project revision")
    if project is not None and project.get("execution_tier") != "offline_sandbox":
        errors.append("project_id: project is not approved for offline_sandbox execution")

    fixtures = _indexed_by_id(fixture_manifest, "fixtures")
    fixture = fixtures.get(fixture_id or "")
    if fixture_id is not None and fixture is None:
        errors.append(f"fixture_id: unknown fixture '{fixture_id}'")
    elif fixture is not None and fixture.get("inert") is not True:
        errors.append("fixture_id: fixture is not marked inert")

    if image is not None and not (
        REGISTRY_IMAGE_DIGEST.fullmatch(image) or LOCAL_IMAGE_ID.fullmatch(image)
    ):
        errors.append("image: expected a registry digest or local sha256 image ID")

    if source_path is not None and project is not None:
        expected_source = (clone_root / str(project.get("local_directory"))).resolve()
        try:
            actual_source = Path(source_path).resolve(strict=True)
        except OSError:
            actual_source = None
        if actual_source != expected_source or not expected_source.is_dir():
            errors.append("source_path: expected the pinned clone directory")
    if fixture_path is not None and fixture is not None:
        expected_fixture = (fixture_root / str(fixture.get("directory"))).resolve()
        try:
            actual_fixture = Path(fixture_path).resolve(strict=True)
        except OSError:
            actual_fixture = None
        if actual_fixture != expected_fixture or not expected_fixture.is_dir():
            errors.append("fixture_path: expected the declared fixture directory")

    if plan.get("source_mount") != "ro":
        errors.append("source_mount: expected 'ro'")
    if plan.get("fixture_mount") != "ro":
        errors.append("fixture_mount: expected 'ro'")

    command = plan.get("command")
    if (
        not isinstance(command, list)
        or not command
        or not all(
            isinstance(argument, str) and argument and "\x00" not in argument
            for argument in command
        )
    ):
        errors.append("command: expected a non-empty argument array")

    _validate_network(plan.get("network"), errors)
    _required_number(
        plan,
        "timeout_seconds",
        errors,
        minimum=1,
        maximum=MAX_TIMEOUT_SECONDS,
    )
    _required_number(plan, "memory_mb", errors, minimum=64, maximum=4096)
    _required_number(plan, "pids_limit", errors, minimum=16, maximum=512)
    _required_number(plan, "cpus", errors, minimum=0.25, maximum=2)
    _required_number(
        plan,
        "output_limit_bytes",
        errors,
        minimum=1024,
        maximum=MAX_OUTPUT_LIMIT_BYTES,
    )
    return errors


def approval_digest(plan: dict[str, object]) -> str:
    canonical = json.dumps(plan, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def build_docker_argv(plan: dict[str, object], scratch_path: Path) -> list[str]:
    source_path = str(plan["source_path"])
    fixture_path = str(plan["fixture_path"])
    memory_mb = int(cast(int | float, plan["memory_mb"]))
    pids_limit = int(cast(int | float, plan["pids_limit"]))
    cpus = float(cast(int | float, plan["cpus"]))
    network = cast(dict[str, object], plan["network"])
    network_mode = cast(str, network["mode"])
    if network_mode != "none":
        raise ValueError("network allowlist execution is not implemented")
    return [
        "docker",
        "run",
        "--rm",
        "--pull=never",
        "--init",
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        str(pids_limit),
        "--memory",
        f"{memory_mb}m",
        "--cpus",
        f"{cpus:g}",
        "--user",
        "65532:65532",
        "--tmpfs",
        "/home/runner:rw,noexec,nosuid,nodev,size=16m",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,nodev,size=32m",
        "-e",
        "HOME=/home/runner",
        "-e",
        "XDG_CONFIG_HOME=/home/runner/.config",
        "-e",
        "XDG_CACHE_HOME=/home/runner/.cache",
        "-e",
        "CI=1",
        "-e",
        "NO_COLOR=1",
        "-v",
        f"{source_path}:/competitor:ro",
        "-v",
        f"{fixture_path}:/fixture:ro",
        "-v",
        f"{scratch_path}:/scratch:rw",
        "-w",
        "/scratch",
        cast(str, plan["image"]),
        *cast(list[str], plan["command"]),
    ]


def redact_output(text: str, sensitive_paths: Sequence[Path]) -> str:
    redacted = text
    paths = {
        Path.home(),
        Path.home().resolve(),
        *sensitive_paths,
        *(path.resolve() for path in sensitive_paths),
    }
    for path in sorted(paths, key=lambda value: len(str(value)), reverse=True):
        redacted = redacted.replace(str(path), "[REDACTED_PATH]")
    for pattern in SECRET_PATTERNS:
        redacted = pattern.sub("[REDACTED_SECRET]", redacted)
    return redacted


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def build_result_envelope(
    *,
    project_id: str,
    revision: str,
    fixture_id: str,
    argument_vector: list[str],
    image: str,
    network_policy: dict[str, object],
    exit_code: int,
    timed_out: bool,
    duration_seconds: float,
    maximum_rss_kb: int | None,
    stdout: bytes,
    stderr: bytes,
    stdout_truncated: bool,
    stderr_truncated: bool,
    files_written: list[dict[str, object]],
) -> dict[str, object]:
    network_mode = network_policy.get("mode")
    return {
        "schema_version": "1",
        "recorded_at": datetime.now(UTC).isoformat(),
        "project_id": project_id,
        "revision": revision,
        "fixture_id": fixture_id,
        "argument_vector": argument_vector,
        "image": image,
        "network_policy": network_policy,
        "network_attempts": None,
        "network_observation": (
            "blocked_not_observed" if network_mode == "none" else "not_measured"
        ),
        "exit_code": exit_code,
        "timed_out": timed_out,
        "duration_seconds": round(duration_seconds, 6),
        "maximum_rss_kb": maximum_rss_kb,
        "stdout_sha256": _sha256(stdout),
        "stderr_sha256": _sha256(stderr),
        "stdout_bytes_captured": len(stdout),
        "stderr_bytes_captured": len(stderr),
        "stdout_truncated": stdout_truncated,
        "stderr_truncated": stderr_truncated,
        "normalized_findings": [],
        "normalization_status": "not_configured",
        "files_written": files_written,
    }


def _drain_bounded(stream: BinaryIO, limit: int) -> tuple[bytes, bool]:
    output = bytearray()
    truncated = False
    while True:
        chunk = stream.read(65_536)
        if not chunk:
            break
        remaining = limit - len(output)
        if remaining > 0:
            output.extend(chunk[:remaining])
        if len(chunk) > remaining:
            truncated = True
    return bytes(output), truncated


def _capture_process(
    argv: Sequence[str], timeout_seconds: float, output_limit: int
) -> tuple[int, bool, float, bytes, bytes, bool, bool]:
    started = time.monotonic()
    process = subprocess.Popen(
        list(argv),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
        close_fds=True,
    )
    assert process.stdout is not None
    assert process.stderr is not None
    captures: dict[str, tuple[bytes, bool]] = {}

    def drain(label: str, stream: BinaryIO) -> None:
        captures[label] = _drain_bounded(stream, output_limit)

    stdout_thread = threading.Thread(target=drain, args=("stdout", process.stdout))
    stderr_thread = threading.Thread(target=drain, args=("stderr", process.stderr))
    stdout_thread.start()
    stderr_thread.start()
    timed_out = False
    try:
        exit_code = process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        process.kill()
        process.wait()
        exit_code = 124
    stdout_thread.join()
    stderr_thread.join()
    duration = time.monotonic() - started
    stdout, stdout_truncated = captures["stdout"]
    stderr, stderr_truncated = captures["stderr"]
    return (
        exit_code,
        timed_out,
        duration,
        stdout,
        stderr,
        stdout_truncated,
        stderr_truncated,
    )


def _inventory_files(root: Path) -> list[dict[str, object]]:
    files: list[dict[str, object]] = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            files.append(
                {
                    "path": path.relative_to(root).as_posix(),
                    "type": "symlink",
                    "target": os.readlink(path),
                }
            )
        elif path.is_file():
            content = path.read_bytes()
            files.append(
                {
                    "path": path.relative_to(root).as_posix(),
                    "type": "file",
                    "bytes": len(content),
                    "sha256": _sha256(content),
                }
            )
    return files


def _validate_command(options: argparse.Namespace) -> int:
    try:
        plan = _load_json(options.plan, "benchmark plan")
        project_index = _load_json(options.project_index, "competitive project index")
        fixture_manifest = _load_json(options.fixture_manifest, "fixture manifest")
    except ValueError as error:
        print(error, file=sys.stderr)
        return 1
    errors = validate_plan(
        plan,
        project_index,
        fixture_manifest,
        options.clone_root.resolve(),
        options.fixture_root.resolve(),
    )
    for validation_error in errors:
        print(f"competitive benchmark: {validation_error}", file=sys.stderr)
    if errors:
        return 1
    preview_scratch = Path("/tmp/agentsec-competitive-scratch-preview")
    print(
        json.dumps(
            {
                "approval_digest": approval_digest(plan),
                "docker_argv": build_docker_argv(plan, preview_scratch),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def _execute_command(options: argparse.Namespace) -> int:
    try:
        plan = _load_json(options.plan, "benchmark plan")
        project_index = _load_json(options.project_index, "competitive project index")
        fixture_manifest = _load_json(options.fixture_manifest, "fixture manifest")
    except ValueError as error:
        print(error, file=sys.stderr)
        return 1
    errors = validate_plan(
        plan,
        project_index,
        fixture_manifest,
        options.clone_root.resolve(),
        options.fixture_root.resolve(),
    )
    for validation_error in errors:
        print(f"competitive benchmark: {validation_error}", file=sys.stderr)
    if errors:
        return 1
    digest = approval_digest(plan)
    if options.approval_digest != digest:
        print("competitive benchmark: approval digest does not match exact plan", file=sys.stderr)
        return 1
    if shutil.which("docker") is None:
        print("competitive benchmark: docker executable not found", file=sys.stderr)
        return 1

    output_root = options.output_root.resolve()
    expected_output_root = DEFAULT_OUTPUT_ROOT.resolve()
    if output_root != expected_output_root:
        print(
            "competitive benchmark: output root must be the ignored local directory",
            file=sys.stderr,
        )
        return 1
    output_root.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="agentsec-competitive-") as temporary:
        scratch = Path(temporary)
        scratch.chmod(0o777)
        argv = build_docker_argv(plan, scratch)
        (
            exit_code,
            timed_out,
            duration,
            stdout,
            stderr,
            stdout_truncated,
            stderr_truncated,
        ) = _capture_process(
            argv,
            float(cast(int | float, plan["timeout_seconds"])),
            int(cast(int | float, plan["output_limit_bytes"])),
        )
        files_written = _inventory_files(scratch)

    envelope = build_result_envelope(
        project_id=cast(str, plan["project_id"]),
        revision=cast(str, plan["revision"]),
        fixture_id=cast(str, plan["fixture_id"]),
        argument_vector=cast(list[str], plan["command"]),
        image=cast(str, plan["image"]),
        network_policy=cast(dict[str, object], plan["network"]),
        exit_code=exit_code,
        timed_out=timed_out,
        duration_seconds=duration,
        maximum_rss_kb=None,
        stdout=stdout,
        stderr=stderr,
        stdout_truncated=stdout_truncated,
        stderr_truncated=stderr_truncated,
        files_written=files_written,
    )
    run_id = (
        f"{plan['project_id']}-{plan['fixture_id']}-"
        f"{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}-{digest[:12]}"
    )
    (output_root / f"{run_id}.stdout").write_bytes(stdout)
    (output_root / f"{run_id}.stderr").write_bytes(stderr)
    with (output_root / "runs.jsonl").open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(envelope, sort_keys=True) + "\n")
    print(json.dumps(envelope, indent=2, sort_keys=True))
    return exit_code


def _self_test() -> int:
    marker_path = Path(tempfile.gettempdir()) / "agentsec-self-test-sensitive"
    raw = f"{marker_path}/file ghp_abcdefghijklmnopqrstuvwxyz123456"
    redacted = redact_output(raw, [marker_path])
    with tempfile.TemporaryDirectory(prefix="agentsec-runner-self-test-") as temporary:
        scratch = Path(temporary)
        (scratch / "marker.txt").write_text("INERT\n", encoding="utf-8")
        files = _inventory_files(scratch)
    result = _capture_process(
        [sys.executable, "-c", "print('SELF_TEST_OK:' + 'x' * 4096)"],
        timeout_seconds=5,
        output_limit=64,
    )
    _, timed_out, _, stdout, _, stdout_truncated, _ = result
    passed = (
        not timed_out
        and stdout.startswith(b"SELF_TEST_OK:")
        and stdout_truncated
        and str(marker_path) not in redacted
        and "ghp_" not in redacted
        and len(files) == 1
    )
    print(
        json.dumps(
            {
                "status": "passed" if passed else "failed",
                "shell": False,
                "network_policy": "none",
                "redaction": str(marker_path) not in redacted and "ghp_" not in redacted,
                "bounded_capture": stdout_truncated and len(stdout) == 64,
                "write_inventory": len(files) == 1,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0 if passed else 1


def _add_common_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--project-index", type=Path, default=DEFAULT_PROJECT_INDEX)
    parser.add_argument("--fixture-manifest", type=Path, default=DEFAULT_FIXTURE_MANIFEST)
    parser.add_argument("--clone-root", type=Path, default=DEFAULT_CLONE_ROOT)
    parser.add_argument("--fixture-root", type=Path, default=DEFAULT_FIXTURE_ROOT)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="subcommand", required=True)
    validate = commands.add_parser("validate", help="Validate and print the exact container plan")
    _add_common_options(validate)
    execute = commands.add_parser("execute", help="Execute an approved exact plan")
    _add_common_options(execute)
    execute.add_argument("--approval-digest", required=True)
    execute.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT_ROOT)
    commands.add_parser("self-test", help="Exercise local runner primitives without a competitor")
    return parser


def main(arguments: Sequence[str] | None = None) -> int:
    options = _parser().parse_args(arguments)
    if options.subcommand == "validate":
        return _validate_command(options)
    if options.subcommand == "execute":
        return _execute_command(options)
    return _self_test()


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Validate and run a receipt-gated competitor benchmark inside a locked container."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
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
DEFAULT_BLUEPRINTS = PROJECT_ROOT / "research" / "competitive-runs" / "plan-blueprints.v1.json"
DEFAULT_PLAN_ROOT = DEFAULT_OUTPUT_ROOT / "plans"

PLAN_FIELDS = frozenset(
    {
        "schema_version",
        "project_id",
        "revision",
        "source_commit",
        "fixture_id",
        "image",
        "source_path",
        "fixture_path",
        "source_tree",
        "fixture_tree",
        "source_mount",
        "fixture_mount",
        "command",
        "network",
        "timeout_seconds",
        "memory_mb",
        "pids_limit",
        "cpus",
        "output_limit_bytes",
        "scratch_mb",
    }
)
NETWORK_FIELDS = frozenset({"mode", "allowlist", "approved"})
TREE_EVIDENCE_FIELDS = frozenset({"sha256", "file_count", "total_bytes"})
BLUEPRINT_FIELDS = frozenset(
    {
        "project_id",
        "fixture_id",
        "image",
        "command",
        "network",
        "timeout_seconds",
        "memory_mb",
        "pids_limit",
        "cpus",
        "output_limit_bytes",
        "scratch_mb",
    }
)
APPROVAL_RECEIPT_FIELDS = frozenset(
    {
        "schema_version",
        "decision",
        "approver",
        "approved_at",
        "scope",
        "plan_digest",
        "statement",
    }
)
REGISTRY_IMAGE_DIGEST = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._/-]*@sha256:[0-9a-f]{64}$"
)
LOCAL_IMAGE_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
REVISION = re.compile(r"^[0-9a-f]{12}$")
FULL_COMMIT = re.compile(r"^[0-9a-f]{40}$")
SAFE_PLAN_ID = re.compile(r"^[a-z0-9][a-z0-9-]*$")
DESTINATION = re.compile(r"^[A-Za-z0-9.-]+:[1-9][0-9]{0,4}$")
SECRET_PATTERNS = (
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
)
MAX_TIMEOUT_SECONDS = 300
MAX_OUTPUT_LIMIT_BYTES = 10_000_000
RESOURCE_NUMBER_FIELDS = frozenset(
    {
        "timeout_seconds",
        "memory_mb",
        "pids_limit",
        "cpus",
        "output_limit_bytes",
        "scratch_mb",
    }
)
SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
CONTAINER_ID = re.compile(r"^[0-9a-f]{64}$")
DOCKER_CONTROL_TIMEOUT_SECONDS = 10
GIT_CONTROL_TIMEOUT_SECONDS = 30
MAX_TREE_FILES = 100_000
MAX_TREE_FILE_BYTES = 64 * 1024 * 1024
MAX_TREE_TOTAL_BYTES = 512 * 1024 * 1024
HASH_CHUNK_BYTES = 64 * 1024


class BenchmarkCleanupError(RuntimeError):
    """Raised when daemon-side container teardown cannot be proven."""


class TreeEvidenceError(ValueError):
    """Raised when a mounted tree cannot be represented within strict limits."""


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
    if not math.isfinite(result):
        errors.append(f"{field}: expected a finite number")
        return None
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


def _canonical_sha256(value: object) -> str:
    canonical = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _stream_file_sha256(path: Path, expected_size: int) -> str:
    if expected_size > MAX_TREE_FILE_BYTES:
        raise TreeEvidenceError(f"{path}: exceeds per-file byte limit")
    digest = hashlib.sha256()
    observed = 0
    try:
        with path.open("rb") as stream:
            before = os.fstat(stream.fileno())
            while True:
                chunk = stream.read(HASH_CHUNK_BYTES)
                if not chunk:
                    break
                observed += len(chunk)
                if observed > MAX_TREE_FILE_BYTES:
                    raise TreeEvidenceError(f"{path}: exceeds per-file byte limit")
                digest.update(chunk)
            after = os.fstat(stream.fileno())
    except OSError as error:
        raise TreeEvidenceError(f"{path}: unable to read tree entry") from error
    if (
        observed != expected_size
        or before.st_size != after.st_size
        or before.st_mtime_ns != after.st_mtime_ns
        or before.st_ino != after.st_ino
    ):
        raise TreeEvidenceError(f"{path}: changed while hashing")
    return digest.hexdigest()


def build_tree_evidence(root: Path) -> dict[str, object]:
    """Hash a confined tree without following links or buffering file contents."""
    try:
        resolved_root = root.resolve(strict=True)
    except OSError as error:
        raise TreeEvidenceError(f"{root}: tree root is unavailable") from error
    if not resolved_root.is_dir():
        raise TreeEvidenceError(f"{root}: tree root is not a directory")

    entries: list[dict[str, object]] = []
    total_bytes = 0
    stack: list[tuple[Path, str]] = [(resolved_root, "")]
    while stack:
        directory, prefix = stack.pop()
        try:
            children = sorted(os.scandir(directory), key=lambda child: child.name)
        except OSError as error:
            raise TreeEvidenceError(f"{directory}: unable to enumerate tree") from error
        for child in reversed(children):
            relative = f"{prefix}/{child.name}" if prefix else child.name
            if "\x00" in relative:
                raise TreeEvidenceError("tree entry contains a NUL byte")
            try:
                metadata = child.stat(follow_symlinks=False)
            except OSError as error:
                raise TreeEvidenceError(f"{relative}: unable to inspect tree entry") from error
            mode = stat.S_IMODE(metadata.st_mode)
            child_path = Path(child.path)
            if stat.S_ISDIR(metadata.st_mode):
                entries.append({"mode": mode, "path": relative, "type": "directory"})
                stack.append((child_path, relative))
            elif stat.S_ISLNK(metadata.st_mode):
                try:
                    target = os.readlink(child_path)
                except OSError as error:
                    raise TreeEvidenceError(f"{relative}: unable to read symlink") from error
                entries.append(
                    {"mode": mode, "path": relative, "target": target, "type": "symlink"}
                )
            elif stat.S_ISREG(metadata.st_mode):
                total_bytes += metadata.st_size
                if total_bytes > MAX_TREE_TOTAL_BYTES:
                    raise TreeEvidenceError("tree exceeds total byte limit")
                entries.append(
                    {
                        "bytes": metadata.st_size,
                        "mode": mode,
                        "path": relative,
                        "sha256": _stream_file_sha256(child_path, metadata.st_size),
                        "type": "file",
                    }
                )
            else:
                raise TreeEvidenceError(f"{relative}: unsupported tree entry type")
            if len(entries) > MAX_TREE_FILES:
                raise TreeEvidenceError("tree exceeds entry count limit")
    entries.sort(key=lambda entry: cast(str, entry["path"]))
    return {
        "file_count": len(entries),
        "sha256": _canonical_sha256(entries),
        "total_bytes": total_bytes,
    }


def _git_stdout(source: Path, *arguments: str) -> bytes:
    try:
        result = subprocess.run(
            ["git", "-C", str(source), *arguments],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            shell=False,
            check=False,
            timeout=GIT_CONTROL_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise TreeEvidenceError("unable to inspect pinned Git source") from error
    if result.returncode != 0:
        raise TreeEvidenceError("unable to inspect pinned Git source")
    return result.stdout


def resolve_source_commit(source: Path, revision: str) -> str:
    try:
        resolved_source = source.resolve(strict=True)
    except OSError as error:
        raise TreeEvidenceError("pinned Git source is unavailable") from error
    if not resolved_source.is_dir():
        raise TreeEvidenceError("pinned Git source is not a directory")
    head = _git_stdout(resolved_source, "rev-parse", "--verify", "HEAD^{commit}").decode(
        "ascii"
    ).strip()
    pinned = _git_stdout(
        resolved_source, "rev-parse", "--verify", f"{revision}^{{commit}}"
    ).decode("ascii").strip()
    if not FULL_COMMIT.fullmatch(head) or not FULL_COMMIT.fullmatch(pinned):
        raise TreeEvidenceError("Git source did not resolve to a full commit")
    if head != pinned:
        raise TreeEvidenceError("Git HEAD does not match the pinned revision")
    return head


def materialize_committed_source(source: Path, full_commit: str, destination: Path) -> None:
    if not FULL_COMMIT.fullmatch(full_commit):
        raise TreeEvidenceError("source commit must be 40 lowercase hexadecimal characters")
    destination.mkdir(parents=True, exist_ok=False)
    archive_path = destination.parent / ".source.tar"
    try:
        with archive_path.open("xb") as archive_stream:
            archived = subprocess.run(
                ["git", "-C", str(source), "archive", "--format=tar", full_commit],
                stdin=subprocess.DEVNULL,
                stdout=archive_stream,
                stderr=subprocess.PIPE,
                shell=False,
                check=False,
                timeout=GIT_CONTROL_TIMEOUT_SECONDS,
            )
        if archived.returncode != 0:
            raise TreeEvidenceError("unable to archive pinned Git source")
        if archive_path.stat().st_size > MAX_TREE_TOTAL_BYTES + 64 * 1024 * 1024:
            raise TreeEvidenceError("Git archive exceeds byte limit")
        entry_count = 0
        total_bytes = 0
        with tarfile.open(archive_path, mode="r:") as archive:
            for member in archive:
                entry_count += 1
                if entry_count > MAX_TREE_FILES:
                    raise TreeEvidenceError("Git tree exceeds entry count limit")
                relative = Path(member.name)
                if (
                    not member.name
                    or relative.is_absolute()
                    or ".." in relative.parts
                    or "\\" in member.name
                ):
                    raise TreeEvidenceError("Git archive contains an unsafe path")
                target = destination / relative
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                    target.chmod(stat.S_IMODE(member.mode))
                elif member.issym():
                    target.parent.mkdir(parents=True, exist_ok=True)
                    os.symlink(member.linkname, target)
                elif member.isfile():
                    if member.size > MAX_TREE_FILE_BYTES:
                        raise TreeEvidenceError("Git blob exceeds per-file byte limit")
                    total_bytes += member.size
                    if total_bytes > MAX_TREE_TOTAL_BYTES:
                        raise TreeEvidenceError("Git tree exceeds total byte limit")
                    source_stream = archive.extractfile(member)
                    if source_stream is None:
                        raise TreeEvidenceError("unable to read Git archive member")
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with source_stream, target.open("xb") as output_stream:
                        remaining = member.size
                        while remaining:
                            chunk = source_stream.read(min(HASH_CHUNK_BYTES, remaining))
                            if not chunk:
                                raise TreeEvidenceError("Git archive member was truncated")
                            output_stream.write(chunk)
                            remaining -= len(chunk)
                    target.chmod(stat.S_IMODE(member.mode))
                else:
                    raise TreeEvidenceError("Git archive contains an unsupported entry type")
    except (OSError, subprocess.TimeoutExpired, tarfile.TarError) as error:
        raise TreeEvidenceError("unable to materialize pinned Git source") from error
    finally:
        archive_path.unlink(missing_ok=True)


def build_committed_source_evidence(source: Path, full_commit: str) -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="agentsec-source-evidence-") as temporary:
        snapshot = Path(temporary) / "source"
        materialize_committed_source(source, full_commit, snapshot)
        return build_tree_evidence(snapshot)


def _copy_file_bounded(source: Path, destination: Path, expected_size: int) -> None:
    if expected_size > MAX_TREE_FILE_BYTES:
        raise TreeEvidenceError(f"{source}: exceeds per-file byte limit")
    observed = 0
    try:
        with source.open("rb") as input_stream, destination.open("xb") as output_stream:
            before = os.fstat(input_stream.fileno())
            while True:
                chunk = input_stream.read(HASH_CHUNK_BYTES)
                if not chunk:
                    break
                observed += len(chunk)
                if observed > MAX_TREE_FILE_BYTES:
                    raise TreeEvidenceError(f"{source}: exceeds per-file byte limit")
                output_stream.write(chunk)
            after = os.fstat(input_stream.fileno())
    except OSError as error:
        raise TreeEvidenceError(f"{source}: unable to copy tree entry") from error
    if (
        observed != expected_size
        or before.st_size != after.st_size
        or before.st_mtime_ns != after.st_mtime_ns
        or before.st_ino != after.st_ino
    ):
        raise TreeEvidenceError(f"{source}: changed while copying")


def copy_tree_snapshot(source: Path, destination: Path) -> None:
    try:
        source_root = source.resolve(strict=True)
    except OSError as error:
        raise TreeEvidenceError("fixture tree is unavailable") from error
    destination.mkdir(parents=True, exist_ok=False)
    total_bytes = 0
    entry_count = 0
    stack: list[tuple[Path, Path]] = [(source_root, destination)]
    while stack:
        source_directory, target_directory = stack.pop()
        try:
            children = sorted(os.scandir(source_directory), key=lambda child: child.name)
        except OSError as error:
            raise TreeEvidenceError("unable to enumerate fixture tree") from error
        for child in children:
            entry_count += 1
            if entry_count > MAX_TREE_FILES:
                raise TreeEvidenceError("tree exceeds entry count limit")
            metadata = child.stat(follow_symlinks=False)
            source_path = Path(child.path)
            target_path = target_directory / child.name
            mode = stat.S_IMODE(metadata.st_mode)
            if stat.S_ISDIR(metadata.st_mode):
                target_path.mkdir()
                target_path.chmod(mode)
                stack.append((source_path, target_path))
            elif stat.S_ISLNK(metadata.st_mode):
                os.symlink(os.readlink(source_path), target_path)
            elif stat.S_ISREG(metadata.st_mode):
                total_bytes += metadata.st_size
                if total_bytes > MAX_TREE_TOTAL_BYTES:
                    raise TreeEvidenceError("tree exceeds total byte limit")
                _copy_file_bounded(source_path, target_path, metadata.st_size)
                target_path.chmod(mode)
            else:
                raise TreeEvidenceError("fixture tree contains an unsupported entry type")


def prepare_runtime_inputs(plan: dict[str, object], runtime_root: Path) -> tuple[Path, Path]:
    source = Path(cast(str, plan["source_path"])).resolve(strict=True)
    fixture = Path(cast(str, plan["fixture_path"])).resolve(strict=True)
    full_commit = cast(str, plan["source_commit"])
    resolved_commit = resolve_source_commit(source, cast(str, plan["revision"]))
    if resolved_commit != full_commit:
        raise TreeEvidenceError("source commit changed after approval")
    source_snapshot = runtime_root / "source"
    fixture_snapshot = runtime_root / "fixture"
    materialize_committed_source(source, full_commit, source_snapshot)
    copy_tree_snapshot(fixture, fixture_snapshot)
    if build_tree_evidence(source_snapshot) != plan["source_tree"]:
        raise TreeEvidenceError("source content changed after approval")
    if build_tree_evidence(fixture_snapshot) != plan["fixture_tree"]:
        raise TreeEvidenceError("fixture content changed after approval")
    return source_snapshot, fixture_snapshot


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


def _validate_tree_evidence(
    value: object, field: str, errors: list[str]
) -> dict[str, object] | None:
    if not isinstance(value, dict):
        errors.append(f"{field}: expected an object")
        return None
    evidence = cast(dict[str, object], value)
    for unknown in sorted(set(evidence) - TREE_EVIDENCE_FIELDS):
        errors.append(f"{field}.{unknown}: unknown field")
    for missing in sorted(TREE_EVIDENCE_FIELDS - set(evidence)):
        errors.append(f"{field}.{missing}: missing required field")
    digest = evidence.get("sha256")
    if not isinstance(digest, str) or not SHA256_HEX.fullmatch(digest):
        errors.append(f"{field}.sha256: expected 64 lowercase hexadecimal characters")
    for number_field in ("file_count", "total_bytes"):
        number = evidence.get(number_field)
        if isinstance(number, bool) or not isinstance(number, int) or number < 0:
            errors.append(f"{field}.{number_field}: expected a non-negative integer")
    return evidence


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
    if plan.get("schema_version") != "2":
        errors.append("schema_version: expected '2'")

    project_id = _required_string(plan, "project_id", errors)
    revision = _required_string(plan, "revision", errors)
    source_commit = _required_string(plan, "source_commit", errors)
    fixture_id = _required_string(plan, "fixture_id", errors)
    image = _required_string(plan, "image", errors)
    source_path = _required_string(plan, "source_path", errors)
    fixture_path = _required_string(plan, "fixture_path", errors)
    source_tree = _validate_tree_evidence(plan.get("source_tree"), "source_tree", errors)
    fixture_tree = _validate_tree_evidence(plan.get("fixture_tree"), "fixture_tree", errors)

    projects = _indexed_by_id(project_index, "projects")
    project = projects.get(project_id or "")
    if project_id is not None and project is None:
        errors.append(f"project_id: unknown project '{project_id}'")
    if revision is not None:
        if not REVISION.fullmatch(revision):
            errors.append("revision: expected 12 lowercase hexadecimal characters")
        elif project is not None and revision != project.get("revision"):
            errors.append("revision: does not match pinned project revision")
    if source_commit is not None and not FULL_COMMIT.fullmatch(source_commit):
        errors.append("source_commit: expected 40 lowercase hexadecimal characters")
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

    actual_source: Path | None = None
    if source_path is not None and project is not None:
        expected_source = (clone_root / str(project.get("local_directory"))).resolve()
        try:
            actual_source = Path(source_path).resolve(strict=True)
        except OSError:
            actual_source = None
        if actual_source != expected_source or not expected_source.is_dir():
            errors.append("source_path: expected the pinned clone directory")
    actual_fixture: Path | None = None
    if fixture_path is not None and fixture is not None:
        expected_fixture = (fixture_root / str(fixture.get("directory"))).resolve()
        try:
            actual_fixture = Path(fixture_path).resolve(strict=True)
        except OSError:
            actual_fixture = None
        if actual_fixture != expected_fixture or not expected_fixture.is_dir():
            errors.append("fixture_path: expected the declared fixture directory")

    if (
        actual_source is not None
        and source_commit is not None
        and FULL_COMMIT.fullmatch(source_commit)
        and source_tree is not None
    ):
        try:
            resolved_commit = resolve_source_commit(actual_source, revision or "")
            observed_source = build_committed_source_evidence(actual_source, resolved_commit)
        except TreeEvidenceError as error:
            errors.append(f"source_tree: {error}")
        else:
            if resolved_commit != source_commit:
                errors.append("source_commit: does not match the pinned Git source")
            if observed_source != source_tree:
                errors.append("source_tree: content does not match the approved plan")
    if actual_fixture is not None and fixture_tree is not None:
        try:
            observed_fixture = build_tree_evidence(actual_fixture)
        except TreeEvidenceError as error:
            errors.append(f"fixture_tree: {error}")
        else:
            if observed_fixture != fixture_tree:
                errors.append("fixture_tree: content does not match the approved plan")

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
    _required_number(plan, "scratch_mb", errors, minimum=8, maximum=256)
    return errors


def build_plan_from_blueprint(
    blueprint: dict[str, object],
    project_index: dict[str, object],
    fixture_manifest: dict[str, object],
    clone_root: Path,
    fixture_root: Path,
) -> dict[str, object]:
    unknown = set(blueprint) - BLUEPRINT_FIELDS
    missing = BLUEPRINT_FIELDS - set(blueprint)
    if unknown or missing:
        details = []
        if unknown:
            details.append(f"unknown fields: {', '.join(sorted(unknown))}")
        if missing:
            details.append(f"missing fields: {', '.join(sorted(missing))}")
        raise ValueError("blueprint: " + "; ".join(details))
    project_id = blueprint.get("project_id")
    fixture_id = blueprint.get("fixture_id")
    if not isinstance(project_id, str) or not SAFE_PLAN_ID.fullmatch(project_id):
        raise ValueError("blueprint.project_id: expected a safe project ID")
    if not isinstance(fixture_id, str) or not SAFE_PLAN_ID.fullmatch(fixture_id):
        raise ValueError("blueprint.fixture_id: expected a safe fixture ID")
    project = _indexed_by_id(project_index, "projects").get(project_id)
    fixture = _indexed_by_id(fixture_manifest, "fixtures").get(fixture_id)
    if project is None:
        raise ValueError(f"blueprint.project_id: unknown project '{project_id}'")
    if fixture is None:
        raise ValueError(f"blueprint.fixture_id: unknown fixture '{fixture_id}'")
    revision = project.get("revision")
    if not isinstance(revision, str) or not REVISION.fullmatch(revision):
        raise ValueError("blueprint.project_id: project has no valid pinned revision")
    source = (clone_root / str(project.get("local_directory"))).resolve()
    fixture_path = (fixture_root / str(fixture.get("directory"))).resolve()
    try:
        full_commit = resolve_source_commit(source, revision)
        source_tree = build_committed_source_evidence(source, full_commit)
        fixture_tree = build_tree_evidence(fixture_path)
    except TreeEvidenceError as error:
        raise ValueError(f"blueprint: {error}") from error
    return {
        **blueprint,
        "schema_version": "2",
        "revision": revision,
        "source_commit": full_commit,
        "source_path": str(source),
        "fixture_path": str(fixture_path),
        "source_mount": "ro",
        "fixture_mount": "ro",
        "source_tree": source_tree,
        "fixture_tree": fixture_tree,
    }


def _generate_command(options: argparse.Namespace) -> int:
    try:
        blueprints = _load_json(options.blueprints, "benchmark blueprints")
        project_index = _load_json(options.project_index, "competitive project index")
        fixture_manifest = _load_json(options.fixture_manifest, "fixture manifest")
    except ValueError as error:
        print(error, file=sys.stderr)
        return 1
    if blueprints.get("schema_version") != "1":
        print("benchmark blueprints: schema_version must be '1'", file=sys.stderr)
        return 1
    raw_plans = blueprints.get("plans")
    if not isinstance(raw_plans, list) or not raw_plans:
        print("benchmark blueprints: plans must be a non-empty array", file=sys.stderr)
        return 1
    output_root = options.output_root.resolve()
    output_root.mkdir(parents=True, exist_ok=True)
    rendered: list[tuple[Path, bytes, str]] = []
    seen_names: set[str] = set()
    for index, raw_blueprint in enumerate(raw_plans):
        if not isinstance(raw_blueprint, dict):
            print(f"benchmark blueprints: plans[{index}] must be an object", file=sys.stderr)
            return 1
        try:
            plan = build_plan_from_blueprint(
                cast(dict[str, object], raw_blueprint),
                project_index,
                fixture_manifest,
                options.clone_root.resolve(),
                options.fixture_root.resolve(),
            )
        except ValueError as error:
            print(f"benchmark blueprints: plans[{index}]: {error}", file=sys.stderr)
            return 1
        errors = validate_plan(
            plan,
            project_index,
            fixture_manifest,
            options.clone_root.resolve(),
            options.fixture_root.resolve(),
        )
        if errors:
            for validation_error in errors:
                print(
                    f"benchmark blueprints: plans[{index}]: {validation_error}",
                    file=sys.stderr,
                )
            return 1
        name = f"{plan['project_id']}-{plan['fixture_id']}.json"
        if name in seen_names:
            print(f"benchmark blueprints: duplicate plan name '{name}'", file=sys.stderr)
            return 1
        seen_names.add(name)
        payload = (json.dumps(plan, indent=2, sort_keys=True) + "\n").encode("utf-8")
        rendered.append((output_root / name, payload, approval_digest(plan)))
    for path, payload, _ in rendered:
        temporary = path.with_name(f".{path.name}.tmp")
        temporary.write_bytes(payload)
        temporary.replace(path)
    print(
        json.dumps(
            {
                "plans": [
                    {"path": str(path), "approval_digest": digest}
                    for path, _, digest in rendered
                ],
                "status": "generated_not_approved",
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def normalize_plan(plan: dict[str, object]) -> dict[str, object]:
    """Return the digest representation without changing runtime semantics."""
    normalized = dict(plan)
    if "source_path" in normalized:
        normalized["source_path"] = "$VERIFIED_PINNED_CLONE"
    if "fixture_path" in normalized:
        normalized["fixture_path"] = "$VERIFIED_FIXTURE"
    for field in RESOURCE_NUMBER_FIELDS:
        value = normalized.get(field)
        if isinstance(value, float) and value.is_integer():
            normalized[field] = int(value)
    return normalized


def approval_digest(plan: dict[str, object]) -> str:
    canonical = json.dumps(
        normalize_plan(plan), sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def approval_statement(digest: str) -> str:
    return f"I approve execution of the exact benchmark plan with SHA-256 digest {digest}."


def validate_approval_receipt(receipt: dict[str, object], digest: str) -> list[str]:
    """Validate a procedural audit receipt without authenticating its author."""
    errors: list[str] = []
    for field in sorted(set(receipt) - APPROVAL_RECEIPT_FIELDS):
        errors.append(f"{field}: unknown field")
    for field in sorted(APPROVAL_RECEIPT_FIELDS - set(receipt)):
        errors.append(f"{field}: missing required field")
    if errors:
        return errors

    if receipt.get("schema_version") != "1":
        errors.append("schema_version: expected '1'")
    if receipt.get("decision") != "approved":
        errors.append("decision: expected 'approved'")
    if not isinstance(receipt.get("approver"), str) or not receipt["approver"]:
        errors.append("approver: expected a non-empty declared identity")
    approved_at = receipt.get("approved_at")
    if not isinstance(approved_at, str):
        errors.append("approved_at: expected an ISO 8601 timestamp with timezone")
    else:
        try:
            parsed = datetime.fromisoformat(approved_at.replace("Z", "+00:00"))
        except ValueError:
            errors.append("approved_at: expected an ISO 8601 timestamp with timezone")
        else:
            if parsed.tzinfo is None or parsed.utcoffset() is None:
                errors.append("approved_at: expected an ISO 8601 timestamp with timezone")
    if receipt.get("scope") != "execute":
        errors.append("scope: expected 'execute'")
    plan_digest = receipt.get("plan_digest")
    if not isinstance(plan_digest, str) or not SHA256_HEX.fullmatch(plan_digest):
        errors.append("plan_digest: expected 64 lowercase hexadecimal characters")
    elif plan_digest != digest:
        errors.append("plan_digest: does not match exact plan")
    if receipt.get("statement") != approval_statement(digest):
        errors.append("statement: does not bind the exact digest")
    return errors


def build_docker_argv(
    plan: dict[str, object],
    *,
    cidfile: Path,
    source_path: Path,
    fixture_path: Path,
) -> list[str]:
    memory_mb = int(cast(int | float, plan["memory_mb"]))
    pids_limit = int(cast(int | float, plan["pids_limit"]))
    cpus = float(cast(int | float, plan["cpus"]))
    scratch_mb = int(cast(int | float, plan["scratch_mb"]))
    network = cast(dict[str, object], plan["network"])
    network_mode = cast(str, network["mode"])
    if network_mode != "none":
        raise ValueError("network allowlist execution is not implemented")
    return [
        "docker",
        "run",
        "--cidfile",
        str(cidfile),
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
        "--tmpfs",
        f"/scratch:rw,noexec,nosuid,nodev,size={scratch_mb}m",
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
    plan_digest: str,
    receipt_sha256: str,
    approval_metadata: dict[str, object],
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
    files_written: list[dict[str, object]] | None,
) -> dict[str, object]:
    network_mode = network_policy.get("mode")
    return {
        "schema_version": "1",
        "recorded_at": datetime.now(UTC).isoformat(),
        "plan_digest": plan_digest,
        "receipt_sha256": receipt_sha256,
        "approval": approval_metadata,
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
        "scratch_write_observation": (
            "inventoried" if files_written is not None else "not_measured_ephemeral_tmpfs"
        ),
    }


def _read_container_id(cidfile: Path) -> str:
    try:
        value = cidfile.read_text(encoding="ascii").strip()
    except (OSError, UnicodeError) as error:
        raise BenchmarkCleanupError("container ID is unavailable for daemon cleanup") from error
    if not CONTAINER_ID.fullmatch(value):
        raise BenchmarkCleanupError("container ID is unavailable for daemon cleanup")
    return value


def _docker_control(arguments: list[str]) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(
            arguments,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            shell=False,
            check=False,
            timeout=DOCKER_CONTROL_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as error:
        raise BenchmarkCleanupError(
            f"bounded Docker cleanup timed out during {arguments[1]}"
        ) from error


def _cleanup_container(cidfile: Path, *, timed_out: bool) -> None:
    container_id = _read_container_id(cidfile)
    if timed_out:
        _docker_control(["docker", "kill", container_id])
    removed = _docker_control(["docker", "rm", "-f", container_id])
    remaining = _docker_control(
        [
            "docker",
            "container",
            "ls",
            "-a",
            "--no-trunc",
            "--filter",
            f"id={container_id}",
            "--format",
            "{{.ID}}",
        ]
    )
    if remaining.returncode != 0:
        raise BenchmarkCleanupError("Docker container absence query failed")
    if remaining.stdout.strip():
        raise BenchmarkCleanupError("Docker container still exists after cleanup")
    if removed.returncode != 0:
        raise BenchmarkCleanupError("Docker container removal command failed")


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


def _capture_docker_process(
    argv: Sequence[str], cidfile: Path, timeout_seconds: float, output_limit: int
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
        try:
            _cleanup_container(cidfile, timed_out=True)
        finally:
            try:
                process.wait(timeout=DOCKER_CONTROL_TIMEOUT_SECONDS)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        exit_code = 124
    else:
        if cidfile.exists():
            _cleanup_container(cidfile, timed_out=False)
    stdout_thread.join(timeout=DOCKER_CONTROL_TIMEOUT_SECONDS)
    stderr_thread.join(timeout=DOCKER_CONTROL_TIMEOUT_SECONDS)
    if stdout_thread.is_alive() or stderr_thread.is_alive():
        process.kill()
        raise BenchmarkCleanupError("Docker output streams did not close after cleanup")
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
    total_bytes = 0
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
            metadata = path.stat()
            total_bytes += metadata.st_size
            if total_bytes > MAX_TREE_TOTAL_BYTES:
                raise TreeEvidenceError("write inventory exceeds total byte limit")
            files.append(
                {
                    "path": path.relative_to(root).as_posix(),
                    "type": "file",
                    "bytes": metadata.st_size,
                    "sha256": _stream_file_sha256(path, metadata.st_size),
                }
            )
        if len(files) > MAX_TREE_FILES:
            raise TreeEvidenceError("write inventory exceeds entry count limit")
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
    preview_cidfile = Path("/tmp/agentsec-competitive-container-preview.cid")
    print(
        json.dumps(
            {
                "approval_digest": approval_digest(plan),
                "docker_argv": build_docker_argv(
                    plan,
                    cidfile=preview_cidfile,
                    source_path=Path(cast(str, plan["source_path"])),
                    fixture_path=Path(cast(str, plan["fixture_path"])),
                ),
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
    try:
        receipt_bytes = options.approval_receipt.read_bytes()
        if len(receipt_bytes) > 64 * 1024:
            raise ValueError("approval receipt: exceeds 65536 bytes")
        receipt_value = json.loads(receipt_bytes)
        if not isinstance(receipt_value, dict):
            raise ValueError("approval receipt: expected a JSON object")
        receipt = cast(dict[str, object], receipt_value)
    except (OSError, json.JSONDecodeError) as error:
        print(f"approval receipt: {error}", file=sys.stderr)
        return 1
    except ValueError as error:
        print(error, file=sys.stderr)
        return 1
    receipt_errors = validate_approval_receipt(receipt, digest)
    for receipt_error in receipt_errors:
        print(f"competitive benchmark: approval receipt: {receipt_error}", file=sys.stderr)
    if receipt_errors:
        return 1

    output_root = options.output_root.resolve()
    expected_output_root = DEFAULT_OUTPUT_ROOT.resolve()
    if output_root != expected_output_root:
        print(
            "competitive benchmark: output root must be the ignored local directory",
            file=sys.stderr,
        )
        return 1
    if shutil.which("docker") is None:
        print("competitive benchmark: docker executable not found", file=sys.stderr)
        return 1
    output_root.mkdir(parents=True, exist_ok=True)

    try:
        with tempfile.TemporaryDirectory(prefix="agentsec-competitive-") as temporary:
            runtime_root = Path(temporary)
            source_snapshot, fixture_snapshot = prepare_runtime_inputs(plan, runtime_root)
            cidfile = runtime_root / "container.cid"
            argv = build_docker_argv(
                plan,
                cidfile=cidfile,
                source_path=source_snapshot,
                fixture_path=fixture_snapshot,
            )
            if build_tree_evidence(source_snapshot) != plan["source_tree"]:
                raise TreeEvidenceError("source content changed immediately before Docker")
            if build_tree_evidence(fixture_snapshot) != plan["fixture_tree"]:
                raise TreeEvidenceError("fixture content changed immediately before Docker")
            (
                exit_code,
                timed_out,
                duration,
                stdout,
                stderr,
                stdout_truncated,
                stderr_truncated,
            ) = _capture_docker_process(
                argv,
                cidfile,
                float(cast(int | float, plan["timeout_seconds"])),
                int(cast(int | float, plan["output_limit_bytes"])),
            )
    except (TreeEvidenceError, BenchmarkCleanupError) as error:
        print(f"competitive benchmark: {error}", file=sys.stderr)
        return 1

    envelope = build_result_envelope(
        plan_digest=digest,
        receipt_sha256=_sha256(receipt_bytes),
        approval_metadata={
            field: receipt[field]
            for field in ("decision", "approver", "approved_at", "scope")
        },
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
        files_written=None,
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


def _add_evidence_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--project-index", type=Path, default=DEFAULT_PROJECT_INDEX)
    parser.add_argument("--fixture-manifest", type=Path, default=DEFAULT_FIXTURE_MANIFEST)
    parser.add_argument("--clone-root", type=Path, default=DEFAULT_CLONE_ROOT)
    parser.add_argument("--fixture-root", type=Path, default=DEFAULT_FIXTURE_ROOT)


def _add_common_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--plan", type=Path, required=True)
    _add_evidence_options(parser)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="subcommand", required=True)
    generate = commands.add_parser(
        "generate", help="Generate local exact plans from tracked path-free blueprints"
    )
    generate.add_argument("--blueprints", type=Path, default=DEFAULT_BLUEPRINTS)
    generate.add_argument("--output-root", type=Path, default=DEFAULT_PLAN_ROOT)
    _add_evidence_options(generate)
    validate = commands.add_parser("validate", help="Validate and print the exact container plan")
    _add_common_options(validate)
    execute = commands.add_parser("execute", help="Execute an approved exact plan")
    _add_common_options(execute)
    execute.add_argument("--approval-digest", required=True)
    execute.add_argument("--approval-receipt", type=Path, required=True)
    execute.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT_ROOT)
    commands.add_parser("self-test", help="Exercise local runner primitives without a competitor")
    return parser


def main(arguments: Sequence[str] | None = None) -> int:
    options = _parser().parse_args(arguments)
    if options.subcommand == "generate":
        return _generate_command(options)
    if options.subcommand == "validate":
        return _validate_command(options)
    if options.subcommand == "execute":
        return _execute_command(options)
    return _self_test()


if __name__ == "__main__":
    raise SystemExit(main())

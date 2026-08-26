from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from types import ModuleType

PROJECT_ROOT = Path(__file__).parents[2]
CHECKER_PATH = PROJECT_ROOT / "scripts" / "check_competitive_images.py"
MANIFEST_PATH = PROJECT_ROOT / "research" / "competitive-images" / "manifest.yaml"
BUILD_GATE_PATH = PROJECT_ROOT / "docs" / "competitive-analysis" / "BUILD-GATE.md"
CC_AUDIT_DOCKERFILE = (
    PROJECT_ROOT / "research" / "competitive-images" / "cc-audit" / "Dockerfile"
)
CC_AUDIT_RUST_IMAGE = (
    "FROM rust:1.93.0-bookworm@sha256:"
    "d0a4aa3ca2e1088ac0c81690914a0d810f2eee188197034edf366ed010a2b382"
    " AS dependencies"
)


def _load_checker() -> ModuleType:
    spec = importlib.util.spec_from_file_location("competitive_image_checker", CHECKER_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_committed_image_manifest_is_valid() -> None:
    result = subprocess.run(
        [sys.executable, str(CHECKER_PATH)],
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["blocked"] == 1
    assert payload["ready"] == 7
    assert payload["recipes"] == 8
    assert len(payload["bundle_digest"]) == 64
    assert payload["bundle_digest"] in BUILD_GATE_PATH.read_text(encoding="utf-8")


def test_local_image_id_is_the_only_runtime_reference_before_build() -> None:
    payload = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))

    for recipe in payload["recipes"]:
        assert "image" not in recipe


def test_cc_audit_dependency_stage_includes_declared_benchmark_target() -> None:
    dockerfile = CC_AUDIT_DOCKERFILE.read_text(encoding="utf-8")
    benchmark_copy = "COPY benches/scan_benchmark.rs ./benches/scan_benchmark.rs"

    assert benchmark_copy in dockerfile
    assert dockerfile.index(benchmark_copy) < dockerfile.index("cargo fetch --locked")


def test_cc_audit_builder_matches_pinned_rust_toolchain() -> None:
    dockerfile = CC_AUDIT_DOCKERFILE.read_text(encoding="utf-8")

    assert CC_AUDIT_RUST_IMAGE in dockerfile


def test_validator_rejects_unpinned_from_image(tmp_path: Path) -> None:
    checker = _load_checker()
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("FROM python:3.12-slim\n", encoding="utf-8")
    payload = {
        "schema_version": "1",
        "platform": "linux/arm64",
        "recipes": [
            {
                "project_id": "example",
                "revision": "0123456789ab",
                "status": "ready",
                "dockerfile": "Dockerfile",
                "tag": "agentsec-bench/example:0123456789ab",
                "runtime_command": ["scan", "/fixture"],
                "fixtures": ["clean-control"],
                "build_network": "dependencies_only",
            }
        ],
    }

    errors = checker.validate_manifest(payload, tmp_path, expected_projects=None)

    assert any("FROM must use an immutable sha256 digest" in error for error in errors)


def test_validator_rejects_source_build_with_network(tmp_path: Path) -> None:
    checker = _load_checker()
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "FROM python:3.12@sha256:" + "a" * 64 + "\nCOPY . .\nRUN python -m build\n",
        encoding="utf-8",
    )
    payload = {
        "schema_version": "1",
        "platform": "linux/arm64",
        "recipes": [
            {
                "project_id": "example",
                "revision": "0123456789ab",
                "status": "ready",
                "dockerfile": "Dockerfile",
                "tag": "agentsec-bench/example:0123456789ab",
                "runtime_command": ["scan", "/fixture"],
                "fixtures": ["clean-control"],
                "build_network": "dependencies_only",
            }
        ],
    }

    errors = checker.validate_manifest(payload, tmp_path, expected_projects=None)

    assert any("source-present RUN must declare --network=none" in error for error in errors)

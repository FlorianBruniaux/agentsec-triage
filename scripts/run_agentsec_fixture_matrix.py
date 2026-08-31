#!/usr/bin/env python3
"""Run the AgentSec baseline three times on every competitive fixture."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import cast

PROJECT_ROOT = Path(__file__).parents[1]
DEFAULT_MANIFEST = PROJECT_ROOT / "research" / "competitive-fixtures" / "manifest.yaml"
DEFAULT_FIXTURE_ROOT = DEFAULT_MANIFEST.parent
LOCAL_OUTPUT_ROOT = PROJECT_ROOT / "research" / "competitive-runs" / "local"
REPEAT_COUNT = 3


class BaselineError(RuntimeError):
    """Raised when the fixture baseline cannot produce trustworthy evidence."""


def _object(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise BaselineError(f"{label}: expected an object")
    return cast(dict[str, object], value)


def _array(value: object, label: str) -> list[object]:
    if not isinstance(value, list):
        raise BaselineError(f"{label}: expected an array")
    return value


def _load_manifest(path: Path) -> list[dict[str, object]]:
    try:
        payload = _object(json.loads(path.read_text(encoding="utf-8")), "manifest")
    except (OSError, json.JSONDecodeError, UnicodeError) as error:
        raise BaselineError(f"manifest: {error}") from error
    if payload.get("schema_version") != "1":
        raise BaselineError("manifest: unsupported schema version")
    fixtures = _array(payload.get("fixtures"), "manifest.fixtures")
    return [
        _object(item, f"manifest.fixtures[{index}]")
        for index, item in enumerate(fixtures)
    ]


def _normalized_payload(payload: Mapping[str, object]) -> dict[str, object]:
    normalized = dict(payload)
    if normalized.get("schema_version") != "2":
        raise BaselineError("scan result: unsupported schema version")
    if normalized.get("root") != "<SCAN_ROOT>":
        raise BaselineError("scan result: root is not redacted")
    if not isinstance(normalized.get("complete"), bool):
        raise BaselineError("scan result: complete must be a boolean")
    for field in ("detectors", "diagnostics", "findings", "not_scanned"):
        _array(normalized.get(field), f"scan result.{field}")
    normalized.pop("elapsed_ms", None)
    return normalized


def _digest(payload: Mapping[str, object]) -> str:
    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _detector_projection(payload: Mapping[str, object]) -> list[dict[str, object]]:
    detectors = _array(payload.get("detectors"), "scan result.detectors")
    projection: list[dict[str, object]] = []
    for index, raw in enumerate(detectors):
        detector = _object(raw, f"scan result.detectors[{index}]")
        projection.append(
            {
                "applicability": detector.get("applicability"),
                "bytes_inspected": detector.get("bytes_inspected"),
                "detector_id": detector.get("detector_id"),
                "files_inspected": detector.get("files_inspected"),
                "files_seen": detector.get("files_seen"),
                "not_scanned": detector.get("not_scanned"),
            }
        )
    return projection


def _summarize_fixture(
    fixture: Mapping[str, object],
    runs: Sequence[tuple[int, Mapping[str, object]]],
) -> dict[str, object]:
    fixture_id = fixture.get("id")
    if len(runs) != REPEAT_COUNT:
        raise BaselineError(f"fixture {fixture_id}: expected {REPEAT_COUNT} runs")
    normalized = [_normalized_payload(payload) for _, payload in runs]
    digests = [_digest(payload) for payload in normalized]
    exit_codes = [exit_code for exit_code, _ in runs]
    if len(set(digests)) != 1:
        raise BaselineError(f"fixture {fixture_id}: normalized output is not deterministic")
    if len(set(exit_codes)) != 1:
        raise BaselineError(f"fixture {fixture_id}: exit code is not deterministic")
    first = normalized[0]
    detectors = _detector_projection(first)
    applicability = (
        "applicable"
        if any(row.get("applicability") == "applicable" for row in detectors)
        else "not_applicable"
    )
    return {
        "applicability": applicability,
        "complete": first["complete"],
        "database_version": first.get("database_version"),
        "detectors": detectors,
        "diagnostics": first["diagnostics"],
        "exit_code": exit_codes[0],
        "finding_count": len(_array(first["findings"], "scan result.findings")),
        "findings": first["findings"],
        "fixture_id": fixture_id,
        "fixture_kind": fixture.get("kind"),
        "normalized_sha256": digests[0],
        "not_scanned": first["not_scanned"],
        "repeat_count": REPEAT_COUNT,
        "tool_version": first.get("tool_version"),
    }


def _run_fixture(root: Path) -> tuple[int, dict[str, object]]:
    environment = os.environ.copy()
    source_path = str(PROJECT_ROOT / "src")
    current_pythonpath = environment.get("PYTHONPATH")
    environment["PYTHONPATH"] = (
        f"{source_path}{os.pathsep}{current_pythonpath}"
        if current_pythonpath
        else source_path
    )
    try:
        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "agentsec",
                "scan",
                str(root),
                "--scope",
                "repository",
                "--format",
                "json",
                "--redact",
            ],
            cwd=PROJECT_ROOT,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
            shell=False,
            timeout=60,
        )
    except subprocess.TimeoutExpired as error:
        raise BaselineError(f"fixture {root.name}: scan timed out") from error
    if completed.returncode not in {0, 1, 2}:
        raise BaselineError(
            f"fixture {root.name}: unexpected exit code {completed.returncode}"
        )
    try:
        payload = _object(json.loads(completed.stdout), f"fixture {root.name} result")
    except (json.JSONDecodeError, UnicodeError) as error:
        raise BaselineError(f"fixture {root.name}: invalid JSON result: {error}") from error
    return completed.returncode, payload


def _validated_output_path(path: Path) -> Path:
    resolved = path.resolve()
    root = LOCAL_OUTPUT_ROOT.resolve()
    try:
        resolved.relative_to(root)
    except ValueError as error:
        raise BaselineError("output must stay under the ignored local run directory") from error
    if resolved.suffix != ".json":
        raise BaselineError("output must use the .json extension")
    return resolved


def _resolved_fixture_root(root: Path, directory: str) -> Path:
    resolved_root = root.resolve()
    resolved_fixture = (resolved_root / directory).resolve()
    try:
        resolved_fixture.relative_to(resolved_root)
    except ValueError as error:
        raise BaselineError(f"fixture {directory}: path resolves outside fixture root") from error
    if not resolved_fixture.is_dir():
        raise BaselineError(f"fixture {directory}: directory not found")
    return resolved_fixture


def _write_output(path: Path, payload: Mapping[str, object]) -> None:
    if path.exists():
        raise BaselineError("output already exists")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    try:
        temporary.write_text(
            json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        temporary.replace(path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--fixture-root", type=Path, default=DEFAULT_FIXTURE_ROOT)
    parser.add_argument(
        "--output",
        type=Path,
        default=LOCAL_OUTPUT_ROOT / "agentsec-fixture-baseline.json",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    options = _parser().parse_args(argv)
    try:
        output = _validated_output_path(options.output)
        fixtures = _load_manifest(options.manifest)
        results: list[dict[str, object]] = []
        for fixture in fixtures:
            directory = fixture.get("directory")
            if not isinstance(directory, str) or not directory:
                raise BaselineError("fixture directory must be a non-empty string")
            fixture_root = _resolved_fixture_root(options.fixture_root, directory)
            runs = [_run_fixture(fixture_root) for _ in range(REPEAT_COUNT)]
            results.append(_summarize_fixture(fixture, runs))
        _write_output(
            output,
            {
                "fixture_count": len(results),
                "fixtures": results,
                "repeat_count": REPEAT_COUNT,
                "schema_version": "1",
                "scope": "repository",
            },
        )
    except (BaselineError, OSError, TypeError, UnicodeError) as error:
        print(f"agentsec fixture baseline: {error}", file=sys.stderr)
        return 2
    print(f"AgentSec fixture baseline written: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

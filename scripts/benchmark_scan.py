from __future__ import annotations

import argparse
import json
import platform
import subprocess
import sys
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import cast


class BenchmarkError(RuntimeError):
    """Raised when a benchmark cannot produce a trustworthy local report."""


def _mapping(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise BenchmarkError(f"{label} must be an object")
    return cast(dict[str, object], value)


def _non_negative_int(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise BenchmarkError(f"{label} must be a non-negative integer")
    return value


def _non_empty_string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise BenchmarkError(f"{label} must be a non-empty string")
    return value


def _parse_scan_payload(raw: str) -> dict[str, object]:
    loaded = cast(object, json.loads(raw))
    payload = _mapping(loaded, "scan result")
    if payload.get("schema_version") != "2":
        raise BenchmarkError("scan result has an unsupported schema version")
    if payload.get("root") != "<SCAN_ROOT>":
        raise BenchmarkError("scan result root is not redacted")
    complete = payload.get("complete")
    if not isinstance(complete, bool):
        raise BenchmarkError("scan result complete must be a boolean")
    _non_empty_string(payload.get("scope"), "scan result scope")
    discovery = _mapping(payload.get("discovery"), "scan result discovery")
    for field in ("entries_seen", "directories_opened", "files_selected"):
        _non_negative_int(discovery.get(field), f"scan result discovery.{field}")
    detectors = payload.get("detectors")
    if not isinstance(detectors, list):
        raise BenchmarkError("scan result detectors must be an array")
    for index, detector in enumerate(detectors):
        row = _mapping(detector, f"scan result detectors[{index}]")
        for field in ("files_seen", "files_inspected", "bytes_inspected"):
            _non_negative_int(row.get(field), f"scan result detectors[{index}].{field}")
    for field in ("findings", "diagnostics"):
        if not isinstance(payload.get(field), list):
            raise BenchmarkError(f"scan result {field} must be an array")
    _non_empty_string(payload.get("tool_version"), "scan result tool_version")
    _non_empty_string(payload.get("database_version"), "scan result database_version")
    return payload


def _report(
    payload: Mapping[str, object], *, elapsed_seconds: float, scan_exit_code: int
) -> dict[str, object]:
    discovery = _mapping(payload["discovery"], "scan result discovery")
    detectors = cast(list[object], payload["detectors"])
    detector_rows = [
        _mapping(item, f"scan result detectors[{index}]")
        for index, item in enumerate(detectors)
    ]
    findings = cast(list[object], payload["findings"])
    diagnostics = cast(list[object], payload["diagnostics"])
    return {
        "benchmark_version": "2",
        "complete": payload["complete"],
        "coverage": {
            "bytes_inspected": sum(
                cast(int, row["bytes_inspected"]) for row in detector_rows
            ),
            "files_inspected": sum(
                cast(int, row["files_inspected"]) for row in detector_rows
            ),
            "files_seen": sum(cast(int, row["files_seen"]) for row in detector_rows),
        },
        "database_version": payload["database_version"],
        "diagnostic_count": len(diagnostics),
        "elapsed_seconds": round(elapsed_seconds, 6),
        "finding_count": len(findings),
        "files_selected": discovery["files_selected"],
        "platform": platform.platform(),
        "python_version": platform.python_version(),
        "root": "<SCAN_ROOT>",
        "scan_exit_code": scan_exit_code,
        "scope": payload["scope"],
        "tool_version": payload["tool_version"],
    }


def _write_report(output: Path, report: Mapping[str, object]) -> None:
    temporary = output.with_name(f".{output.name}.tmp")
    try:
        output.parent.mkdir(parents=True, exist_ok=True)
        temporary.write_text(
            json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        if output.exists():
            raise BenchmarkError("benchmark output already exists")
        temporary.replace(output)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Measure one local AgentSec repository scan without uploading results"
    )
    parser.add_argument("root", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if not args.root.is_dir():
        print("error: scan root must be an existing directory", file=sys.stderr)
        return 2
    if args.output.exists():
        print("error: benchmark output already exists", file=sys.stderr)
        return 2
    started = time.perf_counter()
    try:
        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "agentsec",
                "scan",
                str(args.root),
                "--format",
                "json",
                "--redact",
            ],
            capture_output=True,
            text=True,
            check=False,
            shell=False,
        )
        elapsed = time.perf_counter() - started
        if completed.returncode not in {0, 1, 2}:
            raise BenchmarkError("scanner returned an unexpected exit code")
        payload = _parse_scan_payload(completed.stdout)
        _write_report(
            args.output,
            _report(payload, elapsed_seconds=elapsed, scan_exit_code=completed.returncode),
        )
    except (BenchmarkError, json.JSONDecodeError, OSError, TypeError, UnicodeError) as exc:
        print(f"error: benchmark failed: {exc}", file=sys.stderr)
        return 2
    print(f"benchmark report written: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

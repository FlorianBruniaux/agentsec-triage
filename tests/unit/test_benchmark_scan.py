from __future__ import annotations

import json
import runpy
import subprocess
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import cast

import pytest

PROJECT_ROOT = Path(__file__).parents[2]


def _namespace() -> dict[str, object]:
    return runpy.run_path(str(PROJECT_ROOT / "scripts" / "benchmark_scan.py"))


def _main(namespace: dict[str, object]) -> Callable[[Sequence[str] | None], int]:
    return cast(Callable[[Sequence[str] | None], int], namespace["main"])


def test_benchmark_requires_existing_directory(tmp_path: Path) -> None:
    namespace = _namespace()
    output = tmp_path / "report.json"

    assert _main(namespace)([str(tmp_path / "missing"), "--output", str(output)]) == 2
    assert not output.exists()


def test_benchmark_refuses_existing_output(tmp_path: Path) -> None:
    namespace = _namespace()
    output = tmp_path / "report.json"
    output.write_text("keep", encoding="utf-8")

    assert _main(namespace)([str(tmp_path), "--output", str(output)]) == 2
    assert output.read_text(encoding="utf-8") == "keep"


def test_benchmark_records_completed_real_scan_without_absolute_root(
    tmp_path: Path,
) -> None:
    namespace = _namespace()
    root = tmp_path / "repository"
    root.mkdir()
    output = tmp_path / "report.json"

    assert _main(namespace)([str(root), "--output", str(output)]) == 0

    raw_report = output.read_text(encoding="utf-8")
    report = json.loads(raw_report)
    assert report["benchmark_version"] == "1"
    assert report["root"] == "<SCAN_ROOT>"
    assert report["scan_exit_code"] == 0
    assert report["complete"] is True
    assert report["coverage"] == {
        "bytes_inspected": 0,
        "files_inspected": 0,
        "files_seen": 0,
    }
    assert report["finding_count"] == 0
    assert report["diagnostic_count"] == 0
    assert report["elapsed_seconds"] >= 0
    assert str(root) not in raw_report


def test_benchmark_records_incomplete_real_scan_as_successful_measurement(
    tmp_path: Path,
) -> None:
    namespace = _namespace()
    root = tmp_path / "repository"
    (root / ".git").mkdir(parents=True)
    output = tmp_path / "report.json"

    assert _main(namespace)([str(root), "--output", str(output)]) == 0

    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["scan_exit_code"] == 2
    assert report["complete"] is False
    assert report["diagnostic_count"] >= 1


def test_benchmark_rejects_invalid_json_without_partial_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    namespace = _namespace()
    invalid = subprocess.CompletedProcess(
        args=["agentsec"], returncode=0, stdout="not-json", stderr="secret"
    )
    subprocess_module = cast(object, namespace["subprocess"])
    monkeypatch.setattr(subprocess_module, "run", lambda *args, **kwargs: invalid)
    output = tmp_path / "report.json"

    assert _main(namespace)([str(tmp_path), "--output", str(output)]) == 2
    assert not output.exists()
    assert not (tmp_path / ".report.json.tmp").exists()


def test_benchmark_rejects_incomplete_json_contract_without_partial_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    namespace = _namespace()
    incomplete = subprocess.CompletedProcess(
        args=["agentsec"], returncode=0, stdout="{}", stderr=""
    )
    subprocess_module = cast(object, namespace["subprocess"])
    monkeypatch.setattr(subprocess_module, "run", lambda *args, **kwargs: incomplete)
    output = tmp_path / "report.json"

    assert _main(namespace)([str(tmp_path), "--output", str(output)]) == 2
    assert not output.exists()


def test_benchmark_rejects_unexpected_scanner_exit_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    namespace = _namespace()
    failed = subprocess.CompletedProcess(
        args=["agentsec"], returncode=3, stdout="{}", stderr="private failure"
    )
    subprocess_module = cast(object, namespace["subprocess"])
    monkeypatch.setattr(subprocess_module, "run", lambda *args, **kwargs: failed)
    output = tmp_path / "report.json"

    assert _main(namespace)([str(tmp_path), "--output", str(output)]) == 2
    assert not output.exists()

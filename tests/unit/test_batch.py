from __future__ import annotations

from pathlib import Path

import pytest

from agentsec.batch import (
    BatchInputError,
    read_root_file,
    resolve_batch_roots,
    run_batch,
)
from agentsec.detectors.shai_hulud import ShaiHuludDetector
from agentsec.engine.discovery import DiscoveryLimits
from agentsec.scopes import ScanScope
from agentsec.threat_db import load_bundled_database

LIMITS = DiscoveryLimits(max_file_bytes=1_000_000, max_files=10_000, max_diagnostics=100)


def test_read_root_file_strips_blank_lines_and_preserves_order(tmp_path: Path) -> None:
    path_file = tmp_path / "roots.txt"
    path_file.write_text(" first \n\nsecond\n", encoding="utf-8")

    assert read_root_file(path_file) == (Path("first"), Path("second"))


def test_read_root_file_rejects_invalid_utf8_empty_and_oversized_inputs(
    tmp_path: Path,
) -> None:
    invalid = tmp_path / "invalid.txt"
    invalid.write_bytes(b"\xff")
    with pytest.raises(BatchInputError, match="UTF-8"):
        read_root_file(invalid)

    empty = tmp_path / "empty.txt"
    empty.write_text("\n", encoding="utf-8")
    with pytest.raises(BatchInputError, match="no roots"):
        read_root_file(empty)

    oversized = tmp_path / "oversized.txt"
    oversized.write_bytes(b"x" * (1_048_576 + 1))
    with pytest.raises(BatchInputError, match="1048576"):
        read_root_file(oversized)


def test_read_root_file_rejects_more_than_ten_thousand_roots(tmp_path: Path) -> None:
    path_file = tmp_path / "roots.txt"
    path_file.write_text("x\n" * 10_001, encoding="utf-8")

    with pytest.raises(BatchInputError, match="10000"):
        read_root_file(path_file)


def test_resolve_batch_roots_requires_unique_existing_directories(tmp_path: Path) -> None:
    first = tmp_path / "first"
    first.mkdir()
    missing = tmp_path / "missing"
    regular = tmp_path / "file"
    regular.write_text("x", encoding="utf-8")

    assert resolve_batch_roots((first,)) == (first.resolve(strict=True),)
    with pytest.raises(BatchInputError, match="does not exist"):
        resolve_batch_roots((missing,))
    with pytest.raises(BatchInputError, match="not a directory"):
        resolve_batch_roots((regular,))
    with pytest.raises(BatchInputError, match="duplicate"):
        resolve_batch_roots((first, first / "."))


def test_run_batch_aggregates_child_results_in_input_order(tmp_path: Path) -> None:
    clean = tmp_path / "clean"
    finding = tmp_path / "finding"
    incomplete = tmp_path / "incomplete"
    for root in (clean, finding, incomplete):
        root.mkdir()
    (finding / "package-lock.json").write_text(
        '{"lockfileVersion":3,"packages":{"node_modules/keyv":{"version":"6.0.0"}}}',
        encoding="utf-8",
    )
    (incomplete / "package-lock.json").write_text("not-json", encoding="utf-8")

    result = run_batch(
        (clean, finding, incomplete),
        [ShaiHuludDetector()],
        load_bundled_database(),
        LIMITS,
        scope=ScanScope.SOURCE,
    )

    assert [item.root for item in result.results] == [clean, finding, incomplete]
    assert result.summary.repositories == 3
    assert result.summary.exit_0 == 1
    assert result.summary.exit_1 == 1
    assert result.summary.exit_2 == 1
    assert result.summary.findings == 1
    assert result.complete is False
    assert result.exit_code() == 2

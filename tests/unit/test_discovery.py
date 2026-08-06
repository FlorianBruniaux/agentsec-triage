import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from agentsec.engine import discovery as discovery_module
from agentsec.engine.discovery import DiscoveryLimits, discover
from agentsec.models import DiagnosticKind

LIMITS = DiscoveryLimits(max_file_bytes=4_000_000, max_files=1000, max_diagnostics=100)


def test_missing_root_is_error(tmp_path: Path):
    files, diagnostics = discover(tmp_path / "missing", LIMITS)
    assert files == ()
    assert diagnostics[0].kind is DiagnosticKind.ERROR


def test_files_are_relative_and_sorted(tmp_path: Path):
    (tmp_path / "b.txt").write_text("b")
    (tmp_path / "a.txt").write_text("a")
    files, diagnostics = discover(tmp_path, LIMITS)
    assert diagnostics == ()
    assert [item.relative_path.as_posix() for item in files] == ["a.txt", "b.txt"]


def test_external_symlink_is_reported_but_not_followed(tmp_path: Path):
    outside = tmp_path.parent / "outside-agentsec-test"
    outside.write_text("secret")
    (tmp_path / "escape").symlink_to(outside)
    files, diagnostics = discover(tmp_path, LIMITS)
    assert [item.relative_path.as_posix() for item in files] == ["escape"]
    assert diagnostics == ()
    assert files[0].symlink is True
    assert files[0].absolute_path == tmp_path / "escape"
    assert files[0].size == (tmp_path / "escape").lstat().st_size


def test_external_directory_symlink_is_reported_but_not_traversed(tmp_path: Path):
    outside = tmp_path.parent / "outside-agentsec-directory"
    outside.mkdir()
    (outside / "secret.txt").write_text("secret")
    (tmp_path / "linked-dir").symlink_to(outside, target_is_directory=True)

    files, diagnostics = discover(tmp_path, LIMITS)

    assert [item.relative_path.as_posix() for item in files] == ["linked-dir"]
    assert files[0].symlink is True
    assert diagnostics == ()


def test_windows_reparse_directory_is_reported_but_not_traversed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    junction = tmp_path / "junction"
    junction.mkdir()
    (junction / "secret.txt").write_text("secret")
    original_entry_lstat = discovery_module._safe_entry_lstat

    def reparse_lstat(
        path: Path, name: str, parent_fd: int | None, diagnostics: object
    ):
        entry_stat = original_entry_lstat(path, name, parent_fd, diagnostics)
        assert entry_stat is not None
        if path == junction:
            return SimpleNamespace(
                st_mode=entry_stat.st_mode,
                st_size=entry_stat.st_size,
                st_dev=entry_stat.st_dev,
                st_ino=entry_stat.st_ino,
                st_file_attributes=0x400,
            )
        return entry_stat

    monkeypatch.setattr(discovery_module, "_safe_entry_lstat", reparse_lstat)

    files, diagnostics = discover(tmp_path, LIMITS)

    assert [item.relative_path.as_posix() for item in files] == ["junction"]
    assert files[0].symlink is True
    assert diagnostics == ()


def test_directory_mutated_to_external_symlink_before_open_is_an_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    mutable = tmp_path / "mutable"
    mutable.mkdir()
    outside = tmp_path.parent / "outside-agentsec-race"
    outside.mkdir()
    (outside / "secret.txt").write_text("secret")
    original_lstat = Path.lstat
    mutable_lstat_calls = 0

    def mutate_on_revalidation(path: Path):
        nonlocal mutable_lstat_calls
        if path == mutable:
            mutable_lstat_calls += 1
            if mutable_lstat_calls == 2:
                mutable.rmdir()
                mutable.symlink_to(outside, target_is_directory=True)
        return original_lstat(path)

    monkeypatch.setattr(Path, "lstat", mutate_on_revalidation)

    files, diagnostics = discover(tmp_path, LIMITS)

    assert files == ()
    assert mutable_lstat_calls >= 2
    assert any(
        diagnostic.kind is DiagnosticKind.ERROR and diagnostic.path == mutable
        for diagnostic in diagnostics
    )


def test_directory_mutated_after_open_is_rejected_before_entries_are_processed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    mutable = tmp_path / "mutable-after-open"
    mutable.mkdir()
    (mutable / "payload.txt").write_text("safe")
    outside = tmp_path.parent / "outside-agentsec-after-open"
    outside.mkdir()
    (outside / "payload.txt").write_text("external-secret")
    parked = tmp_path / "parked-original"
    original_open_directory = discovery_module._open_directory

    def mutate_after_open(path: Path, *args: object, **kwargs: object):
        opened = original_open_directory(path, *args, **kwargs)
        if path == mutable and opened is not None:
            mutable.rename(parked)
            mutable.symlink_to(outside, target_is_directory=True)
        return opened

    monkeypatch.setattr(discovery_module, "_supports_fd_traversal", lambda: False)
    monkeypatch.setattr(discovery_module, "_open_directory", mutate_after_open)

    files, diagnostics = discover(tmp_path, LIMITS)

    assert files == ()
    assert any(
        diagnostic.kind is DiagnosticKind.ERROR and diagnostic.path == mutable
        for diagnostic in diagnostics
    )


def test_git_is_pruned_but_evidence_directories_and_oversized_files_are_kept(
    tmp_path: Path,
):
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config").write_text("ignored")
    for directory in ("build", "dist", "node_modules"):
        path = tmp_path / directory
        path.mkdir()
        (path / "payload").write_text("evidence")
    (tmp_path / "oversized.bin").write_bytes(b"x" * 5)
    limits = DiscoveryLimits(max_file_bytes=1, max_files=1000, max_diagnostics=100)

    files, diagnostics = discover(tmp_path, limits)

    assert [item.relative_path.as_posix() for item in files] == [
        "build/payload",
        "dist/payload",
        "node_modules/payload",
        "oversized.bin",
    ]
    assert files[-1].size == 5
    assert diagnostics == ()


def test_depth_limit_keeps_shallow_files_and_reports_truncation(tmp_path: Path):
    level_one = tmp_path / "level-one"
    level_one.mkdir()
    (level_one / "visible.txt").write_text("visible")
    level_two = level_one / "level-two"
    level_two.mkdir()
    (level_two / "hidden.txt").write_text("hidden")
    limits = DiscoveryLimits(
        max_file_bytes=100,
        max_files=100,
        max_diagnostics=100,
        max_depth=1,
    )

    files, diagnostics = discover(tmp_path, limits)

    assert [item.relative_path.as_posix() for item in files] == ["level-one/visible.txt"]
    assert any(
        diagnostic.kind is DiagnosticKind.ERROR and "max_depth" in diagnostic.message
        for diagnostic in diagnostics
    )


def test_depth_limit_above_safe_recursive_bound_is_rejected():
    with pytest.raises(ValueError, match="max_depth"):
        DiscoveryLimits(
            max_file_bytes=100,
            max_files=100,
            max_diagnostics=100,
            max_depth=257,
        )


def test_entry_limit_rejects_oversized_directory_without_partial_ordering(tmp_path: Path):
    for name in ("c.txt", "a.txt", "b.txt"):
        (tmp_path / name).write_text(name)
    limits = DiscoveryLimits(
        max_file_bytes=100,
        max_files=100,
        max_diagnostics=100,
        max_entries=2,
    )

    files, diagnostics = discover(tmp_path, limits)

    assert files == ()
    assert any(
        diagnostic.kind is DiagnosticKind.ERROR and "max_entries" in diagnostic.message
        for diagnostic in diagnostics
    )


def test_directory_limit_is_deterministic_and_marks_discovery_incomplete(tmp_path: Path):
    for name in ("b", "a"):
        directory = tmp_path / name
        directory.mkdir()
        (directory / "payload.txt").write_text(name)
    limits = DiscoveryLimits(
        max_file_bytes=100,
        max_files=100,
        max_diagnostics=100,
        max_directories=2,
    )

    files, diagnostics = discover(tmp_path, limits)

    assert [item.relative_path.as_posix() for item in files] == ["a/payload.txt"]
    assert any(
        diagnostic.kind is DiagnosticKind.ERROR and "max_directories" in diagnostic.message
        for diagnostic in diagnostics
    )


def test_file_limit_is_deterministic_and_marks_discovery_incomplete(tmp_path: Path):
    for name in ("c.txt", "a.txt", "b.txt"):
        (tmp_path / name).write_text(name)
    limits = DiscoveryLimits(max_file_bytes=100, max_files=2, max_diagnostics=100)

    files, diagnostics = discover(tmp_path, limits)

    assert [item.relative_path.as_posix() for item in files] == ["a.txt", "b.txt"]
    assert len(diagnostics) == 1
    assert diagnostics[0].kind is DiagnosticKind.ERROR
    assert "max_files" in diagnostics[0].message


def test_reaching_file_limit_exactly_is_complete(tmp_path: Path):
    (tmp_path / "a.txt").write_text("a")
    limits = DiscoveryLimits(max_file_bytes=100, max_files=1, max_diagnostics=100)

    files, diagnostics = discover(tmp_path, limits)

    assert [item.relative_path.as_posix() for item in files] == ["a.txt"]
    assert diagnostics == ()


def test_file_limit_stops_before_inspecting_remaining_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    for name in ("c.txt", "a.txt", "b.txt"):
        (tmp_path / name).write_text(name)
    inspected: list[str] = []
    original_entry_lstat = discovery_module._safe_entry_lstat

    def recording_lstat(
        path: Path, name: str, parent_fd: int | None, diagnostics: object
    ):
        if path.suffix == ".txt":
            inspected.append(path.name)
        return original_entry_lstat(path, name, parent_fd, diagnostics)

    monkeypatch.setattr(discovery_module, "_safe_entry_lstat", recording_lstat)
    limits = DiscoveryLimits(max_file_bytes=100, max_files=1, max_diagnostics=100)

    files, diagnostics = discover(tmp_path, limits)

    assert [item.relative_path.as_posix() for item in files] == ["a.txt"]
    assert inspected == ["a.txt"]
    assert diagnostics[0].kind is DiagnosticKind.ERROR


def test_lstat_error_is_reported_and_other_files_are_retained(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    bad = tmp_path / "bad.txt"
    bad.write_text("bad")
    (tmp_path / "good.txt").write_text("good")
    original_entry_lstat = discovery_module._safe_entry_lstat

    def selective_lstat(
        path: Path, name: str, parent_fd: int | None, diagnostics: object
    ):
        if path == bad:
            diagnostics.add(path, "cannot inspect entry: denied")
            return None
        return original_entry_lstat(path, name, parent_fd, diagnostics)

    monkeypatch.setattr(discovery_module, "_safe_entry_lstat", selective_lstat)

    files, diagnostics = discover(tmp_path, LIMITS)

    assert [item.relative_path.as_posix() for item in files] == ["good.txt"]
    assert len(diagnostics) == 1
    assert diagnostics[0].kind is DiagnosticKind.ERROR
    assert diagnostics[0].path == bad


def test_walk_error_is_reported_not_clean(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    def failing_scandir(*args: object, **kwargs: object):
        raise PermissionError(13, "denied", str(tmp_path / "private"))

    monkeypatch.setattr(discovery_module.os, "scandir", failing_scandir)

    files, diagnostics = discover(tmp_path, LIMITS)

    assert files == ()
    assert len(diagnostics) == 1
    assert diagnostics[0].kind is DiagnosticKind.ERROR


def test_diagnostics_are_bounded_with_final_truncation_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    for name in ("c.txt", "a.txt", "b.txt"):
        (tmp_path / name).write_text(name)

    original_entry_lstat = discovery_module._safe_entry_lstat

    def denied_lstat(
        path: Path, name: str, parent_fd: int | None, diagnostics: object
    ):
        if path.suffix == ".txt":
            diagnostics.add(path, f"cannot inspect entry: denied: {path.name}")
            return None
        return original_entry_lstat(path, name, parent_fd, diagnostics)

    monkeypatch.setattr(discovery_module, "_safe_entry_lstat", denied_lstat)
    limits = DiscoveryLimits(max_file_bytes=100, max_files=100, max_diagnostics=1)

    files, diagnostics = discover(tmp_path, limits)

    assert files == ()
    assert len(diagnostics) == 2
    assert diagnostics[0].path == tmp_path / "a.txt"
    assert diagnostics[-1].kind is DiagnosticKind.ERROR
    assert "truncated" in diagnostics[-1].message


def test_zero_diagnostic_limit_still_returns_an_error(tmp_path: Path):
    (tmp_path / "file.txt").write_text("data")
    limits = DiscoveryLimits(max_file_bytes=100, max_files=0, max_diagnostics=0)

    files, diagnostics = discover(tmp_path, limits)

    assert files == ()
    assert len(diagnostics) == 1
    assert diagnostics[0].kind is DiagnosticKind.ERROR
    assert "truncated" in diagnostics[0].message


def test_non_directory_root_is_error(tmp_path: Path):
    root = tmp_path / "file.txt"
    root.write_text("not a repository")

    files, diagnostics = discover(root, LIMITS)

    assert files == ()
    assert len(diagnostics) == 1
    assert diagnostics[0].kind is DiagnosticKind.ERROR


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO requires POSIX mkfifo")
def test_fifo_is_not_analyzable_and_reports_incomplete_coverage(tmp_path: Path):
    fifo = tmp_path / "hostile.fifo"
    os.mkfifo(fifo)

    files, diagnostics = discover(tmp_path, LIMITS)

    assert files == ()
    assert any(
        diagnostic.kind is DiagnosticKind.ERROR
        and diagnostic.path == fifo
        and "special" in diagnostic.message
        for diagnostic in diagnostics
    )

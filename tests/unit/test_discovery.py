from pathlib import Path

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
    original_lstat = Path.lstat

    def recording_lstat(path: Path):
        inspected.append(path.name)
        return original_lstat(path)

    monkeypatch.setattr(Path, "lstat", recording_lstat)
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
    original_lstat = Path.lstat

    def selective_lstat(path: Path):
        if path == bad:
            raise PermissionError("denied")
        return original_lstat(path)

    monkeypatch.setattr(Path, "lstat", selective_lstat)

    files, diagnostics = discover(tmp_path, LIMITS)

    assert [item.relative_path.as_posix() for item in files] == ["good.txt"]
    assert len(diagnostics) == 1
    assert diagnostics[0].kind is DiagnosticKind.ERROR
    assert diagnostics[0].path == bad


def test_walk_error_is_reported_not_clean(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    def failing_walk(*args: object, **kwargs: object):
        onerror = kwargs["onerror"]
        assert callable(onerror)
        onerror(PermissionError(13, "denied", str(tmp_path / "private")))
        return iter(())

    monkeypatch.setattr(discovery_module.os, "walk", failing_walk)

    files, diagnostics = discover(tmp_path, LIMITS)

    assert files == ()
    assert len(diagnostics) == 1
    assert diagnostics[0].kind is DiagnosticKind.ERROR


def test_diagnostics_are_bounded_with_final_truncation_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    for name in ("c.txt", "a.txt", "b.txt"):
        (tmp_path / name).write_text(name)

    def denied_lstat(path: Path):
        raise PermissionError(f"denied: {path.name}")

    monkeypatch.setattr(Path, "lstat", denied_lstat)
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

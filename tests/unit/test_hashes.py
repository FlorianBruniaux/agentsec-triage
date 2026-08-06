import hashlib
import os
import stat
from pathlib import Path

import pytest

from agentsec.analyzers.hashes import hash_file
from agentsec.models import Diagnostic, DiagnosticKind


@pytest.mark.parametrize(
    "relative_path",
    [
        Path("payload.js"),
        Path("payload.mjs"),
        Path("payload"),
        Path("payload.bin"),
        Path("dist/payload.js"),
    ],
)
def test_hash_is_extension_and_location_independent(tmp_path: Path, relative_path: Path):
    content = b"known malicious payload bytes\x00\xff"
    path = tmp_path / relative_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)

    digest, diagnostics = hash_file(path, max_bytes=len(content))

    assert diagnostics == ()
    assert digest == hashlib.sha256(content).hexdigest()


def test_file_above_max_bytes_returns_error(tmp_path: Path):
    path = tmp_path / "payload"
    path.write_bytes(b"12345")

    digest, diagnostics = hash_file(path, max_bytes=4)

    _assert_hash_error(path, digest, diagnostics)


def test_symlink_is_never_dereferenced(tmp_path: Path):
    target = tmp_path / "target"
    target.write_bytes(b"known bytes")
    link = tmp_path / "payload.js"
    try:
        link.symlink_to(target)
    except (NotImplementedError, OSError):
        pytest.skip("symlinks are unavailable on this platform")

    digest, diagnostics = hash_file(link, max_bytes=1024)

    _assert_hash_error(link, digest, diagnostics)


@pytest.mark.parametrize("max_bytes", [-1, True])
def test_rejects_invalid_byte_limit(tmp_path: Path, max_bytes: int):
    path = tmp_path / "payload"
    path.write_bytes(b"")

    digest, diagnostics = hash_file(path, max_bytes=max_bytes)

    _assert_hash_error(path, digest, diagnostics)


def test_zero_limit_allows_empty_regular_file(tmp_path: Path):
    path = tmp_path / "empty"
    path.write_bytes(b"")

    digest, diagnostics = hash_file(path, max_bytes=0)

    assert diagnostics == ()
    assert digest == hashlib.sha256(b"").hexdigest()


def test_rejects_non_regular_file(tmp_path: Path):
    digest, diagnostics = hash_file(tmp_path, max_bytes=1024)

    _assert_hash_error(tmp_path, digest, diagnostics)


def test_invalid_payload_path_returns_error():
    path = Path("invalid\x00payload")

    digest, diagnostics = hash_file(path, max_bytes=1024)

    _assert_hash_error(path, digest, diagnostics)


def test_streams_in_chunks_no_larger_than_64_kib(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    path = tmp_path / "large-payload"
    path.write_bytes(b"x" * 150_000)
    original_read = os.read
    read_sizes: list[int] = []

    def recording_read(fd: int, count: int) -> bytes:
        read_sizes.append(count)
        return original_read(fd, count)

    monkeypatch.setattr(os, "read", recording_read)

    digest, diagnostics = hash_file(path, max_bytes=200_000)

    assert diagnostics == ()
    assert digest == hashlib.sha256(path.read_bytes()).hexdigest()
    assert len(read_sizes) >= 3
    assert max(read_sizes) <= 64 * 1024


def test_fails_closed_when_opened_file_identity_differs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    path = tmp_path / "payload"
    replacement = tmp_path / "replacement"
    path.write_bytes(b"first")
    replacement.write_bytes(b"second")
    original_open = os.open

    def switched_open(open_path: os.PathLike[str] | str, flags: int) -> int:
        assert Path(open_path) == path
        return original_open(replacement, flags)

    monkeypatch.setattr(os, "open", switched_open)

    digest, diagnostics = hash_file(path, max_bytes=1024)

    _assert_hash_error(path, digest, diagnostics)


def test_fails_closed_when_file_changes_between_lstat_and_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    path = tmp_path / "payload"
    path.write_bytes(b"first")
    original_open = os.open

    def mutating_open(open_path: os.PathLike[str] | str, flags: int) -> int:
        Path(open_path).write_bytes(b"other")
        return original_open(open_path, flags)

    monkeypatch.setattr(os, "open", mutating_open)

    digest, diagnostics = hash_file(path, max_bytes=1024)

    _assert_hash_error(path, digest, diagnostics)


def test_fails_closed_when_path_becomes_symlink_after_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    path = tmp_path / "payload"
    target = tmp_path / "target"
    path.write_bytes(b"first")
    target.write_bytes(b"target")
    original_open = os.open

    def replacing_open(open_path: os.PathLike[str] | str, flags: int) -> int:
        fd = original_open(open_path, flags)
        Path(open_path).unlink()
        try:
            Path(open_path).symlink_to(target)
        except (NotImplementedError, OSError):
            os.close(fd)
            pytest.skip("symlinks are unavailable on this platform")
        return fd

    monkeypatch.setattr(os, "open", replacing_open)

    digest, diagnostics = hash_file(path, max_bytes=1024)

    _assert_hash_error(path, digest, diagnostics)


def test_fails_closed_when_file_changes_during_hashing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    path = tmp_path / "payload"
    path.write_bytes(b"first")
    original_read = os.read
    changed = False

    def mutating_read(fd: int, count: int) -> bytes:
        nonlocal changed
        chunk = original_read(fd, count)
        if not changed:
            path.write_bytes(b"changed and larger")
            changed = True
        return chunk

    monkeypatch.setattr(os, "read", mutating_read)

    digest, diagnostics = hash_file(path, max_bytes=1024)

    _assert_hash_error(path, digest, diagnostics)


def test_fails_closed_when_file_changes_before_final_path_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    path = tmp_path / "payload"
    path.write_bytes(b"first")
    original_lstat = os.lstat
    calls = 0

    def mutating_lstat(stat_path: os.PathLike[str] | str) -> os.stat_result:
        nonlocal calls
        calls += 1
        if calls == 2:
            Path(stat_path).write_bytes(b"other")
        return original_lstat(stat_path)

    monkeypatch.setattr(os, "lstat", mutating_lstat)

    digest, diagnostics = hash_file(path, max_bytes=1024)

    _assert_hash_error(path, digest, diagnostics)


def test_rejects_opened_reparse_point(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    path = tmp_path / "payload"
    path.write_bytes(b"first")
    original_fstat = os.fstat
    reparse_flag = 0x400
    monkeypatch.setattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", reparse_flag, raising=False)

    class ReparseStat:
        def __init__(self, source: os.stat_result):
            self.st_mode = source.st_mode
            self.st_size = source.st_size
            self.st_dev = source.st_dev
            self.st_ino = source.st_ino
            self.st_mtime_ns = source.st_mtime_ns
            self.st_ctime_ns = source.st_ctime_ns
            self.st_file_attributes = reparse_flag

    def reparse_fstat(fd: int) -> ReparseStat:
        return ReparseStat(original_fstat(fd))

    monkeypatch.setattr(os, "fstat", reparse_fstat)

    digest, diagnostics = hash_file(path, max_bytes=1024)

    _assert_hash_error(path, digest, diagnostics)


def _assert_hash_error(
    path: Path,
    digest: object,
    diagnostics: tuple[Diagnostic, ...],
):
    assert digest is None
    assert len(diagnostics) == 1
    diagnostic = diagnostics[0]
    assert diagnostic.kind is DiagnosticKind.ERROR
    assert diagnostic.path == path

import hashlib
import os
import stat
from pathlib import Path

import pytest

import agentsec.analyzers.safe_io as safe_io
from agentsec.analyzers.hashes import hash_file
from agentsec.models import Diagnostic, DiagnosticKind

_POSIX_SAFE_READER = pytest.mark.skipif(
    os.name == "nt", reason="POSIX descriptor regression"
)


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


def test_hash_absolute_cap_cannot_be_increased_by_caller(tmp_path: Path):
    path = tmp_path / "payload"
    path.write_bytes(b"x" * (4 * 1024 * 1024 + 1))

    digest, diagnostics = hash_file(path, max_bytes=100 * 1024 * 1024)

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


def test_symlinked_parent_directory_is_never_dereferenced(tmp_path: Path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "payload").write_bytes(b"outside bytes")
    scan = tmp_path / "scan"
    scan.mkdir()
    linked_parent = scan / "linked-parent"
    try:
        linked_parent.symlink_to(outside, target_is_directory=True)
    except (NotImplementedError, OSError):
        pytest.skip("symlinks are unavailable on this platform")

    digest, diagnostics = hash_file(linked_parent / "payload", max_bytes=1024)

    _assert_hash_error(linked_parent / "payload", digest, diagnostics)


@_POSIX_SAFE_READER
def test_parent_replaced_by_symlink_during_open_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    scan = tmp_path / "scan"
    parent = scan / "parent"
    outside = tmp_path / "outside"
    parent.mkdir(parents=True)
    outside.mkdir()
    (parent / "payload").write_bytes(b"inside bytes")
    (outside / "payload").write_bytes(b"outside bytes")
    detached = scan / "detached"
    path = parent / "payload"
    original_open_file_at = safe_io._open_file_at

    def racing_open(parent_descriptor: int, filename: str) -> int:
        parent.rename(detached)
        try:
            parent.symlink_to(outside, target_is_directory=True)
        except (NotImplementedError, OSError):
            pytest.skip("symlinks are unavailable on this platform")
        return original_open_file_at(parent_descriptor, filename)

    monkeypatch.setattr(safe_io, "_open_file_at", racing_open)

    digest, diagnostics = hash_file(path, max_bytes=1024)

    _assert_hash_error(path, digest, diagnostics)


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


@_POSIX_SAFE_READER
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


@_POSIX_SAFE_READER
def test_fails_closed_when_opened_file_identity_differs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    path = tmp_path / "payload"
    replacement = tmp_path / "replacement"
    path.write_bytes(b"first")
    replacement.write_bytes(b"second")
    original_open_file_at = safe_io._open_file_at

    def switched_open(parent: int, filename: str) -> int:
        assert filename == path.name
        return original_open_file_at(parent, replacement.name)

    monkeypatch.setattr(safe_io, "_open_file_at", switched_open)

    digest, diagnostics = hash_file(path, max_bytes=1024)

    _assert_hash_error(path, digest, diagnostics)


@_POSIX_SAFE_READER
def test_fails_closed_when_file_changes_between_lstat_and_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    path = tmp_path / "payload"
    path.write_bytes(b"first")
    original_open_file_at = safe_io._open_file_at

    def mutating_open(parent: int, filename: str) -> int:
        path.write_bytes(b"other")
        return original_open_file_at(parent, filename)

    monkeypatch.setattr(safe_io, "_open_file_at", mutating_open)

    digest, diagnostics = hash_file(path, max_bytes=1024)

    _assert_hash_error(path, digest, diagnostics)


@_POSIX_SAFE_READER
def test_fails_closed_when_path_becomes_symlink_after_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    path = tmp_path / "payload"
    target = tmp_path / "target"
    path.write_bytes(b"first")
    target.write_bytes(b"target")
    original_open_file_at = safe_io._open_file_at

    def replacing_open(parent: int, filename: str) -> int:
        fd = original_open_file_at(parent, filename)
        path.unlink()
        try:
            path.symlink_to(target)
        except (NotImplementedError, OSError):
            os.close(fd)
            pytest.skip("symlinks are unavailable on this platform")
        return fd

    monkeypatch.setattr(safe_io, "_open_file_at", replacing_open)

    digest, diagnostics = hash_file(path, max_bytes=1024)

    _assert_hash_error(path, digest, diagnostics)


@_POSIX_SAFE_READER
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


@_POSIX_SAFE_READER
def test_fails_closed_when_file_changes_before_final_path_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    path = tmp_path / "payload"
    path.write_bytes(b"first")
    original_stat_at = safe_io._stat_at
    final_calls = 0

    def mutating_stat_at(parent: int, component: str) -> os.stat_result:
        nonlocal final_calls
        if component == path.name:
            final_calls += 1
            if final_calls == 2:
                path.write_bytes(b"other")
        return original_stat_at(parent, component)

    monkeypatch.setattr(safe_io, "_stat_at", mutating_stat_at)

    digest, diagnostics = hash_file(path, max_bytes=1024)

    _assert_hash_error(path, digest, diagnostics)


@_POSIX_SAFE_READER
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


@pytest.mark.parametrize(
    ("close_target", "read_fails"),
    [
        ("payload", False),
        ("parent", False),
        ("both", False),
        ("payload", True),
    ],
)
@_POSIX_SAFE_READER
def test_close_failure_returns_error_and_attempts_all_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    close_target: str,
    read_fails: bool,
):
    path = tmp_path / "payload"
    path.write_bytes(b"known bytes")
    original_open_file_at = safe_io._open_file_at
    original_open_parent = safe_io._open_parent_directory
    original_close = os.close
    original_read = os.read
    file_descriptors: list[int] = []
    parent_descriptors: list[int] = []
    close_attempts: list[int] = []

    def tracking_open_file_at(parent: int, filename: str) -> int:
        descriptor = original_open_file_at(parent, filename)
        file_descriptors.append(descriptor)
        return descriptor

    def tracking_open_parent(open_path: Path) -> tuple[int, str]:
        result = original_open_parent(open_path)
        parent_descriptors.append(result[0])
        return result

    def failing_close(descriptor: int) -> None:
        close_attempts.append(descriptor)
        payload_failure = bool(
            close_target in {"payload", "both"}
            and file_descriptors
            and descriptor == file_descriptors[0]
        )
        parent_failure = bool(
            close_target in {"parent", "both"}
            and parent_descriptors
            and descriptor == parent_descriptors[0]
        )
        original_close(descriptor)
        if payload_failure or parent_failure:
            raise OSError("simulated close failure")

    def failing_read(descriptor: int, count: int) -> bytes:
        if read_fails:
            raise OSError("simulated primary read failure")
        return original_read(descriptor, count)

    monkeypatch.setattr(safe_io, "_open_file_at", tracking_open_file_at)
    monkeypatch.setattr(safe_io, "_open_parent_directory", tracking_open_parent)
    monkeypatch.setattr(os, "close", failing_close)
    monkeypatch.setattr(os, "read", failing_read)

    digest, diagnostics = hash_file(path, max_bytes=1024)

    _assert_hash_error(path, digest, diagnostics)
    assert diagnostics[0].message == "Unable to hash payload safely"
    assert file_descriptors[0] in close_attempts
    assert parent_descriptors[0] in close_attempts


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

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path
from typing import Protocol

from agentsec.models import Diagnostic, DiagnosticKind

_CHUNK_SIZE = 64 * 1024


class _UnsafeFileError(OSError):
    pass


class _Digest(Protocol):
    def update(self, value: bytes) -> None: ...


def hash_file(
    path: Path, max_bytes: int
) -> tuple[str | None, tuple[Diagnostic, ...]]:
    """Return a bounded SHA-256 digest without trusting names or following links."""
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < 0:
        return None, (_error(path, "Invalid payload hash byte limit"),)

    try:
        path_before = os.lstat(path)
        _require_regular_path(path_before)
        _require_within_limit(path_before.st_size, max_bytes)

        descriptor = os.open(path, _open_flags())
        try:
            opened = os.fstat(descriptor)
            _require_regular_file(opened)
            _require_same_identity(path_before, opened)
            _require_unchanged(path_before, opened)
            _require_within_limit(opened.st_size, max_bytes)

            digest = hashlib.sha256()
            total = _stream_hash(descriptor, digest, max_bytes)

            file_after = os.fstat(descriptor)
            path_after = os.lstat(path)
            _require_regular_file(file_after)
            _require_regular_path(path_after)
            _require_same_identity(opened, file_after)
            _require_same_identity(opened, path_after)
            _require_unchanged(opened, file_after)
            _require_unchanged(file_after, path_after)
            _require_within_limit(file_after.st_size, max_bytes)
            if total != file_after.st_size:
                raise _UnsafeFileError("payload size changed while hashing")
        finally:
            os.close(descriptor)
    except (OSError, OverflowError, ValueError):
        return None, (_error(path, "Unable to hash payload safely"),)

    return digest.hexdigest(), ()


def _open_flags() -> int:
    flags = os.O_RDONLY
    flags |= getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    return flags


def _stream_hash(descriptor: int, digest: _Digest, max_bytes: int) -> int:
    total = 0
    while True:
        read_size = min(_CHUNK_SIZE, max_bytes - total + 1)
        chunk = os.read(descriptor, read_size)
        if not chunk:
            return total
        total += len(chunk)
        if total > max_bytes:
            raise _UnsafeFileError("payload exceeds byte limit")
        digest.update(chunk)


def _require_regular_path(file_stat: os.stat_result) -> None:
    if _is_link_or_reparse(file_stat) or not stat.S_ISREG(file_stat.st_mode):
        raise _UnsafeFileError("payload path is not a safe regular file")


def _require_regular_file(file_stat: os.stat_result) -> None:
    if _is_link_or_reparse(file_stat) or not stat.S_ISREG(file_stat.st_mode):
        raise _UnsafeFileError("opened payload is not a regular file")


def _is_link_or_reparse(file_stat: os.stat_result) -> bool:
    if stat.S_ISLNK(file_stat.st_mode):
        return True
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    attributes = getattr(file_stat, "st_file_attributes", 0)
    return bool(reparse_flag and attributes & reparse_flag)


def _require_within_limit(size: int, max_bytes: int) -> None:
    if size < 0 or size > max_bytes:
        raise _UnsafeFileError("payload exceeds byte limit")


def _require_same_identity(first: os.stat_result, second: os.stat_result) -> None:
    first_identity = _stable_identity(first)
    second_identity = _stable_identity(second)
    if (
        first_identity is not None
        and second_identity is not None
        and first_identity != second_identity
    ):
        raise _UnsafeFileError("payload identity changed while opening")


def _stable_identity(file_stat: os.stat_result) -> tuple[int, int] | None:
    device = getattr(file_stat, "st_dev", None)
    inode = getattr(file_stat, "st_ino", None)
    if not isinstance(device, int) or not isinstance(inode, int) or inode == 0:
        return None
    return device, inode


def _require_unchanged(before: os.stat_result, after: os.stat_result) -> None:
    before_snapshot = (
        stat.S_IFMT(before.st_mode),
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )
    after_snapshot = (
        stat.S_IFMT(after.st_mode),
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )
    if before_snapshot != after_snapshot:
        raise _UnsafeFileError("payload changed while hashing")


def _error(path: Path, message: str) -> Diagnostic:
    return Diagnostic(DiagnosticKind.ERROR, path, message)

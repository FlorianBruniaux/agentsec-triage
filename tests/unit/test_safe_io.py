from __future__ import annotations

from contextlib import suppress
from pathlib import Path

import pytest

from agentsec.analyzers import safe_io
from agentsec.analyzers.safe_io import safe_read_regular_file
from agentsec.models import DiagnosticKind


def test_reads_regular_file_with_exact_limit(tmp_path: Path) -> None:
    path = tmp_path / "payload"
    path.write_bytes(b"safe bytes")

    content, diagnostics = safe_read_regular_file(path, max_bytes=10)

    assert content == b"safe bytes"
    assert diagnostics == ()


def test_rejects_oversized_file_without_partial_content(tmp_path: Path) -> None:
    path = tmp_path / "payload"
    path.write_bytes(b"12345")

    content, diagnostics = safe_read_regular_file(path, max_bytes=4)

    assert content is None
    assert diagnostics[0].kind is DiagnosticKind.ERROR


def test_absolute_safe_read_cap_cannot_be_increased_by_caller(tmp_path: Path) -> None:
    path = tmp_path / "payload"
    path.write_bytes(b"x" * (4 * 1024 * 1024 + 1))

    content, diagnostics = safe_read_regular_file(path, max_bytes=100 * 1024 * 1024)

    assert content is None
    assert diagnostics[0].kind is DiagnosticKind.ERROR


def test_parent_traversal_close_failure_still_closes_following_descriptor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    nested = tmp_path / "nested"
    nested.mkdir()
    path = nested / "payload"
    path.write_bytes(b"payload")
    opened: list[int] = []
    close_attempts: list[int] = []
    real_open = safe_io.os.open
    real_close = safe_io.os.close
    injected = False

    def recording_open(*args: object, **kwargs: object) -> int:
        descriptor = real_open(*args, **kwargs)
        opened.append(descriptor)
        return descriptor

    def failing_close(descriptor: int) -> None:
        nonlocal injected
        close_attempts.append(descriptor)
        if not injected and len(opened) >= 2 and descriptor == opened[-2]:
            injected = True
            real_close(descriptor)
            raise OSError("injected close failure")
        with suppress(OSError):
            real_close(descriptor)

    monkeypatch.setattr(safe_io.os, "open", recording_open)
    monkeypatch.setattr(safe_io.os, "close", failing_close)
    monkeypatch.setattr(safe_io, "_supports_anchored_no_follow", lambda: True)

    content, diagnostics = safe_read_regular_file(path, max_bytes=100)

    assert content is None
    assert diagnostics[0].kind is DiagnosticKind.ERROR
    assert len(opened) >= 2
    assert set(opened[:2]).issubset(close_attempts)


def test_windows_reader_returns_content_instead_of_failing_platform_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "payload"
    api = _FakeWindowsFileApi(b"windows bytes")
    monkeypatch.setattr(safe_io, "_is_windows", lambda: True)
    monkeypatch.setattr(safe_io, "_windows_file_api", lambda: api)

    content, diagnostics = safe_read_regular_file(path, max_bytes=100)

    assert content == b"windows bytes"
    assert diagnostics == ()
    assert api.closed == list(reversed(api.opened))


class _FakeWindowsFileApi:
    def __init__(self, content: bytes) -> None:
        self.content = content
        self.offset = 0
        self.opened: list[int] = []
        self.closed: list[int] = []

    def _handle(self) -> int:
        handle = len(self.opened) + 1
        self.opened.append(handle)
        return handle

    def open_directory(self, path: Path) -> int:
        return self._handle()

    def validate_directory(self, handle: int, path: Path) -> None:
        return None

    def open_file(self, path: Path) -> int:
        return self._handle()

    def validate_file(self, handle: int, path: Path) -> None:
        return None

    def size(self, handle: int) -> int:
        return len(self.content)

    def snapshot(self, handle: int) -> tuple[int, int, int, int]:
        return 1, len(self.content), 1, 1

    def read(self, handle: int, size: int) -> bytes:
        chunk = self.content[self.offset : self.offset + size]
        self.offset += len(chunk)
        return chunk

    def close(self, handle: int) -> None:
        self.closed.append(handle)

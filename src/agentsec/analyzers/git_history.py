from __future__ import annotations

import os
import shutil
import subprocess
import threading
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from agentsec.models import Diagnostic, DiagnosticKind
from agentsec.threat_db import load_bundled_database

_GIT_FORMAT = "%H%x00%an%x00%ae%x00%s%x00%D"
_MAX_GIT_COMMITS = 100_000
_MAX_GIT_STDOUT_BYTES = 64 * 1024 * 1024
_MAX_GIT_STDERR_BYTES = 64 * 1024
_PIPE_CHUNK_SIZE = 64 * 1024
_GIT_TIMEOUT_SECONDS = 10


@dataclass(frozen=True, slots=True)
class GitIndicator:
    commit: str
    author: str
    email: str
    subject: str
    refs: str


class _GitExecutionError(RuntimeError):
    pass


@dataclass(slots=True)
class _PipeResult:
    data: bytearray
    overflow: bool = False
    failed: bool = False


def inspect_git_history(
    root: Path, max_commits: int
) -> tuple[tuple[GitIndicator, ...], tuple[Diagnostic, ...]]:
    """Inspect bounded local history without invoking a shell or repository hooks."""
    if (
        isinstance(max_commits, bool)
        or not isinstance(max_commits, int)
        or max_commits < 0
        or max_commits > _MAX_GIT_COMMITS
    ):
        return (), (_diagnostic(DiagnosticKind.ERROR, root, "Invalid Git commit limit"),)

    safe_path = _absolute_path_entries(os.environ.get("PATH", os.defpath))
    executable = _resolve_git_executable(safe_path)
    if executable is None:
        return (), (_git_failure_diagnostic(root),)

    argv = [
        executable,
        "--no-pager",
        "-c",
        f"core.hooksPath={os.devnull}",
        "-c",
        "log.showSignature=false",
        "-c",
        "protocol.allow=never",
        "-c",
        "protocol.file.allow=never",
        "-c",
        "protocol.ext.allow=never",
        "log",
        "--all",
        "--no-show-signature",
        "--no-ext-diff",
        "--no-textconv",
        f"--max-count={max_commits + 1}",
        f"--format={_GIT_FORMAT}",
    ]
    try:
        returncode, stdout = _run_git_bounded(argv, root, _git_environment(safe_path))
    except _GitExecutionError:
        return (), (
            _diagnostic(DiagnosticKind.ERROR, root, "Unable to inspect bounded Git output"),
        )
    except (OSError, subprocess.SubprocessError, ValueError):
        return (), (_git_failure_diagnostic(root),)

    if returncode != 0:
        return (), (_git_failure_diagnostic(root),)

    records = stdout.splitlines()
    truncated = len(records) > max_commits
    try:
        commits = tuple(_parse_record(record) for record in records[:max_commits])
    except (UnicodeError, ValueError):
        return (), (_diagnostic(DiagnosticKind.ERROR, root, "Unable to parse local Git history"),)

    documented = {
        (item["author"], item["email"], item["subject"])
        for item in load_bundled_database().commit_indicators
    }
    indicators = tuple(
        commit for commit in commits if (commit.author, commit.email, commit.subject) in documented
    )
    diagnostics = (
        (
            _diagnostic(
                DiagnosticKind.ERROR,
                root,
                f"Local Git history truncated at {max_commits} commits",
            ),
        )
        if truncated
        else ()
    )
    return indicators, diagnostics


def _absolute_path_entries(raw_path: str) -> str:
    entries = [entry for entry in raw_path.split(os.pathsep) if entry and Path(entry).is_absolute()]
    return os.pathsep.join(dict.fromkeys(entries))


def _resolve_git_executable(safe_path: str) -> str | None:
    candidate = shutil.which("git", path=safe_path)
    if candidate is None:
        return None
    try:
        resolved = Path(candidate).resolve(strict=True)
    except (OSError, RuntimeError, ValueError):
        return None
    if not resolved.is_absolute() or not resolved.is_file():
        return None
    return str(resolved)


def _git_environment(safe_path: str) -> dict[str, str]:
    preserved = (
        "HOME",
        "USERPROFILE",
        "SYSTEMROOT",
        "WINDIR",
        "TMPDIR",
        "TMP",
        "TEMP",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
    )
    environment = {key: os.environ[key] for key in preserved if key in os.environ}
    environment.update(
        {
            "PATH": safe_path,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_NO_LAZY_FETCH": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_ALLOW_PROTOCOL": "",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_PAGER": "cat",
        }
    )
    return environment


def _run_git_bounded(argv: list[str], root: Path, env: dict[str, str]) -> tuple[int, bytes]:
    process = subprocess.Popen(
        argv,
        cwd=root,
        shell=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        close_fds=True,
        env=env,
    )
    if process.stdout is None or process.stderr is None:
        _kill(process)
        raise _GitExecutionError("Git pipes unavailable")

    stdout_result = _PipeResult(bytearray())
    stderr_result = _PipeResult(bytearray())
    readers = (
        threading.Thread(
            target=_read_pipe_bounded,
            args=(process.stdout, _MAX_GIT_STDOUT_BYTES, process, stdout_result),
            daemon=True,
        ),
        threading.Thread(
            target=_read_pipe_bounded,
            args=(process.stderr, _MAX_GIT_STDERR_BYTES, process, stderr_result),
            daemon=True,
        ),
    )
    for reader in readers:
        reader.start()

    timed_out = False
    try:
        returncode = process.wait(timeout=_GIT_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        timed_out = True
        _kill(process)
        try:
            returncode = process.wait(timeout=1)
        except subprocess.TimeoutExpired as exc:
            raise _GitExecutionError("Git did not terminate") from exc
    finally:
        for reader in readers:
            reader.join(timeout=1)
        process.stdout.close()
        process.stderr.close()

    if timed_out:
        raise subprocess.TimeoutExpired(argv, _GIT_TIMEOUT_SECONDS)
    if any(reader.is_alive() for reader in readers):
        _kill(process)
        raise _GitExecutionError("Git output reader did not terminate")
    if stdout_result.overflow or stderr_result.overflow:
        raise _GitExecutionError("Git output exceeded byte limit")
    if stdout_result.failed or stderr_result.failed:
        raise _GitExecutionError("Unable to read Git output")
    return returncode, bytes(stdout_result.data)


def _read_pipe_bounded(
    stream: BinaryIO,
    limit: int,
    process: subprocess.Popen[bytes],
    result: _PipeResult,
) -> None:
    try:
        while chunk := stream.read(_PIPE_CHUNK_SIZE):
            remaining = limit - len(result.data)
            if remaining > 0:
                result.data.extend(chunk[:remaining])
            if len(chunk) > remaining:
                result.overflow = True
                _kill(process)
    except (OSError, ValueError):
        result.failed = True
        _kill(process)


def _kill(process: subprocess.Popen[bytes]) -> None:
    with suppress(OSError):
        process.kill()


def _parse_record(record: bytes) -> GitIndicator:
    fields = record.split(b"\x00")
    if len(fields) != 5:
        raise ValueError("unexpected Git record field count")
    commit, author, email, subject, refs = (
        field.decode("utf-8", errors="strict") for field in fields
    )
    if (
        len(commit) not in {40, 64}
        or any(char not in "0123456789abcdef" for char in commit)
        or not author
        or not email
        or not subject
    ):
        raise ValueError("invalid Git record")
    return GitIndicator(commit, author, email, subject, refs)


def _git_failure_diagnostic(root: Path) -> Diagnostic:
    kind = DiagnosticKind.ERROR if _has_git_metadata(root) else DiagnosticKind.WARNING
    message = (
        "Unable to read expected local Git history"
        if kind is DiagnosticKind.ERROR
        else "No readable local Git repository"
    )
    return _diagnostic(kind, root, message)


def _has_git_metadata(root: Path) -> bool:
    try:
        return (root / ".git").exists()
    except (OSError, ValueError):
        return False


def _diagnostic(kind: DiagnosticKind, path: Path, message: str) -> Diagnostic:
    return Diagnostic(kind, path, message)

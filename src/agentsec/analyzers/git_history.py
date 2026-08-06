from __future__ import annotations

import os
import shutil
import signal
import stat
import subprocess
import threading
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import IO

from agentsec.models import Diagnostic, DiagnosticKind
from agentsec.threat_db import load_bundled_database

_GIT_FORMAT = "%H%x00%an%x00%ae%x00%s%x00%D"
_MAX_GIT_COMMITS = 100_000
_MAX_GIT_STDOUT_BYTES = 64 * 1024 * 1024
_MAX_GIT_STDERR_BYTES = 64 * 1024
_PIPE_CHUNK_SIZE = 64 * 1024
_GIT_TIMEOUT_SECONDS = 10
_READER_JOIN_SECONDS = 0.25
_REAL_POPEN_TYPE = subprocess.Popen


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
    executable = _resolve_git_executable(safe_path, root)
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


def _resolve_git_executable(safe_path: str, root: Path) -> str | None:
    candidate = shutil.which("git", path=safe_path)
    if candidate is None:
        return None
    candidate_path = Path(candidate)
    if not candidate_path.is_absolute():
        return None
    try:
        candidate_stat = candidate_path.lstat()
        resolved = candidate_path.resolve(strict=True)
        resolved_root = root.resolve(strict=True)
    except (OSError, RuntimeError, ValueError):
        return None
    if (
        stat.S_ISLNK(candidate_stat.st_mode)
        or not stat.S_ISREG(candidate_stat.st_mode)
        or not resolved.is_absolute()
        or not resolved.is_file()
        or candidate_path.is_relative_to(resolved_root)
        or resolved.is_relative_to(resolved_root)
    ):
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
    process = _start_isolated_process(argv, root, env)
    if process.stdout is None or process.stderr is None:
        _terminate_process_tree(process)
        _wait_after_termination(process)
        for stream in (process.stdout, process.stderr):
            if stream is not None:
                with suppress(OSError, ValueError):
                    stream.close()
        raise _GitExecutionError("Git pipes unavailable")

    stdout_result = _PipeResult(bytearray())
    stderr_result = _PipeResult(bytearray())
    readers = (
        threading.Thread(
            target=_read_pipe_bounded,
            args=(process.stdout, _MAX_GIT_STDOUT_BYTES, process, stdout_result),
            name="agentsec-git-stdout",
        ),
        threading.Thread(
            target=_read_pipe_bounded,
            args=(process.stderr, _MAX_GIT_STDERR_BYTES, process, stderr_result),
            name="agentsec-git-stderr",
        ),
    )
    started_readers: list[threading.Thread] = []
    timed_out = False
    start_failed = False
    descendants_held_pipes = False
    returncode = -1
    try:
        try:
            for reader in readers:
                reader.start()
                started_readers.append(reader)
        except RuntimeError:
            start_failed = True
            _terminate_process_tree(process)
        if not start_failed:
            try:
                returncode = process.wait(timeout=_GIT_TIMEOUT_SECONDS)
            except subprocess.TimeoutExpired:
                timed_out = True
                _terminate_process_tree(process)
    finally:
        _wait_after_termination(process)
        for reader in started_readers:
            reader.join(timeout=_READER_JOIN_SECONDS)
        if any(reader.is_alive() for reader in started_readers):
            descendants_held_pipes = True
            _terminate_process_tree(process)
            _wait_after_termination(process)
            for reader in started_readers:
                reader.join(timeout=_READER_JOIN_SECONDS)
        if any(reader.is_alive() for reader in started_readers):
            _force_close_pipe(process.stdout)
            _force_close_pipe(process.stderr)
            for reader in started_readers:
                reader.join(timeout=_READER_JOIN_SECONDS)
        readers_stopped = not any(reader.is_alive() for reader in started_readers)
        if readers_stopped:
            with suppress(OSError, ValueError):
                process.stdout.close()
            with suppress(OSError, ValueError):
                process.stderr.close()

    if start_failed:
        raise _GitExecutionError("Unable to start Git output readers")
    if timed_out:
        raise subprocess.TimeoutExpired(argv, _GIT_TIMEOUT_SECONDS)
    if not readers_stopped:
        raise _GitExecutionError("Git output reader did not terminate")
    if descendants_held_pipes:
        raise _GitExecutionError("Git descendants retained output pipes")
    if stdout_result.overflow or stderr_result.overflow:
        raise _GitExecutionError("Git output exceeded byte limit")
    if stdout_result.failed or stderr_result.failed:
        raise _GitExecutionError("Unable to read Git output")
    return returncode, bytes(stdout_result.data)


def _read_pipe_bounded(
    stream: IO[bytes],
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
                _terminate_process_tree(process)
    except (OSError, ValueError):
        result.failed = True
        _terminate_process_tree(process)


def _start_isolated_process(
    argv: list[str], root: Path, env: dict[str, str]
) -> subprocess.Popen[bytes]:
    if os.name == "nt":
        creation_flags = int(getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200))
        return subprocess.Popen(
            argv,
            cwd=root,
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
            env=env,
            creationflags=creation_flags,
        )
    return subprocess.Popen(
        argv,
        cwd=root,
        shell=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        close_fds=True,
        env=env,
        start_new_session=True,
    )


def _terminate_process_tree(process: subprocess.Popen[bytes]) -> None:
    if os.name == "posix" and isinstance(process, _REAL_POPEN_TYPE):
        with suppress(OSError, ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
            return
    if os.name == "nt" and _taskkill_process_tree(process.pid):
        return
    with suppress(OSError):
        process.kill()


def _taskkill_process_tree(pid: int) -> bool:
    system_root = os.environ.get("SYSTEMROOT")
    if not system_root:
        return False
    helper = Path(system_root) / "System32" / "taskkill.exe"
    try:
        helper_stat = helper.lstat()
        resolved = helper.resolve(strict=True)
    except (OSError, RuntimeError, ValueError):
        return False
    if stat.S_ISLNK(helper_stat.st_mode) or not stat.S_ISREG(helper_stat.st_mode):
        return False
    try:
        subprocess.run(
            [str(resolved), "/PID", str(pid), "/T", "/F"],
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=2,
            check=False,
            env={"SYSTEMROOT": system_root},
        )
    except (OSError, subprocess.SubprocessError, ValueError):
        return False
    return True


def _wait_after_termination(process: subprocess.Popen[bytes]) -> None:
    with suppress(OSError, subprocess.TimeoutExpired):
        process.wait(timeout=1)


def _force_close_pipe(stream: IO[bytes]) -> None:
    try:
        descriptor = stream.fileno()
    except (OSError, ValueError):
        return
    with suppress(OSError):
        os.close(descriptor)


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

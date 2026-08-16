"""Trusted-input Git utility, intentionally unreachable from runtime detectors."""

from __future__ import annotations

import ctypes
import os
import signal
import stat
import subprocess
import threading
import uuid
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Any

from agentsec.models import Diagnostic, DiagnosticKind

_GIT_FORMAT = "%H%x00%an%x00%ae%x00%s%x00%D"
_MAX_GIT_COMMITS = 100_000
_MAX_GIT_STDOUT_BYTES = 64 * 1024 * 1024
_MAX_GIT_STDERR_BYTES = 64 * 1024
_PIPE_CHUNK_SIZE = 64 * 1024
_GIT_TIMEOUT_SECONDS = 10
_READER_JOIN_SECONDS = 0.25
_REAL_POPEN_TYPE = subprocess.Popen


class _Guid(ctypes.Structure):
    _fields_ = [
        ("data1", ctypes.c_uint32),
        ("data2", ctypes.c_uint16),
        ("data3", ctypes.c_uint16),
        ("data4", ctypes.c_uint8 * 8),
    ]


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
    """Inspect history only after a caller independently guarantees metadata trust."""
    if (
        isinstance(max_commits, bool)
        or not isinstance(max_commits, int)
        or max_commits < 0
        or max_commits > _MAX_GIT_COMMITS
    ):
        return (), (_diagnostic(DiagnosticKind.ERROR, root, "Invalid Git commit limit"),)

    executable = _resolve_git_executable(root)
    if executable is None:
        return (), (_git_failure_diagnostic(root),)
    safe_path = _trusted_helper_path(executable)

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
    return commits, diagnostics


def _resolve_git_executable(root: Path) -> str | None:
    try:
        resolved_root = root.resolve(strict=True)
    except (OSError, RuntimeError, ValueError):
        return None
    for trusted_root, candidate in _system_git_candidates():
        resolved = _validate_system_executable(candidate, trusted_root, resolved_root)
        if resolved is not None:
            return str(resolved)
    return None


def _system_git_candidates() -> tuple[tuple[Path, Path], ...]:
    if _platform_is_windows():
        candidates: list[tuple[Path, Path]] = []
        system_directory = _windows_system_directory()
        if system_directory is not None:
            candidates.append((system_directory, system_directory / "git.exe"))
        program_files = _windows_program_files_directory()
        if program_files:
            candidates.extend(
                (
                    (program_files, program_files / "Git" / "cmd" / "git.exe"),
                    (program_files, program_files / "Git" / "bin" / "git.exe"),
                )
            )
        return tuple(candidates)
    return (
        (Path("/usr/bin"), Path("/usr/bin/git")),
        (Path("/bin"), Path("/bin/git")),
    )


def _platform_is_windows() -> bool:
    return os.name == "nt"


def _windows_system_directory() -> Path | None:
    loader = getattr(ctypes, "WinDLL", None)
    if loader is None:
        return None
    try:
        kernel32: Any = loader("kernel32", use_last_error=True)
        get_system_directory: Any = kernel32.GetSystemDirectoryW
        get_system_directory.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32]
        get_system_directory.restype = ctypes.c_uint32
        buffer = ctypes.create_unicode_buffer(32_768)
        length = int(get_system_directory(buffer, len(buffer)))
    except (AttributeError, OSError, TypeError, ValueError):
        return None
    if length <= 0 or length >= len(buffer):
        return None
    return Path(buffer.value)


def _windows_program_files_directory() -> Path | None:
    loader = getattr(ctypes, "WinDLL", None)
    if loader is None:
        return None
    folder_id = _guid_from_uuid(uuid.UUID("905e63b6-c1bf-494e-b29c-65b732d3d21a"))
    path_pointer = ctypes.c_wchar_p()
    free_memory: Any | None = None
    try:
        shell32: Any = loader("shell32", use_last_error=True)
        ole32: Any = loader("ole32", use_last_error=True)
        get_known_folder: Any = shell32.SHGetKnownFolderPath
        get_known_folder.argtypes = [
            ctypes.POINTER(_Guid),
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_wchar_p),
        ]
        get_known_folder.restype = ctypes.c_long
        free_memory = ole32.CoTaskMemFree
        free_memory.argtypes = [ctypes.c_void_p]
        free_memory.restype = None
        result = int(
            get_known_folder(
                ctypes.byref(folder_id),
                0,
                None,
                ctypes.byref(path_pointer),
            )
        )
        if result != 0 or not path_pointer.value:
            return None
        return Path(path_pointer.value)
    except (AttributeError, OSError, TypeError, ValueError):
        return None
    finally:
        if path_pointer and free_memory is not None:
            with suppress(OSError):
                free_memory(path_pointer)


def _guid_from_uuid(value: uuid.UUID) -> _Guid:
    data = value.bytes_le
    return _Guid(
        int.from_bytes(data[0:4], "little"),
        int.from_bytes(data[4:6], "little"),
        int.from_bytes(data[6:8], "little"),
        (ctypes.c_uint8 * 8).from_buffer_copy(data[8:]),
    )


def _validate_system_executable(
    candidate: Path, trusted_root: Path, scan_root: Path
) -> Path | None:
    try:
        candidate_stat = candidate.lstat()
        resolved = candidate.resolve(strict=True)
        resolved_trusted_root = trusted_root.resolve(strict=True)
    except (OSError, RuntimeError, ValueError):
        return None
    if (
        not candidate.is_absolute()
        or stat.S_ISLNK(candidate_stat.st_mode)
        or not stat.S_ISREG(candidate_stat.st_mode)
        or not resolved.is_relative_to(resolved_trusted_root)
        or candidate.is_relative_to(scan_root)
        or resolved.is_relative_to(scan_root)
    ):
        return None
    if not _platform_is_windows() and not _posix_path_is_uncontrolled(candidate):
        return None
    if _platform_is_windows() and not _windows_path_has_no_reparse_components(candidate):
        return None
    return resolved


def _posix_path_is_uncontrolled(path: Path) -> bool:
    geteuid = getattr(os, "geteuid", None)
    if not callable(geteuid):
        return False
    current_uid = int(geteuid())
    for component in (*reversed(path.parents), path):
        try:
            component_stat = component.lstat()
        except (OSError, ValueError):
            return False
        mode = component_stat.st_mode
        if stat.S_ISLNK(mode):
            return False
        if component != path and not stat.S_ISDIR(mode):
            return False
        if component == path and not stat.S_ISREG(mode):
            return False
        if component_stat.st_uid != 0:
            return False
        if mode & (stat.S_IWGRP | stat.S_IWOTH):
            return False
        if current_uid != 0 and component_stat.st_uid == current_uid and mode & stat.S_IWUSR:
            return False
    return True


def _windows_path_has_no_reparse_components(path: Path) -> bool:
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x00000400)
    for component in (*reversed(path.parents), path):
        try:
            component_stat = component.lstat()
        except (OSError, ValueError):
            return False
        if stat.S_ISLNK(component_stat.st_mode):
            return False
        if getattr(component_stat, "st_file_attributes", 0) & reparse_flag:
            return False
    return True


def _trusted_helper_path(executable: str) -> str:
    entries = [str(Path(executable).parent)]
    if _platform_is_windows() and (system_directory := _windows_system_directory()):
        entries.append(str(system_directory))
    return os.pathsep.join(entries)


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
            killpg = getattr(os, "killpg", None)
            sigkill = getattr(signal, "SIGKILL", None)
            if callable(killpg) and sigkill is not None:
                killpg(process.pid, sigkill)
                return
    if os.name == "nt" and _taskkill_process_tree(process.pid):
        return
    with suppress(OSError):
        process.kill()


def _taskkill_process_tree(pid: int) -> bool:
    system_directory = _windows_system_directory()
    if system_directory is None:
        return False
    helper = system_directory / "taskkill.exe"
    try:
        helper_stat = helper.lstat()
        resolved = helper.resolve(strict=True)
    except (OSError, RuntimeError, ValueError):
        return False
    if stat.S_ISLNK(helper_stat.st_mode) or not stat.S_ISREG(helper_stat.st_mode):
        return False
    try:
        completed = subprocess.run(
            [str(resolved), "/PID", str(pid), "/T", "/F"],
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=2,
            check=False,
            env={"PATH": str(system_directory)},
        )
    except (OSError, subprocess.SubprocessError, ValueError):
        return False
    return completed.returncode == 0


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

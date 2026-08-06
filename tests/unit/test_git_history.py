import io
import os
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from agentsec.analyzers import git_history
from agentsec.analyzers.git_history import GitIndicator, inspect_git_history
from agentsec.models import DiagnosticKind


def test_returns_documented_git_indicator_from_local_history(tmp_path: Path):
    root = _repository(
        tmp_path,
        author="claude",
        email="claude@users.noreply.github.com",
        subject="chore: update config",
    )

    indicators, diagnostics = inspect_git_history(root, max_commits=10)

    assert diagnostics == ()
    assert len(indicators) == 1
    indicator = indicators[0]
    assert len(indicator.commit) == 40
    assert indicator.author == "claude"
    assert indicator.email == "claude@users.noreply.github.com"
    assert indicator.subject == "chore: update config"
    assert "HEAD" in indicator.refs


@pytest.mark.parametrize(
    ("author", "email", "subject"),
    [
        ("Human", "human@example.test", "chore: update config"),
        ("claude", "human@example.test", "chore: update config"),
        ("claude", "claude@users.noreply.github.com", "chore: routine update"),
    ],
)
def test_ignores_commits_without_the_complete_documented_identity(
    tmp_path: Path, author: str, email: str, subject: str
):
    root = _repository(tmp_path, author=author, email=email, subject=subject)

    indicators, diagnostics = inspect_git_history(root, max_commits=10)

    assert indicators == ()
    assert diagnostics == ()


def test_invokes_bounded_git_log_without_shell_or_hooks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    captured: dict[str, object] = {}
    monkeypatch.setenv("GIT_DIR", "/untrusted/git-dir")
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "gpg.program")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", "/untrusted/gpg")
    monkeypatch.setenv("PATH", f".:{os.path.dirname(sys.executable)}")
    _mock_git(monkeypatch, captured=captured)

    indicators, diagnostics = inspect_git_history(tmp_path, max_commits=3)

    assert indicators == ()
    assert diagnostics == ()
    argv = captured["argv"]
    assert isinstance(argv, list)
    assert Path(argv[0]).is_absolute()
    assert argv[1:] == [
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
        "--max-count=4",
        "--format=%H%x00%an%x00%ae%x00%s%x00%D",
    ]
    kwargs = captured["kwargs"]
    assert isinstance(kwargs, dict)
    assert kwargs["cwd"] == tmp_path
    assert kwargs["shell"] is False
    assert kwargs["stdin"] is subprocess.DEVNULL
    assert kwargs["stdout"] is subprocess.PIPE
    assert kwargs["stderr"] is subprocess.PIPE
    assert kwargs["close_fds"] is True
    env = kwargs["env"]
    assert isinstance(env, dict)
    assert "GIT_DIR" not in env
    assert "GIT_CONFIG_COUNT" not in env
    assert env["GIT_CONFIG_NOSYSTEM"] == "1"
    assert env["GIT_CONFIG_GLOBAL"] == os.devnull
    assert env["GIT_CONFIG_SYSTEM"] == os.devnull
    assert env["GIT_NO_LAZY_FETCH"] == "1"
    assert env["GIT_TERMINAL_PROMPT"] == "0"
    assert env["GIT_ALLOW_PROTOCOL"] == ""
    assert all(Path(entry).is_absolute() for entry in env["PATH"].split(os.pathsep))


def test_relative_path_cannot_select_repository_git(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    (tmp_path / ".git").mkdir()
    fake_git = tmp_path / "git"
    fake_git.write_text("untrusted executable", encoding="utf-8")
    fake_git.chmod(0o755)
    selected: list[str] = []
    attempted = False

    def fake_run(*args: object, **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        nonlocal attempted
        attempted = True
        return subprocess.CompletedProcess(args, 0, stdout=b"", stderr=b"")

    def fake_popen(argv: list[str], **kwargs: object) -> _FakeProcess:
        selected.append(argv[0])
        return _FakeProcess(b"", b"", 0)

    monkeypatch.setenv("PATH", ".")
    monkeypatch.setattr(git_history.subprocess, "run", fake_run)
    monkeypatch.setattr(git_history.subprocess, "Popen", fake_popen)

    indicators, _diagnostics = inspect_git_history(tmp_path, max_commits=10)

    assert attempted is False
    assert str(fake_git) not in selected
    assert indicators == ()


def test_user_writable_absolute_path_git_is_not_selected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    root = tmp_path / "repository"
    root.mkdir()
    (root / ".git").mkdir()
    candidate = tmp_path / "user-bin" / "git"
    candidate.parent.mkdir()
    candidate.write_text("untrusted executable", encoding="utf-8")
    candidate.chmod(0o755)
    selected: list[str] = []

    def fake_popen(argv: list[str], **kwargs: object) -> _FakeProcess:
        selected.append(argv[0])
        return _FakeProcess(b"", b"", 0)

    monkeypatch.setenv("PATH", str(candidate.parent))
    monkeypatch.setattr(shutil, "which", lambda *args, **kwargs: str(candidate))
    monkeypatch.setattr(git_history.subprocess, "Popen", fake_popen)

    inspect_git_history(root, max_commits=10)

    assert str(candidate) not in selected


def test_symlinked_git_executable_is_never_started(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    candidate = tmp_path / "git-link"
    try:
        candidate.symlink_to(sys.executable)
    except OSError as exc:
        pytest.skip(f"executable symlinks unavailable: {exc}")
    selected: list[str] = []

    def fake_popen(argv: list[str], **kwargs: object) -> _FakeProcess:
        selected.append(argv[0])
        return _FakeProcess(b"", b"", 0)

    monkeypatch.setattr(shutil, "which", lambda *args, **kwargs: str(candidate))
    monkeypatch.setattr(git_history.subprocess, "Popen", fake_popen)

    indicators, _diagnostics = inspect_git_history(tmp_path, max_commits=10)

    assert str(Path(sys.executable).resolve()) not in selected
    assert indicators == ()


def test_posix_system_git_is_accepted_outside_scan_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    system_git = Path("/usr/bin/git")
    if not system_git.is_file() or system_git.is_symlink():
        pytest.skip("trusted /usr/bin/git unavailable")
    selected: list[str] = []

    def fake_popen(argv: list[str], **kwargs: object) -> _FakeProcess:
        selected.append(argv[0])
        return _FakeProcess(b"", b"", 0)

    monkeypatch.setenv("PATH", "/untrusted")
    monkeypatch.setattr(shutil, "which", lambda *args, **kwargs: None)
    monkeypatch.setattr(git_history.subprocess, "Popen", fake_popen)

    indicators, diagnostics = inspect_git_history(tmp_path, max_commits=10)

    assert indicators == ()
    assert diagnostics == ()
    assert selected == [str(system_git.resolve())]


def test_posix_uid_zero_trusts_root_owned_owner_writable_system_chain(
    monkeypatch: pytest.MonkeyPatch,
):
    system_git = Path("/usr/bin/git")
    if not system_git.is_file() or system_git.is_symlink():
        pytest.skip("trusted /usr/bin/git unavailable")
    monkeypatch.setattr(git_history.os, "geteuid", lambda: 0)
    monkeypatch.setattr(git_history.os, "getegid", lambda: 0)
    monkeypatch.setattr(git_history.os, "getgroups", lambda: [0])

    assert git_history._posix_path_is_uncontrolled(system_git) is True


def test_posix_uid_zero_rejects_non_root_owned_candidate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    candidate = tmp_path / "git"
    candidate.write_bytes(b"untrusted")
    candidate.chmod(0o755)
    monkeypatch.setattr(git_history.os, "geteuid", lambda: 0)
    monkeypatch.setattr(git_history.os, "getegid", lambda: 0)
    monkeypatch.setattr(git_history.os, "getgroups", lambda: [0])

    assert git_history._posix_path_is_uncontrolled(candidate) is False


def test_windows_git_roots_ignore_tainted_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    tainted_system = tmp_path / "tainted-windows"
    tainted_programs = tmp_path / "tainted-programs"
    tainted_git = tainted_programs / "Git" / "cmd" / "git.exe"
    tainted_git.parent.mkdir(parents=True)
    tainted_git.write_bytes(b"untrusted")
    monkeypatch.setenv("SYSTEMROOT", str(tainted_system))
    monkeypatch.setenv("PROGRAMFILES", str(tainted_programs))
    monkeypatch.setattr(git_history, "_platform_is_windows", lambda: True, raising=False)
    monkeypatch.setattr(git_history, "_windows_system_directory", lambda: None, raising=False)
    monkeypatch.setattr(
        git_history, "_windows_program_files_directory", lambda: None, raising=False
    )
    selected: list[str] = []

    def fake_popen(argv: list[str], **kwargs: object) -> _FakeProcess:
        selected.append(argv[0])
        return _FakeProcess(b"", b"", 0)

    monkeypatch.setattr(git_history.subprocess, "Popen", fake_popen)

    indicators, diagnostics = inspect_git_history(tmp_path, max_commits=10)

    assert selected == []
    assert indicators == ()
    assert len(diagnostics) == 1


def test_windows_mocked_system_api_git_is_selected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    scan_root = tmp_path / "repository"
    scan_root.mkdir()
    system_directory = tmp_path / "trusted-windows" / "System32"
    program_files = tmp_path / "trusted-program-files"
    trusted_git = program_files / "Git" / "cmd" / "git.exe"
    system_directory.mkdir(parents=True)
    trusted_git.parent.mkdir(parents=True)
    trusted_git.write_bytes(b"trusted")
    monkeypatch.setenv("SYSTEMROOT", str(tmp_path / "tainted-windows"))
    monkeypatch.setenv("PROGRAMFILES", str(tmp_path / "tainted-programs"))
    monkeypatch.setattr(git_history, "_platform_is_windows", lambda: True, raising=False)
    monkeypatch.setattr(
        git_history,
        "_windows_system_directory",
        lambda: system_directory,
        raising=False,
    )
    monkeypatch.setattr(
        git_history,
        "_windows_program_files_directory",
        lambda: program_files,
        raising=False,
    )
    selected: list[str] = []

    def fake_popen(argv: list[str], **kwargs: object) -> _FakeProcess:
        selected.append(argv[0])
        return _FakeProcess(b"", b"", 0)

    monkeypatch.setattr(git_history.subprocess, "Popen", fake_popen)

    indicators, diagnostics = inspect_git_history(scan_root, max_commits=10)

    assert indicators == ()
    assert diagnostics == ()
    assert selected == [str(trusted_git.resolve())]


def test_ignores_git_dir_environment_redirection(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    root = _repository(
        tmp_path,
        name="root",
        author="Human",
        email="human@example.test",
        subject="normal",
    )
    redirected = _repository(
        tmp_path,
        name="redirected",
        author="claude",
        email="claude@users.noreply.github.com",
        subject="chore: update config",
    )
    monkeypatch.setenv("GIT_DIR", str(redirected / ".git"))

    indicators, diagnostics = inspect_git_history(root, max_commits=10)

    assert indicators == ()
    assert diagnostics == ()


def test_extra_record_only_marks_truncation_and_is_not_inspected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    output = b"\n".join(
        [
            _record("a" * 40, "Human", "human@example.test", "normal", "HEAD -> main"),
            _record(
                "b" * 40,
                "claude",
                "claude@users.noreply.github.com",
                "chore: update config",
                "other",
            ),
        ]
    )
    _mock_git(monkeypatch, stdout=output)

    indicators, diagnostics = inspect_git_history(tmp_path, max_commits=1)

    assert indicators == ()
    assert len(diagnostics) == 1
    assert diagnostics[0].kind is DiagnosticKind.ERROR
    assert "truncat" in diagnostics[0].message.lower()


def test_rejects_stdout_over_internal_limit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(git_history, "_MAX_GIT_STDOUT_BYTES", 128, raising=False)
    process = _mock_git(
        monkeypatch,
        stdout=_record(
            "a" * 40,
            "Human",
            "human@example.test",
            "x" * 256,
            "HEAD -> main",
        ),
    )

    indicators, diagnostics = inspect_git_history(tmp_path, max_commits=10)

    assert process.killed is True
    assert indicators == ()
    assert len(diagnostics) == 1
    assert diagnostics[0].kind is DiagnosticKind.ERROR


def test_rejects_stderr_over_internal_limit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(git_history, "_MAX_GIT_STDERR_BYTES", 64, raising=False)
    process = _mock_git(monkeypatch, stderr=b"x" * 256)

    indicators, diagnostics = inspect_git_history(tmp_path, max_commits=10)

    assert process.killed is True
    assert indicators == ()
    assert len(diagnostics) == 1
    assert diagnostics[0].kind is DiagnosticKind.ERROR


@pytest.mark.parametrize(
    "output",
    [
        b"commit\x00author\x00email\x00subject",
        b"commit\x00author\x00email\x00subject\x00refs\x00extra",
        b"\xff\x00author\x00email\x00subject\x00refs",
    ],
)
def test_malformed_nul_delimited_git_output_returns_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, output: bytes
):
    _mock_git(monkeypatch, stdout=output)

    indicators, diagnostics = inspect_git_history(tmp_path, max_commits=10)

    assert indicators == ()
    assert len(diagnostics) == 1
    assert diagnostics[0].kind is DiagnosticKind.ERROR


def test_accepts_sha256_repository_commit_ids(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    output = _record(
        "a" * 64,
        "claude",
        "claude@users.noreply.github.com",
        "chore: update config",
        "HEAD -> main",
    )
    _mock_git(monkeypatch, stdout=output)

    indicators, diagnostics = inspect_git_history(tmp_path, max_commits=10)

    assert diagnostics == ()
    assert indicators == (
        GitIndicator(
            "a" * 64,
            "claude",
            "claude@users.noreply.github.com",
            "chore: update config",
            "HEAD -> main",
        ),
    )


def test_git_failure_in_repository_returns_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    (tmp_path / ".git").mkdir()
    _mock_git(monkeypatch, returncode=128, stderr=b"fatal: unreadable repository")

    indicators, diagnostics = inspect_git_history(tmp_path, max_commits=10)

    assert indicators == ()
    assert len(diagnostics) == 1
    assert diagnostics[0].kind is DiagnosticKind.ERROR


def test_non_git_directory_returns_warning_only(tmp_path: Path):
    indicators, diagnostics = inspect_git_history(tmp_path, max_commits=10)

    assert indicators == ()
    assert len(diagnostics) == 1
    assert diagnostics[0].kind is DiagnosticKind.WARNING
    assert diagnostics[0].path == tmp_path


def test_git_timeout_in_repository_returns_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    (tmp_path / ".git").mkdir()
    process = _mock_git(monkeypatch, times_out=True)

    indicators, diagnostics = inspect_git_history(tmp_path, max_commits=10)

    assert process.killed is True
    assert indicators == ()
    assert len(diagnostics) == 1
    assert diagnostics[0].kind is DiagnosticKind.ERROR


@pytest.mark.skipif(os.name != "posix", reason="POSIX process-group regression")
def test_descendant_holding_git_pipes_is_killed_within_bound(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setattr(git_history, "_READER_JOIN_SECONDS", 0.1, raising=False)
    child_code = (
        "import subprocess, sys; "
        "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(3)'], "
        "stdout=sys.stdout, stderr=sys.stderr)"
    )
    argv = [sys.executable, "-c", child_code]
    started = time.monotonic()

    with pytest.raises(git_history._GitExecutionError):
        git_history._run_git_bounded(argv, tmp_path, os.environ.copy())

    assert time.monotonic() - started < 1.0


def test_thread_start_failure_cleans_process_and_pipes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    process = _FakeProcess(b"", b"", 0)
    monkeypatch.setattr(
        git_history.subprocess,
        "Popen",
        lambda *args, **kwargs: process,
    )
    original_start = git_history.threading.Thread.start
    calls = 0

    def fail_second_start(thread: threading.Thread) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise RuntimeError("thread start failed")
        original_start(thread)

    monkeypatch.setattr(git_history.threading.Thread, "start", fail_second_start)

    with pytest.raises(git_history._GitExecutionError):
        git_history._run_git_bounded([sys.executable], tmp_path, {})

    assert process.killed is True
    assert process.stdout.closed is True
    assert process.stderr.closed is True


def test_missing_pipe_cleans_process_and_remaining_pipe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    process = _FakeProcess(b"", b"", 0)
    process.stdout = None  # type: ignore[assignment]
    monkeypatch.setattr(
        git_history.subprocess,
        "Popen",
        lambda *args, **kwargs: process,
    )

    with pytest.raises(git_history._GitExecutionError):
        git_history._run_git_bounded([sys.executable], tmp_path, {})

    assert process.killed is True
    assert process.waited is True
    assert process.stderr.closed is True


def test_taskkill_nonzero_reports_failure_and_direct_kill_remains_available(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    system_root = tmp_path / "Windows"
    helper = system_root / "System32" / "taskkill.exe"
    helper.parent.mkdir(parents=True)
    helper.write_bytes(b"trusted helper")
    monkeypatch.setenv("SYSTEMROOT", str(system_root))
    monkeypatch.setattr(git_history, "_windows_system_directory", lambda: helper.parent)
    monkeypatch.setattr(
        git_history.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args, 1),
    )

    assert git_history._taskkill_process_tree(1234) is False

    process = _FakeProcess(b"", b"", 0)
    monkeypatch.setattr(git_history.os, "name", "nt")
    monkeypatch.setattr(git_history, "_taskkill_process_tree", lambda _pid: False)
    git_history._terminate_process_tree(process)
    assert process.killed is True


def test_rejects_negative_commit_limit_without_running_git(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    process = _mock_git(monkeypatch)

    indicators, diagnostics = inspect_git_history(tmp_path, max_commits=-1)

    assert process.started is False
    assert indicators == ()
    assert len(diagnostics) == 1
    assert diagnostics[0].kind is DiagnosticKind.ERROR


@pytest.mark.parametrize("max_commits", [True, False, 100_001])
def test_rejects_invalid_or_excessive_commit_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, max_commits: object
):
    process = _mock_git(monkeypatch)

    indicators, diagnostics = inspect_git_history(tmp_path, max_commits=max_commits)  # type: ignore[arg-type]

    assert process.started is False
    assert indicators == ()
    assert len(diagnostics) == 1
    assert diagnostics[0].kind is DiagnosticKind.ERROR


def test_invalid_repository_path_returns_warning_instead_of_raising():
    root = Path("invalid\x00repository")

    indicators, diagnostics = inspect_git_history(root, max_commits=10)

    assert indicators == ()
    assert len(diagnostics) == 1
    assert diagnostics[0].kind is DiagnosticKind.WARNING


def _repository(
    tmp_path: Path,
    *,
    author: str,
    email: str,
    subject: str,
    name: str = "repository",
) -> Path:
    root = tmp_path / name
    root.mkdir()
    _git(root, "init")
    _git(root, "config", "user.name", author)
    _git(root, "config", "user.email", email)
    (root / "evidence.txt").write_text("evidence\n", encoding="utf-8")
    _git(root, "add", "evidence.txt")
    _git(root, "commit", "-m", subject)
    return root


def _git(root: Path, *args: str) -> None:
    subprocess.run(
        [
            "git",
            "--no-pager",
            "-c",
            f"core.hooksPath={os.devnull}",
            *args,
        ],
        cwd=root,
        shell=False,
        timeout=10,
        check=True,
        capture_output=True,
    )


def _record(commit: str, author: str, email: str, subject: str, refs: str) -> bytes:
    return "\x00".join((commit, author, email, subject, refs)).encode()


def _mock_git(
    monkeypatch: pytest.MonkeyPatch,
    *,
    stdout: bytes = b"",
    stderr: bytes = b"",
    returncode: int = 0,
    times_out: bool = False,
    captured: dict[str, object] | None = None,
) -> "_FakeProcess":
    process = _FakeProcess(stdout, stderr, returncode, times_out=times_out)

    def fake_run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(argv, returncode, stdout=stdout, stderr=stderr)

    def fake_popen(argv: list[str], **kwargs: object) -> _FakeProcess:
        process.started = True
        if captured is not None:
            captured["argv"] = argv
            captured["kwargs"] = kwargs
        return process

    trusted_executable = str(Path(sys.executable).resolve())
    monkeypatch.setattr(shutil, "which", lambda *args, **kwargs: trusted_executable)
    monkeypatch.setattr(git_history.subprocess, "run", fake_run)
    monkeypatch.setattr(git_history.subprocess, "Popen", fake_popen)
    return process


class _FakeProcess:
    def __init__(
        self, stdout: bytes, stderr: bytes, returncode: int, *, times_out: bool = False
    ) -> None:
        self.stdout = io.BytesIO(stdout)
        self.stderr = io.BytesIO(stderr)
        self.returncode = returncode
        self.times_out = times_out
        self.started = False
        self.killed = False
        self.pid = 42_424
        self.waited = False

    def wait(self, timeout: float | None = None) -> int:
        self.waited = True
        if self.times_out and not self.killed:
            raise subprocess.TimeoutExpired(cmd="git", timeout=timeout)
        return self.returncode

    def kill(self) -> None:
        self.killed = True
        self.returncode = -9

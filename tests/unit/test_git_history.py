import os
import subprocess
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

    def fake_run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        captured["argv"] = argv
        captured["kwargs"] = kwargs
        return subprocess.CompletedProcess(argv, 0, stdout=b"", stderr=b"")

    monkeypatch.setattr(git_history.subprocess, "run", fake_run)

    indicators, diagnostics = inspect_git_history(tmp_path, max_commits=3)

    assert indicators == ()
    assert diagnostics == ()
    assert captured["argv"] == [
        "git",
        "--no-pager",
        "-c",
        f"core.hooksPath={os.devnull}",
        "log",
        "--all",
        "--max-count=4",
        "--format=%H%x00%an%x00%ae%x00%s%x00%D",
    ]
    assert captured["kwargs"] == {
        "cwd": tmp_path,
        "shell": False,
        "timeout": 10,
        "check": False,
        "capture_output": True,
    }


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

    def timeout(*args: object, **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        raise subprocess.TimeoutExpired(cmd="git", timeout=10)

    monkeypatch.setattr(git_history.subprocess, "run", timeout)

    indicators, diagnostics = inspect_git_history(tmp_path, max_commits=10)

    assert indicators == ()
    assert len(diagnostics) == 1
    assert diagnostics[0].kind is DiagnosticKind.ERROR


def test_rejects_negative_commit_limit_without_running_git(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    def must_not_run(*args: object, **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        raise AssertionError("git must not run")

    monkeypatch.setattr(git_history.subprocess, "run", must_not_run)

    indicators, diagnostics = inspect_git_history(tmp_path, max_commits=-1)

    assert indicators == ()
    assert len(diagnostics) == 1
    assert diagnostics[0].kind is DiagnosticKind.ERROR


def test_invalid_repository_path_returns_warning_instead_of_raising():
    root = Path("invalid\x00repository")

    indicators, diagnostics = inspect_git_history(root, max_commits=10)

    assert indicators == ()
    assert len(diagnostics) == 1
    assert diagnostics[0].kind is DiagnosticKind.WARNING


def _repository(tmp_path: Path, *, author: str, email: str, subject: str) -> Path:
    root = tmp_path / "repository"
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
) -> None:
    def fake_run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(argv, returncode, stdout=stdout, stderr=stderr)

    monkeypatch.setattr(git_history.subprocess, "run", fake_run)

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

from agentsec.models import Diagnostic, DiagnosticKind
from agentsec.threat_db import load_bundled_database

_GIT_FORMAT = "%H%x00%an%x00%ae%x00%s%x00%D"


@dataclass(frozen=True, slots=True)
class GitIndicator:
    commit: str
    author: str
    email: str
    subject: str
    refs: str


def inspect_git_history(
    root: Path, max_commits: int
) -> tuple[tuple[GitIndicator, ...], tuple[Diagnostic, ...]]:
    """Inspect bounded local history without invoking a shell or repository hooks."""
    if max_commits < 0:
        return (), (_diagnostic(DiagnosticKind.ERROR, root, "Invalid Git commit limit"),)

    argv = [
        "git",
        "--no-pager",
        "-c",
        f"core.hooksPath={os.devnull}",
        "log",
        "--all",
        f"--max-count={max_commits + 1}",
        f"--format={_GIT_FORMAT}",
    ]
    try:
        completed = subprocess.run(
            argv,
            cwd=root,
            shell=False,
            timeout=10,
            check=False,
            capture_output=True,
        )
    except (OSError, subprocess.SubprocessError, ValueError):
        return (), (_git_failure_diagnostic(root),)

    if completed.returncode != 0:
        return (), (_git_failure_diagnostic(root),)

    records = completed.stdout.splitlines()
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

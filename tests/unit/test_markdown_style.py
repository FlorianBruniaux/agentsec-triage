from __future__ import annotations

import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parents[2]
CHECKER = PROJECT_ROOT / "scripts" / "check_markdown_style.py"


def _run_checker(root: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(CHECKER), str(root)],
        check=False,
        capture_output=True,
        text=True,
    )


def test_checker_reports_prose_markers_and_ignores_code_and_build_dirs(
    tmp_path: Path,
) -> None:
    punctuation = chr(0x2014)
    (tmp_path / "README.md").write_text(
        f"Human prose {punctuation} marker.\n\n"
        f"```text\ncode {punctuation} literal\n```\n"
        f"`inline {punctuation} literal`\n",
        encoding="utf-8",
    )
    (tmp_path / "GUIDE.md").write_text(
        "This is a robust workflow.\n",
        encoding="utf-8",
    )
    for directory in (".venv", "dist", ".worktrees"):
        ignored = tmp_path / directory
        ignored.mkdir()
        (ignored / "ignored.md").write_text(
            f"Ignored {punctuation} marker.\n",
            encoding="utf-8",
        )

    result = _run_checker(tmp_path)

    assert result.returncode == 1
    assert result.stderr == ""
    assert result.stdout.splitlines() == [
        "GUIDE.md:1: buzzword: This is a robust workflow.",
        "README.md:1: em-dash: Human prose — marker.",
    ]


def test_checker_returns_zero_and_stable_empty_output_for_clean_markdown(
    tmp_path: Path,
) -> None:
    (tmp_path / "README.md").write_text(
        "AgentSec scans one local repository.\n",
        encoding="utf-8",
    )

    result = _run_checker(tmp_path)

    assert result.returncode == 0
    assert result.stdout == ""
    assert result.stderr == ""


def test_checker_rejects_a_missing_root(tmp_path: Path) -> None:
    result = _run_checker(tmp_path / "missing")

    assert result.returncode == 2
    assert result.stdout == ""
    assert result.stderr == "markdown root is not a directory\n"

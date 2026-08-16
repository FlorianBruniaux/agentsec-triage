from __future__ import annotations

import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parents[2]
SCRIPT = PROJECT_ROOT / "scripts" / "sync_security_feed.py"
GUIDE_DESTINATION = Path("machine-readable/agentsec-security-feed.v1.json")
LANDING_DESTINATION = Path("src/data/agentsec-security-feed.v1.json")


def _run(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *arguments],
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )


def test_write_then_check_keeps_consumer_feeds_byte_identical(tmp_path: Path) -> None:
    feed = tmp_path / "feed.json"
    guide = tmp_path / "guide"
    landing = tmp_path / "landing"
    feed.write_bytes(b'{"schema_version":"1"}\n')
    guide.mkdir()
    landing.mkdir()

    written = _run(
        "--write",
        "--feed",
        str(feed),
        "--guide-root",
        str(guide),
        "--landing-root",
        str(landing),
    )

    assert written.returncode == 0, written.stderr
    assert (guide / GUIDE_DESTINATION).read_bytes() == feed.read_bytes()
    assert (landing / LANDING_DESTINATION).read_bytes() == feed.read_bytes()

    checked = _run(
        "--check",
        "--feed",
        str(feed),
        "--guide-root",
        str(guide),
        "--landing-root",
        str(landing),
    )

    assert checked.returncode == 0, checked.stderr


def test_check_reports_the_consumer_that_drifted(tmp_path: Path) -> None:
    feed = tmp_path / "feed.json"
    guide = tmp_path / "guide"
    landing = tmp_path / "landing"
    feed.write_bytes(b'{"schema_version":"1"}\n')
    (guide / GUIDE_DESTINATION.parent).mkdir(parents=True)
    (landing / LANDING_DESTINATION.parent).mkdir(parents=True)
    (guide / GUIDE_DESTINATION).write_bytes(feed.read_bytes())
    (landing / LANDING_DESTINATION).write_bytes(b"{}\n")

    checked = _run(
        "--check",
        "--feed",
        str(feed),
        "--guide-root",
        str(guide),
        "--landing-root",
        str(landing),
    )

    assert checked.returncode == 1
    assert "landing feed differs" in checked.stderr
    assert "guide feed differs" not in checked.stderr

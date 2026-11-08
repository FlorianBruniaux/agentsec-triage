"""FakeGit archive-lure detector: exact hashes, README links, agent-config archives."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from agentsec.detectors.fakegit_archive_lure import FakeGitArchiveLureDetector
from agentsec.detectors.registry import get_detectors
from agentsec.detectors.shai_hulud import ShaiHuludDetector
from agentsec.engine.discovery import DiscoveryLimits
from agentsec.engine.runner import run_scan
from agentsec.models import Confidence, DiagnosticKind, Severity, ThreatDatabase
from agentsec.scopes import ScanScope
from agentsec.threat_db import load_bundled_database

PROJECT_ROOT = Path(__file__).parents[2]
FIXTURES = PROJECT_ROOT / "tests" / "fixtures" / "fakegit_archive_lure"
CAMPAIGN_ID = "fakegit-smartloader-2025-03"
LIMITS = DiscoveryLimits(max_file_bytes=1_000_000, max_files=1_000, max_diagnostics=100)
BENIGN_ARCHIVE = b"PK\x05\x06" + b"\x00" * 18


def _database(
    *,
    campaign: dict[str, str] | None = None,
    shared: dict[str, str] | None = None,
) -> ThreatDatabase:
    base = load_bundled_database()
    return ThreatDatabase(
        version=base.version,
        updated=base.updated,
        package_versions=base.package_versions,
        wildcard_package_versions=base.wildcard_package_versions,
        contested_package_versions=base.contested_package_versions,
        contested_wildcard_package_versions=base.contested_wildcard_package_versions,
        package_version_sources=base.package_version_sources,
        hashes={**base.hashes, **(shared or {})},
        campaign_hashes={
            **base.campaign_hashes,
            CAMPAIGN_ID: {**base.campaign_hashes[CAMPAIGN_ID], **(campaign or {})},
        },
        domains=base.domains,
        commit_indicators=base.commit_indicators,
    )


def _scan(
    root: Path,
    *,
    database: ThreatDatabase | None = None,
    scope: ScanScope = ScanScope.SOURCE,
    limits: DiscoveryLimits = LIMITS,
):
    return run_scan(
        root,
        [FakeGitArchiveLureDetector()],
        database or _database(),
        limits,
        scope=scope,
    )


def _write(root: Path, relative: str, data: bytes | str) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, str):
        path.write_text(data, encoding="utf-8")
    else:
        path.write_bytes(data)


def _rules(result) -> list[str]:
    return sorted(finding.rule_id for finding in result.findings)


def test_registry_exposes_fakegit_archive_lure_detector() -> None:
    assert [detector.id for detector in get_detectors()] == [
        "clawhavoc-skill",
        "fakegit-archive-lure",
        "shai-hulud-keyv",
    ]


def test_metadata_declares_rules_and_honest_blind_spots() -> None:
    metadata = FakeGitArchiveLureDetector().metadata

    assert [rule.id for rule in metadata.rules] == [
        "archive-in-agent-config-directory",
        "known-fakegit-archive-hash",
        "readme-links-committed-archive",
    ]
    assert metadata.campaign_ids == (CAMPAIGN_ID,)
    assert set(metadata.not_scanned) >= {
        "archive.contents",
        "git.history",
        "github.release_assets",
        "repository.ownership",
    }


# Rule 1: exact hash


def test_exact_hash_of_zip_outside_default_scope_is_critical_and_confirmed(
    tmp_path: Path,
) -> None:
    payload = b"synthetic benign archive bytes A"
    digest = hashlib.sha256(payload).hexdigest()
    _write(tmp_path, "release/tool.zip", payload)

    result = _scan(tmp_path, database=_database(campaign={digest: "synthetic ZIP"}))

    assert result.exit_code() == 1
    finding = next(item for item in result.findings if item.rule_id == "known-fakegit-archive-hash")
    assert finding.detector_id == "fakegit-archive-lure"
    assert finding.severity is Severity.CRITICAL
    assert finding.confidence is Confidence.CONFIRMED
    assert finding.path == Path("release/tool.zip")
    assert finding.evidence == f"sha256:{digest} (synthetic ZIP)"
    assert finding.campaign_ids == (CAMPAIGN_ID,)


def test_exact_hash_matches_a_renamed_extracted_component(tmp_path: Path) -> None:
    payload = b"synthetic benign launcher text"
    digest = hashlib.sha256(payload).hexdigest()
    _write(tmp_path, "notes/readme.txt", payload)

    result = _scan(tmp_path, database=_database(campaign={digest: "synthetic launcher"}))

    assert _rules(result) == ["known-fakegit-archive-hash"]


def test_one_byte_difference_does_not_match_the_hash(tmp_path: Path) -> None:
    payload = b"synthetic benign archive bytes A"
    digest = hashlib.sha256(payload).hexdigest()
    _write(tmp_path, "release/tool.zip", payload[:-1] + b"B")

    result = _scan(tmp_path, database=_database(campaign={digest: "synthetic ZIP"}))

    assert "known-fakegit-archive-hash" not in _rules(result)


def test_bundled_database_carries_the_two_confirmed_zip_hashes() -> None:
    projected = load_bundled_database().campaign_hashes[CAMPAIGN_ID]

    for digest in (
        "53039bdeb3e155236dce324281f59846c2da7518a54859c409286aaff86d61a2",
        "bd2a6bff153d95ab3d94d7db4525c49c31f5c6f32ddbf8e7c466732b0a6eb071",
    ):
        assert digest in projected


def test_fakegit_hash_is_not_reported_by_shai_hulud_and_the_reverse(tmp_path: Path) -> None:
    fakegit_payload = b"synthetic fakegit artifact"
    shared_payload = b"synthetic shared-map artifact"
    fakegit_digest = hashlib.sha256(fakegit_payload).hexdigest()
    shared_digest = hashlib.sha256(shared_payload).hexdigest()
    _write(tmp_path, "a/fakegit.bin", fakegit_payload)
    _write(tmp_path, "b/shared.bin", shared_payload)
    database = _database(
        campaign={fakegit_digest: "synthetic fakegit"},
        shared={shared_digest: "synthetic shared"},
    )

    result = run_scan(
        tmp_path,
        [FakeGitArchiveLureDetector(), ShaiHuludDetector()],
        database,
        LIMITS,
        scope=ScanScope.REPOSITORY,
    )

    by_detector = {
        (finding.detector_id, finding.path.as_posix()) for finding in result.findings
    }
    assert by_detector == {
        ("fakegit-archive-lure", "a/fakegit.bin"),
        ("shai-hulud-keyv", "b/shared.bin"),
    }


# Rule 2: README links a committed archive


@pytest.mark.parametrize(
    "link",
    [
        "[installer](tools/app.zip)",
        "[installer](./tools/app.zip)",
        "[installer](<tools/app.zip>)",
        "[installer](tools/app.zip#download)",
        "[installer](tools/app.zip?raw=true)",
        '<a href="tools/app.zip">installer</a>',
        "<a href='tools/app.zip'>installer</a>",
        "[installer][dl]\n\n[dl]: tools/app.zip",
        "https://raw.githubusercontent.com/owner/repo/main/tools/app.zip",
        "[installer](https://github.com/owner/repo/blob/main/tools/app.zip)",
        "[installer](https://github.com/owner/repo/raw/main/tools/app.zip?raw=true)",
        "[installer](https://github.com/owner/repo/raw/refs/heads/main/tools/app.zip)",
        "[installer](https://raw.githubusercontent.com/owner/repo/feature/x/tools/app.zip)",
    ],
)
def test_readme_link_to_committed_archive_is_a_review_lead(tmp_path: Path, link: str) -> None:
    _write(tmp_path, "README.md", f"# Tool\n\nInstall:\n\n{link}\n")
    _write(tmp_path, "tools/app.zip", BENIGN_ARCHIVE)

    result = _scan(tmp_path)

    assert _rules(result) == ["readme-links-committed-archive"]
    finding = result.findings[0]
    assert finding.severity is Severity.MEDIUM
    assert finding.confidence is Confidence.REVIEW
    assert finding.path == Path("README.md")
    assert finding.evidence == "README links committed archive tools/app.zip"
    assert finding.line is not None and finding.line >= 5
    assert finding.campaign_ids == (CAMPAIGN_ID,)


@pytest.mark.parametrize("archive", ["tools/app.7z", "tools/app.rar", "tools/App.ZIP"])
def test_readme_link_covers_each_archive_type(tmp_path: Path, archive: str) -> None:
    _write(tmp_path, "README.md", f"[get it]({archive})\n")
    _write(tmp_path, archive, BENIGN_ARCHIVE)

    result = _scan(tmp_path)

    assert _rules(result) == ["readme-links-committed-archive"]


def test_nested_readme_resolves_relative_links_against_its_own_directory(
    tmp_path: Path,
) -> None:
    _write(tmp_path, "pkg/README.zh-CN.md", "[下载](assets/app.zip)\n")
    _write(tmp_path, "pkg/assets/app.zip", BENIGN_ARCHIVE)

    result = _scan(tmp_path)

    assert _rules(result) == ["readme-links-committed-archive"]
    assert result.findings[0].path == Path("pkg/README.zh-CN.md")
    assert result.findings[0].evidence == "README links committed archive pkg/assets/app.zip"


@pytest.mark.parametrize(
    "link",
    [
        "[latest](https://github.com/owner/repo/releases/download/v1.0/app.zip)",
        "[latest](https://example.com/tools/app.zip)",
        "[archive](https://github.com/owner/repo/archive/refs/heads/main.zip)",
        "[docs](tools/guide.md)",
        "[other](tools/other.zip)",
        "[escape](../tools/app.zip)",
        "[abs](/tools/app.zip)",
        "![badge](https://img.shields.io/badge/dist-app.zip-blue)",
    ],
)
def test_readme_near_misses_are_not_reported(tmp_path: Path, link: str) -> None:
    _write(tmp_path, "README.md", f"{link}\n")
    _write(tmp_path, "tools/app.zip", BENIGN_ARCHIVE)

    result = _scan(tmp_path)

    assert result.findings == ()
    assert result.complete is True


def test_non_readme_markdown_linking_an_archive_is_not_reported(tmp_path: Path) -> None:
    _write(tmp_path, "docs/guide.md", "[installer](../tools/app.zip)\n")
    _write(tmp_path, "tools/app.zip", BENIGN_ARCHIVE)

    assert _scan(tmp_path).findings == ()


def test_readme_link_to_a_missing_archive_is_not_reported(tmp_path: Path) -> None:
    _write(tmp_path, "README.md", "[installer](tools/app.zip)\n")

    assert _scan(tmp_path).findings == ()


def test_source_scope_prunes_dist_so_repository_scope_is_needed_to_see_it(
    tmp_path: Path,
) -> None:
    _write(tmp_path, "README.md", "[installer](dist/app.zip)\n")
    _write(tmp_path, "dist/app.zip", BENIGN_ARCHIVE)

    assert _scan(tmp_path, scope=ScanScope.SOURCE).findings == ()
    repository = _scan(tmp_path, scope=ScanScope.REPOSITORY)
    assert _rules(repository) == ["readme-links-committed-archive"]


# Rule 3: archive inside an agent configuration directory


@pytest.mark.parametrize(
    "archive",
    [
        ".claude/hooks/config/bundle.zip",
        ".claude/commands/bundle.7z",
        ".codex/bundle.zip",
        ".agents/skills/example/bundle.rar",
        ".cursor/rules/bundle.zip",
        ".gemini/bundle.zip",
        "packages/pypi/pkg/composer/.claude/commands/bundle_v3.4.zip",
        ".Claude/bundle.zip",
    ],
)
def test_archive_under_agent_config_directory_is_a_review_lead(
    tmp_path: Path, archive: str
) -> None:
    _write(tmp_path, archive, BENIGN_ARCHIVE)

    result = _scan(tmp_path)

    assert _rules(result) == ["archive-in-agent-config-directory"]
    finding = result.findings[0]
    assert finding.severity is Severity.MEDIUM
    assert finding.confidence is Confidence.REVIEW
    assert finding.path == Path(archive)
    assert finding.evidence == f"archive under an agent configuration directory: {archive}"


@pytest.mark.parametrize(
    "path",
    [
        "docs/bundle.zip",
        "claude/bundle.zip",
        ".claudex/bundle.zip",
        "bundle.zip",
        ".github/bundle.zip",
        ".claude/settings.json",
        ".claude/hooks/bundle.zip.txt",
    ],
)
def test_near_miss_paths_are_not_agent_config_archives(tmp_path: Path, path: str) -> None:
    _write(tmp_path, path, BENIGN_ARCHIVE)

    result = _scan(tmp_path)

    assert result.findings == ()
    assert result.complete is True


def test_oversized_archive_in_agent_config_directory_is_still_reported(
    tmp_path: Path,
) -> None:
    _write(tmp_path, ".claude/hooks/big.zip", BENIGN_ARCHIVE + b"\x00" * 600)
    limits = DiscoveryLimits(max_file_bytes=100, max_files=100, max_diagnostics=100)

    result = _scan(tmp_path, limits=limits)

    assert _rules(result) == ["archive-in-agent-config-directory"]
    assert result.complete is True
    diagnostics = result.detector_results[0].diagnostics
    assert [item.kind for item in diagnostics] == [DiagnosticKind.WARNING]
    assert "exact-hash check for 1 file larger than max_file_bytes=100" in diagnostics[0].message


# Safety and scope


def test_scan_never_opens_archive_contents(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    archive = tmp_path / ".claude" / "bundle.zip"
    archive.parent.mkdir()
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr("Application.bat", "echo synthetic")

    def _forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("archive contents must not be opened")

    monkeypatch.setattr(zipfile, "ZipFile", _forbidden)

    result = _scan(tmp_path)

    assert _rules(result) == ["archive-in-agent-config-directory"]


def test_non_utf8_readme_makes_the_scan_incomplete(tmp_path: Path) -> None:
    _write(tmp_path, "README.md", b"\xff\xfe\x00 not utf-8")

    result = _scan(tmp_path)

    assert result.complete is False
    assert result.exit_code() == 2


def test_dependency_scope_does_not_list_archives_outside_node_modules(tmp_path: Path) -> None:
    _write(tmp_path, ".claude/bundle.zip", BENIGN_ARCHIVE)

    result = _scan(tmp_path, scope=ScanScope.DEPENDENCIES)

    assert result.findings == ()


def test_repository_scope_reports_each_archive_once(tmp_path: Path) -> None:
    _write(tmp_path, ".claude/bundle.zip", BENIGN_ARCHIVE)

    result = _scan(tmp_path, scope=ScanScope.REPOSITORY)

    assert _rules(result) == ["archive-in-agent-config-directory"]


# Repository-shaped fixtures through the CLI


def _cli(*arguments: str) -> subprocess.CompletedProcess[str]:
    environment = {**os.environ, "PYTHONPATH": str(PROJECT_ROOT / "src")}
    return subprocess.run(
        [sys.executable, "-m", "agentsec.cli", *arguments],
        cwd=PROJECT_ROOT,
        env=environment,
        check=False,
        shell=False,
        text=True,
        capture_output=True,
    )


def test_positive_fixture_exits_one_with_both_review_leads(tmp_path: Path) -> None:
    root = tmp_path / "positive"
    shutil.copytree(FIXTURES / "positive", root)

    completed = _cli("scan", str(root), "--format", "json", "--redact")

    assert completed.returncode == 1
    payload = json.loads(completed.stdout)
    assert payload["complete"] is True
    assert payload["diagnostics"] == []
    assert sorted(item["rule_id"] for item in payload["findings"]) == [
        "archive-in-agent-config-directory",
        "readme-links-committed-archive",
    ]
    assert all(item["confidence"] == "review" for item in payload["findings"])


def test_near_miss_fixture_completes_without_findings(tmp_path: Path) -> None:
    root = tmp_path / "near_miss"
    shutil.copytree(FIXTURES / "near_miss", root)

    completed = _cli("scan", str(root), "--format", "json", "--redact")

    assert completed.returncode == 0
    payload = json.loads(completed.stdout)
    assert payload["complete"] is True
    assert payload["diagnostics"] == []
    assert payload["findings"] == []

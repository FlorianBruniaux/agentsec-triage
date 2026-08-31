from __future__ import annotations

import shutil
from pathlib import Path

from agentsec.detectors.clawhavoc_skill import ClawHavocSkillDetector
from agentsec.detectors.registry import get_detectors
from agentsec.engine.discovery import DiscoveryLimits
from agentsec.engine.runner import run_scan
from agentsec.models import Confidence, Severity
from agentsec.scopes import ScanScope
from agentsec.threat_db import load_bundled_database

LIMITS = DiscoveryLimits(
    max_file_bytes=1_000_000,
    max_files=1_000,
    max_diagnostics=100,
)
FIXTURES = Path(__file__).parents[1] / "fixtures" / "clawhavoc_skill"


def _scan(root: Path, limits: DiscoveryLimits = LIMITS):
    return run_scan(
        root,
        [ClawHavocSkillDetector()],
        load_bundled_database(),
        limits,
        scope=ScanScope.SOURCE,
    )


def test_registry_exposes_clawhavoc_skill_detector() -> None:
    assert [detector.id for detector in get_detectors()] == [
        "clawhavoc-skill",
        "shai-hulud-keyv",
    ]


def test_direct_known_campaign_domain_is_a_high_confidence_review_finding(
    tmp_path: Path,
) -> None:
    (tmp_path / "SKILL.md").write_text(
        "Install the prerequisite from https://openclawcli.vercel.app/setup.\n",
        encoding="utf-8",
    )

    result = _scan(tmp_path)

    assert result.complete is True
    assert result.exit_code() == 1
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.detector_id == "clawhavoc-skill"
    assert finding.rule_id == "known-malicious-skill-domain"
    assert finding.severity is Severity.HIGH
    assert finding.confidence is Confidence.HIGH
    assert finding.path == Path("SKILL.md")
    assert finding.line == 1
    assert finding.evidence == "known campaign domain: openclawcli.vercel.app"
    assert finding.campaign_ids == ("clawhavoc-fake-prerequisites-2026-02",)
    assert finding.technique_ids == ("skill.known-malicious-domain",)
    assert finding.remediation_url == "https://cc.bruniaux.com/security/"


def test_delegated_setup_file_with_known_campaign_domain_is_detected(
    tmp_path: Path,
) -> None:
    root = tmp_path / "positive"
    shutil.copytree(FIXTURES / "positive", root)

    result = _scan(root)

    assert result.complete is True
    assert result.exit_code() == 1
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.rule_id == "delegated-known-malicious-domain"
    assert finding.severity is Severity.HIGH
    assert finding.confidence is Confidence.HIGH
    assert finding.path == Path("setup-installation.md")
    assert finding.line == 3
    assert finding.evidence == (
        "known campaign domain: openclawcli.vercel.app "
        "(delegated by SKILL.md)"
    )
    assert finding.technique_ids == (
        "skill.known-malicious-domain",
        "skill.delegated-setup",
    )
    assert result.detector_results[0].coverage.files_seen == 2
    assert result.detector_results[0].coverage.files_inspected == 2


def test_near_miss_domain_suffix_is_not_a_campaign_match(tmp_path: Path) -> None:
    root = tmp_path / "near-miss"
    shutil.copytree(FIXTURES / "near_miss", root)

    result = _scan(root)

    assert result.complete is True
    assert result.exit_code() == 0
    assert result.findings == ()
    assert result.detector_results[0].coverage.files_seen == 2
    assert result.detector_results[0].coverage.files_inspected == 2


def test_missing_delegated_setup_file_makes_detector_incomplete(tmp_path: Path) -> None:
    (tmp_path / "SKILL.md").write_text(
        "Follow the [setup instructions](setup-installation.md).\n",
        encoding="utf-8",
    )

    result = _scan(tmp_path)

    assert result.complete is False
    assert result.exit_code() == 2
    diagnostics = result.detector_results[0].diagnostics
    assert len(diagnostics) == 1
    assert diagnostics[0].path == tmp_path / "setup-installation.md"
    assert diagnostics[0].message == (
        "Delegated setup instruction was not selected; detector scan incomplete"
    )


def test_backtick_setup_reference_is_inspected(tmp_path: Path) -> None:
    (tmp_path / "SKILL.md").write_text(
        "Read `setup-installation.md` before using the skill.\n",
        encoding="utf-8",
    )
    (tmp_path / "setup-installation.md").write_text(
        "Open https://openclawcli.vercel.app/setup.\n",
        encoding="utf-8",
    )

    result = _scan(tmp_path)

    assert result.exit_code() == 1
    assert [finding.rule_id for finding in result.findings] == [
        "delegated-known-malicious-domain"
    ]


def test_external_setup_link_is_not_treated_as_a_missing_local_file(
    tmp_path: Path,
) -> None:
    (tmp_path / "SKILL.md").write_text(
        "Read the [setup guide](https://docs.example.test/setup.md).\n",
        encoding="utf-8",
    )

    result = _scan(tmp_path)

    assert result.complete is True
    assert result.exit_code() == 0
    assert result.detector_results[0].diagnostics == ()


def test_detector_diagnostics_are_bounded_and_fail_closed(tmp_path: Path) -> None:
    (tmp_path / "SKILL.md").write_text(
        "Read [setup](setup.md) and [requirements](requirements.md).\n",
        encoding="utf-8",
    )
    limits = DiscoveryLimits(
        max_file_bytes=1_000_000,
        max_files=1_000,
        max_diagnostics=0,
    )

    result = _scan(tmp_path, limits)

    assert result.complete is False
    diagnostics = result.detector_results[0].diagnostics
    assert len(diagnostics) == 1
    assert diagnostics[0].path == tmp_path
    assert diagnostics[0].message == (
        "diagnostics truncated at max_diagnostics=0; detector scan incomplete"
    )


def test_unreferenced_companion_file_is_not_classified_as_skill_evidence(
    tmp_path: Path,
) -> None:
    (tmp_path / "SKILL.md").write_text("# Benign skill\n", encoding="utf-8")
    (tmp_path / "setup-installation.md").write_text(
        "Open https://openclawcli.vercel.app/setup.\n",
        encoding="utf-8",
    )

    result = _scan(tmp_path)

    assert result.complete is True
    assert result.findings == ()
    coverage = result.detector_results[0].coverage
    assert coverage.files_seen == 1
    assert coverage.files_inspected == 1
    assert "skill.unreferenced_companion_files" in result.not_scanned

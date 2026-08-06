from __future__ import annotations

import hashlib
import shutil
import subprocess
from pathlib import Path

import pytest

from agentsec.detectors.base import ScanContext
from agentsec.detectors.registry import get_detectors
from agentsec.detectors.shai_hulud import ShaiHuludDetector
from agentsec.engine.discovery import DiscoveredFile, DiscoveryLimits
from agentsec.engine.runner import run_scan
from agentsec.models import (
    Confidence,
    Diagnostic,
    DiagnosticKind,
    Severity,
    ThreatDatabase,
)
from agentsec.threat_db import load_bundled_database

FIXTURES = Path(__file__).parents[1] / "fixtures" / "shai_hulud"
LIMITS = DiscoveryLimits(max_file_bytes=1_000_000, max_files=1_000, max_diagnostics=100)


def _database(*, payload: Path | None = None) -> ThreatDatabase:
    base = load_bundled_database()
    hashes = dict(base.hashes)
    if payload is not None:
        hashes[hashlib.sha256(payload.read_bytes()).hexdigest()] = "test payload"
    return ThreatDatabase(
        version=base.version,
        updated=base.updated,
        package_versions=base.package_versions,
        wildcard_package_versions=base.wildcard_package_versions,
        hashes=hashes,
        domains=base.domains,
        commit_indicators=base.commit_indicators,
    )


def _scan(root: Path, database: ThreatDatabase | None = None, limits: DiscoveryLimits = LIMITS):
    return run_scan(root, [ShaiHuludDetector()], database or _database(), limits)


def test_positive_fixture_emits_exact_and_correlated_findings(tmp_path: Path) -> None:
    root = tmp_path / "positive"
    shutil.copytree(FIXTURES / "positive", root)

    result = _scan(root, _database(payload=root / "renamed-payload"))

    assert result.complete is True
    assert result.exit_code() == 1
    findings = {
        (finding.rule_id, finding.evidence): (finding.severity, finding.confidence)
        for finding in result.findings
    }
    assert findings == {
        ("compromised-lockfile-version", "@keyv/mongo@6.0.0"): (
            Severity.CRITICAL,
            Confidence.CONFIRMED,
        ),
        ("compromised-lockfile-version", "keyv@6.0.0"): (
            Severity.CRITICAL,
            Confidence.CONFIRMED,
        ),
        ("compromised-installed-version", "@keyv/mongo@6.0.0"): (
            Severity.CRITICAL,
            Confidence.CONFIRMED,
        ),
        ("compromised-installed-version", "keyv@6.0.0"): (
            Severity.CRITICAL,
            Confidence.CONFIRMED,
        ),
        (
            "campaign-lifecycle-script",
            "@keyv/mongo@6.0.0 preinstall: node setup.mjs",
        ): (Severity.CRITICAL, Confidence.HIGH),
        ("known-payload-hash", "sha256: test payload"): (
            Severity.CRITICAL,
            Confidence.CONFIRMED,
        ),
        ("campaign-startup-hook", "claude SessionStart: node setup.mjs"): (
            Severity.HIGH,
            Confidence.HIGH,
        ),
    }
    assert all(not finding.path.is_absolute() for finding in result.findings)


def test_negative_fixture_only_emits_review_heuristics(tmp_path: Path) -> None:
    root = tmp_path / "negative"
    shutil.copytree(FIXTURES / "negative", root)

    result = _scan(root)

    assert result.complete is True
    assert result.exit_code() == 1
    assert [
        (finding.rule_id, finding.severity, finding.confidence) for finding in result.findings
    ] == [
        ("startup-hook", Severity.MEDIUM, Confidence.REVIEW),
        ("suspicious-lifecycle-script", Severity.MEDIUM, Confidence.REVIEW),
    ]
    assert {finding.evidence for finding in result.findings} == {
        "claude SessionStart: echo repository-ready",
        "unrelated@1.0.0 preinstall: node setup.mjs",
    }


def test_matching_local_git_identity_is_high_confidence(tmp_path: Path) -> None:
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(["git", "config", "user.name", "claude"], cwd=tmp_path, check=True)
    subprocess.run(
        ["git", "config", "user.email", "claude@users.noreply.github.com"],
        cwd=tmp_path,
        check=True,
    )
    (tmp_path / "evidence.txt").write_text("evidence", encoding="utf-8")
    subprocess.run(["git", "add", "evidence.txt"], cwd=tmp_path, check=True)
    subprocess.run(
        ["git", "commit", "-q", "-m", "chore: update config"],
        cwd=tmp_path,
        check=True,
    )

    result = _scan(tmp_path)

    git_findings = [
        finding for finding in result.findings if finding.rule_id == "campaign-git-identity"
    ]
    assert len(git_findings) == 1
    assert git_findings[0].severity is Severity.HIGH
    assert git_findings[0].confidence is Confidence.HIGH
    assert git_findings[0].evidence == (
        "claude <claude@users.noreply.github.com>: chore: update config"
    )


@pytest.mark.parametrize(
    ("name", "content"),
    [
        ("package-lock.json", "not json"),
        ("bun.lockb", "binary-ish"),
    ],
)
def test_malformed_or_unsupported_lockfile_is_incomplete(
    tmp_path: Path, name: str, content: str
) -> None:
    (tmp_path / name).write_text(content, encoding="utf-8")

    result = _scan(tmp_path)

    assert result.complete is False
    assert result.exit_code() == 2
    assert any(
        diagnostic.kind is DiagnosticKind.ERROR
        for diagnostic in result.detector_results[0].diagnostics
    )


def test_unreadable_relevant_file_is_incomplete(tmp_path: Path) -> None:
    lockfile = tmp_path / "package-lock.json"
    lockfile.write_text('{"lockfileVersion": 3, "packages": {}}', encoding="utf-8")
    lockfile.chmod(0)
    try:
        if lockfile.read_text(encoding="utf-8"):
            pytest.skip("test user can bypass unreadable file permissions")
    except PermissionError:
        pass

    try:
        result = _scan(tmp_path)
    finally:
        lockfile.chmod(0o600)

    assert result.complete is False
    assert result.exit_code() == 2


def test_oversized_relevant_file_is_not_read_and_marks_scan_incomplete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lockfile = tmp_path / "package-lock.json"
    lockfile.write_text('{"lockfileVersion": 3, "packages": {}}', encoding="utf-8")
    limits = DiscoveryLimits(max_file_bytes=4, max_files=10, max_diagnostics=10)
    database = _database()
    calls = 0

    def forbidden_read(*args: object, **kwargs: object) -> str:
        nonlocal calls
        calls += 1
        raise AssertionError("oversized file must not be read")

    monkeypatch.setattr(Path, "read_text", forbidden_read)

    result = _scan(tmp_path, database=database, limits=limits)

    assert calls == 0
    assert result.complete is False
    assert result.exit_code() == 2


def test_structured_files_are_not_read_twice_for_hashing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "negative"
    shutil.copytree(FIXTURES / "negative", root)
    import agentsec.detectors.shai_hulud as detector_module

    hashed: list[Path] = []
    real_hash_file = detector_module.hash_file

    def recording_hash(path: Path, max_bytes: int):
        hashed.append(path.relative_to(root))
        return real_hash_file(path, max_bytes)

    monkeypatch.setattr(detector_module, "hash_file", recording_hash)

    _scan(root)

    assert hashed == []


def test_platform_hash_unavailability_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    payload = tmp_path / "payload"
    payload.write_bytes(b"payload")
    (tmp_path / "package-lock.json").write_text(
        '{"lockfileVersion": 3, "packages": {}}',
        encoding="utf-8",
    )
    import agentsec.detectors.shai_hulud as detector_module

    monkeypatch.setattr(
        detector_module,
        "hash_file",
        lambda path, max_bytes: (
            None,
            (Diagnostic(DiagnosticKind.ERROR, path, "Safe payload opening is unavailable"),),
        ),
    )

    result = _scan(tmp_path)

    assert result.complete is False
    assert result.exit_code() == 2


def test_applicability_and_registry_are_explicit(tmp_path: Path) -> None:
    detector = ShaiHuludDetector()
    database = _database()

    def context(relative_path: str) -> ScanContext:
        absolute = tmp_path / relative_path
        return ScanContext(
            root=tmp_path,
            files=(DiscoveredFile(Path(relative_path), absolute, 0, False),),
            database=database,
            limits=LIMITS,
        )

    assert detector.applies(context("package-lock.json")) is True
    assert detector.applies(context("pnpm-lock.yaml")) is True
    assert detector.applies(context("yarn.lock")) is True
    assert detector.applies(context("bun.lock")) is True
    assert detector.applies(context("bun.lockb")) is True
    assert detector.applies(context("node_modules/keyv/package.json")) is True
    assert detector.applies(context(".claude/settings.local.json")) is True
    assert detector.applies(context(".vscode/tasks.json")) is True
    assert detector.applies(context("package.json")) is False
    assert [item.id for item in get_detectors()] == ["shai-hulud-keyv"]


def test_findings_are_deduplicated_and_deterministic(tmp_path: Path) -> None:
    lockfile = tmp_path / "package-lock.json"
    lockfile.write_text(
        '{"lockfileVersion": 1, "dependencies": {'
        '"first": {"version": "1.0.0", "dependencies": {'
        '"keyv": {"version": "6.0.0"}}}, '
        '"second": {"version": "1.0.0", "dependencies": {'
        '"keyv": {"version": "6.0.0"}}}}}',
        encoding="utf-8",
    )

    first = _scan(tmp_path).detector_results[0].findings
    second = _scan(tmp_path).detector_results[0].findings

    assert first == second
    assert [(finding.rule_id, finding.path, finding.evidence) for finding in first].count(
        ("compromised-lockfile-version", Path("package-lock.json"), "keyv@6.0.0")
    ) == 1


def test_symlinked_relevant_file_fails_closed(tmp_path: Path) -> None:
    target = tmp_path / "target.json"
    target.write_text('{"lockfileVersion": 3, "packages": {}}', encoding="utf-8")
    try:
        (tmp_path / "package-lock.json").symlink_to(target)
    except (NotImplementedError, OSError):
        pytest.skip("symlinks are unavailable on this platform")

    result = _scan(tmp_path)

    assert result.complete is False
    assert result.exit_code() == 2


def test_uninspectable_git_metadata_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original_lstat = Path.lstat

    def denied_git_metadata(path: Path):
        if path.name == ".git":
            raise PermissionError("denied")
        return original_lstat(path)

    monkeypatch.setattr(Path, "lstat", denied_git_metadata)

    result = _scan(tmp_path)

    assert result.complete is False
    assert result.exit_code() == 2


def test_detector_diagnostic_truncation_is_an_error(tmp_path: Path) -> None:
    (tmp_path / "package-lock.json").write_text("not json", encoding="utf-8")
    limits = DiscoveryLimits(max_file_bytes=1_000, max_files=10, max_diagnostics=0)

    result = _scan(tmp_path, limits=limits)

    diagnostics = result.detector_results[0].diagnostics
    assert len(diagnostics) == 1
    assert diagnostics[0].kind is DiagnosticKind.ERROR
    assert "truncated" in diagnostics[0].message
    assert result.exit_code() == 2

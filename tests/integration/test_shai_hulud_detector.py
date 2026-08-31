from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from agentsec.analyzers import safe_io
from agentsec.detectors.base import ScanContext
from agentsec.detectors.registry import get_detectors
from agentsec.detectors.shai_hulud import (
    ShaiHuludDetector,
    _is_campaign_invocation,
)
from agentsec.engine.discovery import DiscoveredFile, DiscoveryLimits
from agentsec.engine.runner import run_scan
from agentsec.models import (
    Confidence,
    Diagnostic,
    DiagnosticKind,
    Severity,
    ThreatDatabase,
)
from agentsec.scopes import ScanScope
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
        contested_package_versions=base.contested_package_versions,
        contested_wildcard_package_versions=base.contested_wildcard_package_versions,
        package_version_sources=base.package_version_sources,
        hashes=hashes,
        domains=base.domains,
        commit_indicators=base.commit_indicators,
    )


def _scan(root: Path, database: ThreatDatabase | None = None, limits: DiscoveryLimits = LIMITS):
    return run_scan(
        root,
        [ShaiHuludDetector()],
        database or _database(),
        limits,
        scope=ScanScope.REPOSITORY,
    )


def _git_commit(root: Path, *, subject: str) -> str:
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    subprocess.run(["git", "config", "user.name", "external-marker"], cwd=root, check=True)
    subprocess.run(
        ["git", "config", "user.email", "external-marker@example.test"],
        cwd=root,
        check=True,
    )
    subprocess.run(
        ["git", "commit", "-q", "--allow-empty", "-m", subject], cwd=root, check=True
    )
    return subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _database_with_external_git_marker(subject: str) -> ThreatDatabase:
    base = _database()
    return ThreatDatabase(
        version=base.version,
        updated=base.updated,
        package_versions=base.package_versions,
        wildcard_package_versions=base.wildcard_package_versions,
        contested_package_versions=base.contested_package_versions,
        contested_wildcard_package_versions=base.contested_wildcard_package_versions,
        package_version_sources=base.package_version_sources,
        hashes=base.hashes,
        domains=base.domains,
        commit_indicators=(
            {
                "author": "external-marker",
                "email": "external-marker@example.test",
                "subject": subject,
            },
        ),
    )


def _external_git_metadata(root: Path, external: Path, mode: str, subject: str) -> None:
    if mode == "objects-symlink":
        _git_commit(root, subject=subject)
        external_objects = external / "objects"
        external.mkdir()
        shutil.move(str(root / ".git" / "objects"), external_objects)
        try:
            (root / ".git" / "objects").symlink_to(external_objects, target_is_directory=True)
        except (NotImplementedError, OSError):
            pytest.skip("directory symlinks are unavailable on this platform")
        return

    external.mkdir()
    commit = _git_commit(external, subject=subject)
    root.mkdir()
    if mode == "alternates":
        subprocess.run(["git", "init", "-q", str(root)], check=True)
        (root / ".git" / "objects" / "info" / "alternates").write_text(
            str(external / ".git" / "objects") + "\n",
            encoding="utf-8",
        )
        (root / ".git" / "refs" / "heads" / "main").write_text(
            commit + "\n", encoding="ascii"
        )
        (root / ".git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="ascii")
        return

    assert mode == "gitfile"
    (root / ".git").write_text(
        f"gitdir: {(external / '.git').as_posix()}\n",
        encoding="utf-8",
    )


@pytest.mark.parametrize("metadata_mode", ["objects-symlink", "alternates", "gitfile"])
def test_untrusted_git_metadata_never_invokes_git_or_reads_external_history(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, metadata_mode: str
) -> None:
    root = tmp_path / "scan-root"
    external = tmp_path / "external-history"
    subject = f"external marker via {metadata_mode}"
    _external_git_metadata(root, external, metadata_mode, subject)
    import agentsec.analyzers.git_history as git_history_module

    real_popen = git_history_module.subprocess.Popen
    git_calls: list[tuple[object, ...]] = []

    def recording_popen(*args: object, **kwargs: object):
        git_calls.append(args)
        return real_popen(*args, **kwargs)

    monkeypatch.setattr(git_history_module.subprocess, "Popen", recording_popen)

    result = _scan(root, _database_with_external_git_marker(subject))

    assert git_calls == []
    assert not any(item.rule_id == "campaign-git-identity" for item in result.findings)
    assert result.complete is True
    assert result.exit_code() == 0
    assert "git.history" in result.not_scanned
    assert result.detector_results[0].diagnostics == ()


def test_positive_fixture_emits_exact_and_correlated_findings(tmp_path: Path) -> None:
    root = tmp_path / "positive"
    shutil.copytree(FIXTURES / "positive", root)

    result = _scan(root, _database(payload=root / "renamed-payload"))
    payload_digest = hashlib.sha256((root / "renamed-payload").read_bytes()).hexdigest()

    assert result.complete is True
    assert result.exit_code() == 1
    findings = {
        (finding.rule_id, finding.evidence): (finding.severity, finding.confidence)
        for finding in result.findings
    }
    assert findings == {
        (
            "compromised-lockfile-version",
            "@keyv/mongo@6.0.0 (contested intelligence; sources: JFrog, SafeDep)",
        ): (
            Severity.HIGH,
            Confidence.CONTESTED,
        ),
        ("compromised-lockfile-version", "keyv@6.0.0"): (
            Severity.CRITICAL,
            Confidence.CONFIRMED,
        ),
        (
            "compromised-installed-version",
            "@keyv/mongo@6.0.0 (contested intelligence; sources: JFrog, SafeDep)",
        ): (
            Severity.HIGH,
            Confidence.CONTESTED,
        ),
        ("compromised-installed-version", "keyv@6.0.0"): (
            Severity.CRITICAL,
            Confidence.CONFIRMED,
        ),
        (
            "suspicious-lifecycle-script",
            "@keyv/mongo@6.0.0 preinstall: node setup.mjs",
        ): (Severity.MEDIUM, Confidence.REVIEW),
        ("known-payload-hash", f"sha256:{payload_digest} (test payload)"): (
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


def test_matching_local_git_identity_is_not_scanned_without_confinement(tmp_path: Path) -> None:
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

    assert result.complete is True
    assert result.exit_code() == 0
    assert not any(item.rule_id == "campaign-git-identity" for item in result.findings)
    assert "git.history" in result.not_scanned
    assert result.detector_results[0].diagnostics == ()


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


def test_each_structured_file_is_safely_read_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "negative"
    shutil.copytree(FIXTURES / "negative", root)
    import agentsec.detectors.shai_hulud as detector_module

    read_paths: list[Path] = []
    real_safe_read = detector_module.safe_read_regular_file

    def recording_safe_read(path: Path, max_bytes: int):
        read_paths.append(path)
        return real_safe_read(path, max_bytes)

    monkeypatch.setattr(detector_module, "safe_read_regular_file", recording_safe_read)

    _scan(root)

    expected = {
        root / ".claude/settings.json",
        root / "node_modules/esbuild/package.json",
        root / "node_modules/unrelated/package.json",
        root / "package-lock.json",
    }
    assert len(read_paths) == len(expected)
    assert set(read_paths) == expected


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
        "safe_read_regular_file",
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
    assert detector.applies(context("package.json")) is True
    assert detector.applies(context("payload")) is True
    assert detector.applies(
        ScanContext(
            root=tmp_path,
            files=(),
            database=database,
            limits=LIMITS,
        )
    ) is False
    assert [item.id for item in get_detectors()] == [
        "clawhavoc-skill",
        "shai-hulud-keyv",
    ]


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


def test_internal_symlink_alias_is_non_blocking_when_target_is_covered(tmp_path: Path) -> None:
    target = tmp_path / "target.json"
    target.write_text('{"lockfileVersion": 3, "packages": {}}', encoding="utf-8")
    try:
        (tmp_path / "package-lock.json").symlink_to(target)
    except (NotImplementedError, OSError):
        pytest.skip("symlinks are unavailable on this platform")

    result = _scan(tmp_path)

    assert result.complete is True
    assert result.exit_code() == 0
    assert result.discovery.exclusions[0].reason.value == "internal_symlink_alias"


def test_uninspectable_git_metadata_remains_explicitly_out_of_scope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original_lstat = Path.lstat

    def denied_git_metadata(path: Path):
        if path.name == ".git":
            raise PermissionError("denied")
        return original_lstat(path)

    monkeypatch.setattr(Path, "lstat", denied_git_metadata)

    result = _scan(tmp_path)

    assert result.complete is True
    assert result.exit_code() == 0
    assert "git.history" in result.not_scanned


def test_detector_diagnostic_truncation_is_an_error(tmp_path: Path) -> None:
    (tmp_path / "package-lock.json").write_text("not json", encoding="utf-8")
    limits = DiscoveryLimits(max_file_bytes=1_000, max_files=10, max_diagnostics=0)

    result = _scan(tmp_path, limits=limits)

    diagnostics = result.detector_results[0].diagnostics
    assert len(diagnostics) == 1
    assert diagnostics[0].kind is DiagnosticKind.ERROR
    assert "truncated" in diagnostics[0].message
    assert result.exit_code() == 2


def test_structured_file_is_hashed_and_parsed_from_one_safe_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lockfile = tmp_path / "package-lock.json"
    content = b'{"lockfileVersion":3,"packages":{}}'
    lockfile.write_bytes(content)
    digest = hashlib.sha256(content).hexdigest()
    base = _database()
    database = ThreatDatabase(
        version=base.version,
        updated=base.updated,
        package_versions=base.package_versions,
        wildcard_package_versions=base.wildcard_package_versions,
        contested_package_versions=base.contested_package_versions,
        contested_wildcard_package_versions=base.contested_wildcard_package_versions,
        package_version_sources=base.package_version_sources,
        hashes={**base.hashes, digest: "structured fixture"},
        domains=base.domains,
        commit_indicators=base.commit_indicators,
    )
    import agentsec.detectors.shai_hulud as detector_module

    calls: list[Path] = []
    real_safe_read = detector_module.safe_read_regular_file

    def recording_safe_read(path: Path, max_bytes: int):
        calls.append(path)
        return real_safe_read(path, max_bytes)

    monkeypatch.setattr(detector_module, "safe_read_regular_file", recording_safe_read)

    result = _scan(tmp_path, database)

    assert calls == [lockfile]
    assert result.complete is True
    finding = next(item for item in result.findings if item.rule_id == "known-payload-hash")
    assert finding.evidence == f"sha256:{digest} (structured fixture)"


@pytest.mark.parametrize(
    "package_name",
    [
        "@keyv/",
        "@keyv/mongo/extra",
        "@keyv/invalid name",
        "@keyv/.hidden",
        "@keyv/Mongo",
        "@keyv/" + "a" * 209,
    ],
)
def test_wildcard_ioc_requires_one_valid_scoped_package_segment(
    tmp_path: Path, package_name: str
) -> None:
    lockfile = tmp_path / "package-lock.json"
    lockfile.write_text(
        '{"lockfileVersion":3,"packages":{"node_modules/'
        + package_name
        + '":{"version":"6.0.0"}}}',
        encoding="utf-8",
    )

    result = _scan(tmp_path)

    assert not any(item.rule_id == "compromised-lockfile-version" for item in result.findings)


@pytest.mark.parametrize("package_name", ["@keyv/_mongo", "@keyv/-mongo"])
def test_wildcard_ioc_accepts_valid_leading_punctuation(
    tmp_path: Path, package_name: str
) -> None:
    lockfile = tmp_path / "package-lock.json"
    lockfile.write_text(
        '{"lockfileVersion":3,"packages":{"node_modules/'
        + package_name
        + '":{"version":"6.0.0"}}}',
        encoding="utf-8",
    )

    result = _scan(tmp_path)

    assert any(item.rule_id == "compromised-lockfile-version" for item in result.findings)


def test_echoing_campaign_filename_stays_review_only(tmp_path: Path) -> None:
    settings = tmp_path / ".claude" / "settings.json"
    settings.parent.mkdir()
    settings.write_text(
        json.dumps(
            {
                "hooks": {
                    "SessionStart": [
                        {
                            "matcher": "",
                            "hooks": [{"type": "command", "command": "echo setup.mjs"}],
                        }
                    ]
                }
            }
        ),
        encoding="utf-8",
    )

    result = _scan(tmp_path)

    startup = [item for item in result.findings if "startup-hook" in item.rule_id]
    assert [(item.rule_id, item.severity, item.confidence) for item in startup] == [
        ("startup-hook", Severity.MEDIUM, Confidence.REVIEW)
    ]


def test_any_discovered_file_makes_detector_applicable(tmp_path: Path) -> None:
    path = ".claude/settings.backup.json"
    context = ScanContext(
        root=tmp_path,
        files=(DiscoveredFile(Path(path), tmp_path / path, 0, False),),
        database=_database(),
        limits=LIMITS,
    )

    assert ShaiHuludDetector().applies(context) is True


def test_payload_only_known_hash_is_detected(tmp_path: Path) -> None:
    payload = tmp_path / "renamed-payload"
    payload.write_bytes(b"known malicious payload")

    result = _scan(tmp_path, _database(payload=payload))

    assert result.exit_code() == 1
    assert [item.rule_id for item in result.findings] == ["known-payload-hash"]


def test_package_scope_marker_is_hashed_without_manifest_parse_error(
    tmp_path: Path,
) -> None:
    marker = tmp_path / "node_modules" / "package" / "dist" / "esm" / "package.json"
    marker.parent.mkdir(parents=True)
    marker.write_text('{"type":"module"}')

    result = _scan(tmp_path)

    assert result.complete is True
    assert result.coverage.files_inspected == 1
    assert result.detector_results[0].diagnostics == ()


def test_nested_non_dependency_package_json_is_not_an_installed_manifest(
    tmp_path: Path,
) -> None:
    marker = tmp_path / "fixtures" / "package.json"
    marker.parent.mkdir()
    marker.write_text("not-json")

    result = _scan(tmp_path)

    assert result.complete is True
    assert result.coverage.files_inspected == 1
    assert result.detector_results[0].diagnostics == ()


def test_oversized_files_are_aggregated_into_one_diagnostic(tmp_path: Path) -> None:
    for name in ("a.bin", "b.bin", "c.bin"):
        (tmp_path / name).write_bytes(b"12345")
    limits = DiscoveryLimits(
        max_file_bytes=4,
        max_files=100,
        max_diagnostics=100,
    )

    result = _scan(tmp_path, limits=limits)

    assert result.exit_code() == 2
    assert result.coverage.files_inspected == 0
    assert len(result.detector_results[0].diagnostics) == 1
    assert result.detector_results[0].diagnostics[0].path == tmp_path
    assert result.detector_results[0].diagnostics[0].message == (
        "Refusing to inspect 3 files larger than max_file_bytes=4; scan incomplete"
    )


@pytest.mark.parametrize(
    "command",
    [
        "node setup.mjs",
        "NODE_OPTIONS=x node setup.mjs",
        "env NODE_OPTIONS=x node setup.mjs",
        "env -S 'node setup.mjs'",
        "env -S 'node' setup.mjs",
        "env -S'node setup.mjs'",
        r"env -Snode\ setup.mjs",
        r"env -vSnode\ setup.mjs",
        "env --split-string='node setup.mjs'",
        r"env -S 'node\_setup.mjs'",
        r"env -S 'node setup.mjs\c ignored'",
        "env -S 'INNER=2 node setup.mjs'",
        "env 1A=value node setup.mjs",
        "env A-B=value node setup.mjs",
        "env -u A-B node setup.mjs",
        "env --unset=1A node setup.mjs",
        "A+=value node setup.mjs",
        "A[0]=value node setup.mjs",
        "A[name]=value node setup.mjs",
        "A[0]+=value node setup.mjs",
        "echo harmless\nnode setup.mjs",
        r"node .\setup.mjs",
    ],
)
def test_campaign_invocation_recognizes_executed_script(command: str) -> None:
    assert _is_campaign_invocation(command) is True


@pytest.mark.parametrize(
    "command",
    [
        "echo setup.mjs",
        'node -e "console.log(\'setup.mjs\')"',
        "node --eval=setup.mjs",
        'echo "node setup.mjs"',
        "node safe.js setup.mjs",
        "env -S 'echo setup.mjs'",
        "env -u setup.mjs echo harmless",
        "env --unset=setup.mjs echo harmless",
        "env -C setup.mjs echo harmless",
        "env --chdir=setup.mjs echo harmless",
        "OUTER=1 env INNER=2 -S 'DEEPEST=3 node setup.mjs'",
        "env INNER=2 -u NODE_OPTIONS node setup.mjs",
        "env --unknown node setup.mjs",
        "env -x node setup.mjs",
        "env -S 'echo safe; node setup.mjs'",
        "env -S 'echo safe && node setup.mjs'",
        r"env -S 'echo safe\c node setup.mjs'",
        "env -S 'echo safe # node setup.mjs'",
        "env 1A=value -S 'node setup.mjs'",
        "env -u '' node setup.mjs",
        "env -u A=B node setup.mjs",
        "env --unset= node setup.mjs",
        "env --unset=A=B node setup.mjs",
        "env -u 'A\0B' node setup.mjs",
        "env A=value\0with-nul node setup.mjs",
        "env -0 node setup.mjs",
        "env --null node setup.mjs",
        "env -iv0 node setup.mjs",
        "echo safe A+=node setup.mjs",
        "-A=value node setup.mjs",
        "\x01A=value node setup.mjs",
        "1A=value node setup.mjs",
        "A-B=value node setup.mjs",
        "./tool=value node setup.mjs",
    ],
)
def test_campaign_invocation_rejects_mentions_and_non_entrypoint_arguments(
    command: str,
) -> None:
    assert _is_campaign_invocation(command) is False


def test_campaign_invocation_bounds_nested_env_split_strings() -> None:
    within_limit = _nested_env_split_command("node setup.mjs", depth=4)
    beyond_limit = _nested_env_split_command("node setup.mjs", depth=5)

    assert _is_campaign_invocation(within_limit) is True
    assert _is_campaign_invocation(beyond_limit) is False


def _nested_env_split_command(command: str, depth: int) -> str:
    for _ in range(depth):
        escaped = command.replace("\\", "\\\\").replace(" ", "\\ ")
        command = f"env -S {escaped}"
    return command


@pytest.mark.parametrize("argument_count", [16_385, 250_000])
def test_campaign_correlation_has_no_token_count_bypass(argument_count: int) -> None:
    command = _CountingCommand("node setup.mjs " + "arg " * argument_count)

    assert _is_campaign_invocation(command) is True
    assert command.index_reads <= len(command) * 4


def test_env_split_string_has_no_token_count_bypass() -> None:
    command = "env -S 'node setup.mjs " + "arg " * 16_385 + "'"

    assert _is_campaign_invocation(command) is True


class _CountingCommand(str):
    index_reads: int

    def __new__(cls, value: str):
        instance = super().__new__(cls, value)
        instance.index_reads = 0
        return instance

    def __getitem__(self, key: int | slice) -> str:
        if isinstance(key, int):
            self.index_reads += 1
        return super().__getitem__(key)


def test_structured_file_between_parser_and_hash_caps_is_hashed_then_rejected(
    tmp_path: Path,
) -> None:
    settings = tmp_path / ".claude" / "settings.json"
    settings.parent.mkdir()
    prefix = b'{"hooks":{}}'
    content = prefix + b" " * (2 * 1024 * 1024 - len(prefix))
    settings.write_bytes(content)
    limits = DiscoveryLimits(
        max_file_bytes=10 * 1024 * 1024,
        max_files=100,
        max_diagnostics=100,
    )

    result = _scan(tmp_path, _database(payload=settings), limits)

    assert result.exit_code() == 2
    assert any(item.rule_id == "known-payload-hash" for item in result.findings)
    assert any(
        diagnostic.kind is DiagnosticKind.ERROR
        and "limit" in diagnostic.message.lower()
        for diagnostic in result.detector_results[0].diagnostics
    )


def test_aggregate_byte_budget_stops_before_next_file_and_is_incomplete(
    tmp_path: Path,
) -> None:
    for index in range(100):
        (tmp_path / f"file-{index}.txt").write_bytes(b"x" * 10)
    limits = DiscoveryLimits(
        max_file_bytes=100,
        max_files=100,
        max_diagnostics=100,
        max_total_bytes=20,
    )

    result = _scan(tmp_path, limits=limits)

    assert result.exit_code() == 2
    assert result.coverage.files_seen == 100
    assert result.coverage.files_inspected == 2
    assert result.coverage.bytes_inspected == 20
    budget_diagnostics = [
        item
        for item in result.detector_results[0].diagnostics
        if "max_total_bytes=20" in item.message
    ]
    assert len(budget_diagnostics) == 1
    assert budget_diagnostics[0].path == tmp_path / "file-10.txt"


def test_aggregate_byte_budget_accepts_one_exact_size_file(tmp_path: Path) -> None:
    (tmp_path / "payload.bin").write_bytes(b"1234")
    limits = DiscoveryLimits(
        max_file_bytes=100,
        max_files=100,
        max_diagnostics=100,
        max_total_bytes=4,
    )

    result = _scan(tmp_path, limits=limits)

    assert result.complete is True
    assert result.coverage.files_inspected == 1
    assert result.coverage.bytes_inspected == 4


def test_zero_aggregate_budget_accepts_empty_file(tmp_path: Path) -> None:
    (tmp_path / "empty.bin").write_bytes(b"")
    limits = DiscoveryLimits(
        max_file_bytes=100,
        max_files=100,
        max_diagnostics=100,
        max_total_bytes=0,
    )

    result = _scan(tmp_path, limits=limits)

    assert result.complete is True
    assert result.coverage.files_inspected == 1
    assert result.coverage.bytes_inspected == 0


def test_zero_aggregate_budget_rejects_nonempty_file_without_reading(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "payload.bin").write_bytes(b"x")
    read_calls = 0
    real_read = safe_io.os.read

    def recording_read(descriptor: int, size: int) -> bytes:
        nonlocal read_calls
        read_calls += 1
        return real_read(descriptor, size)

    monkeypatch.setattr(safe_io.os, "read", recording_read)
    limits = DiscoveryLimits(
        max_file_bytes=100,
        max_files=100,
        max_diagnostics=100,
        max_total_bytes=0,
    )

    result = _scan(tmp_path, limits=limits)

    assert result.exit_code() == 2
    assert result.coverage.files_inspected == 0
    assert result.coverage.bytes_inspected == 0
    assert read_calls == 0


@pytest.mark.skipif(os.name == "nt", reason="POSIX descriptor regression")
def test_aggregate_budget_stops_after_failed_physical_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    growing = tmp_path / "a.bin"
    growing.write_bytes(b"1234")
    (tmp_path / "b.bin").write_bytes(b"5678")
    real_read = safe_io.os.read
    bytes_returned = 0
    grew = False

    def grow_then_read(descriptor: int, size: int) -> bytes:
        nonlocal bytes_returned, grew
        if not grew:
            grew = True
            with growing.open("ab") as stream:
                stream.write(b"5")
        chunk = real_read(descriptor, size)
        bytes_returned += len(chunk)
        return chunk

    monkeypatch.setattr(safe_io.os, "read", grow_then_read)
    limits = DiscoveryLimits(
        max_file_bytes=100,
        max_files=100,
        max_diagnostics=100,
        max_total_bytes=8,
    )

    result = _scan(tmp_path, limits=limits)

    assert result.exit_code() == 2
    assert bytes_returned <= 8
    assert result.coverage.files_inspected == 0
    assert result.coverage.bytes_inspected == 0


def test_sparse_file_larger_than_remaining_budget_is_not_read(tmp_path: Path) -> None:
    sparse = tmp_path / "sparse.bin"
    with sparse.open("wb") as stream:
        stream.truncate(2_000_000)
    limits = DiscoveryLimits(
        max_file_bytes=4_000_000,
        max_files=100,
        max_diagnostics=100,
        max_total_bytes=64,
    )

    result = _scan(tmp_path, limits=limits)

    assert result.exit_code() == 2
    assert result.coverage.files_inspected == 0
    assert result.coverage.bytes_inspected == 0
    assert (
        sum("max_total_bytes=64" in item.message for item in result.detector_results[0].diagnostics)
        == 1
    )

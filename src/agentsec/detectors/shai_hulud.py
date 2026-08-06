"""Repository-scoped Shai-Hulud Keyv/cacheable campaign detector."""

from __future__ import annotations

import re
import stat
from pathlib import Path

from agentsec.analyzers.git_history import GitIndicator, inspect_git_history
from agentsec.analyzers.hashes import hash_file
from agentsec.analyzers.lockfiles import ResolvedPackage, parse_lockfile
from agentsec.analyzers.packages import InstalledPackage, inspect_package_manifest
from agentsec.analyzers.startup import StartupHook, inspect_startup_config
from agentsec.detectors.base import ScanContext
from agentsec.engine.discovery import DiscoveredFile
from agentsec.models import (
    Applicability,
    Confidence,
    Coverage,
    DetectorResult,
    Diagnostic,
    DiagnosticKind,
    Finding,
    Severity,
    ThreatDatabase,
)

_CAMPAIGN_ID = "shai-hulud-keyv-2026-08"
_LOCKFILE_NAMES = frozenset(
    {
        "package-lock.json",
        "npm-shrinkwrap.json",
        "pnpm-lock.yaml",
        "pnpm-lock.yml",
        "yarn.lock",
        "bun.lock",
        "bun.lockb",
    }
)
_CAMPAIGN_SCRIPT = re.compile(
    r"(?<![A-Za-z0-9_.-])(?:setup\.mjs|math_symbol\.js|math_init\.js)"
    r"(?![A-Za-z0-9_.-])",
    re.IGNORECASE,
)
_MAX_GIT_COMMITS = 100_000


class ShaiHuludDetector:
    """Compose bounded analyzers into deterministic campaign findings."""

    id = "shai-hulud-keyv"
    version = "1"

    def applies(self, context: ScanContext) -> bool:
        return (
            any(_is_applicability_file(item.relative_path) for item in context.files)
            or (_git_metadata_state(context.root)[0])
        )

    def run(self, context: ScanContext) -> DetectorResult:
        findings: list[Finding] = []
        diagnostics: list[Diagnostic] = []
        inspected_files = 0
        inspected_bytes = 0

        for item in context.files:
            category = _file_category(item.relative_path)
            if category is None:
                category = "payload"

            safety_error = _file_safety_error(item, context)
            if safety_error is not None:
                diagnostics.append(safety_error)
                continue

            if category == "lockfile":
                packages, analyzer_diagnostics = parse_lockfile(item.absolute_path)
                diagnostics.extend(analyzer_diagnostics)
                if not analyzer_diagnostics:
                    inspected_files += 1
                    inspected_bytes += item.size
                for resolved_package in packages:
                    if _is_compromised(
                        resolved_package.name,
                        resolved_package.version,
                        context.database,
                    ):
                        findings.append(_lockfile_finding(resolved_package, item.relative_path))
                continue

            if category == "manifest":
                installed_package, analyzer_diagnostics = inspect_package_manifest(
                    item.absolute_path
                )
                diagnostics.extend(analyzer_diagnostics)
                if not analyzer_diagnostics:
                    inspected_files += 1
                    inspected_bytes += item.size
                if installed_package is not None:
                    findings.extend(
                        _installed_package_findings(
                            installed_package,
                            item.relative_path,
                            context.database,
                        )
                    )
                continue

            if category == "startup":
                hooks, analyzer_diagnostics = inspect_startup_config(item.absolute_path)
                diagnostics.extend(analyzer_diagnostics)
                if not analyzer_diagnostics:
                    inspected_files += 1
                    inspected_bytes += item.size
                findings.extend(_startup_findings(hooks, item.relative_path))
                continue

            digest, analyzer_diagnostics = hash_file(
                item.absolute_path,
                context.limits.max_file_bytes,
            )
            diagnostics.extend(analyzer_diagnostics)
            if not analyzer_diagnostics:
                inspected_files += 1
                inspected_bytes += item.size
            if digest is not None and digest in context.database.hashes:
                findings.append(
                    _finding(
                        rule_id="known-payload-hash",
                        severity=Severity.CRITICAL,
                        confidence=Confidence.CONFIRMED,
                        path=item.relative_path,
                        evidence=f"sha256: {context.database.hashes[digest]}",
                    )
                )

        has_git, git_diagnostic = _git_metadata_state(context.root)
        if git_diagnostic is not None:
            diagnostics.append(git_diagnostic)
        elif has_git:
            indicators, analyzer_diagnostics = inspect_git_history(
                context.root,
                max_commits=min(context.limits.max_files, _MAX_GIT_COMMITS),
            )
            diagnostics.extend(analyzer_diagnostics)
            findings.extend(_git_findings(indicators, context.database))

        return DetectorResult(
            detector_id=self.id,
            applicability=Applicability.APPLICABLE,
            findings=_deduplicate_findings(findings),
            diagnostics=_bounded_diagnostics(
                diagnostics,
                root=context.root,
                limit=context.limits.max_diagnostics,
            ),
            coverage=Coverage(
                files_seen=len(context.files),
                files_inspected=inspected_files,
                bytes_inspected=inspected_bytes,
            ),
        )


def _file_category(path: Path) -> str | None:
    if path.name in _LOCKFILE_NAMES:
        return "lockfile"
    parts = path.parts
    if path.name == "package.json" and "node_modules" in parts[:-1]:
        return "manifest"
    if (
        path.parent == Path(".claude")
        and path.name.startswith("settings")
        and path.suffix == ".json"
    ):
        return "startup"
    if path == Path(".vscode/tasks.json"):
        return "startup"
    return None


def _is_applicability_file(path: Path) -> bool:
    return _file_category(path) is not None


def _file_safety_error(item: DiscoveredFile, context: ScanContext) -> Diagnostic | None:
    if item.symlink:
        return Diagnostic(
            DiagnosticKind.ERROR,
            item.absolute_path,
            "Refusing to inspect symlinked repository file",
        )
    if item.size < 0 or item.size > context.limits.max_file_bytes:
        return Diagnostic(
            DiagnosticKind.ERROR,
            item.absolute_path,
            f"File exceeds max_file_bytes={context.limits.max_file_bytes}; scan incomplete",
        )
    return None


def _is_compromised(name: str, version: str, database: ThreatDatabase) -> bool:
    if version in database.package_versions.get(name, frozenset()):
        return True
    return any(
        name.startswith(prefix) and name != prefix and version in versions
        for prefix, versions in database.wildcard_package_versions.items()
    )


def _lockfile_finding(package: ResolvedPackage, path: Path) -> Finding:
    return _finding(
        rule_id="compromised-lockfile-version",
        severity=Severity.CRITICAL,
        confidence=Confidence.CONFIRMED,
        path=path,
        evidence=f"{package.name}@{package.version}",
    )


def _installed_package_findings(
    package: InstalledPackage,
    path: Path,
    database: ThreatDatabase,
) -> tuple[Finding, ...]:
    compromised = _is_compromised(package.name, package.version, database)
    package_evidence = f"{package.name}@{package.version}"
    findings: list[Finding] = []
    if compromised:
        findings.append(
            _finding(
                rule_id="compromised-installed-version",
                severity=Severity.CRITICAL,
                confidence=Confidence.CONFIRMED,
                path=path,
                evidence=package_evidence,
            )
        )
    if package.preinstall is not None and _CAMPAIGN_SCRIPT.search(package.preinstall):
        findings.append(
            _finding(
                rule_id=(
                    "campaign-lifecycle-script" if compromised else "suspicious-lifecycle-script"
                ),
                severity=Severity.CRITICAL if compromised else Severity.MEDIUM,
                confidence=Confidence.HIGH if compromised else Confidence.REVIEW,
                path=path,
                evidence=f"{package_evidence} preinstall: {package.preinstall}",
            )
        )
    return tuple(findings)


def _startup_findings(hooks: tuple[StartupHook, ...], path: Path) -> tuple[Finding, ...]:
    findings = []
    for hook in hooks:
        campaign_correlated = _CAMPAIGN_SCRIPT.search(hook.command) is not None
        findings.append(
            _finding(
                rule_id="campaign-startup-hook" if campaign_correlated else "startup-hook",
                severity=Severity.HIGH if campaign_correlated else Severity.MEDIUM,
                confidence=Confidence.HIGH if campaign_correlated else Confidence.REVIEW,
                path=path,
                evidence=f"{hook.kind} {hook.event}: {hook.command}",
            )
        )
    return tuple(findings)


def _git_findings(
    indicators: tuple[GitIndicator, ...], database: ThreatDatabase
) -> tuple[Finding, ...]:
    expected = {
        (item["author"], item["email"], item["subject"]) for item in database.commit_indicators
    }
    return tuple(
        _finding(
            rule_id="campaign-git-identity",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            path=Path("."),
            evidence=f"{indicator.author} <{indicator.email}>: {indicator.subject}",
        )
        for indicator in indicators
        if (indicator.author, indicator.email, indicator.subject) in expected
    )


def _git_metadata_state(root: Path) -> tuple[bool, Diagnostic | None]:
    metadata = root / ".git"
    try:
        metadata_stat = metadata.lstat()
    except FileNotFoundError:
        return False, None
    except (OSError, ValueError):
        return True, Diagnostic(
            DiagnosticKind.ERROR,
            metadata,
            "Unable to inspect local Git metadata",
        )

    attributes = getattr(metadata_stat, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    if stat.S_ISLNK(metadata_stat.st_mode) or attributes & reparse_flag:
        return True, Diagnostic(
            DiagnosticKind.ERROR,
            metadata,
            "Refusing unsafe local Git metadata path",
        )
    if not (stat.S_ISDIR(metadata_stat.st_mode) or stat.S_ISREG(metadata_stat.st_mode)):
        return True, Diagnostic(
            DiagnosticKind.ERROR,
            metadata,
            "Unsupported local Git metadata type",
        )
    return True, None


def _finding(
    *,
    rule_id: str,
    severity: Severity,
    confidence: Confidence,
    path: Path,
    evidence: str,
) -> Finding:
    return Finding(
        detector_id="shai-hulud-keyv",
        rule_id=rule_id,
        severity=severity,
        confidence=confidence,
        path=path,
        evidence=evidence,
        campaign_ids=(_CAMPAIGN_ID,),
    )


def _deduplicate_findings(findings: list[Finding]) -> tuple[Finding, ...]:
    unique = {(finding.rule_id, finding.path, finding.evidence): finding for finding in findings}
    return tuple(
        unique[key]
        for key in sorted(
            unique,
            key=lambda item: (item[0], item[1].as_posix(), item[2]),
        )
    )


def _bounded_diagnostics(
    diagnostics: list[Diagnostic], *, root: Path, limit: int
) -> tuple[Diagnostic, ...]:
    unique = {(item.kind, item.path, item.message): item for item in diagnostics}
    ordered = [
        unique[key]
        for key in sorted(
            unique,
            key=lambda item: (item[0], item[1].as_posix(), item[2]),
        )
    ]
    if len(ordered) <= limit:
        return tuple(ordered)
    return (
        *ordered[:limit],
        Diagnostic(
            DiagnosticKind.ERROR,
            root,
            f"diagnostics truncated at max_diagnostics={limit}; detector scan incomplete",
        ),
    )

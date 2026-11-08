"""Repository-scoped FakeGit / SmartLoader archive-lure detector.

The campaign hides its payload in an installer archive committed to a repository
that poses as an agent tool. The README links the archive. SKILL.md and agent
settings files in these repositories are reported clean, so this detector reads
the README, the archive paths, and file hashes. It never opens an archive.
"""

from __future__ import annotations

import hashlib
import html
import posixpath
import re
from pathlib import Path, PurePosixPath
from urllib.parse import unquote, urlsplit

from agentsec.analyzers.safe_io import safe_read_regular_file
from agentsec.detectors.base import DetectorMetadata, DetectorRuleMetadata, ScanContext
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
)
from agentsec.scopes import is_archive_path

_CAMPAIGN_ID = "fakegit-smartloader-2025-03"
_REMEDIATION_URL = "https://cc.bruniaux.com/security/"
_MAX_SAFE_READ_BYTES = 4_000_000
_AGENT_CONFIG_DIRECTORIES = frozenset({".agents", ".claude", ".codex", ".cursor", ".gemini"})
_GITHUB_HOSTS = frozenset({"github.com", "www.github.com"})
_RAW_HOST = "raw.githubusercontent.com"
_MARKDOWN_LINK = re.compile(r"\]\(\s*<?([^\s)>]+)")
_HTML_ATTRIBUTE = re.compile(r"""\b(?:href|src)\s*=\s*["']([^"']+)["']""", re.IGNORECASE)
_REFERENCE_DEFINITION = re.compile(r"^\s{0,3}\[[^\]]+\]:\s*<?(\S+?)>?(?:\s|$)")
_BARE_URL = re.compile(r"https?://[^\s<>()\[\]{}\"']+", re.IGNORECASE)
_TECHNIQUES_BY_RULE = {
    "archive-in-agent-config-directory": ("repository.agent-config-archive",),
    "known-fakegit-archive-hash": ("payload.sha256",),
    "readme-links-committed-archive": ("repository.readme-archive-installer",),
}
_TECHNIQUE_IDS = tuple(
    sorted({technique for techniques in _TECHNIQUES_BY_RULE.values() for technique in techniques})
)


class FakeGitArchiveLureDetector:
    """Compose three bounded checks into campaign-attributed findings."""

    id = "fakegit-archive-lure"
    version = "1"
    rule_ids: tuple[str, ...] = tuple(sorted(_TECHNIQUES_BY_RULE))
    metadata = DetectorMetadata(
        description=(
            "Detect repository-local indicators of the FakeGit / SmartLoader campaign "
            "that poses as agent tools: sourced artifact hashes, README links to a "
            "committed installer archive, and archives inside agent configuration "
            "directories."
        ),
        supported_inputs=(
            "all discovered regular files (SHA-256)",
            "archive files (.7z, .rar, .zip) that the scan scope leaves out of the file list",
            "README*.md files at any depth",
        ),
        campaign_ids=(_CAMPAIGN_ID,),
        technique_ids=_TECHNIQUE_IDS,
        source_references=(
            "https://gist.github.com/fr0gger/3d0288bf0fee3b8df7b618e7c10334d7",
            "https://www.island.io/blog/agentbaiting-how-800-fake-ai-skills-and-mcp-servers-delivered-malware",
            "https://www.linkedin.com/posts/thomas-roccia_we-found-73-github-repos-posing-as-ai-share-7523845292753080320-VZJI/",
            "https://www.trendmicro.com/en_us/research/25/c/ai-assisted-fake-github-repositories.html",
        ),
        limitations=(
            "Archive contents are never opened, unpacked, or executed.",
            "Only confirmed archive and component hashes are bundled; runtime binaries and "
            "lower-confidence sample components are withheld.",
            "A README link counts only when its path suffix matches an archive in the scanned "
            "repository; the owner and repository in an absolute GitHub URL are not compared "
            "with the scanned repository.",
            "A README or archive path is a hunt lead, because legitimate projects also commit "
            "installers and link them.",
            "Files and archives larger than max_file_bytes (4000000 at most) are not hashed; "
            "the scan reports a warning and stays complete.",
            "Only .7z, .rar, and .zip archives are tracked.",
            "The default source scope prunes directories such as dist and build; scan with "
            "--scope repository to include archives stored there.",
            "Threat intelligence is bundled and is not refreshed during a scan.",
        ),
        remediation_url=_REMEDIATION_URL,
        not_scanned=(
            "archive.contents",
            "git.history",
            "github.release_assets",
            "repository.ownership",
        ),
        applicability="at_least_one_discovered_file",
        rules=tuple(
            DetectorRuleMetadata(id=rule_id, technique_ids=technique_ids)
            for rule_id, technique_ids in sorted(_TECHNIQUES_BY_RULE.items())
        ),
    )

    def applies(self, context: ScanContext) -> bool:
        return bool(context.files or context.archives)

    def run(self, context: ScanContext) -> DetectorResult:
        findings: list[Finding] = []
        diagnostics: list[Diagnostic] = []
        candidates = _candidates(context)
        archive_paths = frozenset(
            item.relative_path.as_posix()
            for item in candidates
            if is_archive_path(item.relative_path)
        )
        findings.extend(
            _config_directory_finding(item.relative_path)
            for item in candidates
            if is_archive_path(item.relative_path)
            and _in_agent_config_directory(item.relative_path)
        )

        campaign_hashes = context.database.campaign_hashes.get(_CAMPAIGN_ID, {})
        read_limit = min(context.limits.max_file_bytes, _MAX_SAFE_READ_BYTES)
        inspected_files = 0
        inspected_bytes = 0
        skipped_oversized = 0

        for item in candidates:
            readme = _is_readme(item.relative_path)
            if item.size > read_limit:
                if readme:
                    diagnostics.append(
                        Diagnostic(
                            DiagnosticKind.ERROR,
                            item.absolute_path,
                            "Refusing to inspect README larger than "
                            f"max_file_bytes={context.limits.max_file_bytes}; scan incomplete",
                        )
                    )
                else:
                    skipped_oversized += 1
                continue
            remaining_bytes = context.limits.max_total_bytes - inspected_bytes
            if item.size > remaining_bytes:
                diagnostics.append(
                    Diagnostic(
                        DiagnosticKind.ERROR,
                        item.absolute_path,
                        "Aggregate byte budget reached at "
                        f"max_total_bytes={context.limits.max_total_bytes}; scan incomplete",
                    )
                )
                break
            content, read_diagnostics = safe_read_regular_file(
                item.absolute_path, min(read_limit, remaining_bytes)
            )
            diagnostics.extend(read_diagnostics)
            if content is None:
                continue
            inspected_files += 1
            inspected_bytes += len(content)
            digest = hashlib.sha256(content).hexdigest()
            if digest in campaign_hashes:
                findings.append(_hash_finding(item.relative_path, digest, campaign_hashes[digest]))
            if readme:
                try:
                    text = content.decode("utf-8")
                except UnicodeDecodeError:
                    diagnostics.append(
                        Diagnostic(
                            DiagnosticKind.ERROR,
                            item.absolute_path,
                            "README is not valid UTF-8; scan incomplete",
                        )
                    )
                    continue
                findings.extend(_readme_findings(item.relative_path, text, archive_paths))

        if skipped_oversized:
            noun = "file" if skipped_oversized == 1 else "files"
            diagnostics.append(
                Diagnostic(
                    DiagnosticKind.WARNING,
                    context.root,
                    f"Skipped the exact-hash check for {skipped_oversized} {noun} larger than "
                    f"max_file_bytes={context.limits.max_file_bytes}; "
                    "fakegit-archive-lure hash coverage is partial",
                )
            )

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
                files_seen=len(candidates),
                files_inspected=inspected_files,
                bytes_inspected=inspected_bytes,
            ),
        )


def _candidates(context: ScanContext) -> tuple[DiscoveredFile, ...]:
    unique = {item.relative_path: item for item in (*context.archives, *context.files)}
    return tuple(sorted(unique.values(), key=lambda item: item.relative_path.as_posix()))


def _is_readme(path: Path) -> bool:
    return path.name.lower().startswith("readme") and path.suffix.lower() == ".md"


def _in_agent_config_directory(path: Path) -> bool:
    return any(part.lower() in _AGENT_CONFIG_DIRECTORIES for part in path.parts[:-1])


def _readme_findings(
    readme: Path, text: str, archive_paths: frozenset[str]
) -> tuple[Finding, ...]:
    findings: list[Finding] = []
    readme_directory = PurePosixPath(readme.as_posix()).parent.as_posix()
    for line_number, line in enumerate(text.splitlines(), start=1):
        for target in _link_targets(line):
            archive = _matching_archive(target, readme_directory, archive_paths)
            if archive is not None:
                findings.append(_readme_finding(readme, line_number, archive))
    return tuple(findings)


def _link_targets(line: str) -> tuple[str, ...]:
    targets = [
        *(match.group(1) for match in _MARKDOWN_LINK.finditer(line)),
        *(match.group(1) for match in _HTML_ATTRIBUTE.finditer(line)),
        *(match.group(0).rstrip(".,;:") for match in _BARE_URL.finditer(line)),
    ]
    reference = _REFERENCE_DEFINITION.match(line)
    if reference is not None:
        targets.append(reference.group(1))
    return tuple(html.unescape(target.strip().strip("<>")) for target in targets if target)


def _matching_archive(
    target: str, readme_directory: str, archive_paths: frozenset[str]
) -> str | None:
    for candidate in _candidate_paths(target, readme_directory):
        if candidate in archive_paths:
            return candidate
    return None


def _candidate_paths(target: str, readme_directory: str) -> tuple[str, ...]:
    try:
        parts = urlsplit(target)
    except ValueError:
        return ()
    if parts.scheme or parts.netloc:
        return _github_paths(parts.scheme, parts.hostname, parts.path)
    path = unquote(parts.path)
    if not path or path.startswith("/"):
        return ()
    joined = posixpath.normpath(posixpath.join(readme_directory, path))
    if joined == ".." or joined.startswith("../") or joined.startswith("/"):
        return ()
    return (joined,)


def _github_paths(scheme: str, hostname: str | None, path: str) -> tuple[str, ...]:
    if scheme.lower() not in {"http", "https"} or hostname is None:
        return ()
    segments = [unquote(segment) for segment in path.split("/") if segment]
    host = hostname.lower()
    if host in _GITHUB_HOSTS:
        if len(segments) < 5 or segments[2] not in {"blob", "raw"}:
            return ()
        remainder = segments[3:]
    elif host == _RAW_HOST:
        if len(segments) < 4:
            return ()
        remainder = segments[2:]
    else:
        return ()
    # The first remainder segment starts the ref; a ref may span several segments.
    return tuple("/".join(remainder[start:]) for start in range(1, len(remainder)))


def _hash_finding(path: Path, digest: str, description: str) -> Finding:
    return _finding(
        rule_id="known-fakegit-archive-hash",
        severity=Severity.CRITICAL,
        confidence=Confidence.CONFIRMED,
        path=path,
        evidence=f"sha256:{digest} ({description})",
    )


def _readme_finding(path: Path, line: int, archive: str) -> Finding:
    return _finding(
        rule_id="readme-links-committed-archive",
        severity=Severity.MEDIUM,
        confidence=Confidence.REVIEW,
        path=path,
        evidence=f"README links committed archive {archive}",
        line=line,
    )


def _config_directory_finding(path: Path) -> Finding:
    return _finding(
        rule_id="archive-in-agent-config-directory",
        severity=Severity.MEDIUM,
        confidence=Confidence.REVIEW,
        path=path,
        evidence=f"archive under an agent configuration directory: {path.as_posix()}",
    )


def _finding(
    *,
    rule_id: str,
    severity: Severity,
    confidence: Confidence,
    path: Path,
    evidence: str,
    line: int | None = None,
) -> Finding:
    return Finding(
        detector_id="fakegit-archive-lure",
        rule_id=rule_id,
        severity=severity,
        confidence=confidence,
        path=path,
        line=line,
        evidence=evidence,
        campaign_ids=(_CAMPAIGN_ID,),
        technique_ids=_TECHNIQUES_BY_RULE[rule_id],
        remediation_url=_REMEDIATION_URL,
    )


def _deduplicate_findings(findings: list[Finding]) -> tuple[Finding, ...]:
    unique = {
        (finding.rule_id, finding.path, finding.line, finding.evidence): finding
        for finding in findings
    }
    return tuple(
        unique[key]
        for key in sorted(
            unique,
            key=lambda item: (item[0], item[1].as_posix(), item[2] or 0, item[3]),
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

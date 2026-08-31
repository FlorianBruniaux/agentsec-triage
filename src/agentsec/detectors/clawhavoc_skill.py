"""Repository-scoped ClawHavoc agent-skill detector."""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urlsplit

from agentsec.analyzers.safe_io import safe_read_regular_file
from agentsec.detectors.base import DetectorMetadata, ScanContext
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

_CAMPAIGN_DOMAIN = "openclawcli.vercel.app"
_CAMPAIGN_ID = "clawhavoc-fake-prerequisites-2026-02"
_REMEDIATION_URL = "https://cc.bruniaux.com/security/"
_MARKDOWN_LINK = re.compile(r"\[[^\]]*\]\(\s*<?([^\s)>]+)>?")
_BACKTICK_PATH = re.compile(r"`([^`\r\n]+\.md)`", re.IGNORECASE)
_SETUP_NAME_PARTS = ("install", "prerequisite", "requirement", "setup")
_URL = re.compile(r"https?://[^\s<>()\[\]{}\"']+", re.IGNORECASE)


class ClawHavocSkillDetector:
    """Inspect repository-local skill instructions for sourced campaign evidence."""

    id = "clawhavoc-skill"
    version = "1"
    metadata = DetectorMetadata(
        description=(
            "Detect repository-local agent-skill evidence associated with the "
            "documented ClawHavoc fake-prerequisite campaign."
        ),
        supported_inputs=(
            "repository-local SKILL.md files",
            "same-skill local Markdown setup files referenced by SKILL.md",
        ),
        campaign_ids=(_CAMPAIGN_ID,),
        technique_ids=("skill.known-malicious-domain", "skill.delegated-setup"),
        source_references=(
            "https://www.koi.ai/blog/clawhavoc-341-malicious-clawedbot-skills-found-by-the-bot-they-were-targeting",
            "https://www.trendmicro.com/en_us/research/26/b/openclaw-skills-used-to-distribute-atomic-macos-stealer.html",
        ),
        limitations=(
            "Only exact bundled campaign domains are matched.",
            "Only same-skill Markdown files with setup or installation names are followed.",
            "A finding is evidence to review and does not prove compromise.",
            "Threat intelligence is bundled and is not refreshed during a scan.",
        ),
        remediation_url=_REMEDIATION_URL,
        not_scanned=(
            "skill.registry_history",
            "skill.remote_payloads",
            "skill.runtime_behavior",
            "skill.unreferenced_companion_files",
        ),
    )

    def applies(self, context: ScanContext) -> bool:
        return any(_is_skill_manifest(item.relative_path) for item in context.files)

    def run(self, context: ScanContext) -> DetectorResult:
        skill_files = tuple(
            item for item in context.files if _is_skill_manifest(item.relative_path)
        )
        findings: list[Finding] = []
        diagnostics: list[Diagnostic] = []
        inspected_files = 0
        inspected_bytes = 0
        seen_files = {item.relative_path for item in skill_files}
        files_by_path = {item.relative_path: item for item in context.files}

        for item in skill_files:
            if item.size > context.limits.max_file_bytes:
                diagnostics.append(
                    Diagnostic(
                        DiagnosticKind.ERROR,
                        item.absolute_path,
                        "Refusing to inspect skill instruction larger than "
                        f"max_file_bytes={context.limits.max_file_bytes}; scan incomplete",
                    )
                )
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
                item.absolute_path,
                min(context.limits.max_file_bytes, remaining_bytes),
            )
            diagnostics.extend(read_diagnostics)
            if content is None:
                continue
            inspected_files += 1
            inspected_bytes += len(content)
            try:
                text = content.decode("utf-8")
            except UnicodeDecodeError:
                diagnostics.append(
                    Diagnostic(
                        DiagnosticKind.ERROR,
                        item.absolute_path,
                        "Skill instruction is not valid UTF-8; scan incomplete",
                    )
                )
                continue
            for line_number, line in enumerate(text.splitlines(), start=1):
                if not _line_has_campaign_domain(line, context.database.domains):
                    continue
                findings.append(
                    _domain_finding(
                        path=item.relative_path,
                        line=line_number,
                        delegated_by=None,
                    )
                )

            for referenced_path in _local_setup_references(text, item.relative_path):
                referenced = files_by_path.get(referenced_path)
                if referenced is None:
                    diagnostics.append(
                        Diagnostic(
                            DiagnosticKind.ERROR,
                            context.root / referenced_path,
                            "Delegated setup instruction was not selected; "
                            "detector scan incomplete",
                        )
                    )
                    continue
                seen_files.add(referenced.relative_path)
                if referenced.size > context.limits.max_file_bytes:
                    diagnostics.append(
                        Diagnostic(
                            DiagnosticKind.ERROR,
                            referenced.absolute_path,
                            "Refusing to inspect delegated setup instruction larger than "
                            f"max_file_bytes={context.limits.max_file_bytes}; scan incomplete",
                        )
                    )
                    continue
                remaining_bytes = context.limits.max_total_bytes - inspected_bytes
                if referenced.size > remaining_bytes:
                    diagnostics.append(
                        Diagnostic(
                            DiagnosticKind.ERROR,
                            referenced.absolute_path,
                            "Aggregate byte budget reached at "
                            f"max_total_bytes={context.limits.max_total_bytes}; scan incomplete",
                        )
                    )
                    break
                referenced_content, referenced_diagnostics = safe_read_regular_file(
                    referenced.absolute_path,
                    min(context.limits.max_file_bytes, remaining_bytes),
                )
                diagnostics.extend(referenced_diagnostics)
                if referenced_content is None:
                    continue
                inspected_files += 1
                inspected_bytes += len(referenced_content)
                try:
                    referenced_text = referenced_content.decode("utf-8")
                except UnicodeDecodeError:
                    diagnostics.append(
                        Diagnostic(
                            DiagnosticKind.ERROR,
                            referenced.absolute_path,
                            "Delegated setup instruction is not valid UTF-8; scan incomplete",
                        )
                    )
                    continue
                for line_number, line in enumerate(
                    referenced_text.splitlines(), start=1
                ):
                    if not _line_has_campaign_domain(line, context.database.domains):
                        continue
                    findings.append(
                        _domain_finding(
                            path=referenced.relative_path,
                            line=line_number,
                            delegated_by=item.relative_path,
                        )
                    )

        return DetectorResult(
            detector_id=self.id,
            applicability=Applicability.APPLICABLE,
            findings=tuple(findings),
            diagnostics=_bounded_diagnostics(
                diagnostics,
                root=context.root,
                limit=context.limits.max_diagnostics,
            ),
            coverage=Coverage(
                files_seen=len(seen_files),
                files_inspected=inspected_files,
                bytes_inspected=inspected_bytes,
            ),
        )


def _is_skill_manifest(path: Path) -> bool:
    return path.name == "SKILL.md"


def _local_setup_references(content: str, skill_path: Path) -> tuple[Path, ...]:
    references: set[Path] = set()
    raw_targets = (
        *(match.group(1) for match in _MARKDOWN_LINK.finditer(content)),
        *(match.group(1) for match in _BACKTICK_PATH.finditer(content)),
    )
    for raw_target_value in raw_targets:
        parsed_target = urlsplit(raw_target_value)
        if parsed_target.scheme or parsed_target.netloc:
            continue
        raw_target = parsed_target.path.replace("\\", "/")
        target = Path(raw_target)
        if target.is_absolute() or ".." in target.parts or target.suffix.lower() != ".md":
            continue
        if not any(part in target.name.lower() for part in _SETUP_NAME_PARTS):
            continue
        references.add(skill_path.parent / target)
    return tuple(sorted(references, key=Path.as_posix))


def _domain_finding(
    *, path: Path, line: int, delegated_by: Path | None
) -> Finding:
    technique_ids: tuple[str, ...]
    if delegated_by is None:
        rule_id = "known-malicious-skill-domain"
        evidence = f"known campaign domain: {_CAMPAIGN_DOMAIN}"
        technique_ids = ("skill.known-malicious-domain",)
    else:
        rule_id = "delegated-known-malicious-domain"
        evidence = (
            f"known campaign domain: {_CAMPAIGN_DOMAIN} "
            f"(delegated by {delegated_by.as_posix()})"
        )
        technique_ids = (
            "skill.known-malicious-domain",
            "skill.delegated-setup",
        )
    return Finding(
        detector_id="clawhavoc-skill",
        rule_id=rule_id,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        path=path,
        line=line,
        evidence=evidence,
        campaign_ids=(_CAMPAIGN_ID,),
        technique_ids=technique_ids,
        remediation_url=_REMEDIATION_URL,
    )


def _line_has_campaign_domain(line: str, known_domains: frozenset[str]) -> bool:
    if _CAMPAIGN_DOMAIN not in known_domains:
        return False
    for match in _URL.finditer(line):
        try:
            hostname = urlsplit(match.group(0)).hostname
        except ValueError:
            continue
        if hostname is not None and hostname.lower() == _CAMPAIGN_DOMAIN:
            return True
    return False


def _bounded_diagnostics(
    diagnostics: list[Diagnostic], *, root: Path, limit: int
) -> tuple[Diagnostic, ...]:
    ordered = sorted(
        diagnostics,
        key=lambda diagnostic: (
            diagnostic.kind,
            diagnostic.path.as_posix(),
            diagnostic.message,
        ),
    )
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

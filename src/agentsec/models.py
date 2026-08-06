from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(StrEnum):
    CONFIRMED = "confirmed"
    HIGH = "high"
    REVIEW = "review"
    CONTESTED = "contested"


class DiagnosticKind(StrEnum):
    ERROR = "error"
    WARNING = "warning"


class Applicability(StrEnum):
    APPLICABLE = "applicable"
    NOT_APPLICABLE = "not_applicable"


@dataclass(frozen=True, slots=True)
class Diagnostic:
    kind: DiagnosticKind
    path: Path
    message: str


@dataclass(frozen=True, slots=True)
class Finding:
    detector_id: str
    rule_id: str
    severity: Severity
    confidence: Confidence
    path: Path
    evidence: str
    campaign_ids: tuple[str, ...] = ()
    technique_ids: tuple[str, ...] = ()
    line: int | None = None
    remediation_url: str | None = None


@dataclass(frozen=True, slots=True)
class Coverage:
    files_seen: int = 0
    files_inspected: int = 0
    bytes_inspected: int = 0
    not_scanned: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class DetectorResult:
    detector_id: str
    applicability: Applicability
    findings: tuple[Finding, ...]
    diagnostics: tuple[Diagnostic, ...]
    coverage: Coverage


@dataclass(frozen=True, slots=True)
class ThreatDatabase:
    version: str
    updated: str
    package_versions: Mapping[str, frozenset[str]]
    wildcard_package_versions: Mapping[str, frozenset[str]]
    hashes: Mapping[str, str]
    domains: frozenset[str]
    commit_indicators: tuple[Mapping[str, str], ...]
    complete: bool = True


@dataclass(frozen=True, slots=True)
class ScanResult:
    tool_version: str
    database_version: str
    root: Path
    detector_results: tuple[DetectorResult, ...]
    diagnostics: tuple[Diagnostic, ...]
    elapsed_ms: int

    @property
    def complete(self) -> bool:
        return not any(
            diagnostic.kind is DiagnosticKind.ERROR for diagnostic in self._diagnostics()
        )

    @property
    def findings(self) -> tuple[Finding, ...]:
        return tuple(
            finding
            for detector_result in self.detector_results
            for finding in detector_result.findings
        )

    @property
    def coverage(self) -> Coverage:
        return Coverage(
            files_seen=sum(result.coverage.files_seen for result in self.detector_results),
            files_inspected=sum(
                result.coverage.files_inspected for result in self.detector_results
            ),
            bytes_inspected=sum(
                result.coverage.bytes_inspected for result in self.detector_results
            ),
            not_scanned=self.not_scanned,
        )

    @property
    def not_scanned(self) -> tuple[str, ...]:
        return tuple(
            sorted(
                {
                    capability
                    for result in self.detector_results
                    for capability in result.coverage.not_scanned
                }
            )
        )

    def exit_code(self) -> int:
        if not self.complete:
            return 2
        if self.findings:
            return 1
        return 0

    def to_dict(self) -> dict[str, object]:
        detector_results = sorted(self.detector_results, key=lambda result: result.detector_id)
        findings = sorted(
            (finding for result in detector_results for finding in result.findings),
            key=lambda finding: (
                finding.severity,
                finding.detector_id,
                finding.rule_id,
                str(finding.path),
                finding.evidence,
            ),
        )
        diagnostics = sorted(
            (
                *self.diagnostics,
                *(diagnostic for result in detector_results for diagnostic in result.diagnostics),
            ),
            key=lambda diagnostic: (diagnostic.kind, str(diagnostic.path), diagnostic.message),
        )
        return {
            "tool_version": self.tool_version,
            "database_version": self.database_version,
            "root": str(self.root),
            "complete": self.complete,
            "elapsed_ms": self.elapsed_ms,
            "coverage": self._coverage_to_dict(),
            "not_scanned": list(self.not_scanned),
            "diagnostics": [self._diagnostic_to_dict(diagnostic) for diagnostic in diagnostics],
            "findings": [self._finding_to_dict(finding) for finding in findings],
        }

    def _diagnostics(self) -> tuple[Diagnostic, ...]:
        return (
            *self.diagnostics,
            *(
                diagnostic
                for result in self.detector_results
                if result.applicability is Applicability.APPLICABLE
                for diagnostic in result.diagnostics
            ),
        )

    def _coverage_to_dict(self) -> dict[str, object]:
        coverage = self.coverage
        return {
            "files_seen": coverage.files_seen,
            "files_inspected": coverage.files_inspected,
            "bytes_inspected": coverage.bytes_inspected,
        }

    @staticmethod
    def _diagnostic_to_dict(diagnostic: Diagnostic) -> dict[str, object]:
        return {
            "kind": diagnostic.kind.value,
            "path": str(diagnostic.path),
            "message": diagnostic.message,
        }

    @staticmethod
    def _finding_to_dict(finding: Finding) -> dict[str, object]:
        return {
            "detector_id": finding.detector_id,
            "rule_id": finding.rule_id,
            "severity": finding.severity.value,
            "confidence": finding.confidence.value,
            "path": str(finding.path),
            "evidence": finding.evidence,
            "campaign_ids": list(finding.campaign_ids),
            "technique_ids": list(finding.technique_ids),
            "line": finding.line,
            "remediation_url": finding.remediation_url,
        }

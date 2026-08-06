"""Exception-safe deterministic aggregation of detector results."""

from __future__ import annotations

import logging
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from time import monotonic_ns

from agentsec import __version__
from agentsec.detectors.base import Detector, ScanContext
from agentsec.engine.discovery import (
    DiscoveredFile,
    DiscoveryLimits,
    discover,
    resolve_scan_root,
)
from agentsec.models import (
    Applicability,
    Coverage,
    DetectorResult,
    Diagnostic,
    DiagnosticKind,
    ScanResult,
    ThreatDatabase,
)

_LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class _DiagnosticBuffer:
    root: Path
    limit: int
    items: list[Diagnostic] = field(default_factory=list)
    truncated: bool = False

    def add(self, diagnostic: Diagnostic) -> None:
        if len(self.items) < self.limit:
            self.items.append(diagnostic)
        else:
            self.truncated = True

    def extend(self, diagnostics: Sequence[Diagnostic]) -> None:
        for diagnostic in diagnostics:
            if diagnostic.message.startswith("diagnostics truncated at max_diagnostics="):
                self.truncated = True
            else:
                self.add(diagnostic)

    def finish(self) -> tuple[Diagnostic, ...]:
        diagnostics = sorted(
            self.items,
            key=lambda diagnostic: (
                diagnostic.kind,
                diagnostic.path.as_posix(),
                diagnostic.message,
            ),
        )
        if self.truncated:
            diagnostics.append(
                Diagnostic(
                    kind=DiagnosticKind.ERROR,
                    path=self.root,
                    message=(
                        "diagnostics truncated at "
                        f"max_diagnostics={self.limit}; scan incomplete"
                    ),
                )
            )
        return tuple(diagnostics)


def run_scan(
    root: Path,
    detectors: Sequence[Detector],
    database: ThreatDatabase,
    limits: DiscoveryLimits,
) -> ScanResult:
    """Discover a repository once and aggregate isolated detector executions."""
    started_ns = monotonic_ns()
    scan_root, root_diagnostics = resolve_scan_root(root, limits)
    context_root = scan_root if scan_root is not None else root.absolute()
    files: tuple[DiscoveredFile, ...]
    if scan_root is None:
        files = ()
        discovery_diagnostics = root_diagnostics
    else:
        files, discovery_diagnostics = discover(
            scan_root,
            limits,
            resolved_root=scan_root,
        )
    context = ScanContext(
        root=context_root,
        files=files,
        database=database,
        limits=limits,
    )
    diagnostics = _DiagnosticBuffer(root=context_root, limit=limits.max_diagnostics)
    diagnostics.extend(discovery_diagnostics)
    detector_results: list[DetectorResult] = []

    for detector in sorted(detectors, key=lambda item: item.id):
        try:
            applicable = detector.applies(context)
            if not applicable:
                detector_results.append(_not_applicable_result(detector.id))
                continue
            detector_results.append(detector.run(context))
        except Exception as error:
            _LOGGER.debug("Detector %s failed", detector.id, exc_info=True)
            diagnostics.add(
                Diagnostic(
                    kind=DiagnosticKind.ERROR,
                    path=context_root,
                    message=f"detector failed: {detector.id}: {error}",
                )
            )
            detector_results.append(_failed_detector_result(detector.id))

    elapsed_ms = (monotonic_ns() - started_ns) // 1_000_000
    return ScanResult(
        tool_version=__version__,
        database_version=database.version,
        root=context_root,
        detector_results=tuple(detector_results),
        diagnostics=diagnostics.finish(),
        elapsed_ms=elapsed_ms,
    )


def _not_applicable_result(detector_id: str) -> DetectorResult:
    return DetectorResult(
        detector_id=detector_id,
        applicability=Applicability.NOT_APPLICABLE,
        findings=(),
        diagnostics=(),
        coverage=Coverage(),
    )


def _failed_detector_result(detector_id: str) -> DetectorResult:
    return DetectorResult(
        detector_id=detector_id,
        applicability=Applicability.APPLICABLE,
        findings=(),
        diagnostics=(),
        coverage=Coverage(),
    )

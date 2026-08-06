"""Exception-safe deterministic aggregation of detector results."""

from __future__ import annotations

import logging
from collections.abc import Sequence
from pathlib import Path
from time import monotonic_ns

from agentsec import __version__
from agentsec.detectors.base import Detector, ScanContext
from agentsec.engine.discovery import DiscoveryLimits, discover
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


def run_scan(
    root: Path,
    detectors: Sequence[Detector],
    database: ThreatDatabase,
    limits: DiscoveryLimits,
) -> ScanResult:
    """Discover a repository once and aggregate isolated detector executions."""
    started_ns = monotonic_ns()
    scan_root = root.resolve(strict=False)
    files, discovery_diagnostics = discover(scan_root, limits)
    context = ScanContext(
        root=scan_root,
        files=files,
        database=database,
        limits=limits,
    )
    aggregate_diagnostics = list(discovery_diagnostics)
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
            aggregate_diagnostics.append(
                Diagnostic(
                    kind=DiagnosticKind.ERROR,
                    path=scan_root,
                    message=f"detector failed: {detector.id}: {error}",
                )
            )
            detector_results.append(_failed_detector_result(detector.id))

    elapsed_ms = (monotonic_ns() - started_ns) // 1_000_000
    return ScanResult(
        tool_version=__version__,
        database_version=database.version,
        root=scan_root,
        detector_results=tuple(detector_results),
        diagnostics=tuple(aggregate_diagnostics),
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

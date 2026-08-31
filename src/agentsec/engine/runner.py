"""Exception-safe deterministic aggregation of detector results."""

from __future__ import annotations

import logging
from collections.abc import Callable, Sequence
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
_GLOBAL_NOT_SCANNED = (
    "container.filesystems",
    "host.caches",
    "host.credentials",
    "host.global_config",
    "host.processes",
    "remediation.automatic",
    "remote.ci",
    "remote.repositories",
)


@dataclass(frozen=True, slots=True)
class ProgressState:
    files: int
    directories: int
    entries: int
    complete: bool


ProgressCallback = Callable[[int, str, bool, ProgressState | None], None]


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
    *,
    progress: ProgressCallback | None = None,
) -> ScanResult:
    """Discover a repository once and aggregate isolated detector executions."""
    started_ns = monotonic_ns()
    detector_ids = ",".join(sorted(detector.id for detector in detectors)) or "none"
    _emit_progress(progress, 2, f"Validating repository: requested={root}")
    scan_root, root_diagnostics = resolve_scan_root(root, limits)
    context_root = scan_root if scan_root is not None else root.absolute()
    files: tuple[DiscoveredFile, ...]
    if scan_root is None:
        _emit_progress(
            progress,
            2,
            f"Repository validation failed: diagnostics={len(root_diagnostics)}",
        )
        files = ()
        discovery_diagnostics = root_diagnostics
    else:
        _emit_progress(
            progress,
            2,
            f"Repository validated: root={scan_root} type=directory "
            f"scan_mode=read-only detectors={detector_ids}",
        )
        _emit_progress(
            progress,
            2,
            "Safety limits: "
            f"max_files={limits.max_files} max_entries={limits.max_entries} "
            f"max_directories={limits.max_directories} "
            f"max_file_bytes={limits.max_file_bytes} "
            f"max_total_bytes={limits.max_total_bytes}",
        )
        _emit_progress(progress, 3, "Discovering files")
        discovery_result = discover(
            scan_root,
            limits,
            resolved_root=scan_root,
            progress=lambda file_count, directory_count, entry_count, complete: (
                _emit_progress(
                    progress,
                    3,
                    (
                        "Discovery complete: "
                        if complete
                        else "Discovered "
                    )
                    + (
                        f"files={file_count} directories={directory_count} "
                        f"entries={entry_count}"
                        if complete
                        else (
                            f"{file_count} paths across {directory_count} directories "
                            f"({entry_count} entries seen)"
                        )
                    ),
                    detail=not complete,
                    state=ProgressState(
                        files=file_count,
                        directories=directory_count,
                        entries=entry_count,
                        complete=complete,
                    ),
                )
            ),
        )
        files = discovery_result.files
        discovery_diagnostics = discovery_result.diagnostics
    context = ScanContext(
        root=context_root,
        files=files,
        database=database,
        limits=limits,
        progress=lambda file_count, byte_count: _emit_progress(
            progress,
            4,
            f"Inspected {file_count} files ({byte_count} bytes)",
            detail=True,
        ),
    )
    diagnostics = _DiagnosticBuffer(root=context_root, limit=limits.max_diagnostics)
    diagnostics.extend(discovery_diagnostics)
    detector_results: list[DetectorResult] = []
    selected_not_scanned = {
        capability
        for detector in detectors
        for capability in getattr(getattr(detector, "metadata", None), "not_scanned", ())
    }

    ordered_detectors = sorted(detectors, key=lambda item: item.id)
    _emit_progress(progress, 4, "Running detectors")
    for index, detector in enumerate(ordered_detectors, start=1):
        _emit_progress(
            progress,
            4,
            f"Running detector {index}/{len(ordered_detectors)}: {detector.id}",
            detail=True,
        )
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

    _emit_progress(progress, 5, "Building report")
    elapsed_ms = (monotonic_ns() - started_ns) // 1_000_000
    return ScanResult(
        tool_version=__version__,
        database_version=database.version,
        root=context_root,
        detector_results=tuple(detector_results),
        diagnostics=diagnostics.finish(),
        elapsed_ms=elapsed_ms,
        global_not_scanned=tuple(sorted({*_GLOBAL_NOT_SCANNED, *selected_not_scanned})),
    )


def _emit_progress(
    progress: ProgressCallback | None,
    stage: int,
    message: str,
    *,
    detail: bool = False,
    state: ProgressState | None = None,
) -> None:
    if progress is not None:
        progress(stage, message, detail, state)


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

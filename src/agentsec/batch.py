"""Bounded in-process orchestration for explicit repository roots."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from time import monotonic_ns

from agentsec import __version__
from agentsec.detectors.base import Detector
from agentsec.engine.discovery import DiscoveryLimits
from agentsec.engine.runner import ProgressCallback, run_scan
from agentsec.models import DiagnosticKind, ScanResult, ThreatDatabase
from agentsec.scopes import ScanScope

_MAX_PATH_FILE_BYTES = 1_048_576
_MAX_ROOTS = 10_000


class BatchInputError(ValueError):
    """Raised when explicit batch input cannot be validated safely."""


@dataclass(frozen=True, slots=True)
class BatchSummary:
    repositories: int
    exit_0: int
    exit_1: int
    exit_2: int
    findings: int
    files_selected: int
    files_inspected: int
    bytes_inspected: int
    errors: int
    warnings: int


@dataclass(frozen=True, slots=True)
class BatchResult:
    tool_version: str
    database_version: str
    scope: ScanScope
    results: tuple[ScanResult, ...]
    summary: BatchSummary
    elapsed_ms: int

    @property
    def complete(self) -> bool:
        return self.summary.exit_2 == 0

    def exit_code(self) -> int:
        if self.summary.exit_2:
            return 2
        if self.summary.exit_1:
            return 1
        return 0


def read_root_file(path: Path) -> tuple[Path, ...]:
    """Read a bounded UTF-8 file containing one repository root per line."""
    try:
        if path.stat().st_size > _MAX_PATH_FILE_BYTES:
            raise BatchInputError(
                f"root file exceeds {_MAX_PATH_FILE_BYTES} bytes"
            )
        raw = path.read_bytes()
    except BatchInputError:
        raise
    except OSError as error:
        raise BatchInputError(f"cannot read root file: {path}: {error}") from error
    if len(raw) > _MAX_PATH_FILE_BYTES:
        raise BatchInputError(f"root file exceeds {_MAX_PATH_FILE_BYTES} bytes")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise BatchInputError("root file must be valid UTF-8") from error
    roots = tuple(Path(line.strip()) for line in text.splitlines() if line.strip())
    if not roots:
        raise BatchInputError("root file contains no roots")
    if len(roots) > _MAX_ROOTS:
        raise BatchInputError(f"batch is limited to {_MAX_ROOTS} roots")
    return roots


def resolve_batch_roots(roots: Sequence[Path]) -> tuple[Path, ...]:
    """Strictly resolve and validate explicit roots while preserving order."""
    if not roots:
        raise BatchInputError("batch requires at least one root")
    if len(roots) > _MAX_ROOTS:
        raise BatchInputError(f"batch is limited to {_MAX_ROOTS} roots")
    resolved: list[Path] = []
    seen: set[Path] = set()
    for root in roots:
        try:
            candidate = root.resolve(strict=True)
        except FileNotFoundError as error:
            raise BatchInputError(f"root does not exist: {root}") from error
        except OSError as error:
            raise BatchInputError(f"cannot resolve root: {root}: {error}") from error
        if not candidate.is_dir():
            raise BatchInputError(f"root is not a directory: {root}")
        if candidate in seen:
            raise BatchInputError(f"duplicate resolved root: {candidate}")
        seen.add(candidate)
        resolved.append(candidate)
    return tuple(resolved)


def run_batch(
    roots: Sequence[Path],
    detectors: Sequence[Detector],
    database: ThreatDatabase,
    limits: DiscoveryLimits,
    *,
    scope: ScanScope,
    progress: ProgressCallback | None = None,
) -> BatchResult:
    """Run the same confined scanner once per explicit root, in input order."""
    started_ns = monotonic_ns()
    resolved = resolve_batch_roots(roots)
    results = tuple(
        run_scan(
            root,
            detectors,
            database,
            limits,
            scope=scope,
            progress=progress,
        )
        for root in resolved
    )
    exit_codes = tuple(result.exit_code() for result in results)
    diagnostics = tuple(
        diagnostic
        for result in results
        for diagnostic in (
            *result.diagnostics,
            *(
                item
                for detector_result in result.detector_results
                for item in detector_result.diagnostics
            ),
        )
    )
    summary = BatchSummary(
        repositories=len(results),
        exit_0=exit_codes.count(0),
        exit_1=exit_codes.count(1),
        exit_2=exit_codes.count(2),
        findings=sum(len(result.findings) for result in results),
        files_selected=sum(result.discovery.files_selected for result in results),
        files_inspected=sum(result.coverage.files_inspected for result in results),
        bytes_inspected=sum(result.coverage.bytes_inspected for result in results),
        errors=sum(item.kind is DiagnosticKind.ERROR for item in diagnostics),
        warnings=sum(item.kind is DiagnosticKind.WARNING for item in diagnostics),
    )
    return BatchResult(
        tool_version=__version__,
        database_version=database.version,
        scope=scope,
        results=results,
        summary=summary,
        elapsed_ms=(monotonic_ns() - started_ns) // 1_000_000,
    )

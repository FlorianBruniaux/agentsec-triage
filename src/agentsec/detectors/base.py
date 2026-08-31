"""Contracts shared by all repository detectors."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from agentsec.engine.discovery import DiscoveredFile, DiscoveryLimits
from agentsec.models import DetectorResult, ThreatDatabase
from agentsec.scopes import ScanScope


@dataclass(frozen=True, slots=True)
class DetectorRuleMetadata:
    """Stable identifiers and threat mappings for one active detector rule."""

    id: str
    technique_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class DetectorMetadata:
    """Immutable, machine-readable description of one detector's contract."""

    description: str
    supported_inputs: tuple[str, ...]
    campaign_ids: tuple[str, ...]
    technique_ids: tuple[str, ...]
    source_references: tuple[str, ...]
    limitations: tuple[str, ...]
    remediation_url: str | None
    not_scanned: tuple[str, ...]
    applicability: str = "input_dependent"
    rules: tuple[DetectorRuleMetadata, ...] = ()


@dataclass(frozen=True, slots=True)
class ScanContext:
    """Immutable scan inputs shared by every detector in a run."""

    root: Path
    files: tuple[DiscoveredFile, ...]
    database: ThreatDatabase
    limits: DiscoveryLimits
    scope: ScanScope = ScanScope.SOURCE
    progress: Callable[[int, int], None] | None = None


class Detector(Protocol):
    """A deterministic detector that can participate in a repository scan."""

    id: str
    version: str
    metadata: DetectorMetadata

    def applies(self, context: ScanContext) -> bool: ...

    def run(self, context: ScanContext) -> DetectorResult: ...

"""Contracts shared by all repository detectors."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from agentsec.engine.discovery import DiscoveredFile, DiscoveryLimits
from agentsec.models import DetectorResult, ThreatDatabase


@dataclass(frozen=True, slots=True)
class ScanContext:
    """Immutable scan inputs shared by every detector in a run."""

    root: Path
    files: tuple[DiscoveredFile, ...]
    database: ThreatDatabase
    limits: DiscoveryLimits


class Detector(Protocol):
    """A deterministic detector that can participate in a repository scan."""

    id: str
    version: str

    def applies(self, context: ScanContext) -> bool: ...

    def run(self, context: ScanContext) -> DetectorResult: ...

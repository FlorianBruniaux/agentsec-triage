"""Explicit built-in detector registry."""

from __future__ import annotations

from collections.abc import Sequence

from agentsec.detectors.base import Detector
from agentsec.detectors.shai_hulud import ShaiHuludDetector

_DETECTORS: tuple[Detector, ...] = (ShaiHuludDetector(),)


def get_detectors(ids: Sequence[str] | None = None) -> tuple[Detector, ...]:
    """Return registered detectors, optionally restricted to explicit IDs."""
    if ids is None:
        return _DETECTORS

    requested_ids = frozenset(ids)
    available_ids = frozenset(detector.id for detector in _DETECTORS)
    unknown_ids = sorted(requested_ids - available_ids)
    if unknown_ids:
        raise ValueError(f"unknown detector IDs: {', '.join(unknown_ids)}")

    return tuple(detector for detector in _DETECTORS if detector.id in requested_ids)

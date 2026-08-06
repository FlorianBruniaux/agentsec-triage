"""Detector contracts and the explicit built-in registry."""

from agentsec.detectors.base import Detector, ScanContext
from agentsec.detectors.registry import get_detectors

__all__ = ["Detector", "ScanContext", "get_detectors"]

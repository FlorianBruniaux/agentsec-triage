from __future__ import annotations

import hashlib
from pathlib import Path

from agentsec.analyzers.safe_io import safe_read_regular_file
from agentsec.models import Diagnostic, DiagnosticKind


def hash_file(path: Path, max_bytes: int) -> tuple[str | None, tuple[Diagnostic, ...]]:
    """Return a SHA-256 digest of one bounded, safely read regular file."""
    content, diagnostics = safe_read_regular_file(path, max_bytes)
    if content is None:
        return None, (_error(path, "Unable to hash payload safely"),)
    return hashlib.sha256(content).hexdigest(), diagnostics


def _error(path: Path, message: str) -> Diagnostic:
    return Diagnostic(DiagnosticKind.ERROR, path, message)

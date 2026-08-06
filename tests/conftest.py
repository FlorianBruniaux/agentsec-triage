from pathlib import Path

import pytest

from agentsec.models import ScanResult


@pytest.fixture
def empty_scan_result(tmp_path: Path) -> ScanResult:
    return ScanResult(
        tool_version="0.1.0a0",
        database_version="2.26.0",
        root=tmp_path,
        detector_results=(),
        diagnostics=(),
        elapsed_ms=0,
    )

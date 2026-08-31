from __future__ import annotations

import json

from agentsec.models import ScanResult
from agentsec.redaction import redact_result


def render_json(result: ScanResult, *, redact: bool) -> str:
    """Render a scan result as versioned JSON."""
    payload = scan_payload(result, redact=redact)
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def scan_payload(result: ScanResult, *, redact: bool) -> dict[str, object]:
    """Build a scan-result v2 payload before deterministic JSON rendering."""
    payload: dict[str, object] = {"schema_version": "2", **result.to_dict()}
    if redact:
        payload = redact_result(payload, result.root)
    return payload

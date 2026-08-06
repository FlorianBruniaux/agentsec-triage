from __future__ import annotations

import json

from agentsec.models import ScanResult
from agentsec.redaction import redact_result


def render_json(result: ScanResult, *, redact: bool) -> str:
    """Render a scan result as versioned JSON."""
    payload = {"schema_version": "1", **result.to_dict()}
    if redact:
        payload = redact_result(payload, result.root)
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"

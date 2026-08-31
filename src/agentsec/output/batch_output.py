"""Deterministic JSON and compact human output for batch scans."""

from __future__ import annotations

import json

from agentsec.batch import BatchResult, BatchSummary
from agentsec.output.json_output import scan_payload


def batch_payload(result: BatchResult, *, redact: bool) -> dict[str, object]:
    children: list[dict[str, object]] = []
    for index, child in enumerate(result.results, start=1):
        payload = scan_payload(child, redact=redact)
        if redact:
            replaced = _replace_scan_root(payload, f"<SCAN_ROOT_{index}>")
            if not isinstance(replaced, dict):
                raise TypeError("redacted scan payload must remain an object")
            payload = replaced
        children.append(payload)
    return {
        "schema_version": "1",
        "tool_version": result.tool_version,
        "database_version": result.database_version,
        "scope": result.scope.value,
        "complete": result.complete,
        "elapsed_ms": result.elapsed_ms,
        "summary": _summary_payload(result.summary),
        "results": children,
    }


def render_batch_json(result: BatchResult, *, redact: bool) -> str:
    return json.dumps(
        batch_payload(result, redact=redact),
        indent=2,
        sort_keys=True,
        ensure_ascii=True,
    ) + "\n"


def render_batch_human(result: BatchResult, *, redact: bool) -> str:
    lines = [
        f"AgentSec batch {result.tool_version} | threat database {result.database_version}",
        f"Scope: {result.scope.value}",
        f"Complete: {'yes' if result.complete else 'no'}",
        f"Repositories: {result.summary.repositories}",
        "Results:",
    ]
    for index, child in enumerate(result.results, start=1):
        root = f"<SCAN_ROOT_{index}>" if redact else child.root.as_posix()
        lines.append(
            f"  {root}: exit={child.exit_code()} "
            f"complete={'yes' if child.complete else 'no'} "
            f"findings={len(child.findings)} "
            f"selected={child.discovery.files_selected} "
            f"inspected={child.coverage.files_inspected}"
        )
    summary = result.summary
    lines.extend(
        (
            "Summary: "
            f"exit_0={summary.exit_0} exit_1={summary.exit_1} exit_2={summary.exit_2}",
            f"Coverage: selected={summary.files_selected} "
            f"inspected={summary.files_inspected} bytes={summary.bytes_inspected}",
            f"Diagnostics: errors={summary.errors} warnings={summary.warnings}",
        )
    )
    return "\n".join(lines) + "\n"


def _summary_payload(summary: BatchSummary) -> dict[str, int]:
    return {
        "repositories": summary.repositories,
        "exit_0": summary.exit_0,
        "exit_1": summary.exit_1,
        "exit_2": summary.exit_2,
        "findings": summary.findings,
        "files_selected": summary.files_selected,
        "files_inspected": summary.files_inspected,
        "bytes_inspected": summary.bytes_inspected,
        "errors": summary.errors,
        "warnings": summary.warnings,
    }


def _replace_scan_root(value: object, replacement: str) -> object:
    if isinstance(value, dict):
        return {key: _replace_scan_root(item, replacement) for key, item in value.items()}
    if isinstance(value, list):
        return [_replace_scan_root(item, replacement) for item in value]
    if isinstance(value, str):
        return value.replace("<SCAN_ROOT>", replacement)
    return value

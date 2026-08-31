from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections.abc import Sequence
from hashlib import sha256
from importlib import resources
from pathlib import Path
from typing import NoReturn

from agentsec import __version__
from agentsec.batch import BatchInputError, read_root_file, run_batch
from agentsec.detectors.explain import (
    build_detector_explanation,
    render_detector_explanation_human,
    render_detector_explanation_json,
)
from agentsec.detectors.registry import get_detectors
from agentsec.engine.discovery import DiscoveryLimits
from agentsec.engine.runner import ProgressCallback, ProgressState, run_scan
from agentsec.models import ThreatDatabase
from agentsec.output.batch_output import render_batch_human, render_batch_json
from agentsec.output.human import render_human
from agentsec.output.json_output import render_json
from agentsec.output.sarif_output import render_sarif
from agentsec.redaction import redact_text
from agentsec.scopes import ScanScope
from agentsec.threat_db import ThreatDatabaseError, load_bundled_database

_DEFAULT_MAX_FILE_BYTES = 4_000_000
_DEFAULT_MAX_TOTAL_BYTES = 1_000_000_000
_DEFAULT_MAX_FILES = 1_000_000
_DEFAULT_MAX_GIT_COMMITS = 10_000
_DEFAULT_MAX_DIAGNOSTICS = 100
_DEFAULT_MAX_ENTRIES = 1_000_000
_DEFAULT_MAX_DIRECTORIES = 100_000

_SCHEMA_CONTRACTS = {
    "scan-result-v2": (
        "scan-result-v2.schema.json",
        "https://agentsec.dev/schemas/scan-result-v2.schema.json",
        {
            "schema_version",
            "tool_version",
            "database_version",
            "root",
            "scope",
            "complete",
            "elapsed_ms",
            "discovery",
            "detectors",
            "not_scanned",
            "diagnostics",
            "findings",
        },
    ),
    "batch-result-v1": (
        "batch-result-v1.schema.json",
        "https://agentsec.dev/schemas/batch-result-v1.schema.json",
        {
            "schema_version",
            "tool_version",
            "database_version",
            "scope",
            "complete",
            "elapsed_ms",
            "summary",
            "results",
        },
    ),
    "detector-explain-v1": (
        "detector-explain-v1.schema.json",
        "https://agentsec.dev/schemas/detector-explain-v1.schema.json",
        {
            "schema_version",
            "tool_version",
            "database",
            "detector",
            "counters",
            "intelligence_projection",
        },
    ),
}


class _ArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        self.print_usage(sys.stderr)
        self.exit(2, f"{self.prog}: error: {message}\n")


def build_parser() -> argparse.ArgumentParser:
    parser = _ArgumentParser(prog="agentsec")
    parser.add_argument("--version", action="version", version=f"agentsec {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    scan = commands.add_parser("scan", help="scan one repository")
    scan.add_argument("root", type=Path, help="repository root to inspect")
    scan.add_argument(
        "--scope",
        type=ScanScope,
        choices=tuple(ScanScope),
        default=ScanScope.SOURCE,
        help="scan source, installed dependencies, or the full repository",
    )
    scan.add_argument(
        "--detector",
        action="append",
        dest="detector_ids",
        help="run one detector ID; repeat to select more than one",
    )
    scan.add_argument(
        "--format",
        choices=("human", "json", "sarif"),
        default="human",
        help="final report format written to stdout (default: human)",
    )
    scan.add_argument(
        "--redact",
        action="store_true",
        help="replace the absolute scan root and recognized secret-shaped evidence",
    )
    scan.add_argument(
        "--color",
        choices=("auto", "always", "never"),
        default="always",
        help=(
            "colorize severity labels in human output (default: always). "
            "Use auto to color only on a terminal and honor NO_COLOR, "
            "or never to disable, e.g. before redirecting to a file"
        ),
    )
    scan.add_argument(
        "--progress",
        nargs="?",
        const="always",
        default="auto",
        choices=("auto", "always", "never"),
        help=(
            "show scan phases (default: auto on terminals). "
            "Progress is written to stderr"
        ),
    )
    scan.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="show bounded path and byte counters; implies progress unless disabled",
    )
    scan.add_argument(
        "--max-file-bytes",
        type=_max_file_bytes,
        default=_DEFAULT_MAX_FILE_BYTES,
        help="maximum bytes read from one file (maximum: 4000000)",
    )
    scan.add_argument(
        "--max-total-bytes",
        type=_non_negative,
        default=_DEFAULT_MAX_TOTAL_BYTES,
        help="maximum aggregate bytes read during detector execution",
    )
    scan.add_argument(
        "--max-files",
        type=_non_negative,
        default=_DEFAULT_MAX_FILES,
        help="maximum repository paths discovered",
    )
    scan.add_argument(
        "--max-git-commits",
        type=_non_negative,
        default=_DEFAULT_MAX_GIT_COMMITS,
        help="reserved bound for Git history inspection when supported",
    )
    scan.add_argument(
        "--max-entries",
        type=_max_entries,
        default=_DEFAULT_MAX_ENTRIES,
        help="maximum directory entries visited (maximum: 1000000)",
    )
    scan.add_argument(
        "--max-directories",
        type=_max_directories,
        default=_DEFAULT_MAX_DIRECTORIES,
        help="maximum directories opened (maximum: 100000)",
    )

    batch = commands.add_parser("batch", help="scan explicit repository roots")
    batch.add_argument("roots", nargs="*", type=Path, help="repository roots to inspect")
    batch.add_argument(
        "--from-file",
        type=Path,
        help="UTF-8 file containing one repository root per line",
    )
    batch.add_argument(
        "--scope",
        type=ScanScope,
        choices=tuple(ScanScope),
        default=ScanScope.SOURCE,
        help="scan source, installed dependencies, or each full repository",
    )
    batch.add_argument(
        "--detector",
        action="append",
        dest="detector_ids",
        help="run one detector ID; repeat to select more than one",
    )
    batch.add_argument("--format", choices=("human", "json"), default="human")
    batch.add_argument("--redact", action="store_true")
    batch.add_argument(
        "--progress",
        nargs="?",
        const="always",
        default="auto",
        choices=("auto", "always", "never"),
        help="show child scan phases on stderr",
    )
    batch.add_argument("-v", "--verbose", action="store_true")
    batch.add_argument(
        "--max-file-bytes", type=_max_file_bytes, default=_DEFAULT_MAX_FILE_BYTES
    )
    batch.add_argument(
        "--max-total-bytes", type=_non_negative, default=_DEFAULT_MAX_TOTAL_BYTES
    )
    batch.add_argument("--max-files", type=_non_negative, default=_DEFAULT_MAX_FILES)
    batch.add_argument(
        "--max-git-commits", type=_non_negative, default=_DEFAULT_MAX_GIT_COMMITS
    )
    batch.add_argument("--max-entries", type=_max_entries, default=_DEFAULT_MAX_ENTRIES)
    batch.add_argument(
        "--max-directories", type=_max_directories, default=_DEFAULT_MAX_DIRECTORIES
    )

    detectors = commands.add_parser("detectors", help="inspect built-in detectors")
    detector_commands = detectors.add_subparsers(dest="detectors_command", required=True)
    detector_commands.add_parser("list", help="list detector IDs")
    explain = detector_commands.add_parser("explain", help="explain one detector")
    explain.add_argument("detector_id")
    explain.add_argument(
        "--format",
        choices=("human", "json"),
        default="human",
        help="coverage document format written to stdout (default: human)",
    )

    database = commands.add_parser("db", help="inspect bundled threat data")
    database_commands = database.add_subparsers(dest="database_command", required=True)
    database_commands.add_parser("info", help="show database metadata")
    commands.add_parser("doctor", help="validate local runtime resources")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    try:
        arguments = build_parser().parse_args(argv)
        if arguments.command == "scan":
            return _scan(arguments)
        if arguments.command == "batch":
            return _batch(arguments)
        if arguments.command == "detectors":
            return _detectors(arguments)
        if arguments.command == "db":
            return _db_info()
        if arguments.command == "doctor":
            return _doctor()
    except KeyboardInterrupt:
        print("agentsec: interrupted", file=sys.stderr)
        return 2
    return 2


def _non_negative(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be a non-negative integer") from error
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be a non-negative integer")
    return parsed


def _max_file_bytes(value: str) -> int:
    parsed = _non_negative(value)
    if parsed > _DEFAULT_MAX_FILE_BYTES:
        raise argparse.ArgumentTypeError("must not exceed 4000000 bytes")
    return parsed


def _max_directories(value: str) -> int:
    parsed = _non_negative(value)
    if parsed > _DEFAULT_MAX_DIRECTORIES:
        raise argparse.ArgumentTypeError("must not exceed 100000 directories")
    return parsed


def _max_entries(value: str) -> int:
    parsed = _non_negative(value)
    if parsed > _DEFAULT_MAX_ENTRIES:
        raise argparse.ArgumentTypeError("must not exceed 1000000 entries")
    return parsed


def _scan(arguments: argparse.Namespace) -> int:
    progress = _progress_reporter(arguments)
    if progress is not None:
        progress(1, "Loading threat database", False, None)
    database = _load_database(redact=arguments.redact, root=arguments.root)
    if database is None:
        return 2
    if progress is not None:
        progress(
            1,
            _database_progress_summary(database, redact=arguments.redact),
            False,
            None,
        )
    try:
        detectors = get_detectors(arguments.detector_ids)
    except ValueError as error:
        print(f"agentsec: {error}", file=sys.stderr)
        return 2
    limits = DiscoveryLimits(
        max_file_bytes=arguments.max_file_bytes,
        max_files=arguments.max_files,
        max_diagnostics=_DEFAULT_MAX_DIAGNOSTICS,
        max_total_bytes=arguments.max_total_bytes,
        max_git_commits=arguments.max_git_commits,
        max_entries=arguments.max_entries,
        max_directories=arguments.max_directories,
    )
    result = run_scan(
        arguments.root,
        detectors,
        database,
        limits,
        scope=arguments.scope,
        progress=progress,
    )
    if arguments.format == "json":
        print(render_json(result, redact=arguments.redact), end="")
    elif arguments.format == "sarif":
        print(render_sarif(result, redact=arguments.redact), end="")
    else:
        color = _color_enabled(arguments.color)
        print(render_human(result, redact=arguments.redact, color=color), end="")
    return result.exit_code()


def _batch(arguments: argparse.Namespace) -> int:
    if arguments.roots and arguments.from_file is not None:
        print(
            "agentsec: choose positional roots or --from-file, not both",
            file=sys.stderr,
        )
        return 2
    if not arguments.roots and arguments.from_file is None:
        print("agentsec: batch requires roots or --from-file", file=sys.stderr)
        return 2
    try:
        roots = (
            read_root_file(arguments.from_file)
            if arguments.from_file is not None
            else tuple(arguments.roots)
        )
    except BatchInputError as error:
        print(f"agentsec: {error}", file=sys.stderr)
        return 2
    database = _load_database(redact=arguments.redact)
    if database is None:
        return 2
    try:
        detectors = get_detectors(arguments.detector_ids)
    except ValueError as error:
        print(f"agentsec: {error}", file=sys.stderr)
        return 2
    limits = DiscoveryLimits(
        max_file_bytes=arguments.max_file_bytes,
        max_files=arguments.max_files,
        max_diagnostics=_DEFAULT_MAX_DIAGNOSTICS,
        max_total_bytes=arguments.max_total_bytes,
        max_git_commits=arguments.max_git_commits,
        max_entries=arguments.max_entries,
        max_directories=arguments.max_directories,
    )
    try:
        result = run_batch(
            roots,
            detectors,
            database,
            limits,
            scope=arguments.scope,
            progress=_batch_progress_reporter(arguments),
        )
    except BatchInputError as error:
        print(f"agentsec: {error}", file=sys.stderr)
        return 2
    if arguments.format == "json":
        print(render_batch_json(result, redact=arguments.redact), end="")
    else:
        print(render_batch_human(result, redact=arguments.redact), end="")
    return result.exit_code()


def _color_enabled(mode: str) -> bool:
    if mode == "always":
        return True
    if mode == "never":
        return False
    return sys.stdout.isatty() and "NO_COLOR" not in os.environ


def _database_progress_summary(
    database: ThreatDatabase,
    *,
    redact: bool = False,
) -> str:
    package_records = sum(
        len(versions)
        for mapping in (
            database.package_versions,
            database.wildcard_package_versions,
            database.contested_package_versions,
            database.contested_wildcard_package_versions,
        )
        for versions in mapping.values()
    )
    resource: object = "<REDACTED_PATH>" if redact else resources.files(
        "agentsec.resources"
    ).joinpath("threat-db.json")
    return (
        "Threat database ready: "
        f"version={database.version} updated={database.updated} "
        f"package_records={package_records} hashes={len(database.hashes)} "
        f"domains={len(database.domains)} "
        f"commit_indicators={len(database.commit_indicators)} resource={resource}"
    )


def _progress_reporter(arguments: argparse.Namespace) -> ProgressCallback | None:
    mode = arguments.progress
    interactive = sys.stderr.isatty()
    enabled = mode == "always" or (
        mode == "auto" and (arguments.verbose or interactive)
    )
    if mode == "never" or not enabled:
        return None

    active_width = 0

    def report(
        stage: int,
        message: str,
        detail: bool,
        state: ProgressState | None = None,
    ) -> None:
        nonlocal active_width
        if state is not None and interactive:
            line = _render_discovery_progress(stage, state)
            sys.stderr.write("\r" + line.ljust(active_width))
            sys.stderr.flush()
            active_width = len(line)
            if state.complete:
                sys.stderr.write("\n")
                sys.stderr.flush()
                active_width = 0
            return
        if detail and not arguments.verbose:
            return
        if active_width:
            sys.stderr.write("\n")
            active_width = 0
        visible_message = (
            redact_text(message, arguments.root) if arguments.redact else message
        )
        print(f"[{stage}/5] {visible_message}", file=sys.stderr, flush=True)

    return report


def _batch_progress_reporter(arguments: argparse.Namespace) -> ProgressCallback | None:
    mode = arguments.progress
    enabled = mode == "always" or (
        mode == "auto" and (arguments.verbose or sys.stderr.isatty())
    )
    if mode == "never" or not enabled:
        return None

    def report(
        stage: int,
        message: str,
        detail: bool,
        state: ProgressState | None = None,
    ) -> None:
        if detail and not arguments.verbose:
            return
        if state is not None:
            message = (
                f"files={state.files} directories={state.directories} "
                f"entries={state.entries}"
            )
        print(f"[{stage}/5] {message}", file=sys.stderr, flush=True)

    return report


def _render_discovery_progress(stage: int, state: ProgressState) -> str:
    if state.complete:
        bar = "[============] 100%"
    else:
        width = 12
        travel = (width - 1) * 2
        position = (state.entries // 250) % travel
        if position >= width:
            position = travel - position
        cells = [" "] * width
        cells[position] = ">"
        if position > 0:
            cells[position - 1] = "="
        bar = "[" + "".join(cells) + "]"
    return (
        f"[{stage}/5] {bar} files={state.files} "
        f"directories={state.directories} entries={state.entries}"
    )


def _detectors(arguments: argparse.Namespace) -> int:
    detectors = get_detectors()
    if arguments.detectors_command == "list":
        for detector in detectors:
            print(f"{detector.id}\t{detector.version}")
        return 0
    detector_id = arguments.detector_id
    matching = [detector for detector in detectors if detector.id == detector_id]
    if not matching:
        print(f"agentsec: unknown detector ID: {detector_id}", file=sys.stderr)
        return 2
    detector = matching[0]
    database = _load_database()
    if database is None:
        return 2
    try:
        payload = build_detector_explanation(detector, database)
    except ValueError as error:
        print(f"agentsec: cannot explain detector coverage: {error}", file=sys.stderr)
        return 2
    renderer = (
        render_detector_explanation_json
        if arguments.format == "json"
        else render_detector_explanation_human
    )
    print(renderer(payload), end="")
    return 0


def _db_info() -> int:
    database = _load_database()
    if database is None:
        return 2
    coverage = database.authoring_coverage
    if coverage is None:
        print("agentsec: threat database projection coverage unavailable", file=sys.stderr)
        return 2
    print(
        "\n".join(
            (
                f"threat database: {database.version}",
                f"updated: {database.updated}",
                f"package_versions={len(database.package_versions)}",
                f"wildcard_package_versions={len(database.wildcard_package_versions)}",
                f"contested_package_versions={len(database.contested_package_versions)}",
                "contested_wildcard_package_versions="
                f"{len(database.contested_wildcard_package_versions)}",
                "package_version_sources="
                f"{sum(len(versions) for versions in database.package_version_sources.values())}",
                f"hashes={len(database.hashes)}",
                f"domains={len(database.domains)}",
                f"commit_indicators={len(database.commit_indicators)}",
                f"authoring_malicious_skills={coverage.malicious_skills_total}",
                f"projected_malicious_skills={coverage.malicious_skills_projected}",
                f"ignored_missing_platform={coverage.ignored_missing_platform}",
                "ignored_unsupported_platform="
                f"{coverage.ignored_unsupported_platform}",
                f"ignored_missing_version={coverage.ignored_missing_version}",
                f"projected_cves={coverage.cves_projected}/{coverage.cves_total}",
                "projected_attack_techniques="
                f"{coverage.attack_techniques_projected}/"
                f"{coverage.attack_techniques_total}",
                "projected_campaign_indicators="
                f"{coverage.commit_indicators_projected}/{coverage.campaigns_total}",
            )
        )
    )
    return 0


def _doctor() -> int:
    database = _load_database()
    if database is None:
        return 2
    try:
        for label, (filename, schema_id, required_fields) in _SCHEMA_CONTRACTS.items():
            raw_schema = _read_schema_bytes(filename)
            expected_digest = _read_schema_digest(filename.replace(".json", ".sha256"))
            if sha256(_canonical_text_bytes(raw_schema)).hexdigest() != expected_digest:
                raise ValueError(f"{label} schema integrity digest mismatch")
            schema = json.loads(raw_schema)
            _validate_schema_contract(
                schema,
                schema_id=schema_id,
                required_fields=required_fields,
            )
    except (
        ModuleNotFoundError,
        OSError,
        TypeError,
        UnicodeError,
        ValueError,
        json.JSONDecodeError,
    ) as error:
        print(f"agentsec: local schema validation failed: {error}", file=sys.stderr)
        return 2
    print(
        "\n".join(
            (
                f"Python: {sys.version.split()[0]}",
                f"database: {database.version}",
                "resource: available",
                "scan-result-v2: valid",
                "batch-result-v1: valid",
                "detector-explain-v1: valid",
            )
        )
    )
    return 0


def _canonical_text_bytes(raw: bytes) -> bytes:
    return raw.replace(b"\r\n", b"\n").replace(b"\r", b"\n")


def _read_schema_bytes(filename: str) -> bytes:
    schema = resources.files("agentsec.resources").joinpath(filename)
    try:
        return schema.read_bytes()
    except FileNotFoundError:
        source_schema = (
            Path(__file__).resolve().parents[2] / "schemas" / filename
        )
        return source_schema.read_bytes()


def _read_schema_digest(filename: str) -> str:
    digest = resources.files("agentsec.resources").joinpath(filename)
    try:
        raw = digest.read_text(encoding="ascii")
    except FileNotFoundError:
        source_digest = (
            Path(__file__).resolve().parents[2]
            / "schemas"
            / filename
        )
        raw = source_digest.read_text(encoding="ascii")
    if re.fullmatch(r"[0-9a-f]{64}\n", raw) is None:
        raise ValueError("schema integrity digest is invalid")
    return raw[:-1]


def _validate_schema_contract(
    schema: object,
    *,
    schema_id: str,
    required_fields: set[str],
) -> None:
    if not isinstance(schema, dict):
        raise ValueError("schema root must be an object")
    if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
        raise ValueError("schema has an invalid $schema")
    if schema.get("$id") != schema_id:
        raise ValueError("schema has an invalid $id")
    if schema.get("type") != "object":
        raise ValueError("schema root type must be object")
    required = schema.get("required")
    if not isinstance(required, list) or set(required) != required_fields:
        raise ValueError("schema has invalid required fields")
    properties = schema.get("properties")
    if not isinstance(properties, dict) or not required_fields.issubset(properties):
        raise ValueError("schema has invalid properties")


def _load_database(*, redact: bool = False, root: Path | None = None) -> ThreatDatabase | None:
    try:
        return load_bundled_database()
    except ThreatDatabaseError as error:
        message = redact_text(str(error), root) if redact else str(error)
        print(f"agentsec: cannot load bundled threat database: {message}", file=sys.stderr)
        return None


def entrypoint() -> None:
    raise SystemExit(main())


if __name__ == "__main__":
    entrypoint()

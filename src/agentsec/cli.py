from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from hashlib import sha256
from importlib import resources
from pathlib import Path
from typing import NoReturn

from agentsec import __version__
from agentsec.detectors.registry import get_detectors
from agentsec.engine.discovery import DiscoveryLimits
from agentsec.engine.runner import run_scan
from agentsec.models import ThreatDatabase
from agentsec.output.human import render_human
from agentsec.output.json_output import render_json
from agentsec.redaction import redact_text
from agentsec.threat_db import ThreatDatabaseError, load_bundled_database

_DEFAULT_MAX_FILE_BYTES = 4_000_000
_DEFAULT_MAX_FILES = 1_000_000
_DEFAULT_MAX_GIT_COMMITS = 10_000
_DEFAULT_MAX_DIAGNOSTICS = 100
_SCAN_RESULT_SCHEMA_SHA256 = "86fc1a24eeeb90d8b11a4c3ffc06b2b750852a77b584623b0d77ac2685365ea5"


class _ArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        self.print_usage(sys.stderr)
        self.exit(2, f"{self.prog}: error: {message}\n")


def build_parser() -> argparse.ArgumentParser:
    parser = _ArgumentParser(prog="agentsec")
    parser.add_argument("--version", action="version", version=f"agentsec {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    scan = commands.add_parser("scan", help="scan one repository")
    scan.add_argument("root", type=Path)
    scan.add_argument("--detector", action="append", dest="detector_ids")
    scan.add_argument("--format", choices=("human", "json"), default="human")
    scan.add_argument("--redact", action="store_true")
    scan.add_argument("--max-file-bytes", type=_non_negative, default=_DEFAULT_MAX_FILE_BYTES)
    scan.add_argument("--max-files", type=_non_negative, default=_DEFAULT_MAX_FILES)
    scan.add_argument("--max-git-commits", type=_non_negative, default=_DEFAULT_MAX_GIT_COMMITS)

    detectors = commands.add_parser("detectors", help="inspect built-in detectors")
    detector_commands = detectors.add_subparsers(dest="detectors_command", required=True)
    detector_commands.add_parser("list", help="list detector IDs")
    explain = detector_commands.add_parser("explain", help="explain one detector")
    explain.add_argument("detector_id")

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


def _scan(arguments: argparse.Namespace) -> int:
    database = _load_database(redact=arguments.redact, root=arguments.root)
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
        max_git_commits=arguments.max_git_commits,
    )
    result = run_scan(arguments.root, detectors, database, limits)
    if arguments.format == "json":
        print(render_json(result, redact=arguments.redact), end="")
    else:
        print(render_human(result, redact=arguments.redact), end="")
    return result.exit_code()


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
    print(f"{detector.id}\nversion: {detector.version}")
    return 0


def _db_info() -> int:
    database = _load_database()
    if database is None:
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
            )
        )
    )
    return 0


def _doctor() -> int:
    database = _load_database()
    if database is None:
        return 2
    try:
        raw_schema = _read_schema_bytes()
        if sha256(raw_schema).hexdigest() != _SCAN_RESULT_SCHEMA_SHA256:
            raise ValueError("schema integrity digest mismatch")
        schema = json.loads(raw_schema)
        _validate_schema_contract(schema)
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
                "schema: valid",
            )
        )
    )
    return 0


def _read_schema_bytes() -> bytes:
    schema = resources.files("agentsec.resources").joinpath("scan-result-v1.schema.json")
    try:
        return schema.read_bytes()
    except FileNotFoundError:
        source_schema = (
            Path(__file__).resolve().parents[2] / "schemas" / "scan-result-v1.schema.json"
        )
        return source_schema.read_bytes()


def _validate_schema_contract(schema: object) -> None:
    if not isinstance(schema, dict):
        raise ValueError("schema root must be an object")
    if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
        raise ValueError("schema has an invalid $schema")
    if schema.get("$id") != "https://agentsec.dev/schemas/scan-result-v1.schema.json":
        raise ValueError("schema has an invalid $id")
    if schema.get("type") != "object":
        raise ValueError("schema root type must be object")
    required = schema.get("required")
    expected_fields = {
        "schema_version",
        "tool_version",
        "database_version",
        "root",
        "complete",
        "elapsed_ms",
        "coverage",
        "not_scanned",
        "diagnostics",
        "findings",
    }
    if not isinstance(required, list) or set(required) != expected_fields:
        raise ValueError("schema has invalid required fields")
    properties = schema.get("properties")
    if not isinstance(properties, dict) or not expected_fields.issubset(properties):
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

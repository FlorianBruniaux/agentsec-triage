#!/usr/bin/env python3
"""Validate the version-pinned competitive project index."""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import cast
from urllib.parse import urlparse

PROJECT_ROOT = Path(__file__).parents[1]
DEFAULT_DATA = PROJECT_ROOT / "data" / "competitive-projects.yaml"
DEFAULT_SCHEMA = PROJECT_ROOT / "data" / "competitive-projects.schema.json"
PROFILE_ROOT = Path("docs/competitive-analysis/profiles")

ROOT_FIELDS = frozenset({"schema_version", "projects"})
PROJECT_FIELDS = frozenset(
    {
        "id",
        "name",
        "url",
        "local_directory",
        "revision",
        "category",
        "evidence_status",
        "execution_tier",
        "license",
        "profile",
    }
)
EVIDENCE_STATUSES = frozenset(
    {
        "declared",
        "code_verified",
        "observed",
        "contradicted",
        "not_applicable",
        "not_tested",
    }
)
EXECUTION_TIERS = frozenset(
    {"static_only", "offline_sandbox", "networked_sandbox", "manual_review"}
)
SLUG = re.compile(r"^[a-z0-9][a-z0-9-]*$")
CATEGORY = re.compile(r"^[a-z][a-z0-9_]*$")
REVISION = re.compile(r"^[0-9a-f]{12}$")


def _load_object(path: Path, label: str) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"{label}: {error}") from error
    if not isinstance(value, dict):
        raise ValueError(f"{label}: expected a JSON object")
    return cast(dict[str, object], value)


def _required_string(
    project: dict[str, object],
    field: str,
    index: int,
    errors: list[str],
) -> str | None:
    if field not in project:
        errors.append(f"projects[{index}].{field}: missing required field")
        return None
    value = project[field]
    if not isinstance(value, str) or not value:
        errors.append(f"projects[{index}].{field}: expected a non-empty string")
        return None
    return value


def _valid_github_url(value: str) -> bool:
    parsed = urlparse(value)
    parts = [part for part in parsed.path.split("/") if part]
    return (
        parsed.scheme == "https"
        and parsed.hostname == "github.com"
        and not parsed.params
        and not parsed.query
        and not parsed.fragment
        and len(parts) == 2
    )


def _profile_is_confined(project_root: Path, value: str) -> bool:
    candidate = Path(value)
    if candidate.is_absolute() or candidate.suffix != ".md":
        return False
    expected_root = (project_root / PROFILE_ROOT).resolve()
    resolved = (project_root / candidate).resolve()
    return resolved.parent == expected_root


def _validate_project(
    project: dict[str, object],
    index: int,
    project_root: Path,
    clone_root: Path | None,
    seen_ids: set[str],
    errors: list[str],
) -> None:
    unknown = sorted(set(project) - PROJECT_FIELDS)
    for field in unknown:
        errors.append(f"projects[{index}].{field}: unknown field")

    values = {
        field: _required_string(project, field, index, errors)
        for field in sorted(PROJECT_FIELDS)
    }

    project_id = values["id"]
    if project_id is not None:
        if not SLUG.fullmatch(project_id):
            errors.append(f"projects[{index}].id: invalid slug '{project_id}'")
        if project_id in seen_ids:
            errors.append(f"projects[{index}].id: duplicate value '{project_id}'")
        seen_ids.add(project_id)

    url = values["url"]
    if url is not None and not _valid_github_url(url):
        errors.append(
            f"projects[{index}].url: expected an https://github.com/owner/repository URL"
        )

    local_directory = values["local_directory"]
    if local_directory is not None:
        if not SLUG.fullmatch(local_directory):
            errors.append(f"projects[{index}].local_directory: invalid directory name")
        elif clone_root is not None and not (clone_root / local_directory).is_dir():
            errors.append(
                f"projects[{index}].local_directory: clone directory does not exist"
            )

    revision = values["revision"]
    if revision is not None and not REVISION.fullmatch(revision):
        errors.append(f"projects[{index}].revision: expected 12 lowercase hexadecimal characters")

    category = values["category"]
    if category is not None and not CATEGORY.fullmatch(category):
        errors.append(f"projects[{index}].category: invalid category '{category}'")

    evidence_status = values["evidence_status"]
    if evidence_status is not None and evidence_status not in EVIDENCE_STATUSES:
        errors.append(
            f"projects[{index}].evidence_status: unknown value '{evidence_status}'"
        )

    execution_tier = values["execution_tier"]
    if execution_tier is not None and execution_tier not in EXECUTION_TIERS:
        errors.append(f"projects[{index}].execution_tier: unknown value '{execution_tier}'")

    profile = values["profile"]
    if profile is not None and not _profile_is_confined(project_root, profile):
        errors.append(
            f"projects[{index}].profile: path must stay under "
            "docs/competitive-analysis/profiles"
        )


def validate_index(
    payload: dict[str, object],
    project_root: Path,
    clone_root: Path | None,
) -> list[str]:
    errors: list[str] = []
    for field in sorted(set(payload) - ROOT_FIELDS):
        errors.append(f"{field}: unknown field")

    if payload.get("schema_version") != "1":
        errors.append("schema_version: expected '1'")

    projects_value = payload.get("projects")
    if not isinstance(projects_value, list) or not projects_value:
        errors.append("projects: expected a non-empty array")
        return errors

    seen_ids: set[str] = set()
    for index, value in enumerate(projects_value):
        if not isinstance(value, dict):
            errors.append(f"projects[{index}]: expected an object")
            continue
        project = cast(dict[str, object], value)
        _validate_project(project, index, project_root, clone_root, seen_ids, errors)
    return errors


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=Path, default=DEFAULT_DATA)
    parser.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA)
    parser.add_argument("--project-root", type=Path, default=PROJECT_ROOT)
    parser.add_argument(
        "--clone-root",
        type=Path,
        help="Also require each pinned local clone directory to exist below this path.",
    )
    return parser


def main(arguments: Sequence[str] | None = None) -> int:
    options = _parser().parse_args(arguments)
    try:
        payload = _load_object(options.data, "competitive project index")
        _load_object(options.schema, "competitive project schema")
    except ValueError as load_error:
        print(load_error, file=sys.stderr)
        return 1

    errors = validate_index(
        payload,
        options.project_root.resolve(),
        options.clone_root.resolve() if options.clone_root is not None else None,
    )
    for validation_error in errors:
        print(f"competitive project index: {validation_error}", file=sys.stderr)
    if errors:
        return 1

    projects = cast(list[object], payload["projects"])
    label = "project" if len(projects) == 1 else "projects"
    print(f"Validated {len(projects)} competitive {label}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

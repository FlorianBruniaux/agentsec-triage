#!/usr/bin/env python3
"""Validate controlled competitor image recipes without building them."""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path
from typing import cast

PROJECT_ROOT = Path(__file__).parents[1]
DEFAULT_MANIFEST = PROJECT_ROOT / "research" / "competitive-images" / "manifest.yaml"
DEFAULT_PROJECTS = PROJECT_ROOT / "data" / "competitive-projects.yaml"
COHORT = {
    "aguara",
    "patient-zero",
    "agentshield",
    "cc-audit",
    "skillspector",
    "cisco-skill-scanner",
    "sigil",
    "agent-bom",
}
REVISION = re.compile(r"^[0-9a-f]{12}$")
PINNED_FROM = re.compile(r"^FROM\s+\S+@sha256:[0-9a-f]{64}(?:\s+AS\s+\S+)?$", re.I)


def _load(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected a JSON object")
    return cast(dict[str, object], value)


def _logical_instructions(text: str) -> list[str]:
    instructions: list[str] = []
    current = ""
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        current = f"{current} {line}".strip()
        if current.endswith("\\"):
            current = current[:-1].rstrip()
            continue
        instructions.append(current)
        current = ""
    if current:
        instructions.append(current)
    return instructions


def _validate_dockerfile(path: Path, label: str) -> list[str]:
    errors: list[str] = []
    try:
        instructions = _logical_instructions(path.read_text(encoding="utf-8"))
    except OSError as error:
        return [f"{label}: cannot read Dockerfile: {error}"]
    from_lines = [line for line in instructions if line.upper().startswith("FROM ")]
    if not from_lines:
        errors.append(f"{label}: Dockerfile has no FROM instruction")
    stage_names: set[str] = set()
    for line in from_lines:
        parts = line.split()
        source = parts[1] if len(parts) >= 2 else ""
        if source not in stage_names and not PINNED_FROM.fullmatch(line):
            errors.append(f"{label}: FROM must use an immutable sha256 digest: {line}")
        if len(parts) == 4 and parts[2].upper() == "AS":
            stage_names.add(parts[3])

    source_present = False
    for line in instructions:
        upper = line.upper()
        if upper.startswith("ADD "):
            errors.append(f"{label}: ADD is forbidden")
        if upper.startswith("RUN ") and any(
            marker in line for marker in ("--mount=", "--secret", "--privileged")
        ):
            errors.append(f"{label}: privileged or host-backed RUN option is forbidden")
        if upper.startswith("COPY ") and any(
            marker in line for marker in ("COPY . .", "COPY src ", "COPY bin ", "COPY dist ")
        ):
            source_present = True
        if source_present and upper.startswith("RUN ") and not upper.startswith(
            "RUN --NETWORK=NONE "
        ):
            errors.append(f"{label}: source-present RUN must declare --network=none: {line}")
    return errors


def validate_manifest(
    payload: dict[str, object],
    root: Path,
    expected_projects: dict[str, str] | None,
) -> list[str]:
    errors: list[str] = []
    if payload.get("schema_version") != "1":
        errors.append("schema_version: expected '1'")
    if payload.get("platform") != "linux/arm64":
        errors.append("platform: expected 'linux/arm64'")
    recipes = payload.get("recipes")
    if not isinstance(recipes, list):
        return [*errors, "recipes: expected a list"]

    seen: set[str] = set()
    for index, raw_recipe in enumerate(recipes):
        label = f"recipes[{index}]"
        if not isinstance(raw_recipe, dict):
            errors.append(f"{label}: expected an object")
            continue
        recipe = cast(dict[str, object], raw_recipe)
        project_id = recipe.get("project_id")
        revision = recipe.get("revision")
        status = recipe.get("status")
        if not isinstance(project_id, str) or not project_id:
            errors.append(f"{label}.project_id: expected a non-empty string")
            continue
        label = project_id
        if project_id in seen:
            errors.append(f"{label}: duplicate project")
        seen.add(project_id)
        if not isinstance(revision, str) or not REVISION.fullmatch(revision):
            errors.append(f"{label}.revision: expected 12 lowercase hexadecimal characters")
        if expected_projects is not None and expected_projects.get(project_id) != revision:
            errors.append(f"{label}.revision: does not match the project index")
        if status not in {"ready", "blocked"}:
            errors.append(f"{label}.status: expected 'ready' or 'blocked'")
            continue
        if status == "blocked":
            if not isinstance(recipe.get("blocker"), str) or not recipe.get("blocker"):
                errors.append(f"{label}.blocker: expected a non-empty string")
            evidence = recipe.get("evidence")
            if not isinstance(evidence, str) or not (root / evidence).is_file():
                errors.append(f"{label}.evidence: expected an existing file")
            continue

        dockerfile = recipe.get("dockerfile")
        if not isinstance(dockerfile, str) or not dockerfile:
            errors.append(f"{label}.dockerfile: expected a non-empty string")
        else:
            errors.extend(_validate_dockerfile(root / dockerfile, label))
        expected_tag = f"agentsec-bench/{project_id}:{revision}"
        if recipe.get("tag") != expected_tag:
            errors.append(f"{label}.tag: expected '{expected_tag}'")
        command = recipe.get("runtime_command")
        if not isinstance(command, list) or not command or not all(
            isinstance(value, str) and value and "\x00" not in value for value in command
        ):
            errors.append(f"{label}.runtime_command: expected a non-empty argument array")
        fixtures = recipe.get("fixtures")
        if not isinstance(fixtures, list) or not fixtures or not all(
            isinstance(value, str) and value for value in fixtures
        ):
            errors.append(f"{label}.fixtures: expected a non-empty string list")
        if recipe.get("build_network") != "dependencies_only":
            errors.append(f"{label}.build_network: expected 'dependencies_only'")

    if expected_projects is not None and seen != COHORT:
        errors.append(
            "recipes: expected the approved cohort; "
            f"missing={sorted(COHORT - seen)} extra={sorted(seen - COHORT)}"
        )
    return errors


def bundle_digest(payload: dict[str, object], root: Path, manifest: Path) -> str:
    paths = {manifest}
    recipes = payload.get("recipes")
    if isinstance(recipes, list):
        for raw_recipe in recipes:
            if not isinstance(raw_recipe, dict):
                continue
            recipe = cast(dict[str, object], raw_recipe)
            for field in ("dockerfile", "evidence"):
                value = recipe.get(field)
                if isinstance(value, str):
                    paths.add(root / value)
    digest = hashlib.sha256()
    for path in sorted(paths, key=lambda value: str(value)):
        relative = path.relative_to(root)
        data = path.read_bytes()
        digest.update(str(relative).encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(len(data)).encode("ascii"))
        digest.update(b"\0")
        digest.update(data)
        digest.update(b"\0")
    return digest.hexdigest()


def main() -> int:
    try:
        payload = _load(DEFAULT_MANIFEST)
        project_payload = _load(DEFAULT_PROJECTS)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"competitive images: {error}", file=sys.stderr)
        return 1
    projects = project_payload.get("projects")
    expected: dict[str, str] = {}
    if isinstance(projects, list):
        for value in projects:
            if isinstance(value, dict) and isinstance(value.get("id"), str):
                expected[cast(str, value["id"])] = str(value.get("revision", ""))
    errors = validate_manifest(payload, PROJECT_ROOT, expected)
    if errors:
        for validation_error in errors:
            print(f"competitive images: {validation_error}", file=sys.stderr)
        return 1
    recipes = cast(list[dict[str, object]], payload["recipes"])
    summary = {
        "blocked": sum(recipe.get("status") == "blocked" for recipe in recipes),
        "bundle_digest": bundle_digest(payload, PROJECT_ROOT, DEFAULT_MANIFEST),
        "ready": sum(recipe.get("status") == "ready" for recipe in recipes),
        "recipes": len(recipes),
    }
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

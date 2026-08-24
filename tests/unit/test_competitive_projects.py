from __future__ import annotations

import json
import subprocess
import sys
from copy import deepcopy
from pathlib import Path

from jsonschema import validate

PROJECT_ROOT = Path(__file__).parents[2]
VALIDATOR = PROJECT_ROOT / "scripts" / "check_competitive_projects.py"
DATA = PROJECT_ROOT / "data" / "competitive-projects.yaml"
SCHEMA = PROJECT_ROOT / "data" / "competitive-projects.schema.json"


def _project() -> dict[str, object]:
    return {
        "id": "example-tool",
        "name": "Example Tool",
        "url": "https://github.com/example/example-tool",
        "local_directory": "example-tool",
        "revision": "0123456789ab",
        "category": "pre_trust_repository",
        "evidence_status": "declared",
        "execution_tier": "static_only",
        "license": "unverified",
        "profile": "docs/competitive-analysis/profiles/example-tool.md",
    }


def _payload() -> dict[str, object]:
    return {
        "schema_version": "1",
        "projects": [_project()],
    }


def _validate(
    tmp_path: Path,
    payload: dict[str, object],
    *,
    create_clone: bool = True,
) -> subprocess.CompletedProcess[str]:
    data_path = tmp_path / "competitive-projects.yaml"
    data_path.write_text(json.dumps(payload), encoding="utf-8")
    clone_root = tmp_path / "clones"
    clone_root.mkdir()
    if create_clone:
        (clone_root / "example-tool").mkdir()
    return subprocess.run(
        [
            sys.executable,
            str(VALIDATOR),
            "--data",
            str(data_path),
            "--project-root",
            str(PROJECT_ROOT),
            "--clone-root",
            str(clone_root),
        ],
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )


def test_valid_project_index_passes(tmp_path: Path) -> None:
    result = _validate(tmp_path, _payload())

    assert result.returncode == 0, result.stderr
    assert result.stdout == "Validated 1 competitive project\n"


def test_committed_index_matches_public_schema_and_contains_pinned_cohort() -> None:
    payload = json.loads(DATA.read_text(encoding="utf-8"))
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))

    validate(payload, schema)

    projects = payload["projects"]
    assert len(projects) == 16
    assert all(project["revision"] for project in projects)
    assert all(project["execution_tier"] == "static_only" for project in projects)


def test_missing_revision_fails(tmp_path: Path) -> None:
    payload = _payload()
    project = payload["projects"][0]
    assert isinstance(project, dict)
    del project["revision"]

    result = _validate(tmp_path, payload)

    assert result.returncode == 1
    assert "projects[0].revision: missing required field" in result.stderr


def test_duplicate_project_id_fails(tmp_path: Path) -> None:
    payload = _payload()
    duplicate = deepcopy(payload["projects"][0])
    assert isinstance(duplicate, dict)
    duplicate["local_directory"] = "second-tool"
    duplicate["profile"] = "docs/competitive-analysis/profiles/second-tool.md"
    projects = payload["projects"]
    assert isinstance(projects, list)
    projects.append(duplicate)

    result = _validate(tmp_path, payload)

    assert result.returncode == 1
    assert "projects[1].id: duplicate value 'example-tool'" in result.stderr


def test_non_github_https_url_fails(tmp_path: Path) -> None:
    payload = _payload()
    project = payload["projects"][0]
    assert isinstance(project, dict)
    project["url"] = "http://example.com/example-tool"

    result = _validate(tmp_path, payload)

    assert result.returncode == 1
    assert "projects[0].url: expected an https://github.com/owner/repository URL" in result.stderr


def test_missing_local_clone_fails_when_clone_root_is_requested(tmp_path: Path) -> None:
    result = _validate(tmp_path, _payload(), create_clone=False)

    assert result.returncode == 1
    assert "projects[0].local_directory: clone directory does not exist" in result.stderr


def test_unknown_evidence_status_fails(tmp_path: Path) -> None:
    payload = _payload()
    project = payload["projects"][0]
    assert isinstance(project, dict)
    project["evidence_status"] = "trusted"

    result = _validate(tmp_path, payload)

    assert result.returncode == 1
    assert "projects[0].evidence_status: unknown value 'trusted'" in result.stderr


def test_unknown_execution_tier_fails(tmp_path: Path) -> None:
    payload = _payload()
    project = payload["projects"][0]
    assert isinstance(project, dict)
    project["execution_tier"] = "host"

    result = _validate(tmp_path, payload)

    assert result.returncode == 1
    assert "projects[0].execution_tier: unknown value 'host'" in result.stderr


def test_profile_path_escape_fails(tmp_path: Path) -> None:
    payload = _payload()
    project = payload["projects"][0]
    assert isinstance(project, dict)
    project["profile"] = "../outside.md"

    result = _validate(tmp_path, payload)

    assert result.returncode == 1
    expected = "projects[0].profile: path must stay under docs/competitive-analysis/profiles"
    assert expected in result.stderr

from __future__ import annotations

import tomllib
from pathlib import Path

PROJECT_ROOT = Path(__file__).parents[2]


def _read(relative_path: str) -> str:
    return (PROJECT_ROOT / relative_path).read_text(encoding="utf-8")


def test_readme_documents_the_alpha_contract() -> None:
    readme = _read("README.md").lower()

    for concept in (
        "read-only",
        "offline by default",
        "does not certify",
        "not scanned",
        "https://cc.bruniaux.com/security/",
    ):
        assert concept in readme
    for exit_code in ("`0`", "`1`", "`2`"):
        assert exit_code in readme


def test_readme_documents_exhaustive_traversal_and_expected_self_scan() -> None:
    readme = _read("README.md").lower()

    for concept in (
        "except `.git`",
        "does not honor `.gitignore`",
        "no exclusion",
        "self-scan",
        "bun.lockb",
        "expected exit code is `2`",
    ):
        assert concept in readme


def test_security_has_separate_reporting_workflows() -> None:
    security = _read("SECURITY.md").lower()

    for heading in (
        "## scanner vulnerabilities",
        "## false positives",
        "## false negatives",
        "## ioc corrections",
        "## private disclosure",
    ):
        assert heading in security


def test_contributing_requires_tdd_and_traceable_threat_sources() -> None:
    contributing = _read("CONTRIBUTING.md").lower()

    assert "red-green-refactor" in contributing
    assert "watch the test fail" in contributing
    for requirement in ("source url", "access date", "exact claim", "confidence"):
        assert requirement in contributing
    assert "pip_no_index=1" in contributing
    assert "python -m build --no-isolation" in contributing


def test_changelog_has_unreleased_and_alpha_headings() -> None:
    changelog = _read("CHANGELOG.md")

    assert "## [Unreleased]" in changelog
    assert "## [0.1.0-alpha]" in changelog


def test_license_decision_blocks_public_release_and_tagging() -> None:
    decision = _read("LICENSE-DECISION.md").lower()

    assert "public release is blocked" in decision
    assert "cc by-sa 4.0" in decision
    assert "do not publish" in decision
    assert "do not tag" in decision
    assert "license-file" in decision


def test_ci_is_cross_platform_and_runs_every_alpha_gate() -> None:
    workflow = _read(".github/workflows/tests.yml")

    for runner in ("ubuntu-latest", "macos-latest", "windows-latest"):
        assert runner in workflow
    for python_version in ('"3.11"', '"3.12"', '"3.13"'):
        assert python_version in workflow
    for command in (
        'python -m pip install -e ".[dev]"',
        "python scripts/build_threat_db.py",
        "python scripts/build_scan_schema_digest.py --check",
        "git diff --exit-code -- src/agentsec/resources/threat-db.json",
        "ruff check src tests scripts",
        "mypy src scripts",
        "pytest --cov=agentsec --cov-report=term-missing",
        "python -m build --no-isolation",
        "pip install --no-deps",
        "agentsec doctor",
        "python -m agentsec doctor",
        "agentsec scan . --format json --redact",
        "agentsec scan tests/fixtures/shai_hulud/negative --format json",
    ):
        assert command in workflow
    assert 'PIP_NO_INDEX: "1"' in workflow
    assert 'item["path"].replace("\\\\", "/").endswith(' in workflow


def test_project_config_enforces_coverage_threshold() -> None:
    configuration = tomllib.loads(_read("pyproject.toml"))

    coverage = configuration["tool"]["coverage"]["report"]
    assert coverage["fail_under"] >= 85
    assert coverage["show_missing"] is True


def test_project_config_supports_offline_builds_without_false_license_metadata() -> None:
    configuration = tomllib.loads(_read("pyproject.toml"))

    project = configuration["project"]
    dev_dependencies = project["optional-dependencies"]["dev"]
    assert any(requirement.startswith("hatchling>=") for requirement in dev_dependencies)
    assert project["license-files"] == []


def test_source_distribution_excludes_working_artifacts() -> None:
    configuration = tomllib.loads(_read("pyproject.toml"))

    excluded = set(configuration["tool"]["hatch"]["build"]["targets"]["sdist"]["exclude"])
    for path in ("/.coverage", "/.superpowers", "/build", "/dist"):
        assert path in excluded

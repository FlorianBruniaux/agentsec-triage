from __future__ import annotations

import re
import tomllib
from pathlib import Path

PROJECT_ROOT = Path(__file__).parents[2]
MARKDOWN_LINK = re.compile(
    r"\[[^]]+\]\((?!https?://|mailto:|#)([^)#]+)(?:#[^)]+)?\)"
)


def _read(relative_path: str) -> str:
    return (PROJECT_ROOT / relative_path).read_text(encoding="utf-8")


def _local_links(relative_path: str) -> set[Path]:
    source = PROJECT_ROOT / relative_path
    return {
        (source.parent / match).resolve()
        for match in MARKDOWN_LINK.findall(source.read_text(encoding="utf-8"))
    }


def test_readme_documents_the_alpha_contract() -> None:
    readme = _read("README.md").lower()

    for concept in (
        "read-only",
        "offline by default",
        "does not certify",
        "https://cc.bruniaux.com/security/",
    ):
        assert concept in readme
    for exit_code in ("`0`", "`1`", "`2`"):
        assert exit_code in readme


def test_examples_document_traversal_verdicts_and_self_scan() -> None:
    examples = _read("docs/examples.md").lower()

    for concept in (
        "does not treat `.gitignore` as a security boundary",
        "`source`",
        "`dependencies`",
        "`repository`",
        "vcs metadata",
        "measured exclusions",
        "self-scan",
        "bun.lockb",
        "expected exit code is `2`",
        "<tool_version>",
        "<database_version>",
    ):
        assert concept in examples


def test_docs_explain_progress_and_large_repository_traversal() -> None:
    readme = _read("README.md").lower()
    examples = _read("docs/examples.md").lower()

    for concept in ("--progress", "--verbose", "stderr"):
        assert concept in readme
        assert concept in examples
    for concept in (
        "nested git repositories",
        "scan it separately",
        "internal symlink alias",
        "external,\nbroken, changed",
        "git history",
    ):
        assert concept in examples
    for concept in (
        "threat database",
        "repository validated",
        "indeterminate",
        "100%",
        "--redact",
    ):
        assert concept in examples


def test_public_markdown_links_resolve_locally() -> None:
    for document in (
        "README.md",
        "docs/installation.md",
        "docs/examples.md",
        "PROMPT.md",
    ):
        missing = sorted(path for path in _local_links(document) if not path.exists())
        assert missing == []


def test_public_docs_route_findings_to_manual_response_playbooks() -> None:
    readme = _read("README.md").lower()
    examples = _read("docs/examples.md").lower()
    roadmap = _read("ROADMAP.md").lower()

    assert "response playbooks" in readme
    assert "docs/response-playbooks/" in examples
    assert "destructive automation" in examples
    assert "versioned response playbooks" in roadmap


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


def test_public_repository_docs_preserve_the_data_license_boundary() -> None:
    readme = _read("README.md").lower()
    data_license = _read("LICENSE-DATA.md").lower()
    roadmap = _read("ROADMAP.md").lower()
    normalized_data_license = re.sub(r"\s+", " ", data_license)

    assert "public source repository" in readme
    assert "repository must remain private" not in readme
    assert "public repository visibility does not grant" in normalized_data_license
    assert "configure the public git remote" not in roadmap


def test_license_decision_blocks_package_release_and_tagging() -> None:
    decision = _read("LICENSE-DECISION.md").lower()

    assert "package release is blocked" in decision
    assert "cc by-sa 4.0" in decision
    assert "do not publish" in decision
    assert "do not tag" in decision
    assert "license-file" in decision


def test_competitive_docs_reflect_the_completed_image_build_gate() -> None:
    design = _read("docs/competitive-analysis/BENCHMARK-DESIGN.md").lower()
    gate = _read("docs/competitive-analysis/BUILD-GATE.md").lower()

    assert "seven images built" in design
    assert "runtime execution not approved" in design
    assert "build and competitor execution not approved" not in design
    assert "seven images built" in gate


def test_ci_is_cross_platform_and_runs_every_alpha_gate() -> None:
    workflow = _read(".github/workflows/tests.yml")

    for runner in ("ubuntu-latest", "macos-latest", "windows-latest"):
        assert runner in workflow
    for python_version in ('"3.11"', '"3.12"', '"3.13"'):
        assert python_version in workflow
    for command in (
        'python -m pip install -e ".[dev]"',
        "python scripts/build_threat_db.py",
        "python scripts/build_response_playbooks.py",
        "python scripts/build_scan_schema_digest.py --check",
        "git diff --exit-code -- src/agentsec/resources/threat-db.json",
        "src/agentsec/resources/response-playbooks.json",
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


def test_ci_uses_current_node24_action_majors() -> None:
    workflow = _read(".github/workflows/tests.yml")

    assert "actions/checkout@v7" in workflow
    assert "actions/setup-python@v7" in workflow
    assert "actions/checkout@v4" not in workflow
    assert "actions/setup-python@v5" not in workflow


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

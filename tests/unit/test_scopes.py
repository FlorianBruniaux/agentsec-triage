from pathlib import Path

import pytest

from agentsec.scopes import (
    ExclusionReason,
    ScanScope,
    classify_directory,
    classify_file,
)


@pytest.mark.parametrize(
    ("path", "reason"),
    (
        (Path("node_modules"), ExclusionReason.INSTALLED_DEPENDENCIES),
        (Path("apps/web/node_modules"), ExclusionReason.INSTALLED_DEPENDENCIES),
        (Path(".venv"), ExclusionReason.INSTALLED_DEPENDENCIES),
        (Path(".yarn/cache"), ExclusionReason.INSTALLED_DEPENDENCIES),
        (Path("dist"), ExclusionReason.GENERATED_OR_CACHE),
        (Path("apps/web/.next"), ExclusionReason.GENERATED_OR_CACHE),
    ),
)
def test_source_prunes_dependency_and_generated_directories(
    path: Path, reason: ExclusionReason
) -> None:
    decision = classify_directory(path, ScanScope.SOURCE)

    assert decision.selected is False
    assert decision.prune is True
    assert decision.reason is reason


@pytest.mark.parametrize(
    "path",
    (
        Path(".worktrees"),
        Path(".claude/worktrees"),
        Path(".serena"),
    ),
)
def test_source_prunes_tool_managed_worktree_and_cache_roots(path: Path) -> None:
    decision = classify_directory(path, ScanScope.SOURCE)

    assert decision.prune is True
    assert decision.reason is ExclusionReason.GENERATED_OR_CACHE
    assert classify_directory(path, ScanScope.REPOSITORY).selected is True


@pytest.mark.parametrize("scope", tuple(ScanScope))
@pytest.mark.parametrize("name", (".git", ".hg", ".svn"))
def test_every_scope_prunes_vcs_metadata(scope: ScanScope, name: str) -> None:
    decision = classify_directory(Path("nested") / name, scope)

    assert decision.selected is False
    assert decision.prune is True
    assert decision.reason is ExclusionReason.VCS_METADATA


def test_dependency_scope_keeps_directories_traversable_for_nested_lockfiles() -> None:
    decision = classify_directory(Path("apps/web/src"), ScanScope.DEPENDENCIES)

    assert decision.selected is True
    assert decision.prune is False
    assert decision.reason is None


@pytest.mark.parametrize("path", (Path("asset.PNG"), Path("data.sqlite3")))
def test_source_excludes_known_binary_assets_case_insensitively(path: Path) -> None:
    decision = classify_file(path, ScanScope.SOURCE)

    assert decision.selected is False
    assert decision.prune is False
    assert decision.reason is ExclusionReason.BINARY_ASSET


def test_supported_lockfile_name_wins_over_source_extension_rules() -> None:
    decision = classify_file(Path("nested/package-lock.json"), ScanScope.SOURCE)

    assert decision.selected is True
    assert decision.reason is None


@pytest.mark.parametrize(
    ("path", "selected"),
    (
        (Path("package-lock.json"), True),
        (Path("apps/web/pnpm-lock.yaml"), True),
        (Path("node_modules/keyv/index.js"), True),
        (Path("apps/web/node_modules/keyv/package.json"), True),
        (Path("src/main.py"), False),
    ),
)
def test_dependency_scope_selects_only_lockfiles_and_installed_tree_files(
    path: Path, selected: bool
) -> None:
    decision = classify_file(path, ScanScope.DEPENDENCIES)

    assert decision.selected is selected
    assert decision.prune is False
    assert decision.reason is (
        None if selected else ExclusionReason.OUTSIDE_DEPENDENCY_SCOPE
    )


@pytest.mark.parametrize("path", (Path("asset.png"), Path("src/main.py")))
def test_repository_scope_selects_every_regular_file(path: Path) -> None:
    decision = classify_file(path, ScanScope.REPOSITORY)

    assert decision.selected is True
    assert decision.prune is False
    assert decision.reason is None

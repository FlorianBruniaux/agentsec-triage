"""Deterministic repository scope classification without Git or ignore files."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path


class ScanScope(StrEnum):
    SOURCE = "source"
    DEPENDENCIES = "dependencies"
    REPOSITORY = "repository"


class ExclusionReason(StrEnum):
    BINARY_ASSET = "binary_asset"
    GENERATED_OR_CACHE = "generated_or_cache"
    INSTALLED_DEPENDENCIES = "installed_dependencies"
    INTERNAL_SYMLINK_ALIAS = "internal_symlink_alias"
    OUTSIDE_DEPENDENCY_SCOPE = "outside_dependency_scope"
    VCS_METADATA = "vcs_metadata"


@dataclass(frozen=True, slots=True)
class ScopeDecision:
    selected: bool
    prune: bool
    reason: ExclusionReason | None = None


SUPPORTED_LOCKFILE_NAMES = frozenset(
    {
        "package-lock.json",
        "npm-shrinkwrap.json",
        "pnpm-lock.yaml",
        "pnpm-lock.yml",
        "yarn.lock",
        "bun.lock",
        "bun.lockb",
    }
)

_VCS_DIRECTORIES = frozenset({".git", ".hg", ".svn"})
_DEPENDENCY_DIRECTORIES = frozenset(
    {"node_modules", ".pnpm-store", ".venv", "venv", "__pypackages__"}
)
_GENERATED_DIRECTORIES = frozenset(
    {
        ".cache",
        ".next",
        ".nuxt",
        ".output",
        ".parcel-cache",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        ".tox",
        ".nox",
        ".turbo",
        "build",
        "coverage",
        "dist",
        "htmlcov",
        "out",
        "target",
    }
)
_BINARY_EXTENSIONS = frozenset(
    {
        ".7z",
        ".avi",
        ".bmp",
        ".bz2",
        ".db",
        ".dmg",
        ".eot",
        ".flac",
        ".gif",
        ".gz",
        ".ico",
        ".jpeg",
        ".jpg",
        ".m4a",
        ".mov",
        ".mp3",
        ".mp4",
        ".otf",
        ".pdf",
        ".png",
        ".sqlite",
        ".sqlite3",
        ".tar",
        ".tgz",
        ".ttf",
        ".wav",
        ".webm",
        ".webp",
        ".woff",
        ".woff2",
        ".xz",
        ".zip",
    }
)


def classify_directory(path: Path, scope: ScanScope) -> ScopeDecision:
    """Classify one directory path without reading repository-owned content."""
    if path.name in _VCS_DIRECTORIES:
        return ScopeDecision(False, True, ExclusionReason.VCS_METADATA)
    if scope is not ScanScope.SOURCE:
        return ScopeDecision(True, False)
    if path.name in _DEPENDENCY_DIRECTORIES or _has_yarn_cache_suffix(path):
        return ScopeDecision(False, True, ExclusionReason.INSTALLED_DEPENDENCIES)
    if path.name in _GENERATED_DIRECTORIES:
        return ScopeDecision(False, True, ExclusionReason.GENERATED_OR_CACHE)
    return ScopeDecision(True, False)


def classify_file(path: Path, scope: ScanScope) -> ScopeDecision:
    """Classify one regular file path for the selected scan scope."""
    if path.name in SUPPORTED_LOCKFILE_NAMES:
        return ScopeDecision(True, False)
    if scope is ScanScope.REPOSITORY:
        return ScopeDecision(True, False)
    if scope is ScanScope.DEPENDENCIES:
        if "node_modules" in path.parts:
            return ScopeDecision(True, False)
        return ScopeDecision(False, False, ExclusionReason.OUTSIDE_DEPENDENCY_SCOPE)
    if path.suffix.lower() in _BINARY_EXTENSIONS:
        return ScopeDecision(False, False, ExclusionReason.BINARY_ASSET)
    return ScopeDecision(True, False)


def _has_yarn_cache_suffix(path: Path) -> bool:
    return len(path.parts) >= 2 and path.parts[-2:] == (".yarn", "cache")

import ast
import inspect
import textwrap
from pathlib import Path

import pytest

from agentsec.analyzers.lockfiles import _normalize_jsonc, parse_lockfile
from agentsec.models import DiagnosticKind

FIXTURES = Path(__file__).parents[1] / "fixtures" / "lockfiles"

CASES = [
    ("npm-v1.json", {("keyv", "6.0.0")}),
    ("npm-v3.json", {("@keyv/mongo", "6.0.0")}),
    ("npm-alias.json", {("keyv", "6.0.0")}),
    ("pnpm-v5.yaml", {("@keyv/mongo", "6.0.0")}),
    ("pnpm-v6.yaml", {("@keyv/mongo", "6.0.0")}),
    ("pnpm-v9-quoted.yaml", {("@keyv/mongo", "6.0.0")}),
    ("yarn-classic.lock", {("keyv", "6.0.0")}),
    ("yarn-berry-alias.lock", {("keyv", "6.0.0")}),
    ("bun.lock", {("keyv", "6.0.0")}),
]


@pytest.mark.parametrize(("fixture", "expected"), CASES)
def test_extracts_expected_pairs(fixture: str, expected: set[tuple[str, str]]):
    packages, diagnostics = parse_lockfile(FIXTURES / fixture)

    assert diagnostics == ()
    assert {(package.name, package.version) for package in packages} == expected


def test_extracts_nested_npm_v1_dependencies():
    packages, diagnostics = parse_lockfile(FIXTURES / "npm-v1-nested.json")

    assert diagnostics == ()
    assert [(package.name, package.version) for package in packages] == [
        ("keyv", "6.0.0"),
        ("wrapper", "1.0.0"),
    ]


def test_deduplicates_and_sorts_packages_deterministically():
    path = FIXTURES / "npm-v1-duplicates.json"

    packages, diagnostics = parse_lockfile(path)

    assert diagnostics == ()
    assert [(package.name, package.version, package.source) for package in packages] == [
        ("alpha", "2.0.0", path),
        ("keyv", "6.0.0", path),
    ]


def test_preserves_safe_package_version_without_parser_diagnostic():
    packages, diagnostics = parse_lockfile(FIXTURES / "safe-keyv.lock")

    assert diagnostics == ()
    assert [(package.name, package.version) for package in packages] == [("keyv", "5.6.0")]


def test_malformed_package_lock_fails_closed():
    path = FIXTURES / "malformed-package-lock.json"

    packages, diagnostics = parse_lockfile(path)

    assert packages == ()
    assert len(diagnostics) == 1
    assert diagnostics[0].kind is DiagnosticKind.ERROR
    assert diagnostics[0].path == path
    assert "parse" in diagnostics[0].message.lower()


def test_unreadable_lockfile_fails_closed(tmp_path: Path):
    path = tmp_path / "package-lock.json"
    path.mkdir()

    packages, diagnostics = parse_lockfile(path)

    assert packages == ()
    assert len(diagnostics) == 1
    assert diagnostics[0].kind is DiagnosticKind.ERROR
    assert diagnostics[0].path == path
    assert "read" in diagnostics[0].message.lower()


def test_binary_bun_lock_is_explicitly_unsupported():
    path = FIXTURES / "bun.lockb"

    packages, diagnostics = parse_lockfile(path)

    assert packages == ()
    assert len(diagnostics) == 1
    assert diagnostics[0].kind is DiagnosticKind.ERROR
    assert diagnostics[0].path == path
    assert "unsupported" in diagnostics[0].message.lower()


def test_ignores_npm_workspace_link_without_version(tmp_path: Path):
    path = tmp_path / "package-lock.json"
    path.write_text(
        """{
  "lockfileVersion": 3,
  "packages": {
    "node_modules/workspace-package": {
      "resolved": "packages/workspace-package",
      "link": true
    }
  }
}
""",
        encoding="utf-8",
    )

    packages, diagnostics = parse_lockfile(path)

    assert packages == ()
    assert diagnostics == ()


def test_rejects_yarn_resolution_version_mismatch(tmp_path: Path):
    path = tmp_path / "yarn.lock"
    path.write_text(
        '"local-keyv@npm:keyv@6.0.0":\n'
        "  version: 6.0.0\n"
        '  resolution: "keyv@npm:5.6.0"\n',
        encoding="utf-8",
    )

    _assert_parse_error(path)


def test_rejects_excessively_long_pnpm_lockfile_version(tmp_path: Path):
    path = tmp_path / "pnpm-lock.yaml"
    path.write_text(
        f"lockfileVersion: {'9' * 5_000}\n\npackages:\n",
        encoding="utf-8",
    )

    _assert_parse_error(path)


def test_ignores_npm_near_miss_node_modules_path(tmp_path: Path):
    path = tmp_path / "package-lock.json"
    path.write_text(
        """{
  "lockfileVersion": 3,
  "packages": {
    "not_node_modules/keyv": {"version": "6.0.0"}
  }
}
""",
        encoding="utf-8",
    )

    packages, diagnostics = parse_lockfile(path)

    assert packages == ()
    assert diagnostics == ()


def test_bun_trailing_comma_normalizer_does_not_slice_remaining_suffix():
    tree = ast.parse(textwrap.dedent(inspect.getsource(_normalize_jsonc)))

    assert not any(
        isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Slice)
        for node in ast.walk(tree)
    )


@pytest.mark.parametrize(
    ("filename", "document"),
    [
        (
            "package-lock.json",
            '{"lockfileVersion": 4, "lockfileVersion": 3, "packages": {}}',
        ),
        (
            "package-lock.json",
            """{
  "lockfileVersion": 3,
  "packages": {
    "node_modules/keyv": {"version": "5.6.0", "version": "6.0.0"}
  }
}
""",
        ),
        (
            "bun.lock",
            '{"packages": {"keyv": ["keyv@5.6.0"]}, "packages": {}}',
        ),
        (
            "bun.lock",
            """{
  "packages": {
    "keyv": ["keyv@6.0.0", "", {"integrity": "first", "integrity": "second"}]
  }
}
""",
        ),
    ],
)
def test_rejects_duplicate_json_object_keys(
    tmp_path: Path, filename: str, document: str
):
    path = tmp_path / filename
    path.write_text(document, encoding="utf-8")

    _assert_parse_error(path)


def _assert_parse_error(path: Path) -> None:
    packages, diagnostics = parse_lockfile(path)

    assert packages == ()
    assert len(diagnostics) == 1
    assert diagnostics[0].kind is DiagnosticKind.ERROR
    assert diagnostics[0].path == path

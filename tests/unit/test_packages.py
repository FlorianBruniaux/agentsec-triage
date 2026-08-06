from pathlib import Path

import pytest

from agentsec.analyzers.packages import (
    inspect_package_manifest,
    inspect_package_manifest_content,
)
from agentsec.models import Diagnostic, DiagnosticKind


def test_extracts_scoped_installed_package(tmp_path: Path):
    manifest = tmp_path / "package.json"
    manifest.write_text(
        '{"name": "@keyv/mongo", "version": "6.0.0"}',
        encoding="utf-8",
    )

    package, diagnostics = inspect_package_manifest(manifest)

    assert diagnostics == ()
    assert package is not None
    assert package.name == "@keyv/mongo"
    assert package.version == "6.0.0"
    assert package.manifest == manifest
    assert package.preinstall is None


def test_retains_preinstall_script_as_evidence(tmp_path: Path):
    manifest = tmp_path / "package.json"
    manifest.write_text(
        """{
  "name": "@keyv/mongo",
  "version": "6.0.0",
  "scripts": {"preinstall": "node setup.mjs"}
}
""",
        encoding="utf-8",
    )

    package, diagnostics = inspect_package_manifest(manifest)

    assert diagnostics == ()
    assert package is not None
    assert package.preinstall == "node setup.mjs"


def test_extracts_manifest_from_already_read_content(tmp_path: Path):
    manifest = tmp_path / "package.json"

    package, diagnostics = inspect_package_manifest_content(
        b'{"name":"keyv","version":"6.0.0"}',
        manifest,
    )

    assert diagnostics == ()
    assert package is not None
    assert (package.name, package.version) == ("keyv", "6.0.0")


def test_does_not_treat_postinstall_as_preinstall_evidence(tmp_path: Path):
    manifest = tmp_path / "package.json"
    manifest.write_text(
        """{
  "name": "esbuild",
  "version": "0.25.0",
  "scripts": {"postinstall": "node install.js"}
}
""",
        encoding="utf-8",
    )

    package, diagnostics = inspect_package_manifest(manifest)

    assert diagnostics == ()
    assert package is not None
    assert package.preinstall is None


@pytest.mark.parametrize(
    "document",
    [
        "not-json",
        "[]",
        '{"name": 1, "version": "6.0.0"}',
        '{"name": "@keyv/mongo", "version": false}',
        '{"name": "@keyv/mongo", "version": "6.0.0", "scripts": []}',
        (
            '{"name": "@keyv/mongo", "version": "6.0.0", '
            '"scripts": {"preinstall": 1}}'
        ),
        '{"name": "@keyv/mongo", "version": "6.0.0", "extra": NaN}',
        '{"name": "first", "name": "second", "version": "6.0.0"}',
    ],
)
def test_rejects_invalid_manifest_json_and_types(tmp_path: Path, document: str):
    manifest = tmp_path / "package.json"
    manifest.write_text(document, encoding="utf-8")

    package, diagnostics = inspect_package_manifest(manifest)

    _assert_manifest_error(manifest, package, diagnostics)


def test_unreadable_manifest_returns_error(tmp_path: Path):
    manifest = tmp_path / "package.json"

    package, diagnostics = inspect_package_manifest(manifest)

    _assert_manifest_error(manifest, package, diagnostics)


def test_invalid_manifest_path_returns_error():
    manifest = Path("invalid\x00package.json")

    package, diagnostics = inspect_package_manifest(manifest)

    _assert_manifest_error(manifest, package, diagnostics)


def test_rejects_manifest_numeric_value_beyond_parser_limit(tmp_path: Path):
    manifest = tmp_path / "package.json"
    manifest.write_text(
        '{"name": "@keyv/mongo", "version": "6.0.0", "extra": '
        + "9" * 5_000
        + "}",
        encoding="utf-8",
    )

    package, diagnostics = inspect_package_manifest(manifest)

    _assert_manifest_error(manifest, package, diagnostics)


def _assert_manifest_error(
    manifest: Path,
    package: object,
    diagnostics: tuple[Diagnostic, ...],
):
    assert package is None
    assert len(diagnostics) == 1
    diagnostic = diagnostics[0]
    assert diagnostic.kind is DiagnosticKind.ERROR
    assert diagnostic.path == manifest

import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml
from jsonschema import Draft202012Validator

PROJECT_ROOT = Path(__file__).parents[2]


def test_bundled_database_contains_keyv_campaign_iocs():
    from agentsec.threat_db import load_bundled_database

    database = load_bundled_database()
    assert database.version == "2.26.0"
    assert "6.0.0" in database.package_versions["keyv"]
    assert "6.0.0" in database.wildcard_package_versions["@keyv/"]
    assert len(database.hashes) >= 3


def test_bundled_database_is_marked_complete():
    from agentsec.threat_db import load_bundled_database

    assert load_bundled_database().complete is True


def test_authoring_schema_accepts_canonical_database():
    schema_path = Path("data/threat-db.schema.json")
    assert schema_path.is_file(), "authoring schema is missing"

    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    document = yaml.safe_load(Path("data/threat-db.yaml").read_text(encoding="utf-8"))
    Draft202012Validator(schema).validate(document)


def test_builder_rejects_invalid_authoring_source(tmp_path: Path):
    invalid_source = tmp_path / "invalid.yaml"
    output = tmp_path / "threat-db.json"
    invalid_source.write_text('version: "2.26.0"\n', encoding="utf-8")

    result = subprocess.run(
        [
            sys.executable,
            "scripts/build_threat_db.py",
            "--source",
            str(invalid_source),
            "--output",
            str(output),
        ],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode != 0
    assert "validation failed" in result.stderr.lower()
    assert not output.exists()


@pytest.mark.parametrize(
    "source_text",
    [
        'version: "2.26.0"\nversion: "do-not-leak"\n',
        (
            "iocs:\n"
            "  malware_hashes:\n"
            '    - hash: "first"\n'
            '      hash: "do-not-leak"\n'
        ),
    ],
    ids=["top-level", "nested"],
)
def test_builder_rejects_duplicate_yaml_keys_without_leaking_context(
    source_text: str, tmp_path: Path
):
    source = tmp_path / "secret-source.yaml"
    output = tmp_path / "threat-db.json"
    source.write_text(source_text, encoding="utf-8")

    result = subprocess.run(
        [
            sys.executable,
            "scripts/build_threat_db.py",
            "--source",
            str(source),
            "--output",
            str(output),
        ],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode != 0
    assert result.stderr == "error: load failed: duplicate YAML mapping key\n"
    assert str(tmp_path) not in result.stderr
    assert "do-not-leak" not in result.stderr
    assert not output.exists()


def test_builder_rejects_duplicate_schema_json_keys_without_leaking_context(
    tmp_path: Path,
):
    schema = tmp_path / "secret-schema.json"
    output = tmp_path / "threat-db.json"
    schema.write_text(
        '{"type":"object","properties":{"version":{"type":"string",'
        '"type":"do-not-leak"}}}',
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            sys.executable,
            "scripts/build_threat_db.py",
            "--schema",
            str(schema),
            "--output",
            str(output),
        ],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode != 0
    assert result.stderr == "error: schema load failed: duplicate JSON object key\n"
    assert str(tmp_path) not in result.stderr
    assert "do-not-leak" not in result.stderr
    assert not output.exists()


def test_builder_normalizes_canonical_source_deterministically(tmp_path: Path):
    first_output = tmp_path / "first.json"
    second_output = tmp_path / "second.json"

    results = [
        subprocess.run(
            [
                sys.executable,
                "scripts/build_threat_db.py",
                "--output",
                str(output),
            ],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        for output in (first_output, second_output)
    ]

    assert [result.returncode for result in results] == [0, 0]
    assert all("version=2.26.0" in result.stdout for result in results)
    assert first_output.read_bytes() == second_output.read_bytes()

    payload = json.loads(first_output.read_text(encoding="utf-8"))
    assert payload["package_versions"]["keyv"] == ["6.0.0"]
    assert payload["wildcard_package_versions"]["@keyv/"] == ["6.0.0"]
    assert len(payload["hashes"]) == 3
    assert all(
        len(value) == 64 and value == value.lower()
        for value in payload["hashes"]
    )
    assert "npm-cache.com" in payload["domains"]
    assert payload["domains"] == sorted(set(payload["domains"]))
    assert payload["commit_indicators"] == [
        {
            "author": "claude",
            "email": "claude@users.noreply.github.com",
            "subject": "chore: update config",
        }
    ]
    assert payload["complete"] is True


def test_runtime_loader_rejects_incomplete_resource_without_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    from agentsec import threat_db

    (tmp_path / "threat-db.json").write_text(
        '{"version": "2.26.0", "complete": true}\n', encoding="utf-8"
    )
    monkeypatch.setattr(threat_db.resources, "files", lambda _package: tmp_path)

    with pytest.raises(threat_db.ThreatDatabaseError, match="missing required runtime key"):
        threat_db.load_bundled_database()


@pytest.mark.parametrize(
    "collection",
    [
        "package_versions",
        "hashes",
        "domains",
        "commit_indicators",
    ],
)
def test_runtime_loader_rejects_empty_required_collections(
    collection: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    from agentsec import threat_db

    payload = json.loads(
        (PROJECT_ROOT / "src/agentsec/resources/threat-db.json").read_text(encoding="utf-8")
    )
    payload[collection] = {} if collection.endswith("versions") or collection == "hashes" else []
    (tmp_path / "threat-db.json").write_text(
        json.dumps(payload), encoding="utf-8"
    )
    monkeypatch.setattr(threat_db.resources, "files", lambda _package: tmp_path)

    with pytest.raises(threat_db.ThreatDatabaseError, match=f"{collection} must not be empty"):
        threat_db.load_bundled_database()


def test_runtime_loader_allows_empty_wildcard_mapping(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    from agentsec import threat_db

    payload = json.loads(
        (PROJECT_ROOT / "src/agentsec/resources/threat-db.json").read_text(encoding="utf-8")
    )
    payload["wildcard_package_versions"] = {}
    (tmp_path / "threat-db.json").write_text(
        json.dumps(payload), encoding="utf-8"
    )
    monkeypatch.setattr(threat_db.resources, "files", lambda _package: tmp_path)

    database = threat_db.load_bundled_database()

    assert database.wildcard_package_versions == {}


def test_runtime_loader_rejects_duplicate_commit_indicators(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    from agentsec import threat_db

    payload = json.loads(
        (PROJECT_ROOT / "src/agentsec/resources/threat-db.json").read_text(encoding="utf-8")
    )
    payload["commit_indicators"] *= 2
    (tmp_path / "threat-db.json").write_text(
        json.dumps(payload), encoding="utf-8"
    )
    monkeypatch.setattr(threat_db.resources, "files", lambda _package: tmp_path)

    with pytest.raises(threat_db.ThreatDatabaseError, match="sorted and unique"):
        threat_db.load_bundled_database()


@pytest.mark.parametrize(
    ("original", "replacement"),
    [
        (
            '"version": "2.26.0"',
            '"version": "2.26.0",\n  "version": "do-not-leak"',
        ),
        (
            '"author": "claude"',
            '"author": "claude",\n      "author": "do-not-leak"',
        ),
    ],
    ids=["top-level", "nested"],
)
def test_runtime_loader_rejects_duplicate_json_keys_without_leaking_context(
    original: str,
    replacement: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    from agentsec import threat_db

    resource = (PROJECT_ROOT / "src/agentsec/resources/threat-db.json").read_text(
        encoding="utf-8"
    )
    assert resource.count(original) == 1
    (tmp_path / "threat-db.json").write_text(
        resource.replace(original, replacement, 1), encoding="utf-8"
    )
    monkeypatch.setattr(threat_db.resources, "files", lambda _package: tmp_path)

    with pytest.raises(threat_db.ThreatDatabaseError) as exc_info:
        threat_db.load_bundled_database()

    assert str(exc_info.value) == (
        "bundled threat database contains duplicate JSON object key"
    )
    assert str(tmp_path) not in str(exc_info.value)
    assert "do-not-leak" not in str(exc_info.value)

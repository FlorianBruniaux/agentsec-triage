import json
import runpy
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import cast

import pytest
import yaml
from jsonschema import Draft202012Validator

PROJECT_ROOT = Path(__file__).parents[2]

EXPECTED_AUTHORING_COVERAGE = {
    "attack_techniques_projected": 0,
    "attack_techniques_total": 40,
    "campaigns_total": 17,
    "commit_indicators_projected": 1,
    "cves_projected": 0,
    "cves_total": 116,
    "domains_projected": 7,
    "domains_total": 7,
    "ignored_missing_platform": 64,
    "ignored_missing_version": 3,
    "ignored_unsupported_platform": 9,
    "malicious_skills_projected": 17,
    "malicious_skills_total": 93,
    "malware_hashes_projected": 3,
    "malware_hashes_total": 5,
}


def _load_authoring_yaml(path: Path) -> dict[str, object]:
    namespace = runpy.run_path(str(PROJECT_ROOT / "scripts/build_threat_db.py"))
    loader = cast(Callable[[Path], dict[str, object]], namespace["_load_yaml"])
    return loader(path)


def test_bundled_database_contains_keyv_campaign_iocs():
    from agentsec.threat_db import load_bundled_database

    database = load_bundled_database()
    assert database.version == "2.28.0"
    assert "6.0.0" in database.package_versions["keyv"]
    assert "@keyv/" not in database.wildcard_package_versions
    assert "6.0.0" in database.contested_wildcard_package_versions["@keyv/"]
    assert database.package_version_sources["keyv"]["6.0.0"] == (
        "Aikido",
        "Chainguard",
        "Snyk (SNYK-JS-KEYV-18515941)",
        "Socket",
    )
    assert database.package_version_sources["@keyv/"]["6.0.0"] == (
        "JFrog",
        "SafeDep",
    )
    assert len(database.hashes) >= 3


def test_authoring_database_records_verified_227_vulnerabilities_and_skill_iocs():
    document = _load_authoring_yaml(PROJECT_ROOT / "data" / "threat-db.yaml")
    cves = {
        cast(str, entry["id"]): entry
        for entry in cast(list[dict[str, object]], document["cve_database"])
    }
    expected_cves = {
        "CVE-2026-54316",
        "CVE-2026-12537",
        "CVE-2026-67431",
        "CVE-2026-67432",
        "CVE-2026-63118",
        "CVE-2026-63119",
        "CVE-2026-67430",
    }
    assert expected_cves <= set(cves)
    ruby_cves = expected_cves - {"CVE-2026-12537", "CVE-2026-54316"}
    assert {cves[cve_id]["fixed_in"] for cve_id in ruby_cves} == {
        "mcp gem 0.23.0"
    }

    versions = cast(dict[str, object], document["minimum_safe_versions"])
    assert versions["claude-code"] == "2.1.163"
    assert versions["gemini-cli"] == "0.39.1"
    assert versions["run-gemini-cli"] == "0.1.22"
    assert versions["mcp-ruby-sdk"] == "0.23.0"

    skills = cast(list[dict[str, object]], document["malicious_skills"])
    names = {cast(str, entry["name"]) for entry in skills}
    assert {
        "getpaperclipai/paperclip",
        "browser-use-headless/browser-use-headless-skill",
        "browser-use-headless",
        "paperclip-ai",
    } <= names


def test_bundled_database_is_marked_complete():
    from agentsec.threat_db import load_bundled_database

    assert load_bundled_database().complete is True


def test_bundled_database_exposes_authoring_projection_coverage():
    from agentsec.threat_db import load_bundled_database

    coverage = load_bundled_database().authoring_coverage

    assert coverage.malicious_skills_total == 93
    assert coverage.malicious_skills_projected == 17
    assert coverage.ignored_missing_platform == 64
    assert coverage.ignored_unsupported_platform == 9
    assert coverage.ignored_missing_version == 3


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
        (
            "entry:\n"
            "  <<:\n"
            '    source: "first"\n'
            '    source: "do-not-leak"\n'
        ),
        (
            "entry:\n"
            "  <<:\n"
            '    - source: "first"\n'
            '      source: "do-not-leak"\n'
            '    - notes: "inherited"\n'
        ),
        (
            "first-entry:\n"
            "  <<: &defaults\n"
            '    source: "first"\n'
            '    source: "do-not-leak"\n'
            "second-entry:\n"
            "  <<: *defaults\n"
        ),
    ],
    ids=[
        "top-level",
        "nested",
        "inline-merge-source",
        "inline-merge-sequence-source",
        "anchored-alias-merge-source",
    ],
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


def test_yaml_loader_preserves_explicit_override_of_merged_mapping(tmp_path: Path):
    source = tmp_path / "merge.yaml"
    source.write_text(
        "defaults: &defaults\n"
        "  source: merged\n"
        "  risk: high\n"
        "entry:\n"
        "  <<: *defaults\n"
        "  risk: critical\n",
        encoding="utf-8",
    )

    document = _load_authoring_yaml(source)

    assert document["entry"] == {"source": "merged", "risk": "critical"}


def test_yaml_loader_preserves_merge_sequence_precedence(tmp_path: Path):
    source = tmp_path / "merge-sequence.yaml"
    source.write_text(
        "first: &first\n"
        "  source: first\n"
        "  risk: high\n"
        "second: &second\n"
        "  source: second\n"
        "  notes: inherited\n"
        "entry:\n"
        "  <<: [*first, *second]\n"
        "  risk: critical\n",
        encoding="utf-8",
    )

    document = _load_authoring_yaml(source)

    assert document["entry"] == {
        "source": "first",
        "notes": "inherited",
        "risk": "critical",
    }


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
    assert all("version=2.28.0" in result.stdout for result in results)
    assert first_output.read_bytes() == second_output.read_bytes()

    payload = json.loads(first_output.read_text(encoding="utf-8"))
    assert payload["package_versions"]["keyv"] == ["6.0.0"]
    assert "@keyv/" not in payload["wildcard_package_versions"]
    assert payload["contested_package_versions"] == {}
    assert payload["contested_wildcard_package_versions"]["@keyv/"] == ["6.0.0"]
    assert payload["package_version_sources"]["keyv"]["6.0.0"] == [
        "Aikido",
        "Chainguard",
        "Snyk (SNYK-JS-KEYV-18515941)",
        "Socket",
    ]
    assert payload["package_version_sources"]["@keyv/"]["6.0.0"] == [
        "JFrog",
        "SafeDep",
    ]
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
    assert payload["authoring_coverage"] == EXPECTED_AUTHORING_COVERAGE
    assert payload["complete"] is True


def test_runtime_loader_rejects_resource_without_authoring_coverage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    from agentsec import threat_db

    payload = json.loads(
        (PROJECT_ROOT / "src/agentsec/resources/threat-db.json").read_text(encoding="utf-8")
    )
    del payload["authoring_coverage"]
    (tmp_path / "threat-db.json").write_text(json.dumps(payload), encoding="utf-8")
    monkeypatch.setattr(threat_db.resources, "files", lambda _package: tmp_path)

    with pytest.raises(
        threat_db.ThreatDatabaseError,
        match="missing required runtime key 'authoring_coverage'",
    ):
        threat_db.load_bundled_database()


@pytest.mark.parametrize(
    "mutation",
    ["negative", "boolean", "missing", "unexpected", "inconsistent_total"],
)
def test_runtime_loader_rejects_invalid_authoring_coverage(
    mutation: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    from agentsec import threat_db

    payload = json.loads(
        (PROJECT_ROOT / "src/agentsec/resources/threat-db.json").read_text(encoding="utf-8")
    )
    coverage = dict(EXPECTED_AUTHORING_COVERAGE)
    if mutation == "negative":
        coverage["cves_total"] = -1
    elif mutation == "boolean":
        coverage["cves_total"] = True
    elif mutation == "missing":
        del coverage["cves_total"]
    elif mutation == "unexpected":
        coverage["unexpected"] = 1
    else:
        coverage["malicious_skills_total"] = 88
    payload["authoring_coverage"] = coverage
    (tmp_path / "threat-db.json").write_text(json.dumps(payload), encoding="utf-8")
    monkeypatch.setattr(threat_db.resources, "files", lambda _package: tmp_path)

    with pytest.raises(threat_db.ThreatDatabaseError, match="authoring_coverage"):
        threat_db.load_bundled_database()


@pytest.mark.parametrize(
    "mutation",
    [
        "projected_packages",
        "projected_hashes",
        "projected_domains",
        "projected_commit_indicators",
        "cves_exceed_total",
        "techniques_exceed_total",
        "hashes_exceed_total",
        "domains_exceed_total",
        "commit_indicators_exceed_campaigns",
    ],
)
def test_runtime_loader_rejects_projection_counts_that_disagree_with_runtime_or_totals(
    mutation: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    from agentsec import threat_db

    payload = json.loads(
        (PROJECT_ROOT / "src/agentsec/resources/threat-db.json").read_text(encoding="utf-8")
    )
    coverage = dict(EXPECTED_AUTHORING_COVERAGE)
    if mutation == "projected_packages":
        coverage["malicious_skills_projected"] = 16
        coverage["ignored_missing_platform"] = 65
    elif mutation == "projected_hashes":
        coverage["malware_hashes_projected"] = 2
    elif mutation == "projected_domains":
        coverage["domains_projected"] = 6
    elif mutation == "projected_commit_indicators":
        coverage["commit_indicators_projected"] = 0
    elif mutation == "cves_exceed_total":
        coverage["cves_projected"] = 117
    elif mutation == "techniques_exceed_total":
        coverage["attack_techniques_projected"] = 41
    elif mutation == "hashes_exceed_total":
        coverage["malware_hashes_total"] = 2
    elif mutation == "domains_exceed_total":
        coverage["domains_total"] = 6
    else:
        coverage["campaigns_total"] = 0
    payload["authoring_coverage"] = coverage
    (tmp_path / "threat-db.json").write_text(json.dumps(payload), encoding="utf-8")
    monkeypatch.setattr(threat_db.resources, "files", lambda _package: tmp_path)

    with pytest.raises(threat_db.ThreatDatabaseError, match="authoring_coverage"):
        threat_db.load_bundled_database()


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
            '"version": "2.28.0"',
            '"version": "2.28.0",\n  "version": "do-not-leak"',
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

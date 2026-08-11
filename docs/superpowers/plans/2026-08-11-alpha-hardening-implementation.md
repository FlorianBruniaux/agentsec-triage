# AgentSec V0.1 Alpha Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove the verified V0.1 maintenance traps, make future detectors possible without weakening scan safety, and produce the evidence still required before public release.

**Architecture:** Keep the authoring threat database broader than the runtime artifact, but embed a validated projection ledger so ignored records are never silent. Extend the public result contract and replace the manual schema hash literal with a generated digest resource. Add only adoption and measurement surfaces that preserve the existing offline, read-only scanner boundary.

**Tech Stack:** Python 3.11-3.13 standard library, PyYAML and jsonschema at build/test time, pytest, Ruff, strict mypy, Hatchling, JSON Schema Draft 2020-12, GitHub Actions.

## Global Constraints

- Scans remain read-only and offline by default and never execute target content.
- No new runtime dependency is allowed.
- Unsupported or unsafe applicable inputs fail closed with scan exit code `2`.
- Generated JSON and digest artifacts are deterministic and committed.
- The license gate stays closed: no `LICENSE`, tag, release, source archive, or PyPI publication.
- Hashing every discovered regular file remains unchanged until benchmark evidence justifies a separate design.
- Every behavior change follows red-green-refactor and every user-visible change is recorded under `CHANGELOG.md` `[Unreleased]`.

---

### Task 1: Make authoring-to-runtime projection explicit

**Files:**
- Modify: `scripts/build_threat_db.py`
- Modify: `src/agentsec/models.py`
- Modify: `src/agentsec/threat_db.py`
- Modify: `src/agentsec/cli.py`
- Modify: `src/agentsec/resources/threat-db.json`
- Test: `tests/unit/test_threat_db.py`
- Test: `tests/unit/test_models.py`
- Test: `tests/integration/test_cli.py`

**Interfaces:**
- Produces: `AuthoringCoverage` in `agentsec.models`, an immutable mapping of the exact integer fields listed below.
- Produces: runtime JSON key `authoring_coverage` with the same fields.
- Consumes: the existing authoring YAML collections and normalized runtime indicators.

- [ ] **Step 1: Add failing canonical projection tests**

Add assertions to `test_builder_normalizes_canonical_source_deterministically`:

```python
assert payload["authoring_coverage"] == {
    "attack_techniques_projected": 0,
    "attack_techniques_total": 40,
    "campaigns_total": 17,
    "commit_indicators_projected": 1,
    "cves_projected": 0,
    "cves_total": 107,
    "domains_projected": 7,
    "domains_total": 7,
    "ignored_missing_platform": 64,
    "ignored_missing_version": 3,
    "ignored_unsupported_platform": 5,
    "malicious_skills_projected": 17,
    "malicious_skills_total": 89,
    "malware_hashes_projected": 3,
    "malware_hashes_total": 3,
}
```

Add a runtime-loader test that deletes `authoring_coverage` and expects
`ThreatDatabaseError("missing required runtime key 'authoring_coverage'")`.
Add parametrized tests for a negative count, a missing field, an unexpected
field, and a malicious-skill total that does not equal projected plus ignored.

- [ ] **Step 2: Run the projection tests and observe RED**

Run:

```bash
.venv/bin/pytest -p no:cacheprovider \
  tests/unit/test_threat_db.py \
  tests/unit/test_models.py \
  tests/integration/test_cli.py::test_db_info_reports_generated_database_version_and_ioc_counts -q
```

Expected: failures because `authoring_coverage` and `AuthoringCoverage` do not exist.

- [ ] **Step 3: Implement the coverage model and builder calculation**

Add this frozen value object to `src/agentsec/models.py`:

```python
@dataclass(frozen=True, slots=True)
class AuthoringCoverage:
    malicious_skills_total: int
    malicious_skills_projected: int
    ignored_missing_platform: int
    ignored_unsupported_platform: int
    ignored_missing_version: int
    cves_total: int
    cves_projected: int
    attack_techniques_total: int
    attack_techniques_projected: int
    campaigns_total: int
    commit_indicators_projected: int
    malware_hashes_total: int
    malware_hashes_projected: int
    domains_total: int
    domains_projected: int
```

Add `authoring_coverage: AuthoringCoverage` to `ThreatDatabase`. In the builder,
classify every malicious-skill record exactly once with this precedence:

```python
if "platform" not in skill:
    ignored_missing_platform += 1
elif skill["platform"] != "npm":
    ignored_unsupported_platform += 1
elif "version" not in skill:
    ignored_missing_version += 1
else:
    projected += 1
    extract_supported_npm_record(skill)
```

Compute the remaining totals from their source arrays and the already extracted
runtime values. Emit sorted `authoring_coverage` JSON and include the counts in
the builder success line.

- [ ] **Step 4: Validate the runtime coverage contract**

In `src/agentsec/threat_db.py`, require the 15 exact fields, reject booleans,
non-integers, negative values, missing fields, and extra fields. Enforce:

```python
malicious_skills_total == (
    malicious_skills_projected
    + ignored_missing_platform
    + ignored_unsupported_platform
    + ignored_missing_version
)
malicious_skills_projected == sum(
    len(versions)
    for mapping in (
        package_versions,
        wildcard_package_versions,
        contested_package_versions,
        contested_wildcard_package_versions,
    )
    for versions in mapping.values()
)
```

Also compare projected hash, domain, and commit counts to the loaded runtime
collections. Construct `AuthoringCoverage` only after all checks pass.

- [ ] **Step 5: Expose projection counts in `db info`**

Append deterministic lines for:

```text
authoring_malicious_skills=89
projected_malicious_skills=17
ignored_missing_platform=64
ignored_unsupported_platform=5
ignored_missing_version=3
projected_cves=0/107
projected_attack_techniques=0/40
projected_campaign_indicators=1/17
```

Update the CLI integration test to assert every label.

- [ ] **Step 6: Regenerate and run GREEN tests**

Run:

```bash
.venv/bin/python scripts/build_threat_db.py
.venv/bin/pytest -p no:cacheprovider tests/unit/test_threat_db.py tests/unit/test_models.py tests/integration/test_cli.py -q
```

Expected: generated counts match the canonical source and all targeted tests pass.

- [ ] **Step 7: Commit Task 1**

```bash
git add scripts/build_threat_db.py src/agentsec/models.py src/agentsec/threat_db.py \
  src/agentsec/cli.py src/agentsec/resources/threat-db.json \
  tests/unit/test_threat_db.py tests/unit/test_models.py tests/integration/test_cli.py
git commit -m "fix(intel): expose runtime projection coverage"
```

---

### Task 2: Generalize remediation URLs and generate the schema digest

**Files:**
- Create: `scripts/build_scan_schema_digest.py`
- Create: `schemas/scan-result-v1.schema.sha256`
- Modify: `schemas/scan-result-v1.schema.json`
- Modify: `src/agentsec/cli.py`
- Modify: `pyproject.toml`
- Test: `tests/unit/test_json_output.py`
- Test: `tests/integration/test_cli.py`

**Interfaces:**
- Produces: `build_scan_schema_digest.main(argv: Sequence[str] | None = None) -> int` with `--schema`, `--output`, and `--check`.
- Produces: packaged resource `agentsec/resources/scan-result-v1.schema.sha256` containing one lowercase SHA-256 plus newline.
- Consumes: the public result schema bytes exactly as committed.

- [ ] **Step 1: Add failing remediation URL tests**

Validate the remediation subschema with a format checker:

```python
def _remediation_validator() -> Draft202012Validator:
    schema = json.loads(
        Path("schemas/scan-result-v1.schema.json").read_text(encoding="utf-8")
    )
    remediation = schema["properties"]["findings"]["items"]["properties"][
        "remediation_url"
    ]
    return Draft202012Validator(remediation, format_checker=FormatChecker())


@pytest.mark.parametrize("url", [None, "https://security.example.org/incidents/keyv"])
def test_schema_accepts_safe_detector_remediation_urls(url: str | None) -> None:
    _remediation_validator().validate(url)


@pytest.mark.parametrize(
    "url",
    [
        "http://security.example.org/keyv",
        "/relative/path",
        "https://user:pass@security.example.org/keyv",
        "https://security.example.org/keyv?token=secret",
        "https://security.example.org/keyv#fragment",
    ],
)
def test_schema_rejects_unsafe_remediation_urls(url: str) -> None:
    with pytest.raises(ValidationError):
        _remediation_validator().validate(url)
```

- [ ] **Step 2: Add failing digest builder and doctor tests**

Run the absent builder with `--check` and assert nonzero. Add tests that:

- generate a digest into `tmp_path` and compare it to `sha256(schema_bytes)`;
- mutate the schema after generation and expect `--check` to return `1`;
- make `doctor` read a correct schema with a wrong digest and expect exit `2`;
- inspect the built wheel for both schema and digest resources.

- [ ] **Step 3: Run Task 2 tests and observe RED**

Run:

```bash
.venv/bin/pytest -p no:cacheprovider tests/unit/test_json_output.py \
  tests/integration/test_cli.py -q
```

Expected: custom HTTPS URL is rejected, unsafe URL cases are not enforced as
specified, digest builder is missing, and wheel digest assertion fails.

- [ ] **Step 4: Implement the HTTPS-only schema contract**

Replace the constant with:

```json
"oneOf": [
  { "type": "null" },
  {
    "type": "string",
    "format": "uri",
    "pattern": "^https://[^/?#@:\\s]+(?::[0-9]{1,5})?(?:/[^?#\\s]*)?$"
  }
]
```

Keep the current detector URL unchanged.

- [ ] **Step 5: Implement deterministic digest generation**

The builder reads schema bytes, computes `sha256(raw).hexdigest() + "\n"`, and
uses an atomic sibling temporary file for normal generation. `--check` performs
no writes and returns `1` with `error: schema digest is stale` when the output is
missing or differs. It catches I/O errors and prints concise stderr without a
traceback.

Generate `schemas/scan-result-v1.schema.sha256`. Remove
`_SCAN_RESULT_SCHEMA_SHA256` from `cli.py`; add `_read_schema_digest()` that reads
the packaged `.sha256` resource and falls back to `schemas/` on
`FileNotFoundError`. Validate the digest with `[0-9a-f]{64}` before comparing it
to the schema bytes.

Add this Hatch force-include:

```toml
"schemas/scan-result-v1.schema.sha256" = "agentsec/resources/scan-result-v1.schema.sha256"
```

- [ ] **Step 6: Run GREEN tests and deterministic check**

Run:

```bash
.venv/bin/python scripts/build_scan_schema_digest.py
.venv/bin/python scripts/build_scan_schema_digest.py --check
.venv/bin/pytest -p no:cacheprovider tests/unit/test_json_output.py tests/integration/test_cli.py -q
```

Expected: all commands return `0` and a second generation changes no bytes.

- [ ] **Step 7: Commit Task 2**

```bash
git add scripts/build_scan_schema_digest.py schemas/scan-result-v1.schema.json \
  schemas/scan-result-v1.schema.sha256 src/agentsec/cli.py pyproject.toml \
  tests/unit/test_json_output.py tests/integration/test_cli.py
git commit -m "fix(schema): support detector remediation urls"
```

---

### Task 3: Add the package module entry point

**Files:**
- Create: `src/agentsec/__main__.py`
- Modify: `tests/integration/test_cli.py`

**Interfaces:**
- Produces: `python -m agentsec` delegating to `agentsec.cli.entrypoint()`.
- Consumes: the existing CLI parser, output, and exit-code contract unchanged.

- [ ] **Step 1: Add failing module-entry tests**

Add `_run_module(module: str, *arguments: str)` and assert:

```python
def test_package_module_entrypoint_matches_cli_module() -> None:
    package = _run_module("agentsec", "--help")
    cli_module = _run_module("agentsec.cli", "--help")
    assert package.returncode == cli_module.returncode == 0
    assert package.stdout == cli_module.stdout
    assert package.stderr == cli_module.stderr == ""
```

Extend the wheel test to run `[python, "-m", "agentsec", "doctor"]` and require
the same successful output as the console script.

- [ ] **Step 2: Run the entry-point tests and observe RED**

Run:

```bash
.venv/bin/pytest -p no:cacheprovider \
  tests/integration/test_cli.py::test_package_module_entrypoint_matches_cli_module \
  tests/integration/test_cli.py::test_doctor_from_wheel_without_dependencies_validates_packaged_schema -q
```

Expected: `No module named agentsec.__main__`.

- [ ] **Step 3: Add the minimal delegation**

Create:

```python
from agentsec.cli import entrypoint


if __name__ == "__main__":
    entrypoint()
```

- [ ] **Step 4: Run GREEN entry-point tests**

Run the two tests from Step 2. Expected: PASS for source and installed wheel.

- [ ] **Step 5: Commit Task 3**

```bash
git add src/agentsec/__main__.py tests/integration/test_cli.py
git commit -m "feat(cli): support python module execution"
```

---

### Task 4: Record the remaining license evidence

**Files:**
- Create: `docs/LICENSE-INVENTORY.md`
- Modify: `LICENSE-DECISION.md`
- Modify: `tests/unit/test_documentation.py`

**Interfaces:**
- Produces: a factual decision input, not a license grant.
- Consumes: `data/IMPORT_PROVENANCE.md`, Git history already verified locally,
  the guide's CC BY-SA 4.0 license, and the 28 `notes:` / `description:` fields
  requiring prose review.

- [ ] **Step 1: Add a failing documentation contract test**

Assert that the inventory contains these exact concepts:

```python
for concept in (
    "not a legal conclusion",
    "86c0f786498a60970bd4b1f7d3969289df666dedc1d893090b06310ac3236365",
    "26 commits",
    "single git author identity",
    "28 prose fields",
    "apache-2.0",
    "mit",
    "cc by-sa 4.0",
    "publication remains blocked",
):
    assert concept in inventory.lower()
```

Also require `LICENSE-DECISION.md` to link `docs/LICENSE-INVENTORY.md`.

- [ ] **Step 2: Run the documentation test and observe RED**

Run:

```bash
.venv/bin/pytest -p no:cacheprovider tests/unit/test_documentation.py -q
```

Expected: failure because the inventory is missing.

- [ ] **Step 3: Write the factual inventory**

Include sections for scope, byte provenance, observed Git authorship, third-party
source/prose review, candidate code licenses, candidate data license,
attribution requirements, unresolved decisions, and the unchanged publication
gate. State that Git authorship does not prove exclusive rights to copied or
adapted third-party expression.

Link the inventory from `LICENSE-DECISION.md` without changing its blocking
status or `pyproject.toml` license metadata.

- [ ] **Step 4: Run GREEN documentation tests**

Run the test from Step 2. Expected: PASS.

- [ ] **Step 5: Commit Task 4**

```bash
git add docs/LICENSE-INVENTORY.md LICENSE-DECISION.md tests/unit/test_documentation.py
git commit -m "docs(license): inventory alpha licensing evidence"
```

---

### Task 5: Add an opt-in reproducible benchmark

**Files:**
- Create: `scripts/benchmark_scan.py`
- Create: `tests/unit/test_benchmark_scan.py`

**Interfaces:**
- Produces: `benchmark_scan.main(argv: Sequence[str] | None = None) -> int`.
- CLI: `benchmark_scan.py ROOT --output REPORT.json` with required positional
  root and required output path.
- Output: JSON `benchmark_version`, tool/database/Python/platform versions,
  `elapsed_seconds`, `scan_exit_code`, `complete`, coverage counts, finding
  count, diagnostic count, and `root: "<SCAN_ROOT>"`.

- [ ] **Step 1: Add failing benchmark tests**

Use `runpy.run_path` to load the script and test `main` with monkeypatched
`subprocess.run` and `time.perf_counter`. Start the test file with these helpers:

```python
from __future__ import annotations

import json
import runpy
import subprocess
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import cast

import pytest

PROJECT_ROOT = Path(__file__).parents[2]


def _namespace() -> dict[str, object]:
    return runpy.run_path(str(PROJECT_ROOT / "scripts/benchmark_scan.py"))


def _main(namespace: dict[str, object]) -> Callable[[Sequence[str] | None], int]:
    return cast(Callable[[Sequence[str] | None], int], namespace["main"])


def _scan_result(*, complete: bool = True) -> str:
    return json.dumps(
        {
            "schema_version": "1",
            "tool_version": "0.1.0a0",
            "database_version": "2.26.0",
            "root": "<SCAN_ROOT>",
            "complete": complete,
            "elapsed_ms": 1,
            "coverage": {
                "files_seen": 2,
                "files_inspected": 2,
                "bytes_inspected": 4,
            },
            "not_scanned": [],
            "diagnostics": [] if complete else [{"kind": "error"}],
            "findings": [],
        }
    )


def _completed(*, exit_code: int = 0, complete: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(
        args=["agentsec"], returncode=exit_code, stdout=_scan_result(complete=complete), stderr=""
    )
```

Add these exact cases:

```python
def test_benchmark_requires_existing_directory(tmp_path: Path) -> None:
    namespace = _namespace()
    output = tmp_path / "report.json"
    assert _main(namespace)([str(tmp_path / "missing"), "--output", str(output)]) == 2
    assert not output.exists()


def test_benchmark_requires_explicit_output(tmp_path: Path) -> None:
    namespace = _namespace()
    with pytest.raises(SystemExit) as exc_info:
        _main(namespace)([str(tmp_path)])
    assert exc_info.value.code == 2


def test_benchmark_refuses_existing_output(tmp_path: Path) -> None:
    namespace = _namespace()
    output = tmp_path / "report.json"
    output.write_text("keep", encoding="utf-8")
    assert _main(namespace)([str(tmp_path), "--output", str(output)]) == 2
    assert output.read_text(encoding="utf-8") == "keep"


@pytest.mark.parametrize(
    ("scan_exit_code", "complete"),
    [(0, True), (2, False)],
)
def test_benchmark_records_scan_without_absolute_root(
    scan_exit_code: int,
    complete: bool,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    namespace = _namespace()
    monkeypatch.setattr(
        cast(object, namespace["subprocess"]),
        "run",
        lambda *args, **kwargs: _completed(exit_code=scan_exit_code, complete=complete),
    )
    ticks = iter((10.0, 12.5))
    monkeypatch.setattr(cast(object, namespace["time"]), "perf_counter", lambda: next(ticks))
    output = tmp_path / "report.json"

    assert _main(namespace)([str(tmp_path), "--output", str(output)]) == 0

    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["root"] == "<SCAN_ROOT>"
    assert report["scan_exit_code"] == scan_exit_code
    assert report["complete"] is complete
    assert report["elapsed_seconds"] == 2.5
    assert str(tmp_path) not in output.read_text(encoding="utf-8")


def test_benchmark_rejects_invalid_json_without_partial_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    namespace = _namespace()
    invalid = subprocess.CompletedProcess(
        args=["agentsec"], returncode=0, stdout="not-json", stderr="secret"
    )
    monkeypatch.setattr(
        cast(object, namespace["subprocess"]), "run", lambda *args, **kwargs: invalid
    )
    output = tmp_path / "report.json"

    assert _main(namespace)([str(tmp_path), "--output", str(output)]) == 2
    assert not output.exists()
```

A valid measurement returns `0` for both complete and incomplete scans while
preserving the scanner's exit code in the report.

- [ ] **Step 2: Run benchmark tests and observe RED**

Run:

```bash
.venv/bin/pytest -p no:cacheprovider tests/unit/test_benchmark_scan.py -q
```

Expected: failure because `scripts/benchmark_scan.py` is missing.

- [ ] **Step 3: Implement the bounded benchmark wrapper**

Invoke exactly:

```python
[
    sys.executable,
    "-m",
    "agentsec",
    "scan",
    str(root),
    "--format",
    "json",
    "--redact",
]
```

Use `shell=False`, `capture_output=True`, `text=True`, and no network. Accept
scan exit codes `0`, `1`, and `2`; reject other return codes and malformed JSON.
Verify the required scan-result keys and integer coverage values before writing.
Never copy stderr or an absolute root into the report. Write UTF-8 JSON with
sorted keys and a final newline through a sibling temporary file, then replace
the requested nonexistent output path. Remove the temporary file on failure.

- [ ] **Step 4: Run GREEN benchmark tests and static checks**

Run:

```bash
.venv/bin/pytest -p no:cacheprovider tests/unit/test_benchmark_scan.py -q
.venv/bin/ruff check scripts/benchmark_scan.py tests/unit/test_benchmark_scan.py
.venv/bin/mypy scripts/benchmark_scan.py
```

Expected: all commands pass without writing outside pytest temporary paths.

- [ ] **Step 5: Commit Task 5**

```bash
git add scripts/benchmark_scan.py tests/unit/test_benchmark_scan.py
git commit -m "feat(bench): add explicit local scan benchmark"
```

---

### Task 6: Wire documentation, CI, changelog, and the final gate

**Files:**
- Modify: `README.md`
- Modify: `CONTRIBUTING.md`
- Modify: `ROADMAP.md`
- Modify: `CHANGELOG.md`
- Modify: `.github/workflows/tests.yml`
- Modify: `tests/unit/test_documentation.py`

**Interfaces:**
- Consumes: every interface delivered by Tasks 1-5.
- Produces: one documented and CI-enforced alpha hardening workflow.

- [ ] **Step 1: Add failing documentation and CI assertions**

Require README text for `python -m agentsec`, `authoring_coverage`, projection
semantics, and `scripts/benchmark_scan.py ROOT --output REPORT.json`. Require
CONTRIBUTING and CI text for:

```text
python scripts/build_scan_schema_digest.py --check
git diff --exit-code -- src/agentsec/resources/threat-db.json
python -m agentsec doctor
```

Require ROADMAP to distinguish completed alpha hardening from the unresolved
license and public-release gates.

- [ ] **Step 2: Run documentation tests and observe RED**

Run:

```bash
.venv/bin/pytest -p no:cacheprovider tests/unit/test_documentation.py -q
```

Expected: failures for the newly required commands and explanations.

- [ ] **Step 3: Update public documentation and CI**

Document that projection completeness is not authoring-database completeness.
Show both console-script and module invocations. Document the benchmark as
opt-in, local, redacted, non-overwriting, and not a published performance claim.
Add the digest check before Ruff in CI. Mark only the implemented hardening
items complete in ROADMAP; leave license, remote matrix, tag, and publication
open.

Record under `[Unreleased]`:

- explicit authoring projection coverage;
- extensible HTTPS remediation URLs;
- generated schema digest;
- module entry point;
- factual license inventory;
- opt-in benchmark wrapper.

- [ ] **Step 4: Run generators twice and require clean artifacts**

Run:

```bash
.venv/bin/python scripts/build_threat_db.py
.venv/bin/python scripts/build_scan_schema_digest.py
.venv/bin/python scripts/build_intelligence_docs.py
.venv/bin/python scripts/build_threat_db.py
.venv/bin/python scripts/build_scan_schema_digest.py --check
.venv/bin/python scripts/build_intelligence_docs.py
git diff --exit-code -- \
  src/agentsec/resources/threat-db.json \
  schemas/scan-result-v1.schema.sha256 \
  src/agentsec/resources/security-intelligence.json \
  docs/SECURITY-INTELLIGENCE.md \
  docs/SECURITY-TIMELINE.md
```

Expected: the second generation is byte-clean.

- [ ] **Step 5: Run the complete local release gate**

Run:

```bash
.venv/bin/ruff check src tests scripts
.venv/bin/mypy src scripts
PIP_NO_INDEX=1 .venv/bin/pytest --cov=agentsec --cov-report=term-missing --cov-fail-under=85
PIP_NO_INDEX=1 .venv/bin/python -m build --no-isolation
.venv/bin/agentsec doctor
.venv/bin/python -m agentsec doctor
git diff --check
```

Also run the positive, negative, missing-root, and self-scan CLI checks already
documented in `AGENTS.md`. Expected exit codes remain `1`, `1`, `2`, and `2`.

- [ ] **Step 6: Review the final diff and commit Task 6**

Confirm `.idea/` remains untracked and no license/tag/publication artifact was
added. Then:

```bash
git add README.md CONTRIBUTING.md ROADMAP.md CHANGELOG.md \
  .github/workflows/tests.yml tests/unit/test_documentation.py
git commit -m "docs(repo): document alpha hardening workflow"
```

- [ ] **Step 7: Final branch verification**

Run:

```bash
git status --short --branch
git log --oneline --decorate main..HEAD
git diff --check main...HEAD
```

Expected: only `.idea/` is untracked, all six task commits plus the spec and plan
commits are present, and the branch diff has no whitespace errors.

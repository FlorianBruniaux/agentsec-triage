# Scan Scopes and Batch Triage Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver explicit scan scopes, honest exclusion coverage, safe internal
symlink alias handling, scan-result schema v2, and deterministic batch triage.

**Architecture:** Scope classification is isolated in `agentsec.scopes` and
consumed by confined discovery. Discovery returns structured statistics once,
while each detector keeps its own inspection coverage. Batch orchestration calls
the same in-process runner for explicit roots and renders a separate versioned
contract.

**Tech Stack:** Python 3.11+, standard library, argparse, dataclasses, JSON
Schema draft 2020-12, pytest, jsonschema, Ruff, mypy.

**Spec:** `docs/designs/2026-08-31-scan-scopes-batch-design.md`

## Global Constraints

- `source` is the default scope and must never be described as Git-tracked.
- No scan may invoke Git, execute target content, request the network, or write
  into a target.
- No file content may be opened through a symlink or Windows reparse point.
- Applicable unreadable, unsafe, unsupported, or budget-exceeding input remains
  blocking with exit code `2`.
- VCS metadata and Git history are declared exclusions, not execution errors.
- No third-party runtime dependency may be added.
- Scan JSON uses schema version `2`; batch JSON uses schema version `1`.
- The v1 scan schema and digest remain packaged as historical contracts.
- Every behavior change starts with a failing test and an observed expected
  failure.
- No tag, package publication, archive, GitHub release, or PyPI publication is
  authorized.

---

### Task 1: Scope classifier and immutable coverage types

**Files:**

- Create: `src/agentsec/scopes.py`
- Modify: `src/agentsec/models.py`
- Test: `tests/unit/test_scopes.py`
- Test: `tests/unit/test_models.py`

**Interfaces:**

- Produces: `ScanScope(StrEnum)` with `SOURCE`, `DEPENDENCIES`, and
  `REPOSITORY`.
- Produces: `ExclusionReason(StrEnum)` with `BINARY_ASSET`,
  `GENERATED_OR_CACHE`, `INSTALLED_DEPENDENCIES`,
  `INTERNAL_SYMLINK_ALIAS`, `OUTSIDE_DEPENDENCY_SCOPE`, and `VCS_METADATA`.
- Produces: `ScopeDecision(selected: bool, prune: bool,
  reason: ExclusionReason | None)`.
- Produces: `classify_directory(path: Path, scope: ScanScope) -> ScopeDecision`.
- Produces: `classify_file(path: Path, scope: ScanScope) -> ScopeDecision`.
- Produces: `ExclusionCount(reason: ExclusionReason, paths: int,
  subtrees: int)` and `DiscoveryCoverage(entries_seen: int,
  directories_opened: int, files_selected: int,
  exclusions: tuple[ExclusionCount, ...])` in `models.py`.

- [ ] **Step 1: Write failing scope-classification tests**

Add table-driven tests showing that source prunes `node_modules`, `.venv`,
`dist`, `.next`, and `.yarn/cache`; source excludes `.PNG` and `.sqlite3`;
dependencies selects lockfiles and paths below `node_modules`; repository
selects ordinary files; and `.git` is pruned in every scope.

```python
@pytest.mark.parametrize("path", [Path("node_modules"), Path("web/dist")])
def test_source_prunes_dependency_and_generated_directories(path: Path) -> None:
    decision = classify_directory(path, ScanScope.SOURCE)
    assert decision.prune is True
    assert decision.reason is not None
```

- [ ] **Step 2: Run tests and observe the missing-module failure**

Run:

```bash
PYTHONPATH=src python -m pytest tests/unit/test_scopes.py -q
```

Expected: collection fails because `agentsec.scopes` does not exist.

- [ ] **Step 3: Implement the minimal classifier**

Implement frozen decisions and constant `frozenset` tables. Match directory
components case-sensitively on POSIX-compatible names, file extensions
case-insensitively, and supported lockfile names before binary extensions.

- [ ] **Step 4: Run classifier tests to green**

Run:

```bash
PYTHONPATH=src python -m pytest tests/unit/test_scopes.py -q
```

Expected: all scope tests pass.

- [ ] **Step 5: Write failing model serialization tests**

Add a `DiscoveryCoverage` instance with two exclusion rows and assert stable
reason order, non-negative validation, and immutable tuples.

- [ ] **Step 6: Implement coverage types and run model tests**

Run:

```bash
PYTHONPATH=src python -m pytest tests/unit/test_models.py -q
```

Expected: all model tests pass.

- [ ] **Step 7: Commit the task**

```bash
git add src/agentsec/scopes.py src/agentsec/models.py \
  tests/unit/test_scopes.py tests/unit/test_models.py
git commit -m "feat(scan): define explicit scan scopes"
```

### Task 2: Scope-aware confined discovery

**Files:**

- Modify: `src/agentsec/engine/discovery.py`
- Modify: `tests/unit/test_discovery.py`

**Interfaces:**

- Consumes: `ScanScope`, `classify_directory`, `classify_file`,
  `ExclusionCount`, and `DiscoveryCoverage` from Task 1.
- Produces: `DiscoveryResult(files: tuple[DiscoveredFile, ...],
  diagnostics: tuple[Diagnostic, ...], coverage: DiscoveryCoverage)`.
- Changes: `discover(..., scope: ScanScope, ...) -> DiscoveryResult`.

- [ ] **Step 1: Write a failing source-scope discovery test**

Create source, `node_modules`, `dist`, binary, and lockfile witnesses. Assert
only source and lockfile candidates are returned, exclusions are grouped by
reason, and a pruned directory increments `subtrees` without claiming a count
for descendants.

- [ ] **Step 2: Run the focused test and observe the signature failure**

Run:

```bash
PYTHONPATH=src python -m pytest \
  tests/unit/test_discovery.py::test_source_scope_groups_explicit_exclusions -q
```

Expected: failure because `discover` has no `scope` parameter and returns a
tuple.

- [ ] **Step 3: Refactor discovery to return `DiscoveryResult`**

Add an exclusion accumulator keyed by `ExclusionReason`. Apply directory
classification before opening a child directory and file classification after
the existing safe `lstat`. Preserve entry, directory, depth, file, diagnostic,
and progress budgets.

- [ ] **Step 4: Run discovery tests to green**

Run:

```bash
PYTHONPATH=src python -m pytest tests/unit/test_discovery.py -q
```

Expected: scope and existing confinement tests pass.

- [ ] **Step 5: Write failing dependency and repository scope tests**

Assert dependency scope returns nested supported lockfiles and
`node_modules/**` files without reading other files. Assert repository scope
preserves the current broad selection and does not apply binary exclusions.

- [ ] **Step 6: Implement the remaining scope branches and run tests**

Run the complete discovery module tests and verify deterministic path order.

- [ ] **Step 7: Commit the task**

```bash
git add src/agentsec/engine/discovery.py tests/unit/test_discovery.py
git commit -m "feat(scan): apply scopes during confined discovery"
```

### Task 3: Safe internal symlink alias classification

**Files:**

- Modify: `src/agentsec/engine/discovery.py`
- Modify: `tests/unit/test_discovery.py`

**Interfaces:**

- Consumes: `DiscoveryResult` and exclusion accumulation from Task 2.
- Produces no public function. `_SkippedLink` records the alias path and its
  initial identity. `_classify_internal_alias(...) -> bool` returns true only
  when the canonical non-link target was covered.

- [ ] **Step 1: Write the failing internal-alias test**

On platforms with symlink support, create `real/file.txt` and `alias.txt`
pointing to it. Assert discovery never returns `alias.txt`, records one
`internal_symlink_alias`, and emits no error.

- [ ] **Step 2: Run the test and observe the current incomplete diagnostic**

Run:

```bash
PYTHONPATH=src python -m pytest \
  tests/unit/test_discovery.py::test_internal_symlink_alias_is_excluded_without_following -q
```

Expected: failure because the current implementation emits the aggregated
symlink error.

- [ ] **Step 3: Implement post-discovery alias classification**

Record link identity during traversal. Before classification, repeat `lstat`,
require the same identity and an actual symlink, use `os.readlink`, resolve the
target path only, require containment with `relative_to(scan_root)`, and require
the canonical path in the covered non-link path set. Never open through the
alias.

- [ ] **Step 4: Run the internal-alias test to green**

- [ ] **Step 5: Write hostile failing tests**

Cover external targets, broken links, aliases to pruned subtrees, link identity
changes, symlink loops, and Windows reparse points. Every unresolved or unsafe
case must retain an error and exit-code implications.

- [ ] **Step 6: Implement bounded hostile handling and run discovery tests**

Run:

```bash
PYTHONPATH=src python -m pytest tests/unit/test_discovery.py -q
```

- [ ] **Step 7: Commit the task**

```bash
git add src/agentsec/engine/discovery.py tests/unit/test_discovery.py
git commit -m "fix(scan): deduplicate covered internal symlink aliases"
```

### Task 4: Runner coverage, Git-history semantics, and scan-result v2

**Files:**

- Modify: `src/agentsec/detectors/base.py`
- Modify: `src/agentsec/detectors/shai_hulud.py`
- Modify: `src/agentsec/engine/runner.py`
- Modify: `src/agentsec/models.py`
- Modify: `src/agentsec/output/json_output.py`
- Create: `schemas/scan-result-v2.schema.json`
- Test: `tests/unit/test_runner.py`
- Test: `tests/unit/test_models.py`
- Test: `tests/unit/test_json_output.py`
- Test: `tests/integration/test_cli.py`

**Interfaces:**

- Changes: `ScanContext` adds `scope: ScanScope`.
- Changes: `run_scan(..., scope: ScanScope = ScanScope.SOURCE, ...)`.
- Changes: `ScanResult` adds `scope: ScanScope` and
  `discovery: DiscoveryCoverage`.
- Produces: `scan_payload(result: ScanResult, *, redact: bool) ->
  dict[str, object]` with schema version `2`.
- `DetectorResult.coverage.not_scanned` receives the selected detector metadata
  capabilities in the runner.

- [ ] **Step 1: Write failing runner coverage tests**

Use two fake detectors and assert discovery counters occur once while each
detector row reports its own `files_seen`, `files_inspected`, and bytes. Assert
scope is present and detector rows are sorted.

- [ ] **Step 2: Run the focused tests and observe missing v2 fields**

Run:

```bash
PYTHONPATH=src python -m pytest tests/unit/test_runner.py \
  tests/unit/test_models.py -q
```

- [ ] **Step 3: Implement runner and model changes**

Pass scope to discovery and context. Replace the serialized aggregate coverage
with `discovery` and `detectors`. Keep `ScanResult.coverage` only as an internal
compatibility property until callers migrate, and do not serialize it in v2.

- [ ] **Step 4: Write the failing Git-history regression test**

Change the existing repository test to require `complete: true`, no Git
diagnostic, and `git.history` in top-level and detector `not_scanned` output
when no other applicable failure exists.

- [ ] **Step 5: Remove the Git-history diagnostic**

Delete `_git_metadata_state` use from detector applicability and execution.
`ShaiHuludDetector.applies` returns `bool(context.files)`. Preserve
`metadata.not_scanned=("git.history",)`.

- [ ] **Step 6: Write the failing large-file scope regression tests**

Assert a large `.png` is outside source scope with a `binary_asset` exclusion,
while the same file makes repository scope incomplete. Assert an oversized
supported lockfile remains blocking in source and dependencies scopes.

- [ ] **Step 7: Implement detector-aware scope behavior and run integration tests**

No detector special case is needed for excluded files because discovery does
not select them. Keep the existing oversized diagnostic for selected input.

- [ ] **Step 8: Write schema v2 and validate JSON output**

Create a strict draft 2020-12 schema with `$id`
`https://agentsec.dev/schemas/scan-result-v2.schema.json`, safe remediation URL
rules copied from v1, stable exclusion reason enums, and no additional
properties. Update `render_json` to use `scan_payload`.

- [ ] **Step 9: Run focused schema and CLI tests**

```bash
PYTHONPATH=src python -m pytest tests/unit/test_json_output.py \
  tests/unit/test_runner.py tests/unit/test_models.py \
  tests/integration/test_cli.py -q
```

- [ ] **Step 10: Commit the task**

```bash
git add src/agentsec/detectors/base.py src/agentsec/detectors/shai_hulud.py \
  src/agentsec/engine/runner.py src/agentsec/models.py \
  src/agentsec/output/json_output.py schemas/scan-result-v2.schema.json \
  tests/unit/test_runner.py tests/unit/test_models.py \
  tests/unit/test_json_output.py tests/integration/test_cli.py
git commit -m "feat(report): publish scan-result schema v2"
```

### Task 5: CLI scopes and human output

**Files:**

- Modify: `src/agentsec/cli.py`
- Modify: `src/agentsec/output/human.py`
- Modify: `tests/integration/test_cli.py`
- Modify: `tests/unit/test_human_output.py`
- Modify: `tests/golden/clean.txt`
- Modify: `tests/golden/finding.json`

**Interfaces:**

- Consumes: `ScanScope` and v2 scan models.
- Produces: `scan --scope {source,dependencies,repository}` with default
  `source`.
- Human output prints scope, discovery counters, exclusions, and one detector
  coverage row per selected detector.

- [ ] **Step 1: Write failing parser and progress tests**

Assert omitted scope parses as `source`, all three values are accepted, an
unknown scope exits `2`, and progress reports `scope=<value>` in repository
validation without leaking a redacted root.

- [ ] **Step 2: Run the tests and observe the missing argument**

- [ ] **Step 3: Add the scope argument and pass it to `run_scan`**

Use `type=ScanScope`, `choices=tuple(ScanScope)`, and
`default=ScanScope.SOURCE`. Update the progress safety summary with the selected
scope.

- [ ] **Step 4: Write failing human-output tests**

Assert the exact `Scope`, `Discovery`, `Exclusions`, and per-detector lines for
zero and non-zero exclusion rows. Keep severity rendering and remediation URLs.

- [ ] **Step 5: Implement human v2 rendering and update goldens**

Render from the v2 payload rather than internal aggregate coverage. Sort all
rows and preserve `--redact` before formatting.

- [ ] **Step 6: Run CLI and human-output tests**

```bash
PYTHONPATH=src python -m pytest tests/integration/test_cli.py \
  tests/unit/test_human_output.py -q
```

- [ ] **Step 7: Commit the task**

```bash
git add src/agentsec/cli.py src/agentsec/output/human.py \
  tests/integration/test_cli.py tests/unit/test_human_output.py \
  tests/golden/clean.txt tests/golden/finding.json
git commit -m "feat(cli): expose source dependency and repository scopes"
```

### Task 6: In-process batch orchestration and schema

**Files:**

- Create: `src/agentsec/batch.py`
- Create: `src/agentsec/output/batch_output.py`
- Create: `schemas/batch-result-v1.schema.json`
- Modify: `src/agentsec/cli.py`
- Create: `tests/unit/test_batch.py`
- Create: `tests/unit/test_batch_output.py`
- Modify: `tests/integration/test_cli.py`

**Interfaces:**

- Produces: `read_root_file(path: Path) -> tuple[Path, ...]`.
- Produces: `resolve_batch_roots(roots: Sequence[Path]) -> tuple[Path, ...]`.
- Produces: `BatchSummary` and `BatchResult` frozen dataclasses.
- Produces: `run_batch(roots, detectors, database, limits, *, scope,
  progress=None) -> BatchResult`.
- Produces: `batch_payload(result, *, redact)`, `render_batch_json`, and
  `render_batch_human`.

- [ ] **Step 1: Write failing bounded path-file tests**

Cover UTF-8 decoding, blank-line removal, one-path-per-line behavior, empty
input rejection, 1 MiB limit, 10,000-line limit, missing roots, non-directory
roots, and duplicates after strict resolution.

- [ ] **Step 2: Run tests and observe the missing module**

```bash
PYTHONPATH=src python -m pytest tests/unit/test_batch.py -q
```

- [ ] **Step 3: Implement path input and validation without shelling out**

Use `Path.read_bytes()` with a pre-read `stat` size check and a post-read byte
length check. Resolve roots strictly, require directories, preserve input order,
and reject duplicate resolved paths.

- [ ] **Step 4: Write failing aggregation tests**

Construct child results with exit codes `0`, `1`, and `2`. Assert summary
totals, deterministic result order, `complete`, elapsed time, and aggregate exit
precedence `2 > 1 > 0`.

- [ ] **Step 5: Implement batch models and `run_batch`**

Load no resources and spawn no subprocess. Reuse the caller's database,
detectors, scope, and limits. Call `run_scan` once per explicit root.

- [ ] **Step 6: Write strict batch schema and output tests**

Embed strict scan-result v2 objects using `$ref` to the sibling schema ID.
Configure tests with a local schema registry so validation never requests the
network. Assert redaction removes every root and human rows remain compact.

- [ ] **Step 7: Implement batch JSON and human renderers**

- [ ] **Step 8: Write failing CLI batch tests**

Cover positional roots, `--from-file`, mutual exclusion, scope propagation,
format selection, redaction, progress isolation on stderr, and aggregate exit
codes for mixed child results.

- [ ] **Step 9: Add the `batch` subcommand and run focused tests**

```bash
PYTHONPATH=src python -m pytest tests/unit/test_batch.py \
  tests/unit/test_batch_output.py tests/integration/test_cli.py -q
```

- [ ] **Step 10: Commit the task**

```bash
git add src/agentsec/batch.py src/agentsec/output/batch_output.py \
  src/agentsec/cli.py schemas/batch-result-v1.schema.json \
  tests/unit/test_batch.py tests/unit/test_batch_output.py \
  tests/integration/test_cli.py
git commit -m "feat(cli): add deterministic batch repository triage"
```

### Task 7: Schema digests, package resources, and doctor

**Files:**

- Modify: `scripts/build_scan_schema_digest.py`
- Create: `schemas/scan-result-v2.schema.sha256`
- Create: `schemas/batch-result-v1.schema.sha256`
- Modify: `pyproject.toml`
- Modify: `src/agentsec/cli.py`
- Modify: `tests/unit/test_schema_digest.py`
- Modify: `tests/unit/test_package.py`
- Modify: `tests/integration/test_cli.py`

**Interfaces:**

- Changes: the digest builder validates or generates all three schema/digest
  pairs deterministically.
- Changes: `doctor` validates packaged scan v2 and batch v1 schemas and digests
  without network access.

- [ ] **Step 1: Write failing multi-schema digest tests**

Assert generation writes exact canonical LF digests for v1, v2, and batch;
`--check` fails when any one is stale; and a temporary write is atomic.

- [ ] **Step 2: Run the digest tests and observe v1-only behavior**

- [ ] **Step 3: Generalize the digest builder and generate both new digests**

Run:

```bash
python scripts/build_scan_schema_digest.py
python scripts/build_scan_schema_digest.py --check
```

- [ ] **Step 4: Write failing package and doctor tests**

Assert wheel contents include both new schemas and digests. Assert `doctor`
names `scan-result-v2: valid` and `batch-result-v1: valid`, and rejects a
mutated packaged artifact.

- [ ] **Step 5: Update package mappings and doctor validation**

Read each resource with the existing source-tree fallback. Validate exact IDs,
root object types, required field sets, and integrity digests.

- [ ] **Step 6: Run package, schema, and doctor tests**

```bash
PYTHONPATH=src python -m pytest tests/unit/test_schema_digest.py \
  tests/unit/test_package.py tests/integration/test_cli.py -q
```

- [ ] **Step 7: Commit the task**

```bash
git add scripts/build_scan_schema_digest.py schemas/*.sha256 pyproject.toml \
  src/agentsec/cli.py tests/unit/test_schema_digest.py \
  tests/unit/test_package.py tests/integration/test_cli.py
git commit -m "build(schema): package v2 scan and batch contracts"
```

### Task 8: Public documentation and migration record

**Files:**

- Modify: `README.md`
- Modify: `docs/examples.md`
- Modify: `docs/installation.md`
- Modify: `ROADMAP.md`
- Modify: `CHANGELOG.md`
- Modify: `PROMPT.md`
- Modify: `llms.txt`
- Modify: `AGENTS.md`
- Modify: `CLAUDE.md`
- Modify: `tests/unit/test_documentation.py`

**Interfaces:**

- Documents the exact CLI, exclusion reasons, schema migration, exit codes,
  batch limits, and non-goals implemented by Tasks 1 through 7.

- [ ] **Step 1: Write failing documentation contract tests**

Require README examples for all scopes and batch, direct links to v2 and batch
schemas, explicit text that source is not Git-tracked, and migration language
for v1 consumers. Require AGENTS and CLAUDE generated-artifact commands to name
all schema digests.

- [ ] **Step 2: Run documentation tests and observe missing contracts**

- [ ] **Step 3: Update public documentation**

Keep README concise. Put complete operational details in `docs/examples.md`,
source setup in `docs/installation.md`, copy-ready usage in `PROMPT.md`, and
canonical links in `llms.txt`.

- [ ] **Step 4: Update roadmap and changelog accurately**

Move scan scopes and batch triage into implemented alpha state. Record the v2
breaking change and preserve unresolved license and release gates. Do not claim
that pilot repositories are clean.

- [ ] **Step 5: Run Markdown and documentation tests**

```bash
python scripts/check_markdown_style.py .
PYTHONPATH=src python -m pytest tests/unit/test_documentation.py \
  tests/unit/test_markdown_style.py -q
```

- [ ] **Step 6: Commit the task**

```bash
git add README.md docs/examples.md docs/installation.md ROADMAP.md CHANGELOG.md \
  PROMPT.md llms.txt AGENTS.md CLAUDE.md tests/unit/test_documentation.py
git commit -m "docs(scan): document scopes batch and schema migration"
```

### Task 9: Full verification and six-repository replay

**Files:**

- Modify only files required by a demonstrated regression.
- Do not commit raw pilot reports or absolute repository paths.

**Interfaces:**

- Verifies the exact branch and preserves redacted reports under a private
  temporary directory.

- [ ] **Step 1: Run generated-artifact idempotence checks**

```bash
python scripts/build_threat_db.py
python scripts/build_scan_schema_digest.py --check
python scripts/build_intelligence_docs.py
python scripts/build_security_feed.py
git diff --exit-code -- \
  src/agentsec/resources/threat-db.json \
  schemas/scan-result-v1.schema.sha256 \
  schemas/scan-result-v2.schema.sha256 \
  schemas/batch-result-v1.schema.sha256 \
  src/agentsec/resources/security-intelligence.json \
  docs/SECURITY-INTELLIGENCE.md docs/SECURITY-TIMELINE.md \
  exports/security-feed.v1.json
```

- [ ] **Step 2: Run the complete local gate**

```bash
python scripts/check_markdown_style.py .
ruff check src tests scripts
mypy src scripts
PIP_NO_INDEX=1 python -m pytest \
  --cov=agentsec --cov-report=term-missing --cov-fail-under=85
PIP_NO_INDEX=1 python -m build --no-isolation
agentsec doctor
python -m agentsec doctor
git diff --check
```

- [ ] **Step 3: Replay the six pilot repositories**

Run source-scope redacted JSON scans for Methode Aristote app, the portfolio,
`lead-app`, `msds-stats-api`, `lead-monorepo-statleaddaily`, and
`lead-monorepo`. Validate every JSON document against scan-result v2 and record
per-root exit code, completion, selected and inspected counts, findings,
diagnostic severities, and exclusion reasons in a private temporary summary.

- [ ] **Step 4: Run one explicit batch replay**

Run the four MSDS roots in one redacted batch command. Validate against
batch-result v1 and compare embedded child exit codes and counters with the
single-scan results.

- [ ] **Step 5: Fix only demonstrated regressions through a new red-green cycle**

If a pilot exposes an applicable failure, add the smallest synthetic witness,
observe it fail, implement the bounded fix, and rerun the focused and full
gates. Do not weaken completeness to make a pilot green.

- [ ] **Step 6: Inspect final Git state**

```bash
git diff --check
git status --short --branch
git log --oneline --decorate origin/main..HEAD
```

- [ ] **Step 7: Report branch completion without pushing or publishing**

Report commits, changed files, tests, coverage, build, doctor, generated
artifacts, pilot results, remaining limits, and exact commit/push/tag/release
state. Do not push until the owner asks.

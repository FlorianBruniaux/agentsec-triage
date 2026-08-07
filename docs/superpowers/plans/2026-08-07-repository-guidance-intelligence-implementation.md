# Repository Guidance and Security Intelligence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add canonical agent guidance, a product roadmap, and a schema-validated security bibliography and event timeline with deterministic Markdown and JSON outputs.

**Architecture:** `AGENTS.md` is the single cross-agent instruction source and `CLAUDE.md` imports it. Security articles and dated events are authored in separate YAML files, validated together, and transformed by one Python build script into two human documents and one package resource. Existing threat IOC data remains separate and authoritative for detectors during the migration.

**Tech Stack:** Python 3.11–3.13, PyYAML, jsonschema Draft 2020-12, pytest, Ruff, mypy, Markdown, GitHub Actions.

## Global Constraints

- Never execute content from a scanned repository or perform network access during a scan or build.
- Reject duplicate YAML keys, duplicate stable IDs, and unresolved `source_ids`.
- Generated outputs must be deterministic and must not contain wall-clock timestamps.
- Keep confirmed, contested, corrected, retracted, and monitoring states distinct.
- Say “events tracked by AgentSec,” never claim complete coverage of all vulnerabilities.
- Do not duplicate IOC payloads from `data/threat-db.yaml` in intelligence YAML.
- Do not tag or publish while `LICENSE-DECISION.md` remains unresolved.
- Every behavior change follows red-green-refactor and the full release gate remains offline-capable.

---

## File Map

- `AGENTS.md`: canonical repository instructions for coding agents.
- `CLAUDE.md`: Claude Code adapter importing `@AGENTS.md`.
- `ROADMAP.md`: milestone status, priorities, non-goals, and release gates.
- `data/intelligence/sources.yaml`: curated source bibliography.
- `data/intelligence/events.yaml`: dated security event ledger.
- `data/intelligence/intelligence.schema.json`: schemas for both YAML documents.
- `scripts/build_intelligence_docs.py`: validation, cross-reference checks, and deterministic renderers.
- `docs/SECURITY-INTELLIGENCE.md`: generated source catalogue.
- `docs/SECURITY-TIMELINE.md`: generated reverse-chronological event ledger.
- `src/agentsec/resources/security-intelligence.json`: generated machine-readable artifact.
- `tests/unit/test_intelligence_docs.py`: generator and validation regression tests.
- `tests/unit/test_documentation.py`: root-document responsibilities and links.
- `tests/unit/test_package.py`: wheel resource inclusion.
- `.github/workflows/tests.yml`: generated-artifact drift gate.
- `README.md`, `CHANGELOG.md`, `CONTRIBUTING.md`: user and contributor integration.

---

### Task 1: Canonical Repository Guidance

**Files:**
- Create: `AGENTS.md`
- Create: `CLAUDE.md`
- Create: `ROADMAP.md`
- Modify: `README.md`
- Modify: `CHANGELOG.md`
- Modify: `tests/unit/test_documentation.py`

**Interfaces:**
- Consumes: existing CLI, release-gate, licensing, and threat-source documentation.
- Produces: stable root entry points referenced by contributors and later tasks.

- [ ] **Step 1: Write failing root-document tests**

Add tests that require all five root files, require `CLAUDE.md` to contain
`@AGENTS.md`, reject duplicated release-gate prose in `CLAUDE.md`, and require
README links to `ROADMAP.md`, `docs/SECURITY-INTELLIGENCE.md`, and
`docs/SECURITY-TIMELINE.md`.

```python
@pytest.mark.parametrize(
    "name", ["AGENTS.md", "CLAUDE.md", "README.md", "CHANGELOG.md", "ROADMAP.md"]
)
def test_required_root_documents_exist(project_root: Path, name: str) -> None:
    assert (project_root / name).is_file()


def test_claude_imports_canonical_agent_guidance(project_root: Path) -> None:
    text = (project_root / "CLAUDE.md").read_text(encoding="utf-8")
    assert "@AGENTS.md" in text
    assert "Public release is blocked" not in text
```

- [ ] **Step 2: Run the targeted tests and observe failure**

Run: `.venv/bin/pytest tests/unit/test_documentation.py -q`

Expected: failures for missing `AGENTS.md`, `CLAUDE.md`, and `ROADMAP.md`.

- [ ] **Step 3: Add focused root documents**

`AGENTS.md` must include repository purpose, map, commands, TDD rules, scan safety
invariants, intelligence-data rules, generated-file rules, and the licensing/tag
gate. `CLAUDE.md` contains `@AGENTS.md` plus only Claude-specific navigation.
`ROADMAP.md` separates shipped alpha functionality, pre-release blockers, V0.2
detector work, distribution integrations, and explicit non-goals.

- [ ] **Step 4: Link the documents and record the change**

Add a “Project documentation” section to `README.md`. Add an `[Unreleased] / Added`
entry to `CHANGELOG.md` describing the three new root documents without claiming
publication.

- [ ] **Step 5: Run documentation tests**

Run: `.venv/bin/pytest tests/unit/test_documentation.py -q`

Expected: PASS.

- [ ] **Step 6: Commit Task 1**

```bash
git add AGENTS.md CLAUDE.md ROADMAP.md README.md CHANGELOG.md tests/unit/test_documentation.py
git commit -m "docs(repo): add canonical guidance and roadmap"
```

---

### Task 2: Intelligence Schema and Initial Records

**Files:**
- Create: `data/intelligence/sources.yaml`
- Create: `data/intelligence/events.yaml`
- Create: `data/intelligence/intelligence.schema.json`
- Create: `tests/unit/test_intelligence_docs.py`

**Interfaces:**
- Produces: validated source and event mappings consumed by `load_intelligence()` in Task 3.
- Stable IDs: lowercase ASCII `[a-z0-9][a-z0-9._-]*`.
- Dates: ISO `YYYY-MM-DD`; unknown dates are omitted rather than invented.

- [ ] **Step 1: Write failing schema-fixture tests**

Test that both real YAML documents exist, load as mappings, use schema version
`1`, have unique IDs, and include at least one Shai-Hulud/Keyv source and event.
Add temporary malformed fixtures for a duplicate source ID, an unresolved source
reference, and a contested event.

```python
def test_initial_intelligence_tracks_keyv_campaign(project_root: Path) -> None:
    sources = yaml.safe_load(
        (project_root / "data/intelligence/sources.yaml").read_text(encoding="utf-8")
    )
    events = yaml.safe_load(
        (project_root / "data/intelligence/events.yaml").read_text(encoding="utf-8")
    )
    assert any("keyv" in item["id"] for item in sources["sources"])
    assert any("keyv" in item["id"] for item in events["events"])
```

- [ ] **Step 2: Run the new tests and observe missing-file failure**

Run: `.venv/bin/pytest tests/unit/test_intelligence_docs.py -q`

Expected: failure because `data/intelligence/` does not exist.

- [ ] **Step 3: Add the combined JSON Schema**

Define `$defs.sourceDocument` and `$defs.eventDocument`. Source records require
`id`, `title`, `publisher`, `url`, `source_type`, `topics`, `supports`,
`reviewed_date`, and `status`. Event records require `id`, `event_type`, `title`,
`summary`, `ecosystems`, at least one dated field, `status`, `confidence`,
`source_ids`, `related`, and `detector_coverage`.

Enumerations:

```json
{
  "source_type": ["advisory", "research", "news", "social", "maintainer", "database"],
  "source_status": ["active", "superseded", "retracted"],
  "event_type": ["incident", "disclosure", "vulnerability", "campaign", "correction", "retraction", "remediation", "intelligence_update"],
  "event_status": ["confirmed", "contested", "corrected", "retracted", "monitoring"],
  "confidence": ["confirmed", "high", "review", "contested"],
  "coverage": ["detected", "partial", "not_detected", "not_applicable"]
}
```

- [ ] **Step 4: Add reviewed initial source records**

Seed the bibliography with the campaign sources already cited by the detector:
Aikido, SafeDep, JFrog, Socket, The Hacker News, and the Alex Turnbull LinkedIn
post supplied during project discovery. Each record states only the claim it
supports and uses `reviewed_date: "2026-08-07"`.

- [ ] **Step 5: Add initial event records**

Add one confirmed August 2026 Keyv/cacheable campaign event and one contested
scope intelligence update for `@keyv/*@6.0.0`. Both reference existing source
IDs. The confirmed event uses `detector_coverage.status: partial` because Git
history and host evidence are not scanned. The contested record stays
`status: contested` and `confidence: contested`.

- [ ] **Step 6: Run the data tests**

Run: `.venv/bin/pytest tests/unit/test_intelligence_docs.py -q`

Expected: the existence/shape tests pass; generator tests remain skipped until
Task 3 introduces the module.

- [ ] **Step 7: Commit Task 2**

```bash
git add data/intelligence tests/unit/test_intelligence_docs.py
git commit -m "feat(intel): add structured sources and event ledger"
```

---

### Task 3: Deterministic Intelligence Generator

**Files:**
- Create: `scripts/build_intelligence_docs.py`
- Modify: `tests/unit/test_intelligence_docs.py`
- Generate: `docs/SECURITY-INTELLIGENCE.md`
- Generate: `docs/SECURITY-TIMELINE.md`
- Generate: `src/agentsec/resources/security-intelligence.json`

**Interfaces:**
- Produces: `load_intelligence(sources_path: Path, events_path: Path, schema_path: Path) -> IntelligenceCorpus`.
- Produces: `render_sources_markdown(corpus: IntelligenceCorpus) -> str`.
- Produces: `render_timeline_markdown(corpus: IntelligenceCorpus) -> str`.
- Produces: `render_json(corpus: IntelligenceCorpus) -> str`.
- CLI: `python scripts/build_intelligence_docs.py` writes all three outputs.

- [ ] **Step 1: Write failing loader and renderer tests**

Require duplicate YAML key rejection, schema validation, duplicate ID rejection,
unresolved `source_ids` rejection, reverse chronological event ordering,
visible contested labels, deterministic Markdown, deterministic JSON, and no
wall-clock `generated_at` field.

```python
def test_timeline_is_reverse_chronological(corpus: IntelligenceCorpus) -> None:
    text = render_timeline_markdown(corpus)
    newest = text.index("2026-08-07")
    older = text.index("2026-08-06")
    assert newest < older


def test_machine_output_has_no_wall_clock_timestamp(corpus: IntelligenceCorpus) -> None:
    payload = json.loads(render_json(corpus))
    assert "generated_at" not in payload
```

- [ ] **Step 2: Run targeted tests and observe import failure**

Run: `.venv/bin/pytest tests/unit/test_intelligence_docs.py -q`

Expected: import failure for `scripts.build_intelligence_docs`.

- [ ] **Step 3: Implement strict loading and cross-reference validation**

Use a `yaml.SafeLoader` subclass that rejects duplicate mapping keys. Validate
the source and event documents against their `$defs` using
`Draft202012Validator`. Represent the loaded corpus with frozen dataclasses or
immutable tuples. Raise `IntelligenceBuildError` with stable, path-free messages
for duplicate IDs and unresolved references.

- [ ] **Step 4: Implement deterministic renderers**

Sort sources by `(publisher.casefold(), title.casefold(), id)`. Sort events by
the best available `updated_date`, `disclosed_date`, or `occurred_date`, newest
first, then by ID. Escape Markdown table pipes and normalize trailing newlines.
The JSON artifact contains `schema_version`, `updated`, sorted `sources`, and
sorted `events` with `sort_keys=True` and two-space indentation.

- [ ] **Step 5: Generate and inspect outputs**

Run: `.venv/bin/python scripts/build_intelligence_docs.py`

Expected files:

```text
docs/SECURITY-INTELLIGENCE.md
docs/SECURITY-TIMELINE.md
src/agentsec/resources/security-intelligence.json
```

- [ ] **Step 6: Run generator tests and deterministic diff check**

Run: `.venv/bin/pytest tests/unit/test_intelligence_docs.py -q`

Run the generator a second time, then:

`git diff --exit-code -- docs/SECURITY-INTELLIGENCE.md docs/SECURITY-TIMELINE.md src/agentsec/resources/security-intelligence.json`

Expected: tests pass and the second generation creates no diff.

- [ ] **Step 7: Commit Task 3**

```bash
git add scripts/build_intelligence_docs.py tests/unit/test_intelligence_docs.py docs/SECURITY-INTELLIGENCE.md docs/SECURITY-TIMELINE.md src/agentsec/resources/security-intelligence.json
git commit -m "feat(intel): generate bibliography and security timeline"
```

---

### Task 4: Build, Package, and Contributor Integration

**Files:**
- Modify: `.github/workflows/tests.yml`
- Modify: `CONTRIBUTING.md`
- Modify: `README.md`
- Modify: `CHANGELOG.md`
- Modify: `tests/unit/test_package.py`

**Interfaces:**
- Consumes: Task 3 generator and generated resource.
- Produces: CI drift gate and wheel containing `security-intelligence.json`.

- [ ] **Step 1: Write failing packaging and documentation assertions**

Require the wheel to contain
`agentsec/resources/security-intelligence.json`. Require contributor docs to run
the intelligence generator and require README to explain that the timeline is
tracked coverage, not a complete vulnerability database.

- [ ] **Step 2: Run targeted tests and observe failure**

Run: `.venv/bin/pytest tests/unit/test_package.py tests/unit/test_documentation.py -q`

Expected: failure until package and docs integration is complete.

- [ ] **Step 3: Add CI generated-artifact gate**

After the threat DB build, run:

```yaml
- name: Rebuild security intelligence documents
  run: python scripts/build_intelligence_docs.py

- name: Require deterministic generated intelligence
  run: git diff --exit-code -- docs/SECURITY-INTELLIGENCE.md docs/SECURITY-TIMELINE.md src/agentsec/resources/security-intelligence.json
```

- [ ] **Step 4: Update contributor and user documentation**

Add the intelligence generator to the local release gate. Document stable IDs,
source review requirements, corrections/retractions, and the prohibition on
silently changing contested status. Record the generated intelligence capability
under `[Unreleased]` without claiming a release.

- [ ] **Step 5: Run targeted tests and package build**

Run:

```bash
.venv/bin/pytest tests/unit/test_package.py tests/unit/test_documentation.py -q
PIP_NO_INDEX=1 .venv/bin/python -m build --no-isolation
```

Expected: tests pass and both wheel and sdist build offline.

- [ ] **Step 6: Commit Task 4**

```bash
git add .github/workflows/tests.yml CONTRIBUTING.md README.md CHANGELOG.md tests/unit/test_package.py
git commit -m "build(intel): enforce generated intelligence artifacts"
```

---

### Task 5: Full Verification and Local Merge

**Files:**
- Verify: entire repository
- Merge target: local `main`

**Interfaces:**
- Consumes: all prior tasks on `codex/v0.1-alpha`.
- Produces: clean, verified local `main` containing the complete alpha.

- [ ] **Step 1: Rebuild generated data and require clean diffs**

```bash
.venv/bin/python scripts/build_threat_db.py
.venv/bin/python scripts/build_intelligence_docs.py
git diff --exit-code -- src/agentsec/resources/threat-db.json docs/SECURITY-INTELLIGENCE.md docs/SECURITY-TIMELINE.md src/agentsec/resources/security-intelligence.json
```

- [ ] **Step 2: Run static and test gates**

```bash
.venv/bin/ruff check src tests scripts
.venv/bin/mypy src scripts
PIP_NO_INDEX=1 .venv/bin/pytest --cov=agentsec --cov-report=term-missing --cov-fail-under=85
PIP_NO_INDEX=1 .venv/bin/python -m build --no-isolation
.venv/bin/agentsec doctor
```

Expected: all tests pass, coverage is at least 85%, package builds, and doctor
reports valid resources.

- [ ] **Step 3: Run CLI contract checks**

- Positive fixture exits `1` with confirmed findings.
- Negative fixture exits `1`, is complete, and contains no critical finding.
- Missing root exits `2` and is incomplete.
- Self-scan exits `2` with Git-history and unsupported Bun diagnostics.

- [ ] **Step 4: Confirm clean branch and merge locally**

From the primary checkout, confirm `main` is clean, then merge without rewriting
history:

```bash
git switch main
git merge --ff-only codex/v0.1-alpha
```

If fast-forward is impossible, stop and inspect the divergence instead of
creating an unreviewed merge commit.

- [ ] **Step 5: Verify merged main**

Run `git status --short --branch`, `git log -1 --oneline`, and a focused smoke
test from `/Users/florianbruniaux/Sites/perso/agentsec-triage`.

- [ ] **Step 6: Do not tag while licensing is unresolved**

The intended tag is `v0.1.0-alpha`, matching package version `0.1.0a0`. Do not
create it until `LICENSE-DECISION.md` is resolved and its full release checklist
passes.


# Markdown Style Cleanup Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Review every tracked Markdown file, remove the markers defined by the owner's `ANTI_AI.md`, improve the agent instructions, and prevent the automatically detectable markers from returning.

**Architecture:** Keep `AGENTS.md` as the canonical agent contract and `CLAUDE.md` as its Claude Code adapter. A dependency-free checker scans repository Markdown outside ignored build and environment directories. Generated intelligence pages receive punctuation fixes through `scripts/build_intelligence_docs.py`, followed by deterministic regeneration.

**Tech Stack:** Python 3.11+, standard library, pytest, Ruff, mypy, Markdown, GitHub Actions.

## Global Constraints

- Review all 19 Markdown files tracked when the scope was approved.
- Preserve dates, hashes, URLs, source titles, commands, exit codes, threat claims, license decisions, and historical design decisions.
- Edit generated Markdown through its YAML source or builder, never by hand alone.
- Keep `.gitignore` outside every commit because its current modification belongs to the user.
- Keep public tagging and publication blocked by `LICENSE-DECISION.md`.
- Run the complete release gate before claiming completion.

---

### Task 1: Add a deterministic Markdown marker checker

**Files:**
- Create: `scripts/check_markdown_style.py`
- Create: `tests/unit/test_markdown_style.py`
- Modify: `.github/workflows/tests.yml`

**Interfaces:**
- Produces: `Violation(path: Path, line: int, marker: str, excerpt: str)`.
- Produces: `iter_markdown_files(root: Path) -> Iterator[Path]`.
- Produces: `find_violations(path: Path, text: str) -> list[Violation]`.
- Produces: CLI `python scripts/check_markdown_style.py [ROOT]`, with exit `0` when no violation exists and exit `1` when at least one violation exists.

- [ ] **Step 1: Write focused checker tests**

Add tests that prove the checker detects an em dash and an automatic banned phrase, ignores fenced and inline code, skips `.venv`, `dist`, cache, and worktree directories, reports line numbers, and returns deterministic path order.

```python
def test_find_violations_reports_prose_markers_but_ignores_code(tmp_path: Path) -> None:
    path = tmp_path / "doc.md"
    punctuation = chr(0x2014)
    text = f"Human prose {punctuation} marker.\n\n```text\ncode {punctuation} literal\n```\n`inline {punctuation} literal`\n"
    violations = find_violations(path, text)
    assert [(item.line, item.marker) for item in violations] == [(1, "em-dash")]


def test_iter_markdown_files_skips_generated_environment_directories(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("ok\n", encoding="utf-8")
    hidden = tmp_path / ".venv"
    hidden.mkdir()
    (hidden / "README.md").write_text("ignored\n", encoding="utf-8")
    assert list(iter_markdown_files(tmp_path)) == [tmp_path / "README.md"]
```

- [ ] **Step 2: Run the checker tests and observe the import failure**

Run:

```bash
.venv/bin/pytest tests/unit/test_markdown_style.py -v
```

Expected: FAIL because `scripts/check_markdown_style.py` does not exist.

- [ ] **Step 3: Implement the checker with the standard library**

Use compiled case-insensitive expressions for the automatic markers in
`ANTI_AI.md`. Strip fenced and inline code before matching. Do not rewrite
files. Print one stable `path:line: marker: excerpt` record per match.

- [ ] **Step 4: Run the focused tests**

Run:

```bash
.venv/bin/pytest tests/unit/test_markdown_style.py -v
.venv/bin/ruff check scripts/check_markdown_style.py tests/unit/test_markdown_style.py
.venv/bin/mypy scripts/check_markdown_style.py
```

Expected: PASS.

- [ ] **Step 5: Add the checker to CI and capture the repository baseline**

Add this step before Ruff:

```yaml
      - name: Check Markdown style markers
        run: python scripts/check_markdown_style.py .
```

Run:

```bash
.venv/bin/python scripts/check_markdown_style.py .
```

Expected: exit `1` with every current automatic marker reported.

- [ ] **Step 6: Commit the checker**

```bash
git add scripts/check_markdown_style.py tests/unit/test_markdown_style.py .github/workflows/tests.yml
git commit -m "test(docs): detect markdown style markers"
```

### Task 2: Fix generated intelligence Markdown at the renderer

**Files:**
- Modify: `tests/unit/test_intelligence_docs.py`
- Modify: `scripts/build_intelligence_docs.py`
- Regenerate: `docs/SECURITY-INTELLIGENCE.md`
- Regenerate: `docs/SECURITY-TIMELINE.md`
- Verify unchanged semantics: `src/agentsec/resources/security-intelligence.json`

**Interfaces:**
- Consumes: `render_sources_markdown(corpus)` and `render_timeline_markdown(corpus)`.
- Produces: generated Markdown without style-marker punctuation while keeping source titles and intelligence fields unchanged.

- [ ] **Step 1: Add failing renderer assertions**

Extend `test_renderers_are_deterministic_and_expose_contested_status`:

```python
sources = render_sources_markdown(corpus)
timeline = render_timeline_markdown(corpus)
assert chr(0x2014) not in sources
assert chr(0x2014) not in timeline
assert "not recorded" in timeline
```

- [ ] **Step 2: Run the targeted renderer test and observe failure**

Run:

```bash
.venv/bin/pytest tests/unit/test_intelligence_docs.py::test_renderers_are_deterministic_and_expose_contested_status -v
```

Expected: FAIL because the current renderer uses em dashes and an em dash placeholder.

- [ ] **Step 3: Replace renderer punctuation without changing data**

Use `not recorded` for absent dates. Use colons for headings, coverage labels,
publisher-title separators, and related-record labels. Keep every URL, source
title, date, status, campaign ID, and technique ID unchanged.

- [ ] **Step 4: Regenerate and verify deterministic output**

Run twice:

```bash
.venv/bin/python scripts/build_intelligence_docs.py
```

Then run:

```bash
git diff --exit-code -- src/agentsec/resources/security-intelligence.json
.venv/bin/pytest tests/unit/test_intelligence_docs.py -v
```

Expected: the JSON has no semantic change and the tests pass.

- [ ] **Step 5: Commit the renderer and generated pages**

```bash
git add scripts/build_intelligence_docs.py tests/unit/test_intelligence_docs.py docs/SECURITY-INTELLIGENCE.md docs/SECURITY-TIMELINE.md
git commit -m "fix(docs): remove generated prose markers"
```

### Task 3: Rewrite canonical agent and contributor guidance

**Files:**
- Modify: `AGENTS.md`
- Modify: `CLAUDE.md`
- Modify: `CONTRIBUTING.md`
- Modify: `README.md`
- Modify: `ROADMAP.md`
- Modify: `SECURITY.md`
- Modify: `LICENSE-DECISION.md`
- Modify: `data/IMPORT_PROVENANCE.md`
- Modify: `docs/LICENSE-INVENTORY.md`

**Interfaces:**
- Produces: `AGENTS.md` as the single repository contract.
- Produces: `CLAUDE.md` as a thin adapter that imports `@AGENTS.md`.
- Consumes: the existing scanner behavior, release commands, and license gate.

- [ ] **Step 1: Rewrite `AGENTS.md` and `CLAUDE.md`**

Add the schema-digest check, authoring projection semantics, both CLI entry
points, dirty-worktree protection, generated-file ownership, and final-agent
verification. Remove duplicated rules from `CLAUDE.md`; keep Claude Code
navigation, Plan Mode, and delegation boundaries there.

- [ ] **Step 2: Review the seven remaining canonical records**

Read each file in full. Replace detected markers and empty sentences while
preserving technical meaning. Do not replace quoted source titles, commands,
hashes, dates, URLs, or license language with approximations.

- [ ] **Step 3: Run the checker against this file group**

Run:

```bash
.venv/bin/python scripts/check_markdown_style.py .
```

Expected: remaining violations point only to historical plans or specs.

- [ ] **Step 4: Inspect the semantic diff**

Run:

```bash
git diff --check
git diff -- AGENTS.md CLAUDE.md CONTRIBUTING.md README.md ROADMAP.md SECURITY.md LICENSE-DECISION.md data/IMPORT_PROVENANCE.md docs/LICENSE-INVENTORY.md
```

Confirm that every changed claim still matches the CLI, CI workflow, threat
database, and license decision.

- [ ] **Step 5: Commit the canonical documentation**

```bash
git add AGENTS.md CLAUDE.md CONTRIBUTING.md README.md ROADMAP.md SECURITY.md LICENSE-DECISION.md data/IMPORT_PROVENANCE.md docs/LICENSE-INVENTORY.md
git commit -m "docs(repo): tighten agent and contributor guidance"
```

### Task 4: Clean historical plans and specs

**Files:**
- Modify: `docs/superpowers/plans/2026-08-06-v0.1-alpha-implementation.md`
- Modify: `docs/superpowers/plans/2026-08-07-repository-guidance-intelligence-implementation.md`
- Modify: `docs/superpowers/plans/2026-08-11-alpha-hardening-implementation.md`
- Modify: `docs/superpowers/plans/2026-08-14-markdown-style-cleanup-implementation.md`
- Modify: `docs/superpowers/specs/2026-08-06-agentsec-triage-design.md`
- Modify: `docs/superpowers/specs/2026-08-07-repository-guidance-intelligence-design.md`
- Modify: `docs/superpowers/specs/2026-08-11-alpha-hardening-design.md`
- Modify: `docs/superpowers/specs/2026-08-14-agent-instructions-design.md`

**Interfaces:**
- Produces: historical records with unchanged commands, expected results, architecture, and decisions.

- [ ] **Step 1: Review every historical file in full**

Use the automatic checker as a locator, then inspect paragraph cadence,
repeated sentence openings, vague verbs, negative parallels, decorative
groupings, and claims without a concrete file, command, date, or count.

- [ ] **Step 2: Correct prose without rewriting history**

Change punctuation and sentence structure only where the marker exists. Keep
the original implementation status, code blocks, filenames, test names, hashes,
versions, and expected exit codes.

- [ ] **Step 3: Run the repository checker**

Run:

```bash
.venv/bin/python scripts/check_markdown_style.py .
```

Expected: exit `0` with no reported automatic marker.

- [ ] **Step 4: Perform the manual `ANTI_AI.md` review**

Review all 19 files against the non-automated rules. Record no new document;
the Git diff is the evidence. Check source titles against their YAML records and
confirm that generated Markdown still matches the renderer.

- [ ] **Step 5: Commit the historical cleanup**

```bash
git add docs/superpowers/plans docs/superpowers/specs
git commit -m "docs(history): remove markdown style markers"
```

### Task 5: Update the changelog and run the complete gate

**Files:**
- Modify: `CHANGELOG.md`
- Verify: every tracked Markdown file and generated artifact.

**Interfaces:**
- Consumes: Tasks 1 through 4.
- Produces: one release-gate result on the exact final tree.

- [ ] **Step 1: Record the documentation cleanup under `[Unreleased]`**

State that all tracked Markdown was reviewed, automatic markers now have a CI
gate, generated punctuation comes from the intelligence builder, and agent
instructions gained the missing post-hardening commands. Do not claim that an
automated check can judge every prose rule.

- [ ] **Step 2: Run marker, generator, lint, type, test, build, and doctor gates**

```bash
.venv/bin/python scripts/check_markdown_style.py .
.venv/bin/python scripts/build_threat_db.py
.venv/bin/python scripts/build_scan_schema_digest.py --check
.venv/bin/python scripts/build_intelligence_docs.py
git diff --exit-code -- src/agentsec/resources/threat-db.json schemas/scan-result-v1.schema.sha256 src/agentsec/resources/security-intelligence.json docs/SECURITY-INTELLIGENCE.md docs/SECURITY-TIMELINE.md
.venv/bin/ruff check src tests scripts
.venv/bin/mypy src scripts
PIP_NO_INDEX=1 .venv/bin/pytest --cov=agentsec --cov-report=term-missing --cov-fail-under=85
PIP_NO_INDEX=1 .venv/bin/python -m build --no-isolation
.venv/bin/agentsec doctor
.venv/bin/python -m agentsec doctor
```

Expected: every command exits `0`, the test count has zero failures, and
coverage remains at or above 85 percent.

- [ ] **Step 3: Verify Git scope**

```bash
git diff --check
git status --short --branch
```

Expected: `.gitignore` remains modified and unstaged. No other unrelated file
appears.

- [ ] **Step 4: Commit the changelog**

```bash
git add CHANGELOG.md
git commit -m "docs(changelog): record markdown cleanup"
```

- [ ] **Step 5: Re-run the final checker and status commands**

```bash
.venv/bin/python scripts/check_markdown_style.py .
git status --short --branch
```

Expected: the checker exits `0`; Git reports only the preserved `.gitignore`
change.

# AgentSec Triage: Agent Instructions

## Product contract

AgentSec Triage converts sourced security research into deterministic repository
detectors backed by regression tests. A scan reads one local repository and
runs offline by default. It reports evidence, diagnostics, and coverage limits.
No result certifies that a repository, workstation, dependency set, or account
is clean.

Current release metadata lives in `CHANGELOG.md`. Read `README.md` and
`docs/examples.md` before changing declared coverage or limitations.

## Instruction order

Use these files in order:

1. `AGENTS.md` defines the repository-wide contract.
2. `README.md` defines scanner behavior and public claims.
3. `CONTRIBUTING.md` defines TDD, sourcing, generation, and review evidence.
4. `SECURITY.md` defines vulnerability, false-positive, false-negative, and IOC
   correction intake.
5. `ROADMAP.md` separates shipped work from future work.

`CLAUDE.md` may add Claude Code navigation and orchestration rules. It cannot
relax this file. If two instructions conflict, stop and report the exact files
and clauses before editing.

## Repository map

| Path | Responsibility |
| --- | --- |
| `src/agentsec/` | CLI, scan engine, analyzers, detectors, output, and packaged resources |
| `data/threat-db.yaml` | Authoring data for detector intelligence |
| `data/intelligence/` | Source bibliography and dated event ledger |
| `exports/security-feed.v1.json` | Public metadata feed mirrored to the guide and landing |
| `schemas/` | Public scan-result contracts and committed digest |
| `scripts/` | Deterministic builders, benchmark wrapper, and Markdown checker |
| `tests/` | Unit, integration, fixture, package, safety, and golden tests |
| `docs/installation.md` | Source installation and verification |
| `docs/examples.md` | Scan commands, verdicts, output, and coverage limits |
| `docs/SECURITY-INTELLIGENCE.md` | Generated source catalogue |
| `docs/SECURITY-TIMELINE.md` | Generated event chronology |
| `PROMPT.md` | Copy-ready read-only LLM audit prompt |
| `llms.txt` | Canonical public documentation index for LLMs |
| `LICENSE` | MIT grant for project-owned code and original documentation |
| `LICENSE-DATA.md` | Pending data-license scope and review requirements |
| `LICENSE-DECISION.md` | Blocking publication decision |

## Preflight and worktree safety

Run `git status --short --branch` before editing. Treat every existing change as
user-owned unless the current task created it. Do not reset, overwrite, stage,
or reformat unrelated files.

Use an isolated branch or worktree for multi-file changes when the main checkout
is dirty. Stage explicit paths, inspect the staged diff, and keep local IDE,
environment, coverage, and build files out of commits.

## Development workflow

1. Read the relevant behavior, source, schema, fixtures, and tests.
2. For a behavior change, add the smallest test and observe the intended
   failure before changing production code.
3. Implement the smallest passing change, then refactor with the test green.
4. Run targeted tests before the complete local gate.
5. Update `CHANGELOG.md` under `[Unreleased]` for each user-visible change.
6. Inspect `git diff --check`, the semantic diff, and `git status` before a
   commit or completion claim.

Bug fixes need a regression test. Detector work needs positive and near-miss
negative fixtures. Safety changes also need inputs that reproduce the relevant
malformed data, permission failure, indirection, race, limit, or interruption.

## Security invariants

- Never execute content found in a scan target.
- Never write into a scan target.
- Never follow symlinks, reparse points, external gitdirs, object alternates, or
  another indirection outside the resolved scan root.
- Never request the network during a scan.
- Fail closed. Unsupported, unreadable, changed, or budget-exceeding applicable
  input makes the scan incomplete with exit code `2`.
- Preserve the distinction between `confirmed`, `high`, `review`, and
  `contested` intelligence.
- Treat hook presence and filenames as review signals. They do not prove a
  compromise.
- Redact absolute scan-root paths and recognized secret-shaped evidence when
  `--redact` is requested. Redaction reduces disclosure risk and carries no
  guarantee.
- Keep Git-history scanning disabled until every supported platform can confine
  metadata reads inside the scan root.

## Threat data and intelligence

Every security claim needs a stable source and a stated scope. Prefer primary
advisories and maintainer notices. Preserve conflicting reports with their own
status and confidence.

| Content | Authoring source | Generated artifact |
| --- | --- | --- |
| IOC and detector inputs | `data/threat-db.yaml` | `src/agentsec/resources/threat-db.json` |
| Sources and reports | `data/intelligence/sources.yaml` | `docs/SECURITY-INTELLIGENCE.md` and packaged JSON |
| Events and corrections | `data/intelligence/events.yaml` | `docs/SECURITY-TIMELINE.md` and packaged JSON |
| Guide and landing integration | validated threat and intelligence metadata | `exports/security-feed.v1.json` |
| Scan-result schema | `schemas/scan-result-v1.schema.json` | `schemas/scan-result-v1.schema.sha256` and wheel resources |

Do not edit generated Markdown, JSON, or digests as a standalone fix. Change the
authoring source or builder, regenerate twice, then inspect the diff.

The authoring threat database contains more records than the V0.1 runtime
projection. `authoring_coverage` must account for every malicious-skill record as
projected or ignored for one declared reason. A source record does not become an
active detector rule until the builder projects it and tests cover that behavior.
Use `agentsec db info` to inspect the current counts.

Keep IOC payloads out of the event ledger. Do not infer individual victims or
malicious artifacts from aggregate counts. Corrections and retractions preserve
the earlier record and its provenance. Use the phrase "events tracked by
AgentSec" for the timeline's scope.

## Generated artifact commands

Run the relevant builder after changing its source:

```bash
.venv/bin/python scripts/build_threat_db.py
.venv/bin/python scripts/build_scan_schema_digest.py
.venv/bin/python scripts/build_scan_schema_digest.py --check
.venv/bin/python scripts/build_intelligence_docs.py
.venv/bin/python scripts/build_security_feed.py
```

Then require a clean second generation:

```bash
git diff --exit-code -- \
  src/agentsec/resources/threat-db.json \
  schemas/scan-result-v1.schema.sha256 \
  src/agentsec/resources/security-intelligence.json \
  docs/SECURITY-INTELLIGENCE.md \
  docs/SECURITY-TIMELINE.md \
  exports/security-feed.v1.json
```

## Documentation style

Write concrete claims tied to a file, command, date, count, or source. Remove
canned openings, mechanical transitions, generic buzzwords, decorative closing
lines, and em dashes. Keep lists for paths, steps, commands, options, and other
discrete reference material.

Run the repository checker after changing Markdown:

```bash
.venv/bin/python scripts/check_markdown_style.py .
```

The checker covers deterministic patterns. Review sentence cadence, vague
claims, repeated openings, heavy nominalizations, and copied marketing prose by
reading the diff.

## Complete local gate

Install `.[dev]` before setting `PIP_NO_INDEX=1`. Then run:

```bash
.venv/bin/python scripts/check_markdown_style.py .
.venv/bin/python scripts/build_threat_db.py
.venv/bin/python scripts/build_scan_schema_digest.py --check
.venv/bin/python scripts/build_intelligence_docs.py
.venv/bin/python scripts/build_security_feed.py
git diff --exit-code -- \
  src/agentsec/resources/threat-db.json \
  schemas/scan-result-v1.schema.sha256 \
  src/agentsec/resources/security-intelligence.json \
  docs/SECURITY-INTELLIGENCE.md \
  docs/SECURITY-TIMELINE.md \
  exports/security-feed.v1.json
.venv/bin/ruff check src tests scripts
.venv/bin/mypy src scripts
PIP_NO_INDEX=1 .venv/bin/pytest \
  --cov=agentsec --cov-report=term-missing --cov-fail-under=85
PIP_NO_INDEX=1 .venv/bin/python -m build --no-isolation
.venv/bin/agentsec doctor
.venv/bin/python -m agentsec doctor
```

CI measures the coverage threshold on Linux. macOS and Windows run the full
applicable test suite without comparing mutually exclusive operating-system
branches against the Linux coverage percentage.

Verify four repository-shaped scans. `agentsec scan . --format json --redact`
must exit `2` and report an incomplete result. The lockfile fixture must exit `2`
and report its unsupported binary Bun lockfile. The positive fixture must exit
`1`, complete its applicable checks, and contain a critical finding. The negative
fixture must exit `1`, report `complete: true`, emit no diagnostic, and contain
no critical finding. Do not hide these inputs through exclusions.

## Release gate

`LICENSE-DECISION.md` blocks package and repository publication, tags, GitHub
releases, source archives, and PyPI publication. The narrow generated-feed
exception is recorded in `LICENSE-DATA.md`. Release-specific package and tag values
live in `CHANGELOG.md`. Create no tag until the recorded data licensing review
is resolved.

Do not weaken tests, package metadata, attribution, or the license gate to make
a release appear ready. No agent may select a license, grant redistribution
rights, or publish this repository without an explicit owner decision recorded
in the repository.

## Completion report

Report the files changed, targeted and full verification results, generated
artifact status, changelog entry, commit hash, and any remaining limitation.
State the commit, merge, push, tag, and publication status. Never claim an
action that was not observed in the current session.

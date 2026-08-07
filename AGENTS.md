# AgentSec Triage — Agent Instructions

## Purpose

AgentSec Triage turns sourced security research into deterministic,
regression-tested repository detectors. The scanner is read-only and offline by
default. It reports evidence and coverage boundaries; it never certifies that a
repository or workstation is clean.

## Repository map

- `src/agentsec/`: CLI, scan engine, analyzers, detectors, output, and bundled
  runtime resources.
- `data/threat-db.yaml`: imported detector intelligence during the V0.1 migration.
- `data/intelligence/`: curated source bibliography and dated event ledger.
- `schemas/`: public scan-result contracts.
- `scripts/`: deterministic data and documentation builders.
- `tests/`: unit, integration, fixture, package, and golden regression tests.
- `docs/SECURITY-INTELLIGENCE.md`: generated source catalogue.
- `docs/SECURITY-TIMELINE.md`: generated event chronology.
- `ROADMAP.md`: prioritized product direction and release gates.

## Required workflow

1. Read `README.md`, `SECURITY.md`, `CONTRIBUTING.md`, and the relevant source
   modules before changing behavior.
2. Follow red-green-refactor for every behavior change. Observe the targeted
   test fail for the intended reason before writing production code.
3. Keep changes narrowly scoped. Do not rewrite unrelated user changes.
4. Update `CHANGELOG.md` under `[Unreleased]` for every user-visible change.
5. Run targeted tests, then the complete local release gate before claiming
   completion.

Bug fixes require a regression test. Detector changes require positive and
near-miss negative fixtures. Safety changes also require hostile or malformed
input coverage appropriate to the failure mode.

## Security invariants

- Never execute content found in a scan target.
- Never write into a scan target.
- Never follow symlinks, reparse points, external gitdirs, object alternates, or
  other indirections outside the resolved scan root.
- Never perform network requests during a scan.
- Fail closed: unsupported, unreadable, changed, or budget-exceeding inputs make
  an applicable scan incomplete with exit code `2`.
- Preserve exact distinctions between `confirmed`, `high`, `review`, and
  `contested` intelligence.
- Treat hook presence and filenames as review signals, not proof of compromise.
- Keep absolute scan-root paths and recognized secret-shaped evidence redacted
  when `--redact` is requested. Never describe redaction as a guarantee.
- Do not enable Git-history scanning until strict metadata confinement is proven
  on every supported platform.

## Threat and intelligence data

Every security claim needs a stable source and an explicit scope. Prefer primary
advisories and maintainer notices. Record conflicting reports instead of
silently picking the most alarming one.

- IOC and detector inputs belong in `data/threat-db.yaml`.
- Articles, advisories, and reports belong in
  `data/intelligence/sources.yaml`.
- Dated disclosures, incidents, corrections, and intelligence changes belong in
  `data/intelligence/events.yaml`.
- Do not duplicate IOC payloads in the event ledger.
- Do not infer individual victims or malicious artifacts from aggregate counts.
- Corrections and retractions preserve history and provenance.
- Say “events tracked by AgentSec,” never “all vulnerabilities” or “complete
  security history.”

After changing threat or intelligence data, rebuild the generated artifacts and
require a clean second generation:

```bash
.venv/bin/python scripts/build_threat_db.py
.venv/bin/python scripts/build_intelligence_docs.py
git diff --exit-code -- \
  src/agentsec/resources/threat-db.json \
  src/agentsec/resources/security-intelligence.json \
  docs/SECURITY-INTELLIGENCE.md \
  docs/SECURITY-TIMELINE.md
```

Generated Markdown and JSON are committed artifacts. Edit their YAML inputs or
builder, never the generated files directly.

## Verification commands

```bash
.venv/bin/ruff check src tests scripts
.venv/bin/mypy src scripts
PIP_NO_INDEX=1 .venv/bin/pytest \
  --cov=agentsec --cov-report=term-missing --cov-fail-under=85
PIP_NO_INDEX=1 .venv/bin/python -m build --no-isolation
.venv/bin/agentsec doctor
```

The expected self-scan exit code is `2`: the repository contains `.git`, positive
fixtures, and an unsupported binary Bun lockfile fixture. Never turn that result
into a clean claim or hide those files with exclusions.

## Release gate

`LICENSE-DECISION.md` currently blocks public redistribution, tags, GitHub
releases, source archives, and PyPI publication. The intended first tag is
`v0.1.0-alpha`, matching Python version `0.1.0a0`, but it must not be created
until the recorded code and data licensing review is resolved.

Do not weaken tests, packaging metadata, attribution, or the license gate to make
a release appear ready.


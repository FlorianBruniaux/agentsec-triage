# Contributing

AgentSec turns threat research into executable rules. That makes weak sourcing
and tests that never demonstrated a failure release risks, not paperwork issues.

Public redistribution remains blocked by [LICENSE-DECISION.md](LICENSE-DECISION.md).
Before that decision is resolved, discuss external contributions with the owner
and do not assume that submitting code or data establishes a compatible license.

## Development setup

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e ".[dev]"
.venv/bin/agentsec doctor
```

Use `.venv\Scripts\python` and `.venv\Scripts\agentsec` on Windows.

## Red-green-refactor is required

Every behavior change follows this exact sequence:

1. **Red:** add the smallest test for the required behavior. Run it, watch the test fail,
   and confirm the expected missing behavior, not a typo or broken fixture.
2. **Green:** implement only enough behavior to pass. Run the targeted test, then
   the full suite.
3. **Refactor:** remove duplication or improve names while keeping the tests green.

Bug fixes need a regression test that fails before the fix. Detector changes need
positive and near-miss negative fixtures. Safety changes also need relevant
malformed, permission, symlink or reparse-point, limit, and interruption cases.
Tests must not execute target-repository content or require network access.

## Threat-source requirements

Every new or changed IOC, campaign fact, heuristic, or remediation claim must
record all of the following:

- a stable source URL, preferring a primary advisory, maintainer notice, incident
  report, or vendor publication over an unsourced aggregation;
- source title, publisher, publication date when available, and access date;
- the exact claim supported by the source, separated from our interpretation;
- the affected ecosystem, artifact, version or time scope;
- the proposed confidence (`confirmed`, `high`, `review`, or `contested`) and
  status, including conflicting sources;
- source and contribution license or redistribution constraints when known;
- a minimal synthetic fixture that contains no credential, victim data, or
  redistributed malware.

Do not convert an aggregate count into individual records. Do not treat a URL,
package name, author name, or hook presence as malicious outside the scope the
source supports. Exact IOCs and heuristic hunt signals need different rules,
severities, and confidence. Retractions and corrections must preserve provenance.

Changes to `data/threat-db.yaml` must validate against
`data/threat-db.schema.json`. Rebuild the runtime artifact and verify a clean diff:

```bash
.venv/bin/python scripts/build_threat_db.py
git diff --exit-code -- src/agentsec/resources/threat-db.json
```

The generated runtime artifact contains `authoring_coverage`. Every source
malicious-skill record must be projected or counted under one explicit ignored
reason. Adding data for an unsupported ecosystem does not make that data active
in a detector; its projection count remains visible in the generated artifact
and `agentsec db info`.

After changing `schemas/scan-result-v1.schema.json`, regenerate and check the
committed digest:

```bash
.venv/bin/python scripts/build_scan_schema_digest.py
.venv/bin/python scripts/build_scan_schema_digest.py --check
```

## Security intelligence publishing

Detector inputs and editorial intelligence have different responsibilities:

- Add exact IOC and detector data to `data/threat-db.yaml`.
- Add articles, advisories, maintainer notices, research, news, databases, and
  relevant social context to `data/intelligence/sources.yaml`.
- Add incidents, disclosures, vulnerabilities, campaigns, corrections,
  retractions, remediations, and intelligence changes to
  `data/intelligence/events.yaml`.

Every source and event uses a stable lowercase ID. Every event references at
least one existing source ID and keeps occurrence, disclosure, and update dates
separate. Omit an unknown date rather than estimating it. A social post can
record community context, but it is not an independent authority for an IOC.

Contested events use both `status: contested` and `confidence: contested`.
Corrections and retractions add explicit events and preserve the earlier record;
do not silently rewrite the history. The timeline describes “events tracked by
AgentSec” and must not claim completeness.

After editing either intelligence YAML file, validate and regenerate all public
views:

```bash
.venv/bin/python scripts/build_intelligence_docs.py
git diff --exit-code -- \
  docs/SECURITY-INTELLIGENCE.md \
  docs/SECURITY-TIMELINE.md \
  src/agentsec/resources/security-intelligence.json
```

The generated Markdown and JSON files are committed release artifacts. Do not
edit them directly. Historical backfill from the guide must be reviewed record
by record; aggregate campaign counts are not event records.

## Local release gate

Run every gate before requesting review:

```bash
.venv/bin/python scripts/build_threat_db.py
.venv/bin/python scripts/build_scan_schema_digest.py --check
.venv/bin/python scripts/build_intelligence_docs.py
git diff --exit-code -- src/agentsec/resources/threat-db.json
git diff --exit-code -- docs/SECURITY-INTELLIGENCE.md docs/SECURITY-TIMELINE.md src/agentsec/resources/security-intelligence.json
.venv/bin/ruff check src tests scripts
.venv/bin/mypy src scripts
PIP_NO_INDEX=1 .venv/bin/pytest --cov=agentsec --cov-report=term-missing
PIP_NO_INDEX=1 .venv/bin/python -m build --no-isolation
.venv/bin/agentsec doctor
.venv/bin/python -m agentsec doctor
```

Install `.[dev]` before setting `PIP_NO_INDEX=1`; it includes Hatchling so the
build needs neither an isolated environment nor a package-index request. The full
test suite inherits `PIP_NO_INDEX=1`, including its package build and wheel install.

The CI workflow installs the built wheel with `--no-index --no-deps` in a fresh
virtual environment and runs `doctor` from that environment. The package test
also checks that the wheel contains the generated intelligence JSON. Together,
these gates cover the threat database, result schema, and intelligence resource
without relying on runtime dependencies.

The release gate also runs two repository-shaped scans. `agentsec scan .` must
exit `2`, retain findings from positive fixtures, and report the tracked binary
`bun.lockb` fixture as unsupported. The negative fixture scan must complete with
no critical finding. There is no V0.1 exclusion flag and `.gitignore` is not a
scanner boundary.

## Pull request content

State the threat claim or behavior changed, source and provenance, red test
observed, green verification commands, compatibility impact, and known limits.
Do not describe a partial scan as clean and do not add release, support, coverage,
or security claims that the submitted evidence does not prove.

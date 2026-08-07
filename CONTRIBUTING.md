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

## Local release gate

Run every gate before requesting review:

```bash
.venv/bin/python scripts/build_threat_db.py
git diff --exit-code -- src/agentsec/resources/threat-db.json
.venv/bin/ruff check src tests scripts
.venv/bin/mypy src scripts
.venv/bin/pytest --cov=agentsec --cov-report=term-missing
.venv/bin/python -m build
.venv/bin/agentsec doctor
```

The CI workflow also installs the built wheel with `--no-deps` in a fresh virtual
environment and runs `doctor` from that environment. This checks that the wheel
contains the threat database and result schema without relying on development
dependencies.

## Pull request content

State the threat claim or behavior changed, source and provenance, red test
observed, green verification commands, compatibility impact, and known limits.
Do not describe a partial scan as clean and do not add release, support, coverage,
or security claims that the submitted evidence does not prove.

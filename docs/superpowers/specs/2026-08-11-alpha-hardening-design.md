# AgentSec V0.1 Alpha Hardening Design

## Status

Proposed for implementation after user review. This design responds to the
2026-08-11 external audit and the subsequent local verification. It does not
authorize a public release, a tag, or a license change.

## Goal

Remove the maintenance traps found in the V0.1 alpha without weakening its
read-only, offline, fail-closed security model. Make the current runtime data
projection explicit, prepare the result contract for multiple detectors, add a
source-tree module entry point, and produce evidence needed for the remaining
license and performance decisions.

## Verified baseline

- `data/threat-db.yaml` contains 89 `malicious_skills`: 20 npm, 5 PyPI, and 64
  without a `platform` field.
- Seventeen npm records contain a version and are projected into the runtime
  database: 16 exact package records and one contested wildcard record.
- The runtime artifact also contains three SHA-256 hashes, seven domains, and
  one commit indicator extracted from campaign data.
- The builder does not project the 107 CVE records or the 40 attack-technique
  records into the V0.1 runtime artifact.
- `remediation_url` is restricted to one constant URL by the public result
  schema.
- `doctor` compares the packaged result schema to a digest embedded manually in
  `src/agentsec/cli.py`.
- `python -m agentsec` fails because `src/agentsec/__main__.py` is absent.
- The Shai-Hulud detector safely reads and hashes every discovered regular file
  so renamed known payloads remain detectable. Performance has not been
  benchmarked on a representative corpus.

## Scope

### 1. Explicit threat-data projection

The authoring database remains broader than the runtime artifact. V0.1 must not
copy unused CVEs, techniques, or unsupported package ecosystems into the wheel
merely to make source and runtime counts match.

The builder will compute and embed an `authoring_coverage` object in the runtime
JSON. It will contain stable counts for:

- total malicious-skill records;
- extracted npm records with exact versions;
- ignored records grouped by explicit reason: `missing_platform`,
  `unsupported_platform`, and `missing_version`;
- total and projected counts for CVEs, attack techniques, campaigns, hashes,
  domains, and commit indicators.

`agentsec db info` will display the projection summary. The build command will
also print it. Runtime validation will reject missing, malformed, negative, or
internally inconsistent coverage counts.

Ignoring a record remains valid only when the reason is represented in the
coverage object. The builder will fail for malformed records that claim to be a
supported versioned npm package. It will not raise merely because a record is
from PyPI or lacks a platform in the historical source.

Generated artifacts remain deterministic. A source-data change must change the
committed runtime coverage metadata, so CI drift checks expose additions that
are not projected into a detector.

The existing `complete: true` field continues to mean that the declared runtime
projection was built and validated completely. Documentation will explicitly
state that it does not mean the full authoring database is implemented.

### 2. Detector-extensible remediation contract

The public scan-result schema will accept `remediation_url` as either `null` or
an absolute `https` URL. Arbitrary schemes, relative URLs, credentials, query
strings, and fragments will be rejected. This keeps reports safe to render while
allowing each detector to point to its own reviewed remediation page.

The current Shai-Hulud URL remains unchanged. Positive and negative schema tests
will cover accepted detector-specific HTTPS URLs and rejected unsafe forms.

### 3. Deterministic schema integrity workflow

The schema digest remains a packaging-integrity check, but it will no longer be
maintained as an unexplained literal in `cli.py`.

A focused builder will generate a committed
`schemas/scan-result-v1.schema.sha256` file from the public schema. `doctor` will
load the expected digest from the packaged resource, with the same source-tree
fallback used for the schema. Packaging will include both files. CI and local
release verification will run the builder in check mode and fail on drift.

This mechanism detects accidental schema/package divergence. It is not described
as protection against an attacker able to rewrite the installed package.

### 4. Source-tree module entry point

Add `src/agentsec/__main__.py` as a minimal delegation to
`agentsec.cli.entrypoint`. The following interfaces must behave consistently:

```text
agentsec --help
python -m agentsec --help
python -m agentsec scan <repository>
```

No installation bypass or direct execution of target content is introduced.

### 5. License evidence, not an invented legal conclusion

The existing publication gate stays closed. The implementation will add a
factual license inventory recording:

- the byte-for-byte import and its digest;
- the Git author history observed for the canonical guide database;
- the code files created in this repository;
- third-party source attribution fields requiring prose review;
- the proposed split between a code license and a data license.

The inventory may recommend Apache-2.0 or MIT for code and CC BY-SA 4.0 for
authoring and generated threat data, but it will not select a license on the
user's behalf. `LICENSE-DECISION.md` remains blocking until the user records the
choice and the prose review is complete.

No `LICENSE`, public tag, GitHub release, source archive, or PyPI publication is
created by this hardening work.

### 6. Reproducible performance baseline

Add an opt-in benchmark command that scans one explicitly supplied local root
and records:

- tool, database, Python, and platform versions;
- elapsed wall time;
- process exit code;
- result completion state;
- files seen and inspected;
- bytes inspected;
- finding and diagnostic counts.

The benchmark remains offline and read-only. It refuses a missing root, never
defaults to a home directory, does not upload results, and writes JSON only to a
path explicitly supplied by the operator. Tests use synthetic temporary
repositories. The project will not publish a performance claim until a real
corpus run is recorded and manually reviewed.

Hashing every discovered regular file remains unchanged in this milestone.
Candidate-only hashing would create a false negative for renamed known payloads.
Parallel reads and caching are deferred until the baseline demonstrates a real
bottleneck and the confinement model is preserved.

## Error handling

- Builder projection inconsistencies fail with exit code `1` and a concise
  non-sensitive error.
- Schema digest drift fails the digest builder check and makes `doctor` return
  `2`.
- Unsafe remediation URLs fail schema validation in tests and cannot be emitted
  by registered detector metadata.
- Benchmark scan failures are recorded as results; benchmark setup or output
  failures return `2` without overwriting an existing report partially.

## Test strategy

Every behavior change follows red-green-refactor.

- Threat-data tests cover the canonical counts, each ignored-reason category,
  deterministic generation, malformed supported records, and runtime coverage
  validation.
- Schema tests cover detector-specific HTTPS remediation URLs and unsafe URL
  rejection.
- Digest tests prove generation, drift detection, source-tree fallback, wheel
  inclusion, and `doctor` failure on mismatch.
- CLI integration tests compare console-script and module entry-point behavior.
- Benchmark unit and integration tests use bounded synthetic fixtures and assert
  stable JSON keys without asserting machine-dependent durations.
- The final gate runs generators twice, checks generated-artifact drift, Ruff,
  strict mypy, the full test suite with at least 85 percent coverage, an offline
  wheel and sdist build, `doctor`, CLI fixtures, and `git diff --check`.

## Documentation changes

- `README.md`: module entry point, threat projection semantics, benchmark usage,
  and unchanged alpha limitations.
- `CONTRIBUTING.md`: generator check commands and detector-data projection rule.
- `ROADMAP.md`: mark completed hardening items without claiming release readiness.
- `LICENSE-DECISION.md`: link the factual inventory while preserving the gate.
- `CHANGELOG.md`: record every user-visible change under `[Unreleased]`.

## Non-goals

- Adding ClawHavoc, ToxicSkills, PyPI, CVE, or generic SAST detectors.
- Optimizing file reads before measurement.
- Scanning Git history, host state, remote services, or credentials.
- Automatically remediating findings.
- Selecting licenses or publishing the project without the user's recorded
  decision.
- Claiming that a repository, dependency set, or machine is clean.

## Acceptance criteria

1. No authoring record is omitted without a counted, named projection reason.
2. A second detector can use its own reviewed HTTPS remediation URL without a
   schema edit.
3. Schema changes have a deterministic digest-generation and drift-check path.
4. `python -m agentsec --help` succeeds from an installed package and source
   checkout.
5. The license gate contains enough factual evidence for a separate explicit
   decision but remains closed.
6. A benchmark can produce a reviewed JSON baseline without changing or
   uploading the scan target.
7. All existing security invariants and the complete release test gate continue
   to pass.

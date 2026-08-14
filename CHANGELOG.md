# Changelog

All notable changes to AgentSec Triage are recorded here. The project has no
authorized public release while the licensing decision remains unresolved.

## [Unreleased]

### Added

- Added a dependency-free Markdown style checker and a CI gate for automatic
  prose markers. The checker ignores fenced and inline code plus local build,
  cache, environment, and worktree directories.
- Added canonical `AGENTS.md` repository instructions, a minimal Claude Code
  adapter in `CLAUDE.md`, and a prioritized `ROADMAP.md` with explicit release
  gates and non-goals.
- Added schema-validated YAML authoring for security sources and dated events,
  seeded with six reviewed Keyv/Shai-Hulud sources, a confirmed campaign event,
  and a separately attributed contested-scope event.
- Added deterministic generation of `docs/SECURITY-INTELLIGENCE.md`,
  `docs/SECURITY-TIMELINE.md`, and the packaged
  `security-intelligence.json` resource, with CI drift and wheel-content gates.
- Added `python -m agentsec` as a source and installed-package entry point.
- Added an opt-in local benchmark that writes a new redacted aggregate JSON
  report without copying findings, diagnostics, stderr, or the absolute root.
- Added a factual license evidence inventory that distinguishes the imported
  source digest from the adapted AgentSec authoring file and keeps publication
  blocked pending explicit owner decisions and prose review.
- Added deterministic generation and wheel packaging of the public scan-result
  schema digest.

### Fixed

- Reviewed all 19 Markdown files tracked at the start of the work and removed
  the identified prose markers without changing threat facts, source titles,
  commands, hashes, dates, exit codes, or license decisions. Generated
  intelligence punctuation now comes from its renderer.
- Expanded `AGENTS.md` with post-hardening generation, projection, worktree, and
  verification rules. `CLAUDE.md` now covers Claude Code navigation,
  delegation, generated-file ownership, and final review without duplicating
  the repository contract.
- Made authoring-to-runtime threat-data projection explicit and validated. The
  runtime artifact and `db info` now report projected and ignored records by
  reason instead of silently hiding the builder's V0.1 scope.
- Allowed each detector to provide its own reviewed HTTPS remediation URL while
  rejecting relative, credential-bearing, query-bearing, fragment-bearing, and
  non-HTTPS values in the public result schema.
- Allowed intelligence events to retain multiple distinct lifecycle dates, such
  as occurrence and disclosure, instead of incorrectly requiring exactly one
  date field. Intelligence dates now reject impossible calendar values rather
  than validating only their textual shape.
- Removed the safe reader's one-byte sentinel read. POSIX and Windows reads now
  consume at most the exact remaining physical byte budget, accept exact-size
  and zero-byte files, including empty files at a zero aggregate budget, and use
  post-read identity and metadata checks to reject
  concurrent growth. A failed safe read stops the detector so unreturned bytes
  cannot be spent again on a later file. The public schema again permits `null`
  remediation URLs for protocol-compatible external detectors while the
  built-in detector keeps emitting the canonical security URL.
- Added immutable detector metadata and deterministic `detectors explain`
  output for supported inputs, campaign and technique IDs, canonical sources,
  limitations, remediation, and declared exclusions.
- Added stable V0.1 `not_scanned` capability IDs to human and JSON results,
  without treating out-of-scope capabilities as failed in-scope checks. Every
  finding now links to the security remediation page.
- Added a 1,000,000,000-byte aggregate scan budget and
  `--max-total-bytes`. Budget exhaustion stops before the next unsafe read and
  returns an incomplete result. `--max-file-bytes` now rejects values above the
  safe reader's 4,000,000-byte hard cap.
- Replaced the evidence-only positive golden with a schema-validated semantic
  JSON golden covering verdict, coverage, diagnostics, exclusions, finding
  severity, confidence, paths, campaign and technique IDs, and remediation.
- Preserved contested npm intelligence and package/version source attribution in
  the generated database and immutable runtime model. `@keyv/*@6.0.0` now emits
  `high/contested` findings attributed to JFrog and SafeDep, while exact
  `keyv@6.0.0` remains `critical/confirmed` and lifecycle-only evidence remains
  `medium/review`.
- Disabled local Git-history subprocess execution for untrusted repositories until
  strict metadata confinement is available. Repositories with `.git` now fail
  closed with an incomplete result instead of allowing Git to follow object
  symlinks, alternates, or external gitfiles.
- Canonicalized scan root, diagnostic, and finding paths to forward-slash form in
  deterministic JSON and human output, including Windows paths, and made the CI
  self-scan assertion tolerate native separators defensively.
- Made package builds and the packaging integration test run with
  `PIP_NO_INDEX=1` and `python -m build --no-isolation` after installing the full
  development dependency set, including Hatchling.
- Prevented the blocking `LICENSE-DECISION.md` record from being emitted as a
  wheel `License-File` metadata field.
- Replaced the contradictory clean self-scan expectation with an explicit exit
  `2` gate that preserves positive fixtures and the unsupported `bun.lockb`
  diagnostic; a separate negative-fixture scan proves completed applicable
  behavior.

### Blocked

- Public tagging and publication are blocked pending the code and threat-data
  ownership and compatibility review in `LICENSE-DECISION.md`.

## [0.1.0-alpha] - pending

### Added

- Read-only, offline-by-default repository discovery with bounded traversal,
  diagnostic reporting, and incomplete-scan exit behavior.
- Schema-validated threat database 2.26.0 import and deterministic runtime JSON
  build.
- `shai-hulud-keyv` detector for supported lockfiles, installed package metadata,
  exact payload hashes, and repository-local startup configuration. Local Git
  history is explicitly reported as not scanned until strict confinement exists.
- Human and versioned JSON output, redaction, detector and database inspection,
  and the dependency-free `doctor` command.
- Positive, negative, malformed-input, safety, integration, packaging, and schema
  regression tests.
- User, contributor, security-reporting, licensing-gate, and alpha limitation
  documentation.
- Cross-platform CI targets for Linux, macOS, and Windows on Python 3.11, 3.12,
  and 3.13. Passing status is not claimed until those jobs run.

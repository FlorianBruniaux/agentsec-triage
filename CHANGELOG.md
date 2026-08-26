# Changelog

All notable changes to AgentSec Triage are recorded here. The project has no
authorized public release while the licensing decision remains unresolved.

## [Unreleased]

### Added

- Added a dated scanner-ecosystem inventory covering direct competitors,
  specialized MCP and skill scanners, supply-chain tools, naming collisions,
  product gaps, and the first hands-on evaluation queue. The inventory combines
  the supplied market study, the verified 100,319-repository local corpus, and
  official README checks without treating project claims as benchmark results.
- Added a 15-day competitive-analysis plan with pinned static reviews,
  execution and safety gates, an inert fixture corpus, isolated benchmark
  requirements, product-decision limits, naming checks, roadmap milestones,
  validation criteria, commit boundaries, and rollback conditions.
- Added a schema-validated index for 16 pinned competitor repositories and a
  research methodology that separates declared, code-verified, observed,
  contradicted, unsupported, and untested evidence. The standard-library
  validator can also confirm the external clone directories on demand.
- Added a mandatory competitor profile template and validation for 14 evidence
  sections. Factual table rows must carry an explicit evidence state before a
  profile can enter the static comparison.
- Added pinned static profiles for Aguara, patient-zero, Repo Forensics, and
  cc-audit. The reviews trace scanner boundaries, intelligence updates, CI
  behavior, licenses, incomplete-scan handling, and the runtime witnesses that
  remain blocked behind the benchmark approval gate.
- Added pinned static profiles for AgentShield, Snyk Agent Scan, AgentSeal, and
  Medusa. The reviews separate static repository checks from host inventory,
  hosted analysis, MCP execution, registry traffic, external linters, and
  target-owned configuration.
- Added pinned static profiles for NVIDIA SkillSpector, Cisco Skill Scanner,
  AgentSec by debu-sinha, and Trust Issues. The reviews cover skill-specific
  analyzers, completeness accounting, host hardening, package gates, manual
  reasoning, naming collision, and three documented fail-open or evidence-drift
  cases.
- Added pinned static profiles for Sigil, agent-security-scanner-mcp, Inkog,
  and agent-bom. The reviews cover quarantine workflows, broad MCP scanning,
  hosted source analysis, governance inventory, network boundaries, traversal
  omissions, and fail-closed evidence contracts.
- Added a static comparison matrix for all 16 pinned projects, split by product
  job, safety, coverage honesty, intelligence, distribution, and maintenance.
  The matrix proposes an eight-tool offline benchmark cohort and records why
  the other projects remain excluded from the first controlled run.
- Added a validated corpus of 12 inert competitive fixtures covering clean,
  confirmed, contested, near-miss, hook, editor startup, delayed skill, MCP,
  CI, unsupported lockfile, renamed-content, and symlink-confinement cases.
  The validator rejects executable bits, archives, secret-shaped content,
  undeclared files, unconfined paths, and malformed source attribution.
- Added a host-side competitive benchmark runner with exact-plan digests,
  immutable image requirements, read-only inputs, disabled network, non-root
  execution, dropped capabilities, resource limits, bounded output capture,
  scratch write inventory, output digests, local raw-record isolation, and a
  competitor-free self-test. The design records current measurement and
  normalization limits instead of claiming unsupported containment evidence.
- Added seven locked competitor image recipes, a schema-level recipe validator,
  immutable local image ID support, exact runtime command arrays, fixture
  subsets, and a separate build approval gate. The gate keeps dependency
  retrieval ahead of source copies, disables network for source-present build
  steps, and blocks Sigil before build because the reviewed revision has no
  tracked `Cargo.lock`.
- Recorded five verified local competitor image IDs. The controlled sequence
  built Aguara, patient-zero, AgentShield, `cc-audit`, and SkillSpector without
  running their CLIs. Cisco Skill Scanner remains pending after repeated Docker
  Hub registry failures before context loading; `agent-bom` remains unattempted.
- Added a CoSnitch intelligence fiche for `CVE-2026-24301`, sourced from
  Varonis Threat Labs and NVD. The fiche records the one-click Microsoft
  Copilot Personal chain, the 2026-08-18 server-side fix, and Varonis's report
  that it found no pre-patch exploitation. Detector coverage is
  `not_applicable` because the affected Copilot Web endpoint is hosted by
  Microsoft and produces no repository artifact for AgentSec to inspect. The
  public feed now contains 20 sources and 10 events; runtime database and
  detector counts remain unchanged.
- Added terminal-aware scan progress with `--progress`, forced and disabled
  modes, plus `--verbose` file, directory, and byte counters. Progress is
  bounded, contains no target content, and stays on `stderr` so JSON and human
  reports remain isolated on `stdout`. Progress now reports the loaded threat
  database metadata, resolved repository scope, selected detectors, active
  safety limits, and an indeterminate discovery bar with exact counters. The
  bar reaches `100%` only after traversal finishes. `--redact` hides repository
  and bundled resource paths.
- Added threat database 2.27.0 with seven primary-source-verified CVEs, four
  Paperclip and Browser Use skill or package records, corrected minimum-safe
  versions, 12 reviewed intelligence sources, seven dated fiches, and an
  explicit `not_detected` or `not_applicable` coverage statement for every new
  event. Added the canonical `/update-threat-db` workflow with source promotion,
  generation, synchronization, and publication gates.
- Added a schema-validated, deterministic `security-feed.v1.json` containing
  AgentSec versions, factual database counters, sourced landing metrics,
  detector contracts, and reviewed intelligence fiches. Added byte-for-byte
  guide and landing synchronization, authoring instructions, and a narrow
  CC BY-SA 4.0 feed-publication exception that excludes gated IOC data.
- Added focused source-installation and scan-example guides, a copy-ready
  read-only LLM audit prompt, and a root `llms.txt` index of canonical project
  documentation.
- Selected MIT for project-owned source code and original documentation. Added a
  separate data-license scope record that keeps public redistribution blocked
  until the CC BY-SA 4.0 prose, rights, and attribution review is complete.
- Added an `At a glance` README table that summarizes current scan scope,
  detector coverage, output, exit codes, safety boundaries, and alpha limits,
  with visual emphasis for key concepts and technical literals.
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

- Corrected the `cc-audit` benchmark image dependency stage to include its
  manifest-declared benchmark target before `cargo fetch --locked`. The first
  controlled build attempt and its three immutable image IDs are recorded in
  the renewed build gate. Follow-up corrections align the immutable Rust
  builder image with the repository's exact tracked Rust 1.93.0 toolchain so
  the source build can remain network-disabled, then resolve its declared
  rustup components in the dependency stage before source copy. No competitor
  scanner was executed.
- Stopped traversing nested Git repositories and worktrees as though they were
  part of the requested root. They now produce one warning with an instruction
  to scan the nested repository separately. Symlinks and Windows reparse points
  remain unread, fail closed, and produce one aggregate diagnostic instead of
  exhausting the diagnostic budget one path at a time. Full regular-file hash
  coverage remains enabled for the requested repository. Large monorepositories
  now receive bounded defaults of 1,000,000 directory entries and 100,000
  opened directories, with CLI options that can lower both ceilings.
- Defined the cross-platform test contract. Git checks out tracked text with
  `LF`; runtime schema verification normalizes line endings; redacted root paths
  use a stable delimiter; POSIX descriptor regressions run on POSIX; and Windows
  keeps native safe-reader coverage without a Linux-only percentage comparison.
  CI checks unsupported input plus detector findings against dedicated fixtures.
- Made POSIX capability access fail closed when absent and type-check cleanly on
  Windows without weakening directory or process-tree handling.
- Normalized scan-result schema line endings before computing its digest, so
  Windows `CRLF` checkouts validate against the committed `LF` digest.
- Normalized text input line endings before computing public-feed digests, so
  Windows `CRLF` checkouts generate the same artifact as `LF` checkouts.
- Reduced the README to a concise project entry point. Operational commands,
  coverage details, JSON output, self-scan expectations, privacy guidance, and
  benchmark instructions now have one canonical document each.
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

### Removed

- Removed eight internal implementation plans and design specifications from
  the current public tree. Their historical commits remain unchanged.

### Blocked

- Public visibility, tagging, and publication remain blocked pending the
  threat-data prose, ownership, attribution, and compatibility review in
  `LICENSE-DECISION.md`.

## [0.1.0-alpha] - pending

### Release metadata

| Field | Value |
| --- | --- |
| Python package | `0.1.0a0` |
| Intended Git tag | `v0.1.0-alpha` |
| Threat database | `2.27.0` |
| Detector | `shai-hulud-keyv` version `1` |
| JSON schema | version `1` |
| Python | 3.11, 3.12, and 3.13 |

### Added

- Read-only, offline-by-default repository discovery with bounded traversal,
  diagnostic reporting, and incomplete-scan exit behavior.
- Schema-validated threat database 2.26.0 import, reviewed 2.27.0 intelligence
  update, and deterministic runtime JSON build.
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

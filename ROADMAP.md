# AgentSec Triage Roadmap

This roadmap describes intended work, not shipped guarantees. Priorities may
change when new evidence, false positives, platform constraints, or licensing
requirements appear.

## Current state: V0.1 alpha implementation

Implemented in the current alpha codebase:

- bounded, read-only, offline repository discovery;
- explicit `source`, `dependencies`, and `repository` scopes with measured
  exclusions;
- bounded in-process batch triage for explicit repository roots;
- human, scan-result v2, and batch-result v1 output with per-detector coverage
  and exit codes;
- redaction for report preparation;
- schema-validated threat database import and deterministic runtime artifact;
- validated authoring-to-runtime projection counts with explicit ignored reasons;
- detector-specific HTTPS remediation URLs and packaged digest checks for the
  historical v1, active scan v2, and batch v1 schemas;
- console-script and `python -m agentsec` entry points;
- an opt-in redacted local benchmark without published performance claims;
- a factual license evidence inventory that preserves the publication gate;
- a public source repository with a separate unresolved gated-data license;
- `shai-hulud-keyv` detector for supported npm, pnpm, Yarn, and text Bun
  lockfiles, installed package metadata, payload hashes, and repository startup
  configuration;
- a fully executed Python 3.11–3.13 GitHub Actions matrix on Linux, macOS,
  and Windows, plus guide and landing feed-mirror validation;
- source, package, safety, integration, and golden regression tests.

Git history, host state, remote repositories, remote CI, network traffic,
credential stores, and automatic remediation remain explicitly out of scope.

## Public work tracking

Completed infrastructure work:

- [#1: restore actual GitHub Actions execution](https://github.com/FlorianBruniaux/agentsec-triage/issues/1),
  verified by [run #33320781608](https://github.com/FlorianBruniaux/agentsec-triage/actions/runs/33320781608).

The remaining release and product work is tracked with acceptance criteria:

- [#6: resolve the public-source and gated-data license boundary](https://github.com/FlorianBruniaux/agentsec-triage/issues/6);
- [#3: run seven digest-approved clean-control benchmarks](https://github.com/FlorianBruniaux/agentsec-triage/issues/3);
- [#4: run the fixture matrix with an AgentSec baseline](https://github.com/FlorianBruniaux/agentsec-triage/issues/4);
- [#7: publish benchmark results and top-three teardowns](https://github.com/FlorianBruniaux/agentsec-triage/issues/7);
- [#2: convert competitive evidence into product decisions](https://github.com/FlorianBruniaux/agentsec-triage/issues/2);
- [#5: select a collision-resistant product name](https://github.com/FlorianBruniaux/agentsec-triage/issues/5).

## P0: Make the alpha releasable

- Complete the 28-field third-party prose review recorded in
  `docs/LICENSE-INVENTORY.md`.
- Record the owner's explicit code-license and data-license decisions.
- Resolve the code and threat-data review in `LICENSE-DECISION.md`.
- Select compatible code and data licenses with SPDX metadata and attribution.
- Keep the fully verified alpha history on local `main` before any release tag.
- Fix failures found outside the local macOS environment.
- Create the annotated `v0.1.0-alpha` tag only after every release gate passes.
- Publish checksums and a signed provenance statement with release artifacts.

## P1: Intelligence publishing

- Maintain a structured, attributable bibliography of relevant security sources.
- Maintain a dated ledger of tracked incidents, disclosures, corrections,
  retractions, remediations, and contested intelligence.
- Generate human-readable intelligence and timeline documents.
- Generate a versioned JSON artifact for the guide and landing.
- Backfill historical records from the guide threat database one reviewed record
  at a time; never synthesize individual events from aggregate counts.
- Define a correction and retraction policy with preserved history.

## P1: Detector expansion

- Add ClawHavoc and ToxicSkills repository detectors with synthetic fixtures.
- Add generic agent-skill and repository-persistence checks without treating
  every hook or instruction file as malicious.
- Add MCP configuration and vulnerable-version checks backed by exact sources.
- Add dangerous CI workflow and package-install execution checks.
- Add additional npm and PyPI campaign modules behind stable detector IDs.

Every detector must declare supported inputs, limitations, sources, techniques,
remediation, and stable `not_scanned` capability IDs.

## P2: Distribution and integrations

- Provide a GitHub Action with pinned, checksummed releases.
- Add SARIF output for GitHub Code Scanning and compatible platforms.
- Add documented pre-commit and CI recipes without making local hooks mandatory.
- Let the Claude Code Ultimate Guide consume a pinned AgentSec release artifact.
- Replace hardcoded landing security versions, dates, counts, and stale source
  paths with generated data.
- Add an AgentSec installation and scan CTA to `https://cc.bruniaux.com/security/`.

## P3: Advanced analysis

- Revisit local Git-history inspection only after strict object, alternates,
  gitfile, symlink, race, and platform confinement is demonstrated.
- Add optional incremental caching without making cached results authoritative.
- Evaluate SBOM correlation and package-manager-native metadata as additional
  evidence, not a replacement for lockfile and installed-tree inspection.
- Define signed intelligence updates and rollback-safe database upgrades.

## Explicit non-goals

- Claiming that a repository, workstation, dependency set, or account is clean.
- Becoming an antivirus, EDR, generic SAST, or full secret scanner.
- Executing suspicious payloads or repository hooks for analysis.
- Uploading repositories or findings by default.
- Automatically deleting files, rotating credentials, or rewriting configuration.
- Treating social posts, filenames, package names, or aggregate counts as
  confirmed compromise without supporting evidence.

## Definition of done for a milestone

A milestone is complete only when its behavior is documented, its supported
inputs and exclusions are explicit, new behavior has regression tests, generated
artifacts are deterministic, the full offline release gate passes, and the
changelog records the outcome without overstating coverage.

# AgentSec Triage Roadmap

This roadmap describes intended work, not shipped guarantees. Priorities may
change when new evidence, false positives, platform constraints, or licensing
requirements appear.

## Current state — V0.1 alpha implementation

Implemented on `codex/v0.1-alpha`:

- bounded, read-only, offline repository discovery;
- human and versioned JSON results with explicit coverage and exit codes;
- redaction for report preparation;
- schema-validated threat database import and deterministic runtime artifact;
- `shai-hulud-keyv` detector for supported npm, pnpm, Yarn, and text Bun
  lockfiles, installed package metadata, payload hashes, and repository startup
  configuration;
- cross-platform Python 3.11–3.13 CI configuration;
- source, package, safety, integration, and golden regression tests.

Git history, host state, remote repositories, remote CI, network traffic,
credential stores, and automatic remediation remain explicitly out of scope.

## P0 — Make the alpha releasable

- Resolve the code and threat-data review in `LICENSE-DECISION.md`.
- Select compatible code and data licenses with SPDX metadata and attribution.
- Merge the verified alpha branch into local `main`.
- Configure the public Git remote and run the full GitHub Actions matrix.
- Fix failures found outside the local macOS environment.
- Create the annotated `v0.1.0-alpha` tag only after every release gate passes.
- Publish checksums and a signed provenance statement with release artifacts.

## P1 — Intelligence publishing

- Maintain a structured, attributable bibliography of relevant security sources.
- Maintain a dated ledger of tracked incidents, disclosures, corrections,
  retractions, remediations, and contested intelligence.
- Generate human-readable intelligence and timeline documents.
- Generate a versioned JSON artifact for the guide and landing.
- Backfill historical records from the guide threat database one reviewed record
  at a time; never synthesize individual events from aggregate counts.
- Define a correction and retraction policy with preserved history.

## P1 — Detector expansion

- Add ClawHavoc and ToxicSkills repository detectors with synthetic fixtures.
- Add generic agent-skill and repository-persistence checks without treating
  every hook or instruction file as malicious.
- Add MCP configuration and vulnerable-version checks backed by exact sources.
- Add dangerous CI workflow and package-install execution checks.
- Add additional npm and PyPI campaign modules behind stable detector IDs.

Every detector must declare supported inputs, limitations, sources, techniques,
remediation, and stable `not_scanned` capability IDs.

## P2 — Distribution and integrations

- Provide a GitHub Action with pinned, checksummed releases.
- Add SARIF output for GitHub Code Scanning and compatible platforms.
- Add documented pre-commit and CI recipes without making local hooks mandatory.
- Let the Claude Code Ultimate Guide consume a pinned AgentSec release artifact.
- Replace hardcoded landing security versions, dates, counts, and stale source
  paths with generated data.
- Add an AgentSec installation and scan CTA to `https://cc.bruniaux.com/security/`.

## P3 — Advanced analysis

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


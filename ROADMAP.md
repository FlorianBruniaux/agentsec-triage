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
- human, scan-result v2, SARIF 2.1.0, and batch-result v1 output with
  per-detector coverage and exit codes;
- a repository-local composite GitHub Action that runs checked-out source,
  validates fail-closed SARIF, and preserves scanner exit codes without
  downloading an unpublished release;
- redaction for report preparation;
- schema-validated threat database import and deterministic runtime artifact;
- validated authoring-to-runtime projection counts with explicit ignored reasons;
- detector-specific HTTPS remediation URLs and packaged digest checks for the
  historical scan v1, active scan v2, batch v1, and detector-explain v1 schemas;
- deterministic human and JSON detector coverage explanations with active
  rules, sources, applicability, supported inputs, database projection states,
  limitations, remediation, and stable `not_scanned` capability IDs;
- sourced, versioned response playbooks for every active Shai-Hulud/Keyv and
  ClawHavoc rule, with exact confidence handling, manual phases, deterministic
  rule mapping, and destructive automation forbidden;
- console-script and `python -m agentsec` entry points;
- an opt-in redacted local benchmark without published performance claims;
- a deterministic 430-field prose inventory with stable source locators,
  value digests, review state, required action, and a byte-for-byte drift check;
- a schema-enforced correction and retraction ledger that preserves earlier
  events and publishes explicit affected-event references;
- a public source repository with a separate unresolved gated-data license;
- `shai-hulud-keyv` detector for supported npm, pnpm, Yarn, and text Bun
  lockfiles, installed package metadata, payload hashes, and repository startup
  configuration;
- `clawhavoc-skill` detector for the exact sourced fake-prerequisite campaign
  domain in `SKILL.md` and explicitly delegated local setup instructions,
  without classifying a filename or delegation as compromise;
- a fully executed Python 3.11–3.13 GitHub Actions matrix on Linux, macOS,
  and Windows, plus guide and landing feed-mirror validation;
- seven digest-approved, network-disabled competitor `clean-control` runs with
  reviewed aggregate observations and no published raw output;
- eight validated positive, near-miss, unsupported, and confinement plans for
  the first three teardown candidates, with a separate procedural approval
  receipt required before Docker discovery and every result still `not_tested`;
- a three-run deterministic AgentSec fixture-baseline harness that keeps its
  machine report under the ignored local benchmark boundary;
- a provisional naming brief with dated official registry and domain evidence,
  a reproducible blind comprehension kit, one blocked candidate, and no
  authorized rename;
- source, package, safety, integration, and golden regression tests.

Git history, host state, remote repositories, remote CI, network traffic,
credential stores, and automatic remediation remain explicitly out of scope.

## Public work tracking

The accepted parity requirements, differentiation bets, rejected scope, and
delivery order live in `docs/competitive-analysis/PRODUCT-DECISIONS.md`.

Completed infrastructure work:

- [#1: restore actual GitHub Actions execution](https://github.com/FlorianBruniaux/agentsec-triage/issues/1),
  with the current Linux, macOS, Windows, package, scanner-fixture, and consumer
  mirror gate verified by [run #33428744702](https://github.com/FlorianBruniaux/agentsec-triage/actions/runs/33428744702).
- [#3: run seven digest-approved clean-control benchmarks](https://github.com/FlorianBruniaux/agentsec-triage/issues/3),
  recorded in `docs/competitive-analysis/BENCHMARK-RESULTS.md` with bounded raw
  output retained only in the ignored local run directory.
- [#2: convert competitive evidence into product decisions](https://github.com/FlorianBruniaux/agentsec-triage/issues/2),
  recorded in `docs/competitive-analysis/PRODUCT-DECISIONS.md` and implemented
  through the accepted alpha sequence.

The remaining release and product work is tracked with acceptance criteria:

- [#6: resolve the public-source and gated-data license boundary](https://github.com/FlorianBruniaux/agentsec-triage/issues/6);
- [#4: run the fixture matrix with an AgentSec baseline](https://github.com/FlorianBruniaux/agentsec-triage/issues/4);
- [#7: publish benchmark results and top-three teardowns](https://github.com/FlorianBruniaux/agentsec-triage/issues/7);
- [#5: select a collision-resistant product name](https://github.com/FlorianBruniaux/agentsec-triage/issues/5).

## P0: Make the alpha releasable

- Resolve every `UNKNOWN` classification in the generated 430-field inventory
  through evidenced independent authorship, permission, rewrite, or removal.
- Record the owner's explicit data-license, third-party-content, attribution,
  packaging, and release decisions.
- Resolve the threat-data review in `LICENSE-DECISION.md`; the MIT code-license
  decision is already recorded.
- Select the final data license and combined-package SPDX metadata with exact
  path scope and attribution.
- Keep the fully verified alpha history on local `main` before any release tag.
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

## P1: Detector expansion

- Expand the first exact-domain ClawHavoc rule with additional sourced
  ClawHavoc and ToxicSkills indicators and synthetic near-miss fixtures.
- Add generic agent-skill and repository-persistence checks without treating
  every hook or instruction file as malicious.
- Add MCP configuration and vulnerable-version checks backed by exact sources.
- Add dangerous CI workflow and package-install execution checks.
- Add additional npm and PyPI campaign modules behind stable detector IDs.

Every detector must declare supported inputs, limitations, sources, techniques,
remediation, and stable `not_scanned` capability IDs.

## P2: Distribution and integrations

- Preserve fail-closed scan coverage in deterministic SARIF 2.1.0 output.
- Promote the repository-local action to remote consumption only after a
  pinned, checksummed release and signed provenance are authorized.
- Add documented pre-commit and CI recipes without making local hooks mandatory.
- Let the Claude Code Ultimate Guide consume a pinned AgentSec release artifact.
- Route finding remediation URLs to individual playbooks only after stable
  public playbook URLs exist and automated link checks cover them.

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

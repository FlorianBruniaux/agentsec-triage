# Changelog

All notable changes to AgentSec Triage are recorded here. The project has no
authorized public release while the licensing decision remains unresolved.

## [Unreleased]

### Fixed

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

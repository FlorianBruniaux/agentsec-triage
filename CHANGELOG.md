# Changelog

All notable changes to AgentSec Triage are recorded here. The project has no
authorized public release while the licensing decision remains unresolved.

## [Unreleased]

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
  exact payload hashes, repository-local startup configuration, and bounded local
  Git history.
- Human and versioned JSON output, redaction, detector and database inspection,
  and the dependency-free `doctor` command.
- Positive, negative, malformed-input, safety, integration, packaging, and schema
  regression tests.
- User, contributor, security-reporting, licensing-gate, and alpha limitation
  documentation.
- Cross-platform CI targets for Linux, macOS, and Windows on Python 3.11, 3.12,
  and 3.13. Passing status is not claimed until those jobs run.


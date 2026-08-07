# AgentSec Triage — Technical Design

**Status:** Design approved in conversation; pending review of this written specification  
**Date:** 2026-08-06  
**Working repository name:** `agentsec-triage`  
**Working CLI name:** `agentsec`

## 1. Purpose

AgentSec Triage is a deterministic, read-only command-line tool that checks a
local repository for evidence associated with documented attacks against
developers, software supply chains, and AI coding-agent configuration.

The project converts threat research into executable, regression-tested
detectors. Each detector states what it checks, what it cannot check, the
evidence behind its rules, and the remediation guidance for a positive result.

The repository becomes the technical source of truth for:

- the structured threat database;
- detector implementations and their versions;
- positive and negative fixtures;
- result schemas;
- machine-readable release artifacts.

The security page at <https://cc.bruniaux.com/security/> remains an editorial
and educational interface. Automatic integration with that page is explicitly
outside the first release.

## 2. Product Positioning

The product promise is:

> Transparent, tested detectors that search a repository for known evidence of
> documented attacks targeting developers and coding agents.

AgentSec Triage is not:

- a general-purpose SAST scanner;
- an EDR, antivirus, or malware-removal tool;
- a replacement for dependency or secret scanners;
- proof that a repository or workstation is clean;
- an LLM-based security verdict;
- a workstation, container, cloud-account, or remote-GitHub scanner in V1.

## 3. Initial Product Scope

The initial product scope, from the first alpha through `v1.0.0`, scans one local
repository and detects local Git metadata presence without inspecting its history.
It must be:

- read-only;
- offline by default;
- deterministic;
- usable interactively and in CI;
- explicit about incomplete coverage;
- safe to run against an untrusted repository.

V1 may inspect repository files, local lockfiles, installed dependency metadata,
symlinks, and startup configuration. It must not execute code from the target
repository or follow symlinks outside the scan root. Local Git history is not
scanned until its metadata can be confined atomically; `.git` presence makes the
alpha result explicitly incomplete.

The following remain out of scope until separately designed:

- developer-machine caches and processes;
- global IDE or agent configuration;
- Docker/container image filesystems;
- credential stores and token validity;
- remote GitHub repositories, organizations, and CI logs;
- automatic remediation;
- network-based IOC updates during a scan.

## 4. Selected Architecture

The project uses a shared Python CLI and modular detectors. A collection of
standalone scripts was rejected because it would duplicate traversal, error
handling, result formatting, and security controls. A hosted threat-intelligence
platform was rejected as premature for V1.

Target repository structure:

```text
agentsec-triage/
├── README.md
├── LICENSE
├── SECURITY.md
├── CONTRIBUTING.md
├── CHANGELOG.md
├── pyproject.toml
├── src/agentsec/
│   ├── __init__.py
│   ├── cli.py
│   ├── models.py
│   ├── engine/
│   │   ├── discovery.py
│   │   ├── diagnostics.py
│   │   └── runner.py
│   ├── detectors/
│   │   ├── base.py
│   │   ├── shai_hulud.py
│   │   ├── clawhavoc.py
│   │   └── repo_persistence.py
│   └── output/
│       ├── human.py
│       └── json.py
├── data/
│   ├── threat-db.yaml
│   ├── threat-db.schema.json
│   ├── campaigns/
│   └── generated/threat-db.json
├── schemas/
│   └── scan-result-v1.schema.json
├── tests/
│   ├── fixtures/
│   ├── unit/
│   ├── integration/
│   └── golden/
└── .github/workflows/
    ├── tests.yml
    └── release.yml
```

Python 3.11 or newer is the provisional runtime target. The authored threat
database remains YAML, while releases contain a generated and validated JSON
artifact. The runtime must never silently substitute an incomplete IOC database.

## 5. CLI Contract

Initial commands:

```bash
agentsec scan .
agentsec scan . --detector shai-hulud-keyv
agentsec scan . --format json
agentsec scan . --format json --redact
agentsec detectors list
agentsec detectors explain shai-hulud-keyv
agentsec db info
agentsec doctor
```

Exit codes:

- `0`: scan completed and no findings were produced;
- `1`: one or more findings require action or review;
- `2`: the scan is incomplete or an error prevents a clean verdict.

A nonexistent root, unreadable file, malformed required input, unsupported
binary lockfile, interrupted scan, or explicitly limited traversal cannot return
exit code `0` with a clean verdict.

Applicability and completeness are evaluated per detector. A detector that does
not apply to the repository, such as an npm campaign detector in a repository
with no Node.js artifacts, reports `not_applicable` rather than an error. An
unsupported artifact makes coverage incomplete only when it is authoritative
for an applicable detector or could conceal relevant evidence. The aggregate
result is complete only when every selected applicable detector completes.

## 6. Core Data Model

Every detector declares:

- stable detector ID and detector version;
- immutable typed metadata available through `detectors explain`;
- campaign or technique IDs;
- affected ecosystems;
- supported inputs;
- source references;
- IOC and heuristic rules;
- known limitations;
- remediation guidance;
- optional educational URL.

V0.1 uses stable dotted capability IDs for declared exclusions. The aggregate
always reports host processes, caches, global configuration, credentials,
remote repositories and CI, container filesystems, and automatic remediation
as not scanned. The Shai-Hulud detector also declares `git.history`. These
declarations do not change completeness; an attempted in-scope check that hits
an I/O, parser, Git-confinement, or resource limit does.

Every finding includes:

- detector and rule IDs;
- severity;
- confidence;
- evidence category;
- path and optional line number;
- concise, redacted evidence;
- campaign or technique references;
- remediation reference.

The aggregate `ScanResult` includes:

- tool and threat-database versions;
- scan root;
- `complete` status;
- findings;
- errors and warnings;
- coverage statistics;
- explicit `not_scanned` capabilities;
- elapsed time.

Repository reads have two independent limits: a 4,000,000-byte safe-reader hard
cap per file and a 1,000,000,000-byte default aggregate budget. Before each
read, the detector compares the discovered size with the remaining aggregate
budget and stops with one deterministic error if the next file would reach or
exceed that budget. Parser-specific limits remain stricter where applicable.

The `--redact` option replaces user-specific absolute path prefixes and potential
secret material with stable placeholders so beta reports can be shared safely.

Confidence values distinguish at least:

- `confirmed`: exact known IOC or cryptographic match;
- `high`: strongly correlated campaign evidence;
- `review`: heuristic or suspicious configuration requiring human judgment;
- `contested`: intelligence sources disagree and the disagreement is preserved.

## 7. Initial Detectors

### 7.1 `shai-hulud-keyv`

Repository-focused coverage for the August 2026 Keyv/cacheable npm campaign:

- exact compromised package/version pairs in supported lockfiles;
- npm aliases and historical/current npm, pnpm, and Yarn formats;
- exact compromised package/version pairs in installed package metadata;
- separately modeled contested package/version pairs, reported with source
  attribution and never upgraded to confirmed compromise;
- lifecycle scripts correlated with compromised packages;
- complete SHA-256 payload matches regardless of filename or extension;
- Claude Code startup hooks and VS Code `folderOpen` tasks;
- explicit incomplete reporting for local Git history, whose bundled indicators
  are not evaluated by the alpha runtime until strict metadata confinement exists;
- explicit reporting of unsupported formats and unscanned host-level evidence.

The existing guide script is reference material only. The corrected candidate is
also reference material; the detector is reimplemented behind tests rather than
copied as trusted production code.

### 7.2 `clawhavoc-toxic-skills`

Repository coverage for known malicious agent assets:

- exact malicious skill and author names;
- known typosquats and package names;
- known domains, URLs, repositories, IPs, and hashes;
- fake prerequisite and remote installer patterns;
- encoded execution and hidden-Unicode indicators;
- persistent-instruction targets such as agent memory and instruction files.

Exact IOC matches and heuristic content matches must use different severities and
confidence values.

### 7.3 `repo-persistence-trust-abuse`

Technique-focused coverage for repository-triggered persistence and trust abuse:

- Claude Code startup events;
- VS Code automatic folder-open tasks;
- auto-starting MCP configuration;
- symlinks escaping the repository root;
- symlinks targeting sensitive paths;
- suspicious agent/IDE configuration across supported config directories;
- malformed or unreadable configuration reported as incomplete coverage.

Legitimate hooks are common. Hook presence alone is a review finding, not proof
of compromise.

## 8. Threat Database Migration

The canonical import source is the guide's `examples/commands/resources/
threat-db.yaml` version 2.26.0. The stale skill copy must not be imported.

Before the new repository is declared canonical, the data must be normalized:

1. Add a JSON Schema and CI validation.
2. Assign stable IDs to sources, campaigns, IOC entries, and techniques.
3. Replace free-form source references with `source_ids` where possible.
4. Separate confirmed IOC, hunt signals, heuristics, and contested claims.
5. Add `first_seen`, `last_verified`, `status`, and `confidence` where relevant.
6. Distinguish individual records from aggregated campaign counts.
7. Define correction, retraction, and deprecation procedures.
8. Complete a licensing and attribution review before accepting contributions.

The guide retains its current copy during migration. Canonical ownership changes
only after a tagged release passes schema, detector, and integration tests.

## 9. Error Handling and Safety

The scanner must:

- never execute repository content;
- never write into the scan root;
- never follow symlinks outside the root;
- perform no network requests by default;
- redact potential secrets from evidence;
- bound file sizes, recursion, diagnostics, and memory usage;
- handle hostile filenames and malformed content;
- expose unsupported formats as incomplete coverage;
- produce deterministic ordering in human and JSON output;
- make interruption explicit and return exit code `2`.

## 10. Testing Strategy

Every detector requires positive, near-miss negative, malformed, permission,
symlink, depth, and interruption fixtures. JSON output uses golden tests and a
versioned schema.

Mandatory Shai-Hulud regression coverage includes:

- npm lockfile versions 1, 2, and 3;
- npm package aliases;
- pnpm v5, v6, and v9 syntax, including quoted scoped keys;
- Yarn Classic and Berry aliases/resolutions;
- `@keyv/*@6.0.0` wildcard-scope packages as `high/contested`, preserving JFrog
  and SafeDep attribution while lifecycle-only evidence remains `medium/review`;
- known hashes in `.js`, `.mjs`, extensionless, renamed, and `dist/` files;
- legitimate `setup.mjs` and esbuild lifecycle-script controls;
- nonexistent roots and malformed JSON;
- unreadable inputs and symlinked configuration;
- unsupported `bun.lockb` producing an incomplete result.

CI initially targets current supported Python versions on Linux, macOS, and
Windows. Threat-data validation, unit tests, integration tests, and package build
must all pass before release.

## 11. Release Plan

### `v0.1.0-alpha`

- repository skeleton and contributor/security documentation;
- schema-validated import of the canonical threat database, with the detector
  consuming only its relevant records;
- core engine and result schema;
- Shai-Hulud detector;
- human and JSON output;
- cross-platform CI.

### `v0.2.0-beta`

- ClawHavoc/ToxicSkills detector;
- persistence/trust-abuse detector;
- public beta feedback templates;
- documented false-positive and false-negative reporting workflow.

### `v0.3.0`

- SARIF output;
- GitHub Action;
- PyPI release suitable for `uvx`/`pipx`;
- signed or checksummed release artifacts.

### `v1.0.0`

- stable CLI and JSON schemas;
- stable detector contract;
- documented threat-data governance;
- completed migration of technical source-of-truth ownership.

## 12. Future Landing Integration

Landing integration is not part of V1. The future contract is intentionally
preserved through generated release artifacts:

- the landing consumes a tagged, pinned release rather than `main`;
- generated JSON feeds campaign, technique, IOC, and aggregate data;
- each detector may link to a stable educational campaign page;
- the landing links back to detector source, tests, and release version;
- hardcoded landing copies are removed only after parity checks.

## 13. V1 Acceptance Criteria

V1 is publishable when:

- three detectors are implemented and documented;
- all detectors have positive and negative regression fixtures;
- no incomplete scan can claim a clean verdict;
- the threat database validates against its schema;
- scans work without network access;
- redacted JSON output can be shared without absolute user paths or secrets;
- the JSON result schema is documented and versioned;
- supported CI platforms pass;
- README limitations explicitly reject a clean-machine guarantee;
- the uncorrected guide script is no longer presented as the reliable release.

## 14. Deferred Decisions

The following decisions are deliberately deferred to implementation planning or
specialized review:

- final repository and package names;
- final code and data licenses;
- exact Python support window;
- signing technology for releases;
- remote intelligence-update protocol;
- landing build integration;
- host-level and organization-level scanning.

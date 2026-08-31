# AgentSec Triage Examples

These examples run against explicit local repository roots. AgentSec reads
selected target files but does not execute them or request the network during a
scan.

Complete the [source installation](installation.md) first.

## Common scans

```bash
# Human-readable output
agentsec scan /path/to/repository

# Inspect installed dependency metadata and lockfiles
agentsec scan /path/to/repository --scope dependencies

# Inspect the broad repository tree, including generated and binary paths
agentsec scan /path/to/repository --scope repository

# Versioned JSON for local automation
agentsec scan /path/to/repository --format json

# SARIF 2.1.0 for compatible code-scanning consumers
agentsec scan /path/to/repository --format sarif > agentsec.sarif

# Redact the scan root and recognized secret-shaped values
agentsec scan /path/to/repository --format json --redact

# Show scan phases on stderr
agentsec scan /path/to/repository --progress

# Add bounded file, directory, and byte counters
agentsec scan /path/to/repository --verbose

# Keep stderr silent for non-interactive automation
agentsec scan /path/to/repository --format json --progress=never

# Run one detector explicitly
agentsec scan /path/to/repository --detector shai-hulud-keyv

# Lower the aggregate read budget
agentsec scan /path/to/repository --max-total-bytes 100000000

# Lower traversal budgets for a constrained environment
agentsec scan /path/to/repository --max-entries 250000 --max-directories 25000

# Inspect local resources and detector registration
agentsec doctor
agentsec db info
agentsec detectors list
agentsec detectors explain shai-hulud-keyv
```

## Batch triage

Batch mode accepts explicit roots and calls the same scanner in process. It
does not discover repositories across a parent directory.

```bash
agentsec batch /path/to/repo-a /path/to/repo-b --format json --redact

# One UTF-8 path per non-empty line, limited to 1 MiB and 10,000 roots
agentsec batch --from-file /path/to/roots.txt --scope source --format json
```

Batch exit code is the highest child class: `2` takes precedence over `1`,
which takes precedence over `0`. Human output prints one compact row per root.
JSON embeds every scan-result v2 report and follows
[`batch-result-v1`](../schemas/batch-result-v1.schema.json).

## Verdicts and exit codes

| Exit code | Meaning |
| --- | --- |
| `0` | Every applicable selected detector completed and produced no findings. This is not a clean-machine guarantee. |
| `1` | One or more findings require action or review. Inspect severity, confidence, evidence, and diagnostics. |
| `2` | The scan is incomplete or an error prevents a clean verdict. Do not treat it as a pass. |

Human, JSON, and SARIF output include the selected scope, completion, discovery
exclusions, per-detector coverage, diagnostics, findings, and stable
`not_scanned` capability IDs.

## Scan scopes and repository traversal

AgentSec does not treat `.gitignore` as a security boundary. Instead, each run
uses one deterministic scope and reports every excluded category:

| Scope | Selected paths |
| --- | --- |
| `source` | Ordinary source and configuration plus supported lockfiles. Installed dependencies, generated or cache trees such as `.worktrees`, `.claude/worktrees`, and `.serena`, binary assets, and VCS metadata are excluded. This is the default. |
| `dependencies` | Supported lockfiles and paths below installed `node_modules`. Other source paths are excluded. |
| `repository` | The broad regular-file tree, including installed dependencies, generated trees, and binary paths. VCS metadata remains excluded. |

An exclusion is not a detector inspection. Scan-result v2 therefore separates
`discovery` counters and exclusion reasons from each row under `detectors`.
Broader scopes can hit file or byte limits and become incomplete.

Nested Git repositories and worktrees are separate scan roots. AgentSec detects
their own `.git` marker, skips the nested tree, emits one warning, and tells the
operator to scan it separately for coverage. This prevents a local
`.claude/worktrees` directory from multiplying the same repository and its
dependencies inside one scan. The root repository remains the requested scope.

AgentSec never opens content through symlinks or Windows reparse points. An
internal symlink alias is a measured, non-blocking exclusion only when its
canonical non-link target was independently covered in the same run. External,
broken, changed, pruned-target, or otherwise unsafe links remain blocking.
AgentSec does not invoke Git for an untrusted repository. Git history and VCS
metadata are explicit `not_scanned` or exclusion boundaries, not scan errors.

## Progress output

`--progress` prints the five scan phases to `stderr`. The default `auto` mode
shows them only when `stderr` is a terminal. `--progress=always` forces them and
`--progress=never` disables them. `--verbose` enables progress in non-terminal
runs and adds bounded counters every 1,000 discovered or inspected files.

The first phase confirms the threat database version, update date, bundled
resource location, and active package, hash, domain, and commit-indicator
counts. The second phase prints `Repository validated` with the resolved root,
read-only scan mode, selected detectors, and active safety limits.

During discovery, an interactive terminal receives an indeterminate activity
bar with exact file, directory, and entry counts. AgentSec does not invent a
percentage because the final repository size is unknown until traversal ends.
The bar displays `100%` only when the discovery phase has finished. Redirected
output and CI receive stable newline-delimited messages without terminal control
sequences.

Progress never includes target file content. It shows the resolved repository
and bundled resource paths by default so the operator can confirm the scan
scope. Add `--redact` to replace those paths in progress and report output.
JSON, SARIF, and human reports remain on `stdout`.

## Current detector coverage

The current detector checks evidence associated with the Shai-Hulud Keyv and
cacheable campaign.

| Area | Behavior |
| --- | --- |
| npm | Parses supported `package-lock.json` and `npm-shrinkwrap.json` forms and checks exact package-version pairs. |
| pnpm | Parses tested text lockfile forms. Unsupported or malformed authoritative input makes the scan incomplete. |
| Yarn | Parses tested Classic and Berry forms, including supported aliases and resolutions. |
| Bun | Parses text `bun.lock`; binary `bun.lockb` is unsupported and makes an applicable scan incomplete. |
| Installed packages | Checks local `node_modules/**/package.json` metadata and correlated lifecycle commands in `dependencies` and `repository` scopes. |
| Payloads | Hashes inspected regular files and matches exact SHA-256 indicators. File-size and traversal limits apply. |
| Startup configuration | Checks repository-local Claude Code startup hooks and VS Code `folderOpen` tasks. Hook presence alone is a review finding unless campaign evidence correlates it. |
| Git history | Not scanned until metadata reads can be confined inside the scan root on every supported platform. |

Finding confidence is part of the verdict. `confirmed` means an exact known IOC
match. `high` means strongly correlated evidence. `review` is a heuristic
that needs human analysis. A finding is evidence to investigate, not automatic
proof of compromise.

## Coverage limits

- Host processes, caches, global IDE or agent configuration, credential stores,
  token validity, container images, cloud accounts, remote repositories, remote
  CI logs, and network traffic are not scanned.
- Intelligence is bundled at build time. A scan does not fetch updates or verify
  IOC freshness.
- Files are limited to 4,000,000 bytes. The aggregate read budget defaults to
  1,000,000,000 bytes and can be lowered with `--max-total-bytes`.
- Traversal defaults to at most 1,000,000 directory entries and 100,000 opened
  directories. These hard safety ceilings can only be lowered with
  `--max-entries` and `--max-directories`.
- Package manifests and startup configuration have parser-specific 1 MiB caps.
  Lockfiles have a parser-specific 4 MiB cap.
- Unsupported, unreadable, changed, or budget-exceeding applicable input makes
  the result incomplete instead of silently clean.
- Nested Git repositories are skipped with a warning and must be scanned as
  separate roots. Covered internal symlink aliases are measured exclusions;
  unresolved or unsafe indirection keeps the scan incomplete.
- `--redact` reduces disclosure risk but cannot guarantee removal of arbitrary
  sensitive content.

Stable `not_scanned` IDs report excluded host processes, caches, global
configuration, credentials, remote repositories and CI, container filesystems,
Git history, and automatic remediation.

## Self-scan

A self-scan of the AgentSec source repository is intentionally incomplete:

```bash
agentsec scan . --format json --redact
```

The expected exit code is `2` while the tracked binary `bun.lockb` remains an
unsupported authoritative lockfile. The default source scope excludes `.git`,
the local `.venv`, and build output without reporting their descendants as
inspected. CI also checks positive and negative detector fixtures directly. The
self-scan remains an incomplete-coverage check rather than an oracle for
individual detectors.

The negative fixture demonstrates completed applicable checks without hiding
files:

```bash
agentsec scan tests/fixtures/shai_hulud/negative --format json
```

It exits `1` because benign startup hooks are `review` findings. It must
report `complete: true`, no diagnostic, and no critical finding.

## JSON output

JSON follows the active [scan-result v2 schema](../schemas/scan-result-v2.schema.json).
The [v1 schema](../schemas/scan-result-v1.schema.json) is retained only for
historical consumers. New CLI output is not backward-compatible with v1.
Release values are recorded in the [changelog](../CHANGELOG.md); placeholders
below keep this example stable.

```json
{
  "schema_version": "2",
  "tool_version": "<TOOL_VERSION>",
  "database_version": "<DATABASE_VERSION>",
  "root": "<SCAN_ROOT>",
  "scope": "source",
  "complete": true,
  "elapsed_ms": 4,
  "discovery": {
    "entries_seen": 8,
    "directories_opened": 3,
    "files_selected": 2,
    "exclusions": [
      {
        "reason": "installed_dependencies",
        "paths": 1,
        "subtrees": 1
      }
    ]
  },
  "detectors": [
    {
      "detector_id": "shai-hulud-keyv",
      "applicability": "applicable",
      "files_seen": 2,
      "files_inspected": 2,
      "bytes_inspected": 512,
      "not_scanned": ["git.history"]
    }
  ],
  "not_scanned": [
    "git.history",
    "host.credentials",
    "remote.repositories"
  ],
  "diagnostics": [],
  "findings": [
    {
      "detector_id": "shai-hulud-keyv",
      "rule_id": "compromised-lockfile-version",
      "severity": "critical",
      "confidence": "confirmed",
      "path": "package-lock.json",
      "evidence": "keyv@6.0.0",
      "campaign_ids": ["shai-hulud-keyv-2026-08"],
      "technique_ids": ["npm.compromised-version"],
      "line": null,
      "remediation_url": "https://cc.bruniaux.com/security/"
    }
  ]
}
```

The example illustrates the schema. It is not a claim about a real scan.

The bundled database preserves disputed `@keyv/*@6.0.0` intelligence as a
separate class. A match such as `@keyv/mongo@6.0.0` is reported
`high/contested` with source attribution. It is not promoted to
`critical/confirmed`; a matching lifecycle command remains an independent
`medium/review` heuristic.

## SARIF output

`agentsec scan --format sarif` emits deterministic SARIF `2.1.0`. It is a
representation of the same scan verdict, not a separate analysis mode.

```bash
agentsec scan /path/to/repository --format sarif --redact > agentsec.sarif
scan_exit=$?
```

The SARIF `run` contains:

- one rule ID composed as `<detector_id>/<rule_id>`;
- relative, URI-encoded finding locations under `%SRCROOT%`;
- SARIF levels mapped as `critical/high → error`, `medium → warning`, and
  `low/info → note`;
- original severity, confidence, campaigns, techniques, and remediation URL in
  result properties;
- `agentsec.complete`, diagnostics, discovery exclusions, per-detector
  coverage, and `agentsec.notScanned` in run properties;
- the AgentSec exit code and completion state in `invocations`.

Preserve `scan_exit` in CI. A SARIF file can contain findings from completed
checks while the overall scan remains incomplete. Exit code `2` and
`agentsec.complete: false` must therefore fail the surrounding job. SARIF is
currently available for `scan`; `batch` continues to support human and JSON
output only. AgentSec does not upload the file or configure a code-scanning
service.

## Local performance benchmark

The optional wrapper measures one explicitly supplied repository:

```bash
.venv/bin/python scripts/benchmark_scan.py /path/to/repository \
  --output /path/to/new-report.json
```

It records completion, coverage, counts, versions, wall time, and the scanner
exit code. It does not copy findings, diagnostics, stderr, or the absolute scan
root. The output path must not exist. Exit codes `0`, `1`, and `2` remain
valid measurements in `scan_exit_code`.

Benchmark results depend on hardware, filesystem, repository content, caches,
and platform. This project does not publish a speed claim from one run.

## Privacy and reporting

AgentSec does not transmit the scan root or results. Use `--redact`, inspect the
output manually, and share only the minimum evidence needed.

Use the [security policy](../SECURITY.md) for scanner vulnerabilities, false
positives, false negatives, and IOC corrections. The related educational page
is <https://cc.bruniaux.com/security/>.

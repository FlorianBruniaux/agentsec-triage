# AgentSec Triage Examples

These examples run against one local repository. AgentSec reads target files but
does not execute them or request the network during a scan.

Complete the [source installation](installation.md) first.

## Common scans

```bash
# Human-readable output
agentsec scan /path/to/repository

# Versioned JSON for local automation
agentsec scan /path/to/repository --format json

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

## Verdicts and exit codes

| Exit code | Meaning |
| --- | --- |
| `0` | Every applicable selected detector completed and produced no findings. This is not a clean-machine guarantee. |
| `1` | One or more findings require action or review. Inspect severity, confidence, evidence, and diagnostics. |
| `2` | The scan is incomplete or an error prevents a clean verdict. Do not treat it as a pass. |

Human and JSON output include completion, coverage, diagnostics, findings, the
selected detector, and stable `not_scanned` capability IDs.

## Repository traversal

AgentSec visits every directory entry under the scan root except `.git`. It
does not honor `.gitignore` or other ignore files and has no exclusion option.
Generated content, dependencies, fixtures, and virtual environments remain in
scope so a hostile repository cannot hide evidence behind developer-tool ignore
rules.

Nested Git repositories and worktrees are separate scan roots. AgentSec detects
their own `.git` marker, skips the nested tree, emits one warning, and tells the
operator to scan it separately for coverage. This prevents a local
`.claude/worktrees` directory from multiplying the same repository and its
dependencies inside one scan. The root repository remains the requested scope.

AgentSec does not follow symlinks or Windows reparse points outside the resolved
scan root. Symlinked paths produce one aggregated diagnostic with their total
count, not one line per alias. Their content remains unread and the result is
incomplete. AgentSec does not invoke Git for an untrusted repository. A root
`.git` directory or gitfile produces an incomplete-coverage diagnostic instead
of allowing reads through object symlinks, alternates, or an external gitdir.

## Progress output

`--progress` prints the five scan phases to `stderr`. The default `auto` mode
shows them only when `stderr` is a terminal. `--progress=always` forces them and
`--progress=never` disables them. `--verbose` enables progress in non-terminal
runs and adds bounded counters every 1,000 discovered or inspected files.

Progress never includes target file content or absolute target paths. JSON and
human reports remain on `stdout`.

## Current detector coverage

The current detector checks evidence associated with the Shai-Hulud Keyv and
cacheable campaign.

| Area | Behavior |
| --- | --- |
| npm | Parses supported `package-lock.json` and `npm-shrinkwrap.json` forms and checks exact package-version pairs. |
| pnpm | Parses tested text lockfile forms. Unsupported or malformed authoritative input makes the scan incomplete. |
| Yarn | Parses tested Classic and Berry forms, including supported aliases and resolutions. |
| Bun | Parses text `bun.lock`; binary `bun.lockb` is unsupported and makes an applicable scan incomplete. |
| Installed packages | Checks local `node_modules/**/package.json` metadata and correlated lifecycle commands. |
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
  separate roots. Symlinked paths are not followed and make the requested scan
  incomplete through one aggregated diagnostic.
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

The expected exit code is `2`. The repository `.git` metadata produces the
unscanned-history diagnostic. A local `.venv` or build output may add further
diagnostics. CI checks the unsupported Bun lockfile plus positive and negative
detector inputs against their fixtures directly. The full self-scan remains an
incomplete-coverage check rather than an oracle for individual detectors.

The negative fixture demonstrates completed applicable checks without hiding
files:

```bash
agentsec scan tests/fixtures/shai_hulud/negative --format json
```

It exits `1` because benign startup hooks are `review` findings. It must
report `complete: true`, no diagnostic, and no critical finding.

## JSON output

JSON follows the [public scan-result schema](../schemas/scan-result-v1.schema.json).
Release values are recorded in the [changelog](../CHANGELOG.md); placeholders
below keep this example stable.

```json
{
  "schema_version": "<SCHEMA_VERSION>",
  "tool_version": "<TOOL_VERSION>",
  "database_version": "<DATABASE_VERSION>",
  "root": "<SCAN_ROOT>",
  "complete": true,
  "elapsed_ms": 4,
  "coverage": {
    "files_seen": 2,
    "files_inspected": 2,
    "bytes_inspected": 512
  },
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

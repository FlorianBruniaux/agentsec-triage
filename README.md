# AgentSec Triage

AgentSec Triage is an alpha command-line scanner for evidence associated with
documented attacks against developers, software supply chains, and coding-agent
configuration. It scans files inside one local repository. Scans are
deterministic, read-only, and offline by default. Local Git history is not scanned
in this alpha because Git metadata cannot yet be confined atomically to the scan
root.

This alpha does not certify that a repository, workstation, dependency set, or
account is clean. It is not an antivirus, EDR, general SAST, dependency scanner,
or secret scanner. A result covers only the implemented detector, supported
inputs, and limits reported by that run.

Public distribution is blocked by the unresolved [license decision](LICENSE-DECISION.md).
The commands below are for review from this source tree, not a published package.

## Quick start from source

Python 3.11 through 3.13 is the supported alpha target.

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e ".[dev]"
.venv/bin/agentsec doctor
.venv/bin/agentsec scan /path/to/repository
```

On Windows PowerShell, use `.venv\Scripts\python` and
`.venv\Scripts\agentsec` instead of the `bin` paths. Do not install from PyPI:
no public release is authorized while the licensing gate is open.

## Scan examples

```bash
# Human output
agentsec scan .

# Versioned JSON output suitable for local automation
agentsec scan . --format json

# Replace the scan root and recognized secret-shaped values before output
agentsec scan . --format json --redact

# Run one detector explicitly
agentsec scan . --detector shai-hulud-keyv

# Tighten the aggregate read budget; the default is 1,000,000,000 bytes
agentsec scan . --max-total-bytes 100000000

# Inspect local resources and detector registration
agentsec doctor
agentsec db info
agentsec detectors list
agentsec detectors explain shai-hulud-keyv
```

AgentSec never executes files from the target repository. It does not follow
symlinks or Windows reparse points outside the resolved scan root. It does not
invoke Git for an untrusted repository. When `.git` exists as a directory or
gitfile, the scan reports incomplete coverage with exit code `2` instead of
risking reads through object symlinks, alternates, or an external gitdir.

Traversal is exhaustive by design. AgentSec visits every directory entry under
the scan root except `.git`, does not honor `.gitignore` or other ignore files,
and has no exclusion option in V0.1. Ignored, generated, dependency, fixture, and
virtual-environment content remains in scope. This avoids letting a hostile
repository hide evidence behind developer-tool ignore rules.

## Verdicts and exit codes

| Exit code | Meaning |
| --- | --- |
| `0` | Every applicable selected detector completed and produced no findings. This is not a clean-machine guarantee. |
| `1` | One or more findings require action or review. Inspect severity, confidence, evidence, and diagnostics. |
| `2` | The scan is incomplete or an error prevents a clean verdict. Do not treat it as a pass. |

Human and JSON output include completion, coverage, diagnostics, findings, and
the selected detector and V0.1-wide `not_scanned` / **Not scanned** capability
IDs. Declared exclusions are transparency metadata. They do not make an
otherwise completed in-scope scan incomplete.

## V0.1 coverage

The alpha ships one detector, `shai-hulud-keyv` version 1, backed by the bundled
threat database version 2.26.0.

| Area | V0.1 behavior |
| --- | --- |
| npm | Parses supported `package-lock.json` and `npm-shrinkwrap.json` variants and checks exact compromised package/version pairs. |
| pnpm | Parses tested v5, v6, and v9 text lockfile forms. Unsupported or malformed authoritative input makes the scan incomplete. |
| Yarn | Parses tested Classic and Berry lockfile forms, including supported aliases and resolutions. |
| Bun | Parses supported text `bun.lock`; binary `bun.lockb` is not supported and makes an applicable scan incomplete. |
| Installed packages | Checks local `node_modules/**/package.json` metadata and correlated lifecycle commands. |
| Payloads | Hashes inspected regular files and matches exact SHA-256 indicators from the bundled database. File-size and traversal limits apply. |
| Startup configuration | Checks repository-local Claude Code startup hooks and VS Code `folderOpen` tasks. Hook presence alone is a review finding unless campaign evidence correlates it. |
| Git history | Not scanned. A `.git` directory or gitfile emits `Local Git history not scanned: strict metadata confinement unavailable` and makes the result incomplete. No Git-history IOC finding is produced. |

Finding confidence is part of the verdict. `confirmed` means an exact known IOC
match. `high` means strongly correlated evidence. `review` is a heuristic that
needs human analysis. A finding is evidence to investigate, not automatic proof
of compromise.

## V0.1 alpha limitations and threat model

- Only the repository-scoped Shai-Hulud Keyv/cacheable detector is implemented.
  ClawHavoc/ToxicSkills and general persistence or trust-abuse detection are not
  present in V0.1.
- Host processes, caches, global IDE or agent configuration, credential stores,
  token validity, container images, cloud accounts, remote repositories, remote
  CI logs, and network traffic are not scanned.
- Scans do not fetch intelligence or verify IOC freshness. The bundled database
  is fixed at build time.
- File, directory-entry, diagnostic, and byte bounds protect the scanner.
  A file that exactly fills the remaining byte budget is accepted. A later file
  or a file that exceeds the remaining budget makes the result incomplete
  rather than silently clean. A failed safe read stops further file reads so
  bytes consumed before a concurrent-change error cannot be spent twice. At a
  zero aggregate budget, empty files are inspected normally while any nonempty
  file is rejected before a physical read.
- The safe reader accepts at most 4,000,000 bytes per file. The aggregate read
  budget defaults to 1,000,000,000 bytes and can be lowered with
  `--max-total-bytes`. Package manifests and repository startup configuration
  have stricter parser-specific 1 MiB caps. Lockfiles have a parser-specific
  4 MiB cap.
- Stable `not_scanned` IDs report the V0.1 exclusions for host processes,
  caches, global configuration, credentials, remote repositories and CI,
  container filesystems, Git history, and automatic remediation.
- `--redact` recognizes specific path and secret-shaped patterns. It reduces
  disclosure risk but is not a guarantee that arbitrary sensitive content was
  removed. Review output before sharing it.
- Linux, macOS, and Windows with Python 3.11, 3.12, and 3.13 are CI targets. This
  source checkout was not locally verified on all nine combinations. On every
  platform, local Git history remains disabled until strict metadata confinement
  can be guaranteed.

## Self-scan release expectation

A self-scan of this repository is intentionally not a clean or complete scan:

```bash
agentsec scan . --format json --redact
```

The expected exit code is `2`. The repository's `.git` metadata must produce the
documented unscanned-history diagnostic. The tracked positive fixtures must
remain visible as findings, while `tests/fixtures/lockfiles/bun.lockb` must produce
the documented unsupported-format diagnostic. Local `.venv` symlinks and
generated build artifacts may add further incomplete-coverage diagnostics. The
release gate checks this exact shape and never treats self-scan output as a
clean-machine claim.

The supported negative fixture provides a completed applicable scan without
hiding files:

```bash
agentsec scan tests/fixtures/shai_hulud/negative --format json
```

It currently exits `1` because its benign startup hooks are `review` findings. It
must report `complete: true`, no diagnostic, and no critical finding.

## JSON output

JSON follows [`schemas/scan-result-v1.schema.json`](schemas/scan-result-v1.schema.json).
This abridged example shows the shape of a confirmed finding:

```json
{
  "schema_version": "1",
  "tool_version": "0.1.0a0",
  "database_version": "2.26.0",
  "root": "<SCAN_ROOT>",
  "complete": true,
  "elapsed_ms": 4,
  "coverage": {
    "files_seen": 2,
    "files_inspected": 2,
    "bytes_inspected": 512
  },
  "not_scanned": [
    "container.filesystems",
    "git.history",
    "host.caches",
    "host.credentials",
    "host.global_config",
    "host.processes",
    "remediation.automatic",
    "remote.ci",
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

The example values illustrate the schema. They are not a claim about a real scan.

The bundled database preserves the disputed `@keyv/*@6.0.0` intelligence as a
separate class. Matches such as `@keyv/mongo@6.0.0` are reported
`high/contested`, with the JFrog and SafeDep attribution in evidence. They are
not promoted to `critical/confirmed`; a matching lifecycle command remains the
independent `medium/review` heuristic.

## Privacy and reporting

Scanning is local and offline by default. AgentSec does not transmit the scan
root or results. Use `--redact` before preparing a report, inspect the redacted
file manually, and share only the minimum evidence needed.

Use [SECURITY.md](SECURITY.md) for scanner vulnerabilities, false positives,
false negatives, and IOC corrections. The related educational page is
<https://cc.bruniaux.com/security/>.

## Contributing

Contributions must follow the test-first and threat-source requirements in
[CONTRIBUTING.md](CONTRIBUTING.md). Public redistribution and release remain
blocked until [LICENSE-DECISION.md](LICENSE-DECISION.md) is resolved.

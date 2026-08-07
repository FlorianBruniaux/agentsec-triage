# AgentSec Triage

AgentSec Triage is an alpha command-line scanner for evidence associated with
documented attacks against developers, software supply chains, and coding-agent
configuration. It scans one local repository and its local Git metadata. Scans
are deterministic, read-only, and offline by default.

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

# Inspect local resources and detector registration
agentsec doctor
agentsec db info
agentsec detectors list
agentsec detectors explain shai-hulud-keyv
```

AgentSec never executes files from the target repository. It does not follow
symlinks or Windows reparse points outside the resolved scan root. Git inspection
uses a bounded command with repository hooks, external protocols, prompts, and
lazy fetching disabled.

## Verdicts and exit codes

| Exit code | Meaning |
| --- | --- |
| `0` | Every applicable selected detector completed and produced no findings. This is not a clean-machine guarantee. |
| `1` | One or more findings require action or review. Inspect severity, confidence, evidence, and diagnostics. |
| `2` | The scan is incomplete or an error prevents a clean verdict. Do not treat it as a pass. |

Human and JSON output include completion, coverage, diagnostics, findings, and
the detector-declared `not_scanned` / **Not scanned** list. An empty list does
not expand the threat model: the fixed V0.1 exclusions below still apply.

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
| Git history | Checks bounded local history for exact documented campaign identity tuples when a trusted system Git executable is available. |

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
- File, directory-entry, diagnostic, byte, and Git-history bounds protect the
  scanner. Reaching a relevant bound makes the result incomplete rather than
  silently clean.
- `--redact` recognizes specific path and secret-shaped patterns. It reduces
  disclosure risk but is not a guarantee that arbitrary sensitive content was
  removed. Review output before sharing it.
- Linux, macOS, and Windows with Python 3.11, 3.12, and 3.13 are CI targets. This
  source checkout was not locally verified on all nine combinations. On Windows,
  reparse-point traversal is refused and local Git history is available only when
  a trusted Git executable can be resolved from a system or Program Files
  location; otherwise the scan reports incomplete coverage with exit code `2`.

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
  "not_scanned": [],
  "diagnostics": [],
  "findings": [
    {
      "detector_id": "shai-hulud-keyv",
      "rule_id": "compromised-lockfile-version",
      "severity": "critical",
      "confidence": "confirmed",
      "path": "package-lock.json",
      "evidence": "@keyv/mongo@6.0.0",
      "campaign_ids": ["shai-hulud-keyv-2026-08"],
      "technique_ids": [],
      "line": null,
      "remediation_url": null
    }
  ]
}
```

The example values illustrate the schema. They are not a claim about a real scan.

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


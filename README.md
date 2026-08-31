# AgentSec Triage

[![Tests](https://github.com/FlorianBruniaux/agentsec-triage/actions/workflows/tests.yml/badge.svg?branch=main)](https://github.com/FlorianBruniaux/agentsec-triage/actions/workflows/tests.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/)
[![Status: alpha](https://img.shields.io/badge/status-alpha-orange)](CHANGELOG.md)

Turn sourced threat intelligence into deterministic checks for local
repositories. AgentSec scans one explicit root, reports what it inspected, and
fails closed when applicable evidence cannot be read reliably.

Scans are **read-only** and **offline by default**. AgentSec does not certify
that a repository, workstation, dependency set, or account is clean.

![AgentSec workflow: repository source, lockfiles, and agent configuration pass through a bounded offline scan, campaign detection, coverage-aware reporting, and manual response outputs.](docs/assets/agentsec-workflow.png)

AgentSec is a public source repository in alpha. Install it from a checked-out
copy; no package or tagged release is authorized yet.

## Start here

| Goal | Command or guide | Result |
| --- | --- | --- |
| Install from source | [Installation guide](docs/installation.md) | Local `agentsec` command and runtime verification |
| Check the installation | `agentsec doctor` | Database, schema, and packaged-resource status |
| Scan one repository | `agentsec scan /path/to/repo --progress --verbose --redact` | Human verdict with phase and bounded progress details on `stderr` |
| Produce machine output | `agentsec scan /path/to/repo --format json --redact` | Versioned scan-result v2 JSON |
| Export for code scanning | `agentsec scan /path/to/repo --format sarif --redact > agentsec.sarif` | SARIF 2.1.0 with completion and coverage metadata |
| Explain one detector | `agentsec detectors explain shai-hulud-keyv` | Rules, inputs, sources, limits, and `not_scanned` capabilities |
| Scan an explicit list | `agentsec batch /repo/a /repo/b --format json --redact` | Ordered batch result with aggregate exit status |

Read the [examples and verdict guide](docs/examples.md) before automating the
result. Exit code `2` means incomplete coverage, not success.

## What it checks today

AgentSec currently ships two detector families. The wider intelligence catalogue
contains research that has not been promoted into executable checks.

| Detector | Repository evidence | Main inputs |
| --- | --- | --- |
| `shai-hulud-keyv` | Documented compromised package versions, payload hashes, lifecycle scripts, and repository startup hooks associated with the Shai-Hulud/Keyv campaign | Supported `npm`, `pnpm`, Yarn, and text Bun lockfiles; installed package metadata; `.claude` settings; VS Code tasks; regular-file SHA-256 |
| `clawhavoc-skill` | Exact bundled campaign domains in `SKILL.md` or explicitly delegated same-skill setup instructions | Repository-local `SKILL.md` and referenced Markdown setup files |

Run `agentsec detectors explain DETECTOR_ID --format json` for the current
coverage contract. Binary `bun.lockb`, Git history, remote repositories,
registry history, remote payloads, runtime behavior, host credentials, and host
processes are not inspected.

## Read the result

| Exit code | Meaning |
| --- | --- |
| `0` | Applicable checks completed and produced no finding. This is not a clean-system certificate. |
| `1` | At least one finding requires action or review. |
| `2` | The scan failed or applicable coverage is incomplete. Findings already collected remain in the report. |

Reports keep **findings**, **diagnostics**, **discovery exclusions**,
**per-detector coverage**, and **unsupported capabilities** separate. This
prevents a skipped input from being presented as a successful check.

Versioned [response playbooks](docs/response-playbooks/) separate evidence
collection, manual containment, remediation, and verification. AgentSec does
not perform destructive remediation.

## Scope and safety

The default `source` scope excludes installed dependencies, generated trees,
caches, binary assets, and VCS metadata while retaining supported lockfiles.
Choose a broader scope explicitly when the investigation needs it:

```bash
agentsec scan /path/to/repo --scope dependencies
agentsec scan /path/to/repo --scope repository
```

AgentSec does not execute target content, invoke Git on the target repository,
request the network during a scan, or follow filesystem indirection outside the
scan root. Unreadable, changed, unsupported, or budget-exceeding applicable
inputs make the result incomplete.

AgentSec is not an antivirus, EDR, general SAST, dependency scanner, or secret
scanner. Its result covers only the implemented detectors and supported inputs
reported by that run.

## Outputs and automation

- Human output for local review.
- [Scan-result v2 JSON](schemas/scan-result-v2.schema.json) and
  [batch-result v1 JSON](schemas/batch-result-v1.schema.json).
- SARIF 2.1.0 with AgentSec completion, coverage, diagnostic, and exclusion
  properties.
- A repository-local [GitHub Action](action.yml) that runs checked-out source,
  validates SARIF, and preserves exit codes.
- A versioned [public security feed](exports/security-feed.v1.json) mirrored into
  the Claude Code Ultimate Guide and its landing page, with drift rejected in
  CI.

Remote Action use remains blocked until a release is authorized. See the
[project overview](docs/project-overview.md) for the data flow, product
surfaces, sources of truth, and integration boundaries.

## Documentation

| Need | Document |
| --- | --- |
| Install and run the first scan | [Installation](docs/installation.md) |
| Interpret human, JSON, SARIF, and incomplete results | [Examples and verdicts](docs/examples.md) |
| Understand architecture and canonical files | [Project overview](docs/project-overview.md) |
| Respond to a finding | [Response playbooks](docs/response-playbooks/) |
| Review sources and dated events | [Security intelligence](docs/SECURITY-INTELLIGENCE.md) and [timeline](docs/SECURITY-TIMELINE.md) |
| Add a source, event, IOC, or detector | [Intelligence authoring](docs/intelligence-authoring.md) |
| Give the task to an LLM | [Copy-ready prompt](PROMPT.md) and [LLM index](llms.txt) |
| Review priorities and shipped work | [Roadmap](ROADMAP.md) and [changelog](CHANGELOG.md) |
| Report a vulnerability or incorrect result | [Security policy](SECURITY.md) |
| Contribute code or intelligence | [Contributing](CONTRIBUTING.md) |

The related educational security page is <https://cc.bruniaux.com/security/>.

## License status

Project-owned code and original documentation use the [MIT License](LICENSE).
The paths listed in [LICENSE-DATA.md](LICENSE-DATA.md) remain unavailable for
public redistribution while their separate rights and CC BY-SA 4.0 review is
open.

Public visibility does not authorize a package, tag, source archive, GitHub
Release, or redistribution of gated data. The blocking decisions are recorded
in [LICENSE-DECISION.md](LICENSE-DECISION.md).

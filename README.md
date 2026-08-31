# AgentSec Triage

AgentSec Triage is an alpha command-line scanner for evidence associated with
documented attacks against developers, software supply chains, and coding-agent
configuration. It scans explicit local repository roots. Scans are
**deterministic**, **read-only**, and **offline by default**.

AgentSec does not certify that a repository, workstation, dependency set, or
account is clean. It is not an antivirus, EDR, general SAST, dependency scanner,
or secret scanner. A result covers only the implemented detectors, supported
inputs, and limits reported by that run.

## At a glance

| Question | Answer |
| --- | --- |
| What does it scan? | **Source**, **installed dependencies**, or the **full repository**, according to an explicit scope. |
| What does it detect today? | Evidence associated with the documented **Shai-Hulud/Keyv campaign**, plus exact **ClawHavoc** campaign-domain references in `SKILL.md` and explicitly delegated local setup instructions. |
| Which package formats are covered? | Supported `npm`, `pnpm`, `Yarn`, and `Bun` text lockfiles. Installed `node_modules` metadata requires `--scope dependencies` or `--scope repository`. Binary `bun.lockb` is **unsupported**. |
| How does it run? | **Deterministically**, **read-only**, and **offline by default**. It does not follow symlinks outside the scan root or invoke Git on the target repository. |
| What does it return? | Human-readable, versioned `JSON`, or `SARIF 2.1.0` with measured **discovery exclusions**, per-detector **coverage**, findings, diagnostics, and completion status. |
| What happens after a finding? | Versioned **response playbooks** separate evidence collection, manual containment, remediation, and verification without destructive automation. |
| What do exit codes mean? | `0`: completed checks found nothing; `1`: findings require action or review; `2`: the scan is incomplete or failed. |
| Can it run in GitHub Actions? | A repository-local composite [`action.yml`](action.yml) runs the checked-out source and preserves exit codes. Remote action use and release installation remain blocked by the data-license gate. |
| What does it not do? | It does not certify a repository as **clean** and does not replace antivirus, `EDR`, `SAST`, dependency, or secret scanning. |
| What is the current status? | **Alpha**, public source repository, and **no authorized package or tagged release**. See the [changelog](CHANGELOG.md). |

## Try it from source

Follow the [installation guide](docs/installation.md), then scan one repository:

```bash
agentsec scan /path/to/repository --format json --redact
```

The default `source` scope excludes installed dependencies, generated or cache
trees, binary assets, and VCS metadata while keeping supported lockfiles. Use
an explicit broader scope when the investigation requires it:

```bash
agentsec scan /path/to/repository --scope dependencies
agentsec scan /path/to/repository --scope repository
agentsec scan /path/to/repository --format sarif --redact > agentsec.sarif
agentsec batch /path/to/repo-a /path/to/repo-b --format json --redact
```

For an interactive scan with phase and bounded counter updates:

```bash
agentsec scan /path/to/repository --progress --verbose --redact
```

Progress is written to `stderr`. It confirms the loaded threat database,
validated repository, scan limits, live discovery counts, and phase completion.
The human, JSON, or SARIF report remains isolated on `stdout`, so local
automation can parse it without stripping status lines. Use `--redact` when
paths must not appear in progress output.

Read the [examples and verdict guide](docs/examples.md) before interpreting the
result. In particular, exit code `2` is an incomplete scan, not a pass.

Current scan JSON follows [scan-result v2](schemas/scan-result-v2.schema.json).
Batch JSON follows [batch-result v1](schemas/batch-result-v1.schema.json). The
older [scan-result v1](schemas/scan-result-v1.schema.json) remains available as
a historical contract, but new CLI output no longer conforms to it. Scan SARIF
uses the standard `2.1.0` envelope and keeps AgentSec completion, diagnostics,
exclusions, detector coverage, and `not_scanned` capabilities under explicit
`agentsec.*` properties. SARIF output preserves the scan exit code; an
incomplete scan still exits `2`.

The repository-local composite action invokes that SARIF path without fetching
or installing AgentSec. It stages the report outside the scan root, validates
the completion metadata, publishes the configured file, and returns the exact
scanner exit class. See the [pinned local-action example](docs/examples/agentsec-local-action.yml).
This is not a remotely consumable release: no authorized package, release
checksum, or provenance artifact exists while the data-license decision is
open.

Inspect the implemented coverage contract without scanning a repository:

```bash
agentsec detectors explain shai-hulud-keyv --format json
```

The machine output follows
[detector-explain v1](schemas/detector-explain-v1.schema.json). It separates
active rules and sources, threat records that are only documented or partially
projected, and stable capabilities that remain `not_scanned`.

## Documentation

- [Installation](docs/installation.md): source setup, verification, and Windows commands.
- [Examples](docs/examples.md): scans, verdicts, JSON, SARIF, coverage limits, and benchmark.
- [Local action manifest](action.yml): checked-out source wrapper with fail-closed SARIF.
- [Pinned action workflow](docs/examples/agentsec-local-action.yml): local consumer example with full third-party action SHAs.
- [Response playbooks](docs/response-playbooks/): sourced, manual response steps for every active detector rule.
- [Copy-ready LLM prompt](PROMPT.md): ask an LLM to run a read-only repository triage.
- [LLM index](llms.txt): compact map of canonical project documentation.
- [Security policy](SECURITY.md): vulnerabilities, false results, and IOC corrections.
- [Security intelligence](docs/SECURITY-INTELLIGENCE.md): reviewed sources.
- [Security timeline](docs/SECURITY-TIMELINE.md): events tracked by AgentSec.
- [Scanner ecosystem](docs/ECOSYSTEM.md): competitors, adjacent tools, naming collisions, and product gaps.
- [Competitive analysis plan](docs/COMPETITIVE-ANALYSIS-PLAN.md): static reviews, isolated benchmarks, product gates, and naming work.
- [Product decisions](docs/competitive-analysis/PRODUCT-DECISIONS.md): accepted parity, differentiation, scope, and delivery sequence.
- [Benchmark results](docs/competitive-analysis/BENCHMARK-RESULTS.md): observed clean controls, AgentSec baseline, prepared plans, and explicit unknowns.
- [Naming brief](docs/NAMING.md): collision screening, shortlist, comprehension gate, and migration surface.
- [Naming test kit](docs/naming-comprehension-test-kit.md): blind protocol, reproducible order, scoring, and decision threshold.
- [License prose inventory](docs/LICENSE-PROSE-INVENTORY.json): generated 430-field review ledger with stable digests and source locators.
- [Intelligence authoring](docs/intelligence-authoring.md): add a source, fiche, IOC, or detector.
- [Threat database update command](.claude/commands/update-threat-db.md): source review, promotion gates, generation, and consumer sync.
- [Public security feed](exports/security-feed.v1.json): versioned metadata consumed by the guide and landing.
- [Roadmap](ROADMAP.md): priorities, release gates, and non-goals.
- [Changelog](CHANGELOG.md): release-specific versions and implemented changes.
- [Contributing](CONTRIBUTING.md): test-first and threat-source requirements.

## Safety boundary

AgentSec never executes files from the target repository, follows filesystem
indirection outside the scan root, or requests the network during a scan.
Unsupported, unreadable, changed, or budget-exceeding applicable input makes the
scan incomplete. Review redacted output before sharing it.

The related educational security page is <https://cc.bruniaux.com/security/>.

## License status

Project-owned code and original documentation are licensed under the
[MIT License](LICENSE). The data paths listed in
[LICENSE-DATA.md](LICENSE-DATA.md) remain unavailable for public redistribution
until their separate rights and CC BY-SA 4.0 review is complete. The narrow
public-feed exception and excluded fields are recorded in that file.

The source repository is publicly visible. That visibility does not grant a
separate license for the gated data paths. Do not publish a package, tag,
source archive, or GitHub release while
[LICENSE-DECISION.md](LICENSE-DECISION.md) is unresolved.

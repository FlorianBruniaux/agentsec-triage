# When to Use AgentSec

Use AgentSec when the question is: **does this repository contain evidence that
matches a supported coding-agent or supply-chain campaign, and did the scan
inspect every applicable input it claims to cover?**

AgentSec is a repository triage tool. It is not a general security scanner and
does not certify that a repository or machine is clean.

## Good times to run it

| Moment | What AgentSec contributes |
| --- | --- |
| Before opening or delegating to an unfamiliar repository | A read-only, offline preflight over supported repository evidence without executing target content |
| After a campaign disclosure | A deterministic check for the exact package versions, hashes, commands, or domains promoted into an active detector |
| After lockfile, hook, task, or skill changes | A repeatable comparison against the bundled intelligence version |
| In repository CI | Versioned JSON or SARIF plus an exit code that distinguishes findings from incomplete coverage |
| During incident triage | Source-linked findings and response playbooks that preserve confidence and contested intelligence |

Run `agentsec detectors list` and `agentsec detectors explain DETECTOR_ID`
before relying on a scan. The intelligence catalogue is broader than runtime
coverage. AgentSec currently implements two detector families for selected
Shai-Hulud/Keyv and ClawHavoc evidence.

## Choose another control for a different question

| Question | Better control | Relationship to AgentSec |
| --- | --- | --- |
| Which dependencies have published vulnerabilities across my technology stack? | Software composition analysis such as OSV-Scanner or Grype | Complementary. AgentSec checks selected campaign evidence rather than providing broad CVE coverage. |
| Does the application source contain common coding vulnerabilities? | Language-aware SAST | Complementary. Generic source vulnerability analysis is outside AgentSec scope. |
| Did the repository expose credentials? | A dedicated secret scanner | Complementary. AgentSec does not claim general secret detection. |
| Is the workstation compromised or is an agent behaving maliciously now? | EDR, process and network monitoring, or an agent runtime control | Required for host evidence. AgentSec does not inspect processes, network traffic, credentials, or persistence. |
| Are installed skills, MCP servers, and agent configurations broadly safe? | A skill, MCP, or host-configuration scanner | Usually broader. AgentSec checks only repository artifacts covered by its active campaign rules. |
| Should an unfamiliar repository receive a broad trust verdict? | A broader preflight scanner or a combined review workflow | AgentSec supplies campaign evidence and coverage facts, not a universal GO or NO-GO verdict. |

For concrete products in each category, use the dated
[repository and agent security scanner ecosystem](ECOSYSTEM.md). That study
compares AgentSec with Aguara, patient-zero, Repo Forensics, AgentShield, Snyk
Agent Scan, AgentSeal, Medusa, cc-audit, DeepSafe Scan, skill scanners, MCP
scanners, SCA tools, and runtime controls. Project claims in that document are
labelled by evidence level and are not treated as benchmark results.

## Closest alternatives in the current study

This table summarizes declared scope from the ecosystem snapshot dated
2026-08-24. It is a selection aid, not a detection benchmark.

| Project | Prefer it when | Prefer AgentSec when |
| --- | --- | --- |
| [Aguara](https://github.com/garagon/aguara) | You need a broader repository preflight, more distribution formats, or optional intelligence updates | You need a smaller campaign rule set with explicit source-to-fixture traceability and incomplete-coverage semantics |
| [patient-zero](https://github.com/0xSteph/patient-zero) | You need a wider supply-chain incident workflow, install blocking, process checks, persistence checks, or a frequently refreshed IOC feed | You need a bounded repository-only scan that uses a reviewed bundled snapshot and makes no network request |
| [Repo Forensics](https://github.com/alexgreensh/repo-forensics) | You need post-incident Git and host traces in addition to repository artifacts | You need strict repository confinement and deterministic evidence without host inspection |
| [AgentShield](https://github.com/affaan-m/agentshield) | You need a broad audit of agent configuration, permissions, secrets, hooks, MCP, and workflows | You need findings tied to a tracked campaign, confidence state, correction history, and reproducible detector fixtures |
| [Snyk Agent Scan](https://github.com/snyk/agent-scan) or [AgentSeal](https://github.com/getagentseal/agentseal) | You need machine-wide discovery, installed components, or live MCP analysis | You cannot execute configured servers, send repository evidence to an API, or extend the scan beyond one explicit root |

AgentSec does not currently beat these projects on breadth or distribution. Its
case rests on evidence provenance, coverage honesty, confinement, and
reproducibility. The controlled comparisons recorded in
[`docs/competitive-analysis/`](competitive-analysis/) must remain the source
for any future claim about observed behavior.

## Why use AgentSec alongside broader scanners

Local scanning, deterministic rules, SARIF, GitHub Actions, skill checks, and
malicious-package intelligence already exist elsewhere. AgentSec concentrates
on six properties that need to remain visible in the result:

1. **Campaign traceability.** A promoted rule links the source, event, IOC,
   fixture, regression test, finding, and response guidance.
2. **Coverage as data.** `detected`, `partial`, `not_detected`,
   `not_applicable`, and `not_scanned` remain separate states.
3. **Fail-closed results.** An unreadable or unsupported applicable input makes
   the scan incomplete with exit code `2`; it is not reported as a clean check.
4. **Attributable intelligence.** Conflicting reports, corrections,
   retractions, dates, and confidence keep their sources and status.
5. **Repository confinement.** The scanner does not execute target content,
   write into the target, request the network, or follow filesystem indirection
   outside the selected root.
6. **Reproducible evidence.** Inert positive and near-miss fixtures prove the
   behavior of each active detector rule.

The trade-off is breadth. Aguara declares a wider repository preflight scope,
patient-zero covers a broader campaign-response workflow, AgentShield focuses
on agent configuration and hardening, and host or runtime scanners observe
surfaces AgentSec cannot see. AgentSec is useful when provenance, deterministic
repository evidence, and explicit incomplete coverage matter more than a large
count of generic checks.

## Relationship to cc.bruniaux.com/security

[The Claude Code Guide security page](https://cc.bruniaux.com/security/) is the
human-readable security and threat-intelligence surface. AgentSec began with a
byte-identical import of version `2.26.0` from the guide's canonical
`threat-db.yaml`; the import path and digest are recorded in
[`data/IMPORT_PROVENANCE.md`](../data/IMPORT_PROVENANCE.md). AgentSec then
adapted that database for deterministic validation and detector confidence.

The current flow is:

```text
reviewed sources and incidents
  -> data/intelligence/ and data/threat-db.yaml
  -> validated builders
  -> bundled threat-db.json used by offline scans
  -> findings, diagnostics, coverage, and response guidance
  -> exports/security-feed.v1.json
  -> guide and landing mirrors, including cc.bruniaux.com/security
```

This relationship has three consequences:

- every scan records the bundled database version and works without contacting
  the guide or another remote service;
- the security page can publish reviewed incidents with `detected`, `partial`,
  `not_detected`, or `not_applicable` coverage, so its catalogue size must not
  be read as the number of active scanner rules;
- AgentSec findings link back to the security page for context and remediation,
  while CI checks that the versioned public feed has not diverged between the
  AgentSec, guide, and landing repositories.

The complete authoring database is not the public feed. The feed excludes the
gated fields listed in [`LICENSE-DATA.md`](../LICENSE-DATA.md), and package,
tag, archive, and remote Action publication remain blocked by
[`LICENSE-DECISION.md`](../LICENSE-DECISION.md).

## A practical security stack

For an unfamiliar coding-agent repository, combine controls by question:

1. Run AgentSec for supported campaign evidence and coverage gaps.
2. Run SCA for broad dependency vulnerabilities and a secret scanner for
   credential exposure.
3. Run language-aware SAST and the repository's tests for application code.
4. Review agent permissions, hooks, skills, MCP configuration, and CI trust
   with a broader configuration scanner when those surfaces matter.
5. Use host and runtime monitoring if the repository may already have executed.

No single result from this stack proves that the repository, workstation,
dependency graph, remote account, or agent session is clean.

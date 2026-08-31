# Product decisions from competitive evidence

Status: **accepted for the V0.1 alpha sequence**

Decision date: 2026-08-31

These decisions use the 16 pinned static profiles, seven digest-approved
`clean-control` runs, and the 12-fixture AgentSec baseline. They do not infer
detection parity from one negative fixture.

## Product contract

AgentSec scans an explicit repository before trust or installation. It runs
offline, never executes target content, and converts reviewed attack-campaign
research into local evidence. Every result states what was inspected, skipped,
unsupported, or outside scope. No result certifies that a repository, machine,
dependency set, or account is clean.

## Parity requirements

| Requirement | Accepted proof | Current state |
| --- | --- | --- |
| Reproducible installation | Pinned artifact, checksum, provenance, and clean install verification | Blocked by data-license gate |
| Multiple detector families | Sourced positive and near-miss fixture per family, stable IDs, and explicit limits | One active family; skill expansion in progress |
| SARIF 2.1.0 | Deterministic output preserving incomplete exit `2`, diagnostics, exclusions, and `not_scanned` | Implemented locally; integration pending |
| Pinned GitHub Action | Commit-pinned action and dependencies, offline scan, SARIF artifact, fixture test, and no implicit upload | Source action in progress; release pin blocked |
| Explain and coverage interface | Each detector exposes sources, inputs, rules, applicability, limits, remediation, and unsupported capabilities | Partial through `detectors explain` and scan-result v2 |

## Differentiation bets

### Campaign-to-detector traceability

User job: answer whether a repository contains evidence tied to a reviewed
campaign.

Proof:

- every campaign rule cites a stable source;
- the runtime artifact maps campaign, technique, detector, rule, confidence,
  severity, and remediation;
- positive, contested, and near-miss fixtures preserve those distinctions;
- generated artifacts are deterministic and digest-checked.

### Fail-closed coverage

User job: distinguish "no finding" from "not inspected".

Proof:

- unreadable, unsupported, changed, or budget-exceeding applicable input makes
  `complete=false` and exits `2`;
- human, JSON, SARIF, and batch output retain the same completion boundary;
- every detector reports applicability, inspected counts, and `not_scanned`;
- a zero-applicability scan never receives a safety grade.

### Campaign response playbooks

User job: move from local evidence to bounded containment and verification
steps without automatic remediation.

Proof:

- every confirmed or contested campaign finding links to a versioned playbook;
- the playbook separates evidence collection, containment, remediation, and
  follow-up verification;
- destructive actions remain manual and explicitly authorized;
- corrections and retractions preserve earlier provenance.

## Rejected scope for V0.1

- aggregate safety grades or claims that a repository is clean;
- host process, credential, cache, global configuration, or account scanning;
- generic SAST, secret scanning, EDR, malware detonation, or hosted governance;
- target execution, automatic deletion, credential rotation, or configuration
  rewriting;
- Git-history inspection until cross-platform metadata confinement is proven.

## Accepted delivery sequence

1. Integrate deterministic SARIF while preserving incomplete semantics.
2. Add delayed-skill instruction coverage because the positive fixture is an
   observed AgentSec gap and the intelligence database already carries a
   sourced campaign technique.
3. Add a source-pinned GitHub Action without publishing a package or release.
4. Complete the explain and analyzer-status ledger for every active detector.
5. Add versioned campaign response playbooks, then repeat the fixture matrix.

MCP and privileged-CI detectors follow the delayed-skill detector. Their
positive fixtures currently produce no AgentSec finding, but the product keeps
the first alpha sequence bounded to one new detector family at a time.

## Naming consequence

The current name collides with other projects. Naming may now evaluate terms
that communicate three properties: repository pre-trust scanning,
campaign-linked evidence, and explicit incomplete coverage. The naming process
must not imply host protection, antivirus coverage, or a clean certification.

## Evidence boundary

The clean-control report supports output and completion decisions. It does not
rank detection quality. Positive competitor fixtures remain behind a separate
digest approval gate, and the first three teardown candidates remain
SkillSpector, AgentShield, and agent-bom until that evidence exists.

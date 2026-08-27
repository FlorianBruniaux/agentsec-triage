# Competitive analysis methodology

## Purpose

This protocol distinguishes project claims, code evidence, and behavior observed
in an isolated run. It supports product decisions for AgentSec without treating
a README, a star count, or a missing finding as proof.

The tracked cohort contains 16 projects in
[`data/competitive-projects.yaml`](../../data/competitive-projects.yaml). Each
entry records the GitHub URL, a 12-character Git revision, the local clone name,
the current evidence state, the execution tier, and the expected profile path.

## Scope

The comparison covers these user jobs:

- repository inspection before trust or installation;
- response to a documented attack campaign;
- pull-request and CI policy enforcement;
- explanation of evidence, coverage limits, and remediation;
- agent configuration, MCP, skill, package, and host inventory where relevant;
- intelligence sourcing, corrections, update mechanics, and rollback;
- installation, output contracts, tests, and contribution cost.

Generic SAST, generic SCA, EDR, runtime policy enforcement, and hosted governance
remain comparison context. They do not become AgentSec requirements by default.

## Evidence states

| State | Required evidence |
| --- | --- |
| `declared` | Official README, documentation, package metadata, or release note |
| `code_verified` | Pinned implementation, rule, test, fixture, workflow, or schema |
| `observed` | Reproducible isolated run with recorded arguments and environment |
| `contradicted` | Declared behavior conflicts with pinned code or an applicable run |
| `not_applicable` | The criterion is outside the project's documented job |
| `not_tested` | Static evidence is insufficient and no safe run has been completed |

Use `path:line@revision` for repository evidence. Example:
`README.md:42@819eafb5fa66`. External facts require the official URL and access
date. Record the exact release or commit when documentation can move.

An undocumented feature is `not_tested`, not absent. A clean result on an
unsupported fixture is `not_applicable`, not a successful detection test.

## Result vocabulary

Runtime criteria use `pass`, `partial`, `fail`, `not_applicable`, or
`not_tested`. Do not calculate one total score across tools with different
declared jobs. Publish separate matrices for product job, safety, coverage,
intelligence, distribution, and maintenance.

## Static review protocol

1. Confirm that the clone HEAD matches the revision in the project index.
2. Inspect tracked files only. Ignore local build products, caches, and generated
   files that are absent from Git.
3. Read the README, license, security policy, package metadata, entrypoints,
   rules or detectors, output model, updater, CI workflows, tests, and a small
   representative fixture set.
4. Trace three consequential claims from documentation into code and tests.
5. Record repository reads, target writes, subprocesses, network requests,
   package-manager calls, model calls, environment access, and host discovery.
6. Record contradictions and unknowns without filling gaps from assumption.
7. Cite every factual capability row with pinned evidence.

Static inspection does not execute installers, hooks, package scripts, MCP
servers, binaries, or repository content.

## Comparison axes

- **Pre-trust repository scan:** useful before opening or installing a clone.
- **Campaign response:** maps a disclosure to observable repository evidence.
- **Pull-request gate:** offers stable output and honest incomplete behavior.
- **Incident explanation:** connects evidence, source, scope, and next action.
- **Safety:** confines reads and avoids target execution or hidden network use.
- **Coverage honesty:** distinguishes no finding, unsupported input, and failure.
- **Intelligence lifecycle:** tracks provenance, conflicts, corrections, updates,
  signatures, and rollback.
- **Distribution:** installs reproducibly and exposes common CI formats.
- **Maintainability:** makes the cost of adding a rule or campaign measurable.

## Selection gates

### Static gate

At most eight projects may proceed to controlled execution. Each candidate needs
meaningful product overlap, runnable pinned code, a safe isolation path, and a
question that static inspection cannot answer.

### Safety gate

Record and approve the exact argument vector, image digest, mount policy,
network policy, timeout, resource limits, and fixture subset before execution.
Stop if a tool requires host credentials, privileged access, writable source or
fixture mounts, or an unconfined MCP command.

### Product gate

Select no more than five parity requirements and three differentiation bets.
Each decision needs a user job, input, output, regression witness, safety
boundary, completion gate, and competitor evidence.

### Naming gate

Naming starts after the product promise is approved. Candidate checks cover
GitHub, package registries, Homebrew, search results, domains, and relevant
trademark databases. The decision records one name and two fallbacks.

## Execution tiers

| Tier | Meaning |
| --- | --- |
| `static_only` | No execution approved; inspect the pinned repository only |
| `offline_sandbox` | Disposable non-root environment with network disabled |
| `networked_sandbox` | Disposable environment with an explicit destination allowlist |
| `manual_review` | Required behavior cannot be safely automated |

All projects start at `static_only`. A later gate changes the tier. No tier
authorizes execution on the host workstation or against a real repository.

## Data and publication boundaries

- Use synthetic inert fixtures and non-routable domains.
- Do not include credentials, victim data, executable malware, or copied rule
  corpora.
- Do not copy competitor source, rules, fixtures, prose, databases, or raw
  output into AgentSec.
- Keep raw run records ignored under `research/competitive-runs/local/`.
- Publish redacted observations, commands, revisions, limitations, and result
  digests only.
- Preserve license notices and record `unverified` until the pinned license has
  been inspected.
- The AgentSec data-license decision remains a separate release blocker.

## Validation

Validate the tracked structure without requiring local clones:

```bash
.venv/bin/python scripts/check_competitive_projects.py
```

Validate the local research checkout explicitly:

```bash
.venv/bin/python scripts/check_competitive_projects.py \
  --clone-root /Users/florianbruniaux/Sites/divers-test/agent-security-ecosystem
```

The schema is published at
[`data/competitive-projects.schema.json`](../../data/competitive-projects.schema.json).
The `.yaml` index uses the JSON subset of YAML so the repository validator can
parse it with the Python standard library.

# Local competitive run records

This directory is the boundary between reproducible benchmark design and raw
third-party output.

## What stays local

The runner writes these files under `local/`:

- raw bounded `stdout` and `stderr` captures;
- append-only JSON Lines result envelopes;
- temporary run plans that contain absolute clone paths;
- any manual notes copied from a container observation.

The directory and raw extensions are ignored by Git. Do not override those
rules. The path-free source for the current eight plans is the tracked
`plan-blueprints.v1.json` file. Reconstruct the local plans with:

```bash
.venv/bin/python scripts/run_competitive_benchmark.py generate
```

This command verifies the real pinned Git commits and hashes bounded snapshots.
It does not invoke Docker or a competitor CLI. Competitor output can contain
machine paths, copied source fragments, environment details, or text that
should not enter AgentSec history.

## What may be published

Only a reviewed aggregate may enter
`docs/competitive-analysis/BENCHMARK-RESULTS.md`. It can contain:

- project ID and pinned revision;
- fixture ID and applicability decision;
- exact container argument vector;
- pinned image digest;
- network, mount, timeout, process, CPU, and memory policy;
- exit code, timeout state, output digests, and ephemeral-scratch state;
- normalized finding IDs, paths, severities, and coverage state;
- redacted contradictions and operational notes.

Do not publish raw competitor output, copied rules, repository source, absolute
host paths, tokens, credentials, or personal data.

## Approval boundary

`scripts/run_competitive_benchmark.py validate` prints a SHA-256 plan digest
over the canonical plan. It never creates an approval receipt. `execute`
refuses a different plan or digest and requires a separate receipt JSON with
an explicit `approved` decision, declared approver identity, timezone-aware
date, `execute` scope, matching digest, and exact approval statement.
Changing any semantic plan field or either mounted tree changes the plan digest
and requires another review and a new receipt. Relocating an otherwise verified
clone or fixture root does not change the digest because host paths normalize
to logical slots after path and content validation. Every future run envelope
records the full plan digest, the receipt SHA-256, and the receipt's declared
decision, approver, timestamp, and scope.

The receipt is a procedural audit gate. This local runner does not authenticate
the declared identity cryptographically and does not treat the receipt as an
identity barrier. It records the review assertion needed before the existing
container path may continue.

Execution rematerializes the approved source commit and copies the fixture into
disposable snapshots. It rechecks both tree digests immediately before Docker.
Scratch uses a size-bounded `tmpfs`; the record states that scratch files were
not measured after teardown. On timeout, the cidfile identifies the daemon-side
container for bounded kill, removal, and disappearance verification.

The runner does not install or build a competitor. Container image construction
is a separate untrusted-code operation and needs its own reviewed command,
network policy, and pinned resulting digest.

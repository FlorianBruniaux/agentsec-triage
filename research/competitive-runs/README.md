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
rules. Competitor output can contain machine paths, copied source fragments,
environment details, or text that should not enter AgentSec history.

## What may be published

Only a reviewed aggregate may enter
`docs/competitive-analysis/BENCHMARK-RESULTS.md`. It can contain:

- project ID and pinned revision;
- fixture ID and applicability decision;
- exact container argument vector;
- pinned image digest;
- network, mount, timeout, process, CPU, and memory policy;
- exit code, timeout state, output digests, and relative scratch writes;
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
Changing any plan field requires another review and a new receipt.

The receipt is a procedural audit gate. This local runner does not authenticate
the declared identity cryptographically and does not treat the receipt as an
identity barrier. It records the review assertion needed before the existing
container path may continue.

The runner does not install or build a competitor. Container image construction
is a separate untrusted-code operation and needs its own reviewed command,
network policy, and pinned resulting digest.

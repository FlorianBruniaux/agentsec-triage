# Controlled competitor benchmark design

Status: **infrastructure validated, competitor execution not approved**

This design converts the static shortlist into reproducible observations while
keeping third-party code away from the host and real repositories. It does not
rank incomparable products with one score.

## Approved static cohort

The owner approved these eight projects for benchmark design:

| Project | Revision | Approved tier | Primary unresolved question |
| --- | --- | --- | --- |
| Aguara | `819eafb5fa66` | `offline_sandbox` | Do omitted inputs change completion and exit status? |
| patient-zero | `331320c152aa` | `offline_sandbox` | Does offline repository mode avoid host reads and fail closed? |
| AgentShield | `bdad15dd28da` | `offline_sandbox` | Does static mode report unreadable and outside-root configuration? |
| cc-audit | `bdb657474624` | `offline_sandbox` | Does partial scanner failure produce an incomplete verdict? |
| NVIDIA SkillSpector | `698e2bf29c7d` | `offline_sandbox` | Does blocked OSV traffic alter completeness in no-LLM mode? |
| Cisco Skill Scanner | `48f59347a54b` | `offline_sandbox` | Does a skipped skill force a nonzero batch verdict? |
| Sigil | `0f73627236d5` | `offline_sandbox` | Does a fresh network-blocked scan expose missing feeds and skipped reads? |
| agent-bom | `9ceeb22fff1f` | `offline_sandbox` | Does its evidence ledger preserve every relevant omission? |

This approval authorizes design and inert fixture preparation. It does not
authorize image builds or competitor execution.

## Fixture truth table

Every input is synthetic and source-attributed. Harmless commands exist only as
text. No fixture contains executable malware, a real credential, victim data,
an archive, or an executable permission bit.

| Fixture | Kind | Expected property | Main applicable classes |
| --- | --- | --- | --- |
| `clean-control` | negative | No campaign or agent-startup evidence | all |
| `shai-hulud-confirmed` | positive | Confirmed compromised npm version | campaign, package, repository |
| `keyv-contested` | positive | Contested scope remains distinguishable | campaign, package, repository |
| `lifecycle-near-miss` | near-miss | Benign lifecycle script is not promoted to compromise | campaign, package, repository |
| `renamed-payload-hash` | positive | Harmless content digest is independent from filename | campaign, repository |
| `claude-hook-review` | positive | Session-start hook is reviewable evidence | agent config, repository |
| `vscode-startup-review` | positive | Folder-open task is reviewable evidence | agent config, repository |
| `skill-delayed-instruction` | positive | Secondary skill instruction is inspected | skill, repository |
| `mcp-inline-fetch-exec` | positive | Inline MCP command and URL are visible | MCP, agent config, repository |
| `ci-untrusted-trigger` | positive | Privileged trigger consumes pull-request content | CI, repository |
| `unsupported-binary-lock` | unsupported | Binary lockfile is unsupported, not clean | campaign, package, repository |
| `confinement-symlink` | safety | Outside-root link is skipped or makes coverage incomplete | repository, agent config, skill, package |

The manifest at `research/competitive-fixtures/manifest.yaml` is the source of
truth. Its validator checks declared files, source URLs, controls, permissions,
archives, secret shapes, and path confinement.

## Exact plan contract

One plan describes one project and one fixture. Required fields are:

- pinned project ID and 12-character revision from the cohort index;
- fixture ID and exact direct-child paths below the approved roots;
- image reference pinned with `@sha256:<64 lowercase hex characters>`;
- read-only source and fixture mount declarations;
- argument vector as an array, never a shell string;
- network mode, allowlist, and explicit approval state;
- timeout, memory, process, CPU, and bounded-output limits.

The first cohort accepts only `network.mode=none`. The runner rejects an
approved allowlist because no destination-enforcement backend exists yet.
Claiming an allowlist while using a normal Docker bridge would be security
theater.

Validation prints the canonical plan digest and exact Docker argument vector.
Execution requires the same digest. Any field change invalidates approval.

## Container policy

Every run uses:

- an image pinned by immutable SHA-256 digest with `--pull=never`;
- a non-root `65532:65532` user;
- network disabled;
- a read-only root filesystem;
- all Linux capabilities dropped;
- `no-new-privileges`;
- explicit CPU, memory, process, timeout, and output limits;
- an empty temporary home and temporary directory;
- competitor source mounted read-only at `/competitor`;
- one fixture mounted read-only at `/fixture`;
- one disposable writable scratch directory at `/scratch`;
- no host home, Docker socket, credentials, SSH agent, cloud config, or real
  repository mount.

The scratch inventory records only relative path, type, byte count, and digest.
The runner never treats a file written by a competitor as trusted input.

## Result envelope

Each local JSON Lines record contains:

- project, revision, fixture, image, argument vector, and network policy;
- exit code, timeout state, duration, and maximum RSS when available;
- bounded stdout and stderr byte counts, digests, and truncation states;
- relative scratch writes and their digests;
- network observation state;
- normalized findings and normalization state.

Raw bounded streams remain ignored under
`research/competitive-runs/local/`. Tracked documentation receives reviewed,
redacted aggregates only.

Three limitations remain explicit:

1. `network=none` blocks traffic but does not identify attempted destinations.
2. Maximum RSS is `null` until a portable per-container measurement exists.
3. Normalized findings stay empty until a reviewed adapter exists for each
   selected tool. A generic regex parser would create false comparability.

## Execution order and stop rules

For each approved image:

1. review image-construction commands and resulting digest;
2. review every generated plan and approval digest;
3. run `clean-control` first;
4. run the applicable near-miss control;
5. stop if the tool writes outside scratch, tries to execute fixture content,
   requires credentials, cannot work without host scope, or defeats limits;
6. run applicable positive, unsupported, and safety fixtures;
7. repeat deterministic cases three times;
8. compare exit code, finding IDs, paths, severity, coverage, and output digest;
9. publish only redacted observations and explicit `not_applicable` or
   `not_tested` cells.

A missing finding is not a failure until the fixture matches the tool's
documented input and mode. A clean result with missing evidence is recorded as
a completeness failure, independently from detection.

## Local infrastructure self-test

The self-test executes only a hard-coded Python marker command from this
repository. It proves bounded pipe capture, `shell=False`, redaction, scratch
write inventory, and the disabled-network policy label. It does not prove
Docker availability or competitor behavior.

```bash
.venv/bin/python scripts/run_competitive_benchmark.py self-test
```

Image construction and the eight sets of exact plan digests form the next
safety gate. No competitor command runs before that review.

# Controlled competitor benchmark design

Status: **seven images built, runtime execution not approved**

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

The cohort approval authorized design and inert fixture preparation. A later
digest-bound gate authorized and completed seven image builds. It did not
authorize competitor execution.

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
- image reference pinned with either a registry digest
  `name@sha256:<64 lowercase hex characters>` or a local immutable Docker image
  ID `sha256:<64 lowercase hex characters>`;
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

The approval digest canonicalizes only equivalent integral resource values, such
as `1` and `1.0` CPUs. It preserves all paths, image IDs, commands, mounts, and
network fields. The runner rejects an output root outside its ignored local
boundary before it looks up Docker, so a malformed output destination cannot
reach a competitor invocation.

## Container policy

Every run uses:

- an image pinned by immutable registry digest or local image ID with
  `--pull=never`;
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

## Prepared teardown plans

The following plans were validated on 2026-08-31 and remain under the ignored
local plan directory. They use the image IDs in `BUILD-GATE.md`, read-only
source and fixture mounts, network mode `none`, 30 seconds, 512 MB, 64
processes, one CPU, and a 1,000,000-byte limit per stream. The SHA-256 values
bind each complete local plan, including its private absolute paths. They do
not authorize execution and are not runtime observations.

| Project | Fixture | Kind | Applicability | Runtime state | Approval digest |
| --- | --- | --- | --- | --- | --- |
| NVIDIA SkillSpector | `skill-delayed-instruction` | positive | applicable to its documented skill surface | `not_tested` | `f04329a636edb6fe5322758f9b3c4093cf7ae7c0b72bc575fa3567d15169766d` |
| NVIDIA SkillSpector | `lifecycle-near-miss` | near miss | `not_applicable`: package lifecycle input is outside the skill-only plan | `not_applicable` | none |
| NVIDIA SkillSpector | `unsupported-binary-lock` | unsupported | `not_applicable`: package lockfile input is outside the skill-only plan | `not_applicable` | none |
| NVIDIA SkillSpector | `confinement-symlink` | safety | applicable to the skill fixture's outside-root link | `not_tested` | `a9a018bcc746c707a9986a3af0950506930cd58c030b9a3c5ee36a8060fa482d` |
| AgentShield | `claude-hook-review` | positive | applicable to its documented agent-configuration surface | `not_tested` | `93d7764b6cfd0c9aee548004965cdbbf28800eb8eca5bf165e9cdbb466ee6ded` |
| AgentShield | `lifecycle-near-miss` | near miss | `not_applicable`: package lifecycle input is outside the configuration plan | `not_applicable` | none |
| AgentShield | `unsupported-binary-lock` | unsupported | `not_applicable`: package lockfile input is outside the configuration plan | `not_applicable` | none |
| AgentShield | `confinement-symlink` | safety | applicable to an outside-root configuration link | `not_tested` | `cde5000d0a1a6053d5c36304c3e02c1d01f1a7dc4f178d5402e06f230a9bd0eb` |
| agent-bom | `shai-hulud-confirmed` | positive | applicable to the documented package scan | `not_tested` | `56fab351a755f74302d48bef7cef87a66d6bcdae49f84d71ac4ee0322210cc68` |
| agent-bom | `lifecycle-near-miss` | near miss | applicable package-manifest control | `not_tested` | `6574cf12df8f13f3c09d3d0186c9332019f07b885d05205ddd34b322544f543a` |
| agent-bom | `unsupported-binary-lock` | unsupported | applicable unsupported-input check | `not_tested` | `019536c562c49f3e066642937facdabca94b8d7a7abf97d1d7eca9eb8fe26fd0` |
| agent-bom | `confinement-symlink` | safety | applicable repository-confinement check | `not_tested` | `74bcbcdee7ee52ef7dae30f128dc132611ad064ad48ecf9d92fd1f0086d7baa1` |

`not_applicable` has no exact plan or digest. It is not a clean result.
`not_tested` records the remaining runtime evidence gap only for planned rows.
Any run still needs the exact reviewed plan and matching digest supplied to
`execute` after a separate owner approval.

## Local infrastructure self-test

The self-test executes only a hard-coded Python marker command from this
repository. It proves bounded pipe capture, `shell=False`, redaction, scratch
write inventory, and the disabled-network policy label. It does not prove
Docker availability or competitor behavior.

```bash
.venv/bin/python scripts/run_competitive_benchmark.py self-test
```

Seven image recipes, their exact source revisions, and their verified local
image IDs are recorded in `BUILD-GATE.md`. Sigil stopped before build because
its pinned source has no tracked `Cargo.lock`. Seven images built without
running a competitor CLI. The exact clean-control plans and approval digests
form the next safety gate, so runtime execution is not approved.

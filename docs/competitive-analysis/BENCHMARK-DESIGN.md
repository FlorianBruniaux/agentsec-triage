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

- pinned project ID, 12-character revision, and resolved 40-character Git
  commit from the cohort index and local clone;
- fixture ID and exact direct-child paths below the approved roots;
- deterministic source and fixture tree evidence covering relative paths,
  regular-file content digests, symlink targets, and relevant modes;
- image reference pinned with either a registry digest
  `name@sha256:<64 lowercase hex characters>` or a local immutable Docker image
  ID `sha256:<64 lowercase hex characters>`;
- read-only source and fixture mount declarations;
- argument vector as an array, never a shell string;
- network mode, allowlist, and explicit approval state;
- timeout, memory, process, CPU, bounded-output, and bounded-scratch limits.

The first cohort accepts only `network.mode=none`. The runner rejects an
approved allowlist because no destination-enforcement backend exists yet.
Claiming an allowlist while using a normal Docker bridge would be security
theater.

Validation prints the canonical plan digest and exact Docker argument vector.
It never creates an approval receipt. Execution requires the same digest and a
separate receipt with decision `approved`, a declared approver identity, a
timezone-aware date, scope `execute`, the matching digest, and this exact
statement:

```text
I approve execution of the exact benchmark plan with SHA-256 digest <digest>.
```

The receipt is a procedural audit gate, not an identity barrier. The local
runner cannot authenticate the declared identity cryptographically. It only
checks that a distinct review assertion is bound to the exact plan. Any field
change invalidates that binding.

The plan digest canonicalizes equivalent integral resource values, such as `1`
and `1.0` CPUs, and replaces verified host-specific source and fixture paths
with stable logical slots. It preserves image IDs, commands, mounts, network
fields, the full Git commit, and both tree-evidence digests. Path validation
still requires the declared pinned clone and fixture before digesting or
executing. The runner rejects non-finite numeric values. It rejects an output
root outside its ignored local boundary before it looks up Docker, so a
malformed destination cannot reach a competitor invocation.

The tracked path-free blueprint at
`research/competitive-runs/plan-blueprints.v1.json` reconstructs the eight
current plans on a machine that has the pinned clones:

```bash
.venv/bin/python scripts/run_competitive_benchmark.py generate
```

Generation verifies each clone's real `HEAD`, materializes the exact commit,
hashes source and fixture files by bounded streaming, and writes host-specific
plans under the ignored `research/competitive-runs/local/plans/` directory.
Execution repeats that work into disposable snapshots and compares the evidence
again immediately before `docker run`.

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
- one 64 MB disposable `tmpfs` scratch directory at `/scratch`, mounted with
  `noexec`, `nosuid`, and `nodev`;
- no host home, Docker socket, credentials, SSH agent, cloud config, or real
  repository mount.

The scratch filesystem disappears with the container. Current runtime records
therefore state `not_measured_ephemeral_tmpfs` instead of claiming a post-run
file inventory. Bounded scratch takes precedence over retaining untrusted
competitor writes on the host.

## Result envelope

Each local JSON Lines record contains:

- project, revision, fixture, image, argument vector, and network policy;
- full plan digest, approval-receipt digest, and the receipt's declared
  decision, approver, timestamp, and scope;
- exit code, timeout state, duration, and maximum RSS when available;
- bounded stdout and stderr byte counts, digests, and truncation states;
- explicit ephemeral-scratch observation state;
- network observation state;
- normalized findings and normalization state.

Raw bounded streams remain ignored under
`research/competitive-runs/local/`. Tracked documentation receives reviewed,
redacted aggregates only.

Three limitations remain explicit:

1. `network=none` blocks traffic but does not identify attempted destinations.
2. Maximum RSS is `null` until a portable per-container measurement exists.
3. Scratch file paths and contents are not measured after the bounded `tmpfs`
   disappears.
4. Normalized findings stay empty until a reviewed adapter exists for each
   selected tool. A generic regex parser would create false comparability.

## Execution order and stop rules

For each approved image:

1. review image-construction commands and resulting digest;
2. review every generated plan, its digest, and its separate approval receipt;
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

The following plans were regenerated and validated on 2026-08-31 from the
tracked blueprint. They remain under the ignored local plan directory. They use
the image IDs in `BUILD-GATE.md`, read-only source and fixture snapshots,
network mode `none`, 30 seconds, 512 MB, 64 processes, one CPU, a 1,000,000-byte
limit per stream, and 64 MB of scratch `tmpfs`. The SHA-256 values bind each
complete semantic plan, including its full source commit and both mounted-tree
digests, while canonicalizing verified host paths. They do not authorize
execution, do not have approval receipts, and are not runtime observations.

| Project | Fixture | Kind | Applicability | Runtime state | Plan digest |
| --- | --- | --- | --- | --- | --- |
| NVIDIA SkillSpector | `skill-delayed-instruction` | positive | applicable to its documented skill surface | `not_tested` | `26bfa9fc3630ebfbddf6af2f5bfbfb0e920fd4c2b6c89c5ad02682315aa00bae` |
| NVIDIA SkillSpector | `lifecycle-near-miss` | near miss | `not_applicable`: package lifecycle input is outside the skill-only plan | `not_applicable` | none |
| NVIDIA SkillSpector | `unsupported-binary-lock` | unsupported | `not_applicable`: package lockfile input is outside the skill-only plan | `not_applicable` | none |
| NVIDIA SkillSpector | `confinement-symlink` | safety | applicable to the skill fixture's outside-root link | `not_tested` | `f9d78a12c2f0c59966a3fc719da85d14daf7a71c7c8bc4aecc4331c3d6c3dabf` |
| AgentShield | `claude-hook-review` | positive | applicable to its documented agent-configuration surface | `not_tested` | `778c962fa766a09d35777a5f057fe87b421b1d3e16ac02e69f97af57bbf9b550` |
| AgentShield | `lifecycle-near-miss` | near miss | `not_applicable`: package lifecycle input is outside the configuration plan | `not_applicable` | none |
| AgentShield | `unsupported-binary-lock` | unsupported | `not_applicable`: package lockfile input is outside the configuration plan | `not_applicable` | none |
| AgentShield | `confinement-symlink` | safety | applicable to an outside-root configuration link | `not_tested` | `48cf26a39ea09d796288fc4c29be90271fecfcd3069b6b7f6e9038c0d743158f` |
| agent-bom | `shai-hulud-confirmed` | positive | applicable to the documented package scan | `not_tested` | `ca07f3d5a7d3cda1c16e84254716ebfb9c18b38875466e63f09998272f5ed090` |
| agent-bom | `lifecycle-near-miss` | near miss | applicable package-manifest control | `not_tested` | `c1b3ba131a93239ce1bb15388f01d07f1f564c7ef4d48608baa8155eb5493150` |
| agent-bom | `unsupported-binary-lock` | unsupported | applicable unsupported-input check | `not_tested` | `189913ba71053748aeef3cc3b8318df19f2b97d1914a3a61b948d2f0a28aeef1` |
| agent-bom | `confinement-symlink` | safety | applicable repository-confinement check | `not_tested` | `68e445b8099f2a2f4e0b720662c90058a420275d482098e6605bbcfe2a29cf91` |

`not_applicable` has no exact plan or digest. It is not a clean result.
`not_tested` records the remaining runtime evidence gap only for planned rows.
Any run still needs the exact reviewed plan, matching digest, and separate
procedural approval receipt supplied to `execute`. The runner does not verify
the approver's identity.

## Local infrastructure self-test

The self-test executes only a hard-coded Python marker command from this
repository. It proves bounded pipe capture, `shell=False`, redaction, the
bounded local inventory primitive, and the disabled-network policy label. It
does not prove Docker availability, daemon-side timeout cleanup, or competitor
behavior.

```bash
.venv/bin/python scripts/run_competitive_benchmark.py self-test
```

Seven image recipes, their exact source revisions, and their verified local
image IDs are recorded in `BUILD-GATE.md`. Sigil stopped before build because
its pinned source has no tracked `Cargo.lock`. Seven images built without
running a competitor CLI. The exact clean-control plans and plan digests form
the next procedural safety gate, so runtime execution is not approved.

# Controlled competitor benchmark results

Status: **clean-control gate complete; fixture matrix not yet approved**

Run date: 2026-08-31

This report contains reviewed observations from one inert `clean-control` run
for each of seven pinned competitor images. It is not a product ranking. It
does not compare detection breadth, true-positive performance, false-positive
performance, or behavior on positive fixtures.

## Execution boundary

Every run used the exact digest-approved plan recorded in `BUILD-GATE.md`:

- immutable local image ID and `--pull=never`;
- network mode `none`;
- read-only competitor source, fixture, and container filesystem;
- non-root user `65532:65532`;
- all Linux capabilities dropped and `no-new-privileges` enabled;
- 30-second timeout, 512 MB memory, 64 processes, and one CPU;
- bounded standard output and error capture;
- disposable scratch storage with a post-run write inventory.

All seven runs completed without a timeout or scratch write. The runner cannot
observe blocked network attempts from outside the container. A tool's own error
message can therefore show an attempted fetch, but `network_attempts` remains
`null` in the run envelope.

Raw output remains in the ignored local run directory. The table publishes
only reviewed fields and SHA-256 digests.

## Clean-control observations

Evidence states follow `METHODOLOGY.md`. `Observed` means the exact pinned
container produced the value during this gate. `Unknown` means the output did
not provide enough evidence for the claim.

| Project | Revision | Exit | Observed coverage and diagnostics | Clean-control interpretation | Captured-output SHA-256 |
| --- | --- | ---: | --- | --- | --- |
| Aguara | `819eafb5fa66` | `0` | Reported one file scanned, 192 rules loaded, no findings, risk score `0`, and verdict `0`. It emitted no skipped-input, error, or completion field. | No finding was observed. Completion and omitted-input handling remain **unknown**. | stdout `3382d671adb472eb19e635edb93c43db8075c95328141857362e59779d919196` |
| patient-zero | `331320c152aa` | `2` | Reported one lockfile, zero packages checked, GitHub disabled, and `failed to list processes: spawn ps ENOENT`. | The process-check failure produced a nonzero exit and remained visible. This is an **observed fail-closed behavior** for the clean control. | stdout `dde7d4dbbf79f5e411c33ada31cb275e95fcbfc18f5e8d8682e16605ff4e525c` |
| AgentShield | `bdad15dd28da` | `0` | Reported one file scanned, no findings, grade `A`, score `100`, nine registered harness adapters, and zero matched adapters. It emitted no completion field. | The grade and score do not expose whether an applicable harness was present. Coverage completeness remains **unknown**. | stdout `5e0fccdb3302eb879588a42d0f94eb9346254bb36f4892b8f999435b91d82617` |
| cc-audit | `bdb657474624` | `2` | Refused to scan because `.cc-audit.yaml` was absent and suggested `cc-audit init`. No structured result was emitted. | The tool failed visibly. A reviewed, inert configuration fixture is required before a functional comparison. | stderr `e8be73bfe5eee48d1e1d6c6f192dff1ab3b0a074f1e0c9b25436925088594e91` |
| NVIDIA SkillSpector | `698e2bf29c7d` | `0` | Reported successful execution, one of one component inspected, 100% coverage, analyzer-level completed, not-applicable, and disabled states, no issues, and no ledger exceptions. | This was the strongest **observed analyzer ledger** in the clean-control cohort. Positive, skipped, and unsupported fixtures remain untested. | stdout `30812694c797dc85a41efb501002d32cd9c8be6ffedc33213f98011ec06017e3` |
| Cisco Skill Scanner | `48f59347a54b` | `1` | Reported a failed fetch of the LiteLLM model-cost map, then refused the fixture because `SKILL.md` was absent. No structured result was emitted. | The fixture was not applicable to this skill-only scanner. The error also shows an **observed attempted remote lookup** whose connection failed under network mode `none`. | stderr `efc0da30dbc3d9c1f8f51a65ed9ac5b48d69c96c7e0404b10143b46e986bd063` |
| agent-bom | `9ceeb22fff1f` | `0` | Reported outcome `complete`, one source, zero requested scopes, zero complete scopes, an empty scope list, no findings, and no warnings. | The output preserves an evidence structure, but the `complete` outcome does not state what was requested when the scope count is zero. | stdout `f06470a81684ccc09d72ddca4191c9ec0db8d21620676410d72d8f2cc0598a87` |

## AgentSec baseline

Commit `9a07571` scanned all 12 fixtures three times with `--scope repository
--format json --redact`. The harness removed only `elapsed_ms` before comparing
the normalized payloads. All 12 fixtures produced identical normalized output
and exit status across their three runs.

| Fixture | Kind | Complete | Exit | Findings | Observed result |
| --- | --- | ---: | ---: | ---: | --- |
| `clean-control` | negative | yes | `0` | 0 | No false positive |
| `shai-hulud-confirmed` | positive | yes | `1` | 1 | Confirmed compromised version detected |
| `keyv-contested` | positive | yes | `1` | 1 | Contested version preserved as a finding |
| `lifecycle-near-miss` | near miss | yes | `0` | 0 | Benign lifecycle script not promoted |
| `renamed-payload-hash` | positive | yes | `0` | 0 | Expected content-hash evidence not detected |
| `claude-hook-review` | positive | yes | `1` | 1 | Session-start hook exposed for review |
| `vscode-startup-review` | positive | yes | `1` | 1 | Folder-open task exposed for review |
| `skill-delayed-instruction` | positive | yes | `0` | 0 | Delayed skill instruction not detected |
| `mcp-inline-fetch-exec` | positive | yes | `0` | 0 | MCP command evidence not detected |
| `ci-untrusted-trigger` | positive | yes | `0` | 0 | Privileged CI trigger not detected |
| `unsupported-binary-lock` | unsupported | no | `2` | 0 | Unsupported Bun lockfile reported as incomplete |
| `confinement-symlink` | safety | no | `2` | 0 | Outside-root link reported as incomplete |

The ignored machine report preserves each full normalized SHA-256, finding,
diagnostic, detector ledger, and capability exclusion. It is not published
because the local report is the raw benchmark boundary.

This baseline demonstrates deterministic output and exposes current detection
gaps. AgentSec still has one detector family, while several competitors expose
broader rule or analyzer catalogues.

## Decisions supported by this gate

The clean-control evidence supports four product decisions:

1. Keep `complete` independent from severity and finding count.
2. Keep `not_scanned`, diagnostics, and detector applicability in every
   machine-readable output, including SARIF.
3. Do not add an aggregate safety grade that can hide a zero-applicability
   scan.
4. Add an analyzer-status ledger comparable to SkillSpector's completed,
   disabled, not-applicable, skipped, and failed states without copying its
   product model.
5. Prioritize skill, MCP, CI, and content-hash detectors because their positive
   fixtures currently produce no finding.

## Prepared teardown plans and remaining runtime gate

Eight exact, bounded plans now cover the first teardown candidates:
SkillSpector, AgentShield, and agent-bom. The fixture-level applicability
decisions and SHA-256 digests are recorded in `BENCHMARK-DESIGN.md`. The plans
were validated only. Docker and every competitor CLI remain uninvoked for this
gate, so all planned observations remain `not_tested`.

SkillSpector and AgentShield have no plan for `lifecycle-near-miss` or
`unsupported-binary-lock`. Those package-oriented inputs are
`not_applicable` to their selected skill and configuration paths. That is not
a successful clean scan. agent-bom has plans for a confirmed package version,
a lifecycle near miss, an unsupported binary lockfile, and a confinement link.

The remaining gate must:

1. obtain explicit owner approval for each exact plan and matching digest;
2. run the approved case three times with the existing isolation policy;
3. compare normalized evidence without converting a missing finding into a
   detection claim;
4. preserve unsupported, skipped, unreadable, and outside-root inputs as
   incomplete or `not_applicable`, according to the observed tool contract;
5. publish only reviewed, redacted aggregates after the repeated runs.

The target questions are unchanged: SkillSpector's analyzer ledger,
AgentShield's score-to-applicability relationship, and agent-bom's
completion-to-requested-scope relationship. No answer is available until the
separate runtime approval and execution evidence exist.

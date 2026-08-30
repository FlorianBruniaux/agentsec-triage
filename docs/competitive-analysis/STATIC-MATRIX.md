# Static competitor matrix

Snapshot date: **2026-08-24**

This matrix summarizes the 16 pinned profiles. It contains no runtime benchmark
results. A project can be strong at its declared job and still be unsuitable as
a model for AgentSec's repository-triage contract.

## Evidence legend

| Code | Meaning |
| --- | --- |
| `D` | `declared` in official project material |
| `CV` | `code_verified` at the pinned revision |
| `X` | `contradicted` by pinned code or versioned evidence |
| `NA` | `not_applicable` to the project's declared job |
| `NT` | `not_tested` or not established by static evidence |

No cell means that a detector works in practice. Runtime claims remain `NT`
until an approved isolated run records an observation.

## Product jobs

| Project | Pre-trust repository job | Campaign response | Pull request or CI | Incident explanation |
| --- | --- | --- | --- | --- |
| [Aguara](profiles/aguara.md) | `CV` broad local scan | `D` signed intelligence updates | `CV` Action, SARIF, changed-file mode | `CV` evidence and remediation |
| [patient-zero](profiles/patient-zero.md) | `CV` repository and host triage | `CV` normalized IOC workflow | `X` Action can pass on scanner failure | `CV` campaign-oriented findings |
| [Repo Forensics](profiles/repo-forensics.md) | `X` full mode can execute hooks | `CV` pre-install and incident scripts | `NT` exact safe CI mode | `CV` broad forensic report |
| [AgentShield](profiles/agentshield.md) | `CV` agent-configuration scan | `NA` no campaign model found | `CV` Action and report formats | `CV` rule evidence and fixes |
| [Snyk Agent Scan](profiles/snyk-agent-scan.md) | `NA` host inventory is primary | `NA` no campaign workflow found | `D` enterprise background mode | `D` hosted scoring |
| [AgentSeal](profiles/agentseal.md) | `CV` host and project discovery | `NA` no campaign model found | `D` Docker Action and SARIF | `CV` trust score and baseline delta |
| [Medusa](profiles/medusa.md) | `CV` broad repository scan | `NT` signature provenance | `D` CLI reports | `CV` multi-scanner aggregation |
| [cc-audit](profiles/cc-audit.md) | `CV` Claude artifact scan | `D` malware and CVE databases | `X` Action builds shell arguments | `D` multiple report formats |
| [NVIDIA SkillSpector](profiles/skillspector.md) | `CV` skill preflight | `NA` no campaign workflow found | `D` structured output and policy | `CV` analyzer ledger and rationale |
| [Cisco Skill Scanner](profiles/cisco-skill-scanner.md) | `CV` skill and archive scan | `NA` no campaign workflow found | `X` skipped skills can still exit 0 | `CV` analyzer findings |
| [AgentSec by debu-sinha](profiles/agentsec-debu-sinha.md) | `CV` host and project configuration | `NA` no campaign model found | `X` scanner errors can exit 0 | `CV` findings and hardening advice |
| [Trust Issues](profiles/trust-issues.md) | `CV` repository triage script | `NA` manual reasoning workflow | `NT` no stable CI contract established | `CV` human-led evidence review |
| [Sigil](profiles/sigil.md) | `CV` quarantine-first scan | `D` live feed enrichment | `D` Action and verdict output | `CV` findings and approval ledger |
| [agent-security-scanner-mcp](profiles/agent-security-scanner-mcp.md) | `CV` broad project scan | `NA` no campaign model found | `X` failures can produce a clean exit | `CV` grade and issue output |
| [Inkog](profiles/inkog.md) | `CV` local collection, hosted analysis | `NA` no campaign model found | `D` Action and SARIF | `D` proprietary server findings |
| [agent-bom](profiles/agent-bom.md) | `CV` repository and package inventory | `NT` campaign-to-detector traceability | `CV` fail-closed outcome and SARIF | `CV` evidence, impact, and coverage |

## Safety and coverage honesty

| Project | Target execution | Network boundary | Read confinement | Incomplete-scan contract |
| --- | --- | --- | --- | --- |
| Aguara | `CV` static scan | `CV` updates are explicit | `X` unreadable and large files vanish | `X` omissions can look clean |
| patient-zero | `CV` install scripts disabled | `X` refresh is default | `X` scope expands into host state | `X` no distinct incomplete exit |
| Repo Forensics | `X` full scan executes hooks | `NT` offline path unobserved | `NT` broad readers | `X` missing sandbox does not block DAST |
| AgentShield | `CV` default static mode | `CV` online modes opt in | `X` fixed-path symlink escape | `NT` unreadable entry behavior |
| Snyk Agent Scan | `CV` MCP mode can execute with consent | `CV` analysis API is required | `CV` intentionally host-wide | `NT` hosted coverage is opaque |
| AgentSeal | `CV` live mode is separate | `X` registry traffic is default | `X` skill symlinks are followed | `CV` failed enrichment is invisible |
| Medusa | `NT` external tools need tracing | `CV` remote paths use network | `X` target config controls scanners | `NT` subprocess failure semantics |
| cc-audit | `CV` core parser is static | `NT` update and remote modes | `X` explicit symlink escape | `X` partial scanner failure yields output |
| NVIDIA SkillSpector | `CV` static skill scan | `X` no-LLM mode still uses OSV | `CV` no-follow reads | `NT` incomplete exit behavior |
| Cisco Skill Scanner | `CV` analyzers inspect data | `CV` online analyzers opt in | `CV` resolved-root checks | `X` skipped skill can still exit 0 |
| AgentSec by debu-sinha | `CV` scan is static | `CV` network modes are explicit | `X` fixed-path symlink escape | `X` scanner error can be low severity |
| Trust Issues | `CV` shell scanner is static | `CV` scanner offline, research online | `CV` non-following traversal | `X` read errors are hidden |
| Sigil | `CV` static scan path | `X` full scan contacts feeds | `X` unreadable files vanish | `X` exit checks findings only |
| agent-security-scanner-mcp | `CV` target code not invoked | `D` rule mode local | `X` directory symlinks followed | `X` skips and errors can grade clean |
| Inkog | `CV` collection is static | `CV` redacted source is uploaded | `NT` hosted boundary | `CV` unreadable files silently skipped |
| agent-bom | `D` read-first default | `CV` transport-level offline mode | `CV` resolved-root checks | `CV` degraded scan outcome exits 1 |

## Intelligence, distribution, and maintenance

| Project | Intelligence lifecycle | Distribution evidence | Maintenance signal |
| --- | --- | --- | --- |
| Aguara | `CV` signed bundle verification | `D` binary, Action, Homebrew, Docker | `CV` typed Go rules and tests |
| patient-zero | `X` unsigned default remote IOC refresh | `D` npm, hooks, Action | `CV` campaign-centric data paths |
| Repo Forensics | `D` optional IOC updates | `D` scripts, plugin, skill, Action | `NT` large script fleet cost |
| AgentShield | `CV` bundled rules and opt-in services | `CV` CLI and Action | `CV` rule engine and fixtures |
| Snyk Agent Scan | `NT` hosted detector lifecycle | `D` uvx, signed binary, enterprise mode | `NT` service-side contribution cost |
| AgentSeal | `CV` hosted registry and local blocklist | `D` Python, npm, Action | `CV` modular scanners and tests |
| Medusa | `NT` rule provenance and uniqueness | `D` Python CLI | `NT` external scanner coordination cost |
| cc-audit | `CV` local databases and updater paths | `D` Rust CLI and Action | `X` advertised breadth exceeds verified paths |
| NVIDIA SkillSpector | `CV` static rules plus OSV and optional LLM | `D` Python CLI | `CV` analyzer ledger and limits |
| Cisco Skill Scanner | `CV` local analyzers plus opt-in services | `D` Python CLI | `CV` modular analyzers and structured skips |
| AgentSec by debu-sinha | `CV` bundled checks and explicit network tools | `D` Python package | `CV` adapter and scanner registries |
| Trust Issues | `D` web research plus local signatures | `D` skill and shell workflow | `X` README benchmark drifted from results |
| Sigil | `CV` live advisory and exploitation feeds | `D` Rust CLI, MCP, Action | `CV` phases, cache, and ledger modules |
| agent-security-scanner-mcp | `CV` bundled package rules | `D` npm, MCP, Action, Apify | `CV` many command-specific analyzers |
| Inkog | `NT` proprietary server lifecycle | `D` Go CLI and Action | `NT` detector contribution is service-controlled |
| agent-bom | `CV` local database, OSV gaps, broad feeds | `D` PyPI, image, Action, API, Helm, MCP | `CV` schemas, evidence model, extensive tests |

## Static contradictions that matter

These issues are recorded independently from feature breadth. They are not a
ranking and do not prove runtime exploitability.

| Risk pattern | Projects with pinned evidence | Product lesson |
| --- | --- | --- |
| A clean exit can hide skipped or failed coverage | Aguara, patient-zero, cc-audit, Cisco Skill Scanner, AgentSec by debu-sinha, Trust Issues, Sigil, agent-security-scanner-mcp | Completion state must be independent from finding severity |
| Repository or declared-root escape is possible | AgentShield, AgentSeal, cc-audit, AgentSec by debu-sinha, agent-security-scanner-mcp | Confinement needs resolved paths, no-follow reads, and regression witnesses |
| Default behavior contacts a service or feed | patient-zero, AgentSeal, Sigil | Offline must be a tested transport property |
| Meaningful analysis is hosted or opaque | Snyk Agent Scan, Inkog | Local reproducibility and inspectable evidence are a credible distinction |
| Target content or configuration can influence the scanner | Repo Forensics, Medusa | Never execute target hooks or trust target-owned scanner configuration by default |
| Published benchmark or feature evidence drifted | Trust Issues, cc-audit | Versioned fixtures and generated results must stay tied to releases |

## Controlled benchmark shortlist

Eight projects meet the static gate. Selection favors product overlap, a
network-disabled path, runnable pinned code, and one unresolved question that a
static review cannot answer.

| Project | Tier | Exact question for the controlled run | Why selected |
| --- | --- | --- | --- |
| Aguara | `offline_sandbox` | Do unreadable, oversized, and explicit symlink inputs affect diagnostics and exit status? | Closest broad deterministic pre-trust competitor |
| patient-zero | `offline_sandbox` | Can offline repository-only mode avoid host reads and fail closed on scanner errors? | Closest campaign-response competitor |
| AgentShield | `offline_sandbox` | Does default static mode stay confined and report unreadable configuration? | Strong agent-configuration and CI product |
| cc-audit | `offline_sandbox` | Does one failed scanner or outside-root explicit path produce an incomplete verdict? | Deterministic Claude-focused implementation |
| NVIDIA SkillSpector | `offline_sandbox` | What happens when OSV is blocked and a skill contains unreadable or oversized files? | Strongest inspection ledger and file-safety design |
| Cisco Skill Scanner | `offline_sandbox` | Does a skipped skill remain visible and force a nonzero batch verdict? | Mature skill-specific analyzer architecture |
| Sigil | `offline_sandbox` | Does a network-blocked fresh scan report missing feeds and skipped reads? | Quarantine and approval workflow comparison |
| agent-bom | `offline_sandbox` | Does offline mode preserve a complete evidence ledger for all inert omissions? | Strongest fail-closed and governance reference |

This shortlist was approved for benchmark design and image construction. Seven
images were built and re-inspected under the separate gate recorded in
`BUILD-GATE.md`; Sigil remains blocked. No competitor command may run until the
owner approves the matching clean-control plan digest. Each plan records the
exact image ID, argument vector, read-only mounts, disabled network, timeout,
and resource limits.

## Exclusions from the first controlled run

| Project | Reason for exclusion | Revisit condition |
| --- | --- | --- |
| Repo Forensics | Full mode executes target hooks and a safe comparable subset is not yet established | Review an exact no-DAST path manually |
| Snyk Agent Scan | Meaningful analysis uses a hosted API and MCP scanning can execute configured servers | Approve synthetic upload and destination-restricted network capture |
| AgentSeal | Overlaps AgentShield but adds default registry traffic and host baseline writes | Replace a cohort member if host-wide behavior becomes central |
| Medusa | External scanner subprocesses and target-owned configuration expand the containment problem | Trace each subprocess before any run |
| AgentSec by debu-sinha | Useful naming and safety evidence, but less campaign overlap than the selected cohort | Add after the root-escape witness is stable |
| Trust Issues | Human-led research workflow is not comparable to deterministic CI scanners | Evaluate separately as a response playbook |
| agent-security-scanner-mcp | Broad scope overlaps selected tools and its symlink boundary needs a dedicated Node sandbox | Add if broad source scanning becomes a parity goal |
| Inkog | Substantive analysis uploads source to a proprietary hosted service | Require explicit data-transfer and account approval |

## Static product signal

The evidence supports a narrow thesis:

> AgentSec should turn a reviewed campaign into a reproducible, local
> repository check with source-linked evidence and a fail-closed account of what
> was inspected, skipped, unsupported, or outside repository scope.

Five capabilities look like market parity candidates: reproducible
installation, more than one campaign detector, SARIF, a pinned GitHub Action,
and an explain or coverage interface. Three distinctions remain credible:
campaign-to-detector traceability, fail-closed coverage semantics, and
campaign-specific response playbooks.

These are inputs to the later product gate. They do not authorize scanner
changes, naming, or public claims before controlled observations are complete.

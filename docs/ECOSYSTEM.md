# Repository and Agent Security Scanner Ecosystem

Snapshot date: **2026-08-24**

This document maps projects that overlap with AgentSec Triage's current or
planned scope. It supports product positioning, naming, roadmap decisions, and
competitive testing. It is not an endorsement, a security certification, or a
benchmark result.

## Read this first

The ecosystem is already crowded. Local execution, deterministic rules,
offline operation, SARIF, GitHub Actions, MCP inspection, skill scanning, and
malicious-package intelligence are not unique features by themselves.

The strongest product territory still available is narrower:

> Convert a documented campaign into a reproducible repository check that
> explains the evidence found, the sources used, and the surfaces the scan
> could not verify.

AgentSec Triage currently implements that contract for evidence associated
with Shai-Hulud/Keyv. It does not yet have enough detector breadth,
distribution, or public validation to own this position.

## Sources and evidence levels

This inventory combines three inputs:

1. A Perplexity Deep Research market study supplied on 2026-08-24.
2. The read-only corpus at
   `/Users/florianbruniaux/Sites/perso/agentic-ecosystem-map/data/corpus.sqlite`.
3. Official project README files reviewed for the closest projects.

The corpus passed `PRAGMA quick_check` on 2026-08-24 and contained:

| Table | Rows |
| --- | ---: |
| `depots` | 100,319 |
| `readmes` | 54,644 |
| `audits` | 22,283 |
| `audits` with `mentionnable='oui'` | 1,779 |

Evidence labels used below:

| Label | Meaning |
| --- | --- |
| **README** | Claim checked against an official project README or official product page. |
| **Corpus** | Project and summary found in the SQLite corpus. The summary is the project's own description. |
| **Study** | Project or claim appeared in the supplied market study but was not independently checked for this snapshot. |

Project claims remain claims until reproduced. Counts of rules, engines,
precision, coverage, supported frameworks, and scanned skills are not treated
as comparative proof.

## Scope and classification

A project is included when it covers at least one of these surfaces:

- local repositories before installation, trust, or agent delegation;
- known-malicious packages or campaign indicators in dependency metadata;
- coding-agent instructions, hooks, permissions, or configuration;
- agent skills or plugins;
- MCP configurations, servers, tools, or manifests;
- CI workflows and repository persistence used by agent or supply-chain attacks;
- threat intelligence that can feed repository detection.

The catalogue excludes generic agent frameworks, general offensive-security
agents, SOC platforms, runtime guardrails, generic SAST, generic secret
scanners, and generic SCA unless they materially overlap with this job.

## Closest projects

These projects deserve hands-on testing before product or naming decisions.

| Project | Primary job | Main surfaces | Execution model | Distribution | Why it matters |
| --- | --- | --- | --- | --- | --- |
| [Aguara](https://github.com/garagon/aguara) | Trust preflight for repositories and agents | Packages, lockfiles, install scripts, MCP, skills, instructions, CI | Local, deterministic, no LLM; optional signed intel update | Binary, Homebrew, Docker, GitHub Action, Go library, MCP; JSON, SARIF, Markdown | Broadest direct feature competitor. It already covers most obvious roadmap items. **README** |
| [patient-zero](https://github.com/0xSteph/patient-zero) | Campaign-driven supply-chain triage and install blocking | npm, Python, MCP, processes, persistence, optional GitHub account | Local scan plus hourly normalized IOC feed | `npx`, install interceptor, pre-commit, GitHub Action, SARIF | Closest positioning competitor. It explicitly answers the new-campaign incident question. **README** |
| [Repo Forensics](https://github.com/alexgreensh/repo-forensics) | Pre-install and post-incident agent repository forensics | Repositories, skills, MCP, dependencies, Git and host traces | Local scripts with optional IOC updates and agent hooks | Standalone scripts, Claude plugin, Codex skill, GitHub Action | Broader incident and host coverage. Its large scanner-count claims require benchmarking. **README** |
| [AgentShield](https://github.com/affaan-m/agentshield) | Audit agent configuration and permissions | Claude Code configuration, hooks, MCP, permissions, secrets, workflows | Local static rules with optional advanced analysis | CLI, GitHub Action, GitHub App, multiple report formats | Strong configuration and hardening competitor with mature presentation. **README** |
| [Snyk Agent Scan](https://github.com/snyk/agent-scan) | Discover and assess installed agent components | Agent installations, MCP servers, skills, prompts, tools | Local discovery plus Snyk analysis API; MCP stdio scanning can execute configured servers with consent | `uvx`, signed binary, enterprise background mode; JSON | Broad host discovery and commercial integration. Its execution and API model differ from a confined offline scanner. **README** |
| [AgentSeal](https://github.com/getagentseal/agentseal) | Machine-wide AI agent security toolkit | Skills, MCP configs, live MCP servers, watcher, prompt-injection testing | Local CLI with static and live checks | CLI and SARIF | Broader host and runtime-adjacent scope. **README** |
| [Medusa](https://github.com/Pantheon-Security/medusa) | Broad AI-first repository security scanner | Source code, secrets, Claude Code configuration, skills, hooks, signatures | Local scanner with broad pattern catalogue | CLI and Git repository scanning | Much broader than campaign triage. Its breadth and precision claims need independent tests. **README** |
| [cc-audit](https://github.com/ryo-ebata/cc-audit) | Deterministic Claude Code artifact scan | Skills, hooks, MCP configurations | Local, static, no AI | CLI | Close on safety model and deterministic agent-config scanning, narrower on campaign intelligence. **Corpus** |
| [DeepSafe Scan](https://github.com/XiaoYiWeio/deepsafe-scan) | Preflight scan before trusting a coding-agent repository | Instructions, hooks, credential exfiltration, backdoors | Local static scanner | CLI | Competes directly on the before-opening-a-repository job. **Corpus** |
| [Ship Safe](https://github.com/asamassekou10/ship-safe) | Agent-era repository configuration scanner | CI/CD, permissions, MCP injection, secrets, dependencies | Local CLI | CLI | Overlaps with repository trust and CI posture rather than incident campaigns. **Corpus** |
| [agent-security-scanner-mcp](https://github.com/sinewaveai/agent-security-scanner-mcp) | Broad scanner exposed to coding agents | Repositories, MCP, prompts, packages, AST and taint analysis | Local and MCP-oriented; some external services may apply | CLI and MCP | Large claimed scope and direct coding-agent workflow integration. Claims require reproduction. **Corpus**, **Study** |
| [Trust Issues](https://github.com/howshannon/trust-issues) | Adversarial review before installing a repo, skill, MCP server, or package | Repository contents plus reasoning pass | Read-only scanner followed by five-persona LLM review | Agent-oriented workflow | Differentiates through an explicit GO, GO WITH MITIGATIONS, or NO-GO decision. Non-deterministic reasoning separates it from AgentSec's contract. **README** |
| [Sigil](https://github.com/NOMARJ/sigil) | Quarantine-first security audit for agent code | Repositories, packages, agent tooling | Automated audit with quarantine workflow | CLI | Strong trust-decision framing. Published capability maturity needs hands-on review. **README** |
| [Inkog](https://github.com/inkog-io/inkog) | Static security analysis for agent applications | Agent code, frameworks, MCP, skills, governance | Static scanner with optional service integration | CLI, MCP, GitHub Actions | Competes on agent application flaws and compliance, not primarily campaign evidence. **Corpus**, **Study** |
| [agent-bom](https://github.com/msaad00/agent-bom) | AI/MCP infrastructure inventory and governance | Agents, MCP, cloud, containers, infrastructure | Local scanners plus self-hosted control plane | CLI, API, dashboard, evidence formats | Adjacent control-plane vision. Too broad to copy at the current stage. **Corpus**, **Study** |
| [AgentSec by debu-sinha](https://github.com/debu-sinha/agentsec) | Scan and harden agent installations | OpenClaw, MCP, skills | Local CLI | CLI and CI-oriented outputs | Direct naming and command collision. The current AgentSec name should be retired before publication. **README**, **Corpus** |

## What is and is not differentiated

### Common capabilities

These capabilities are expected or already offered by multiple projects:

- local scanning;
- no telemetry or optional network access;
- static and deterministic rules;
- JSON and SARIF;
- GitHub Actions;
- MCP and skill scanning;
- malicious-package intelligence;
- pre-install or pre-trust workflows;
- rule explanations and remediation;
- signed releases or signed intelligence updates.

### Defensible product contract

AgentSec can differentiate if the following properties remain first-class and
become visible in every output:

1. **Campaign to detector traceability:** source, event, IOC, rule, synthetic
   fixture, regression test, finding, and remediation remain linked.
2. **Coverage as data:** detected, partial, not detected, not applicable, and
   not scanned remain distinct states.
3. **Fail-closed triage:** applicable unreadable or unsupported input produces
   an incomplete result rather than a clean result.
4. **Intelligence lifecycle:** conflicting reports, corrections, retractions,
   occurrence dates, disclosure dates, and confidence remain attributable.
5. **Safe repository confinement:** no target code execution, no writes to the
   target, no network during a scan, and no filesystem escape through links or
   Git metadata.
6. **Reproducible evidence:** a user can inspect why a detector exists and run
   the same synthetic witness that proves it works.

The first three properties are useful to users. The last three create trust in
the implementation. None compensate for having only one active detector.

## Direct and cross-surface catalogue

This table lists retained corpus projects whose declared scope overlaps local
repository, coding-agent, package, configuration, or trust scanning.

| Project | Declared focus | Evidence |
| --- | --- | --- |
| [Aguara](https://github.com/garagon/aguara) | Agent and software-supply-chain trust engine | README, Corpus |
| [patient-zero](https://github.com/0xSteph/patient-zero) | Campaign IOC triage, install blocking, CI | README, Corpus |
| [Repo Forensics](https://github.com/alexgreensh/repo-forensics) | Agent repositories, skills, plugins, MCP, post-incident traces | README, Corpus |
| [AgentShield](https://github.com/affaan-m/agentshield) | Agent configuration, MCP, permissions and hooks | README, Corpus |
| [Snyk Agent Scan](https://github.com/snyk/agent-scan) | Installed agents, MCP servers and skills | README, Corpus |
| [AgentSeal](https://github.com/getagentseal/agentseal) | Machine-wide skills and MCP security | README, Corpus |
| [Medusa](https://github.com/Pantheon-Security/medusa) | Broad repository and Claude Code compromise scanning | README, Corpus |
| [Ship Safe](https://github.com/asamassekou10/ship-safe) | CI/CD, permissions, MCP, secrets and dependencies | Corpus |
| [OpenHack](https://github.com/openhackai/OpenHack) | General agentic security scanner | Corpus |
| [cc-audit](https://github.com/ryo-ebata/cc-audit) | Static Claude Code artifact scanner | Corpus |
| [DeepSafe Scan](https://github.com/XiaoYiWeio/deepsafe-scan) | Coding-agent repository preflight | Corpus |
| [git-gud-security](https://github.com/kidsmeal/git-gud-security) | Repositories, applications, skills, plugins and MCP | Corpus |
| [Immunogen](https://github.com/Mocinjay/immunogen) | Offline security scan for AI-built applications | Corpus |
| [Trust Issues](https://github.com/howshannon/trust-issues) | Read-only pre-install adversarial review | README, Corpus |
| [Sigil](https://github.com/NOMARJ/sigil) | Quarantine-first audit for agent code | README, Corpus |
| [AgentSec](https://github.com/debu-sinha/agentsec) | Agent installation scanner and hardener | README, Corpus |
| [Inkog](https://github.com/inkog-io/inkog) | Static scanner for agent applications and compliance | Corpus, Study |
| [agent-security-scanner-mcp](https://github.com/sinewaveai/agent-security-scanner-mcp) | Repository, MCP, prompt and package scanner | Corpus, Study |
| [agent-bom](https://github.com/msaad00/agent-bom) | AI/MCP infrastructure scanner and control plane | Corpus, Study |
| [AI Infra Guard](https://github.com/Tencent/AI-Infra-Guard) | Agent, skill, MCP, infrastructure and red-team scanning | Corpus |
| [Agentic Radar](https://github.com/splx-ai/agentic-radar) | Security scanner for agentic workflows | Corpus |
| [Semia](https://github.com/berabuddies/Semia) | Security audit for agent skills | Corpus |
| [SkillGuardrail](https://github.com/T-Zevin/SkillGuardrail) | Guarded pre-install workflow for agent skills | Corpus |
| [SkillWard](https://github.com/Fangcun-AI/SkillWard) | Agent skill scanner | Corpus |
| [SkillFortify](https://github.com/qualixar/skillfortify) | Skills, plugins, supply-chain verification and SBOM | Corpus |
| [PromptSonar](https://github.com/meghal86/promptsonar) | Local prompt, MCP and agent-workflow scan | Corpus |
| [Coyote Security Scanner](https://github.com/Zen-Open-Source/coyote-security-scanner) | GitHub repositories and AI agents | Corpus |
| [cfgaudit](https://github.com/cfgaudit/cfgaudit) | Claude Code, Cursor and agent configuration audit | Corpus |
| [Tirith](https://github.com/sheeki03/tirith) | Terminal interception for developers and agents | Corpus |
| [ProofLayer Code Scanner](https://www.proof-layer.com/code-scanner) | Coding-agent configuration security | Study |
| [AgentCop](https://agentcop.live/) | Static and runtime enforcement for agent applications | Study |
| [g0](https://guard0.ai/g0) | Broad agent security scanner and governance | Study |
| [AgentSec by Semiotic AI](https://agentsec.sh/) | Agent skill and MCP security toolkit | Study |

## Agent skill and plugin scanners

This segment is crowded and changes quickly. It is useful for rule ideas and
test corpora, but becoming another generic `SKILL.md` regex scanner would not
create a durable position.

| Project | Declared focus | Evidence |
| --- | --- | --- |
| [NVIDIA SkillSpector](https://github.com/NVIDIA/SkillSpector) | Static, AST, YARA and optional model-assisted skill analysis | README, Corpus |
| [Cisco Skill Scanner](https://github.com/cisco-ai-defense/skill-scanner) | Static, YARA, data-flow and optional model-assisted skill analysis | README, Corpus |
| [Semia](https://github.com/berabuddies/Semia) | Agent skill audit | Corpus |
| [SkillGuardrail](https://github.com/T-Zevin/SkillGuardrail) | Quarantine and policy before skill installation | Corpus |
| [SkillWard](https://github.com/Fangcun-AI/SkillWard) | Skill threat detection | Corpus |
| [SkillFortify](https://github.com/qualixar/skillfortify) | Skills, plugins, SBOM and supply-chain checks | Corpus |
| [Claude Skill Antivirus](https://github.com/claude-world/claude-skill-antivirus) | Multi-engine Claude Code skill scan | Corpus |
| [Skill Sentinel](https://github.com/enkryptai/skill-sentinel) | Multi-agent analysis of skill packages | Corpus |
| [skill-audit](https://github.com/pors/skill-audit) | Prompt injection, secrets and dangerous patterns | Corpus |
| [SkillsGuard](https://github.com/Teycir/SkillsGuard) | Static `SKILL.md` and bundled-script scanning | Corpus |
| [AI Skill Scanner](https://github.com/suchithnarayan/ai-skill-scanner) | Rules, model analysis, taint and CI | Corpus |
| [Skill Sentinel](https://github.com/EvolutionUnleashed/skill-sentinel) | Skill prompt injection and supply-chain checks | Corpus |
| [skill-lint](https://github.com/LichAmnesia/skill-lint) | Claude Code and agent skill linting | Corpus |
| [SkillScan](https://github.com/NMitchem/SkillScan) | Static, model-assisted and sandboxed skill analysis | Corpus |
| [SkillGuard](https://github.com/obielin/skillguard) | Prompt injection, exfiltration and malicious payloads | Corpus |
| [SkillGuard](https://github.com/yangyixxxx/skillguard) | Local-first rule-based skill scanning | Corpus |
| [AgentVerus Scanner](https://github.com/agentverus/agentverus-scanner) | Agent skill threat categories | Corpus |
| [SkillScan Security](https://github.com/kurtpayne/skillscan-security) | IOC, malware and model classification for skills and MCP bundles | Corpus |
| [SkillVault](https://github.com/Khaledgarbaya/skillvault) | Open-source agent skill scanner | Corpus |
| [Sclawhub](https://github.com/mladjan/Sclawhub) | OpenClaw skill scanner | Corpus |
| [SkillGuard](https://github.com/LLMSecurity/skillguard) | OWASP Agentic Top 10 and MITRE ATLAS skill audit | Corpus |
| [skill-scanner](https://github.com/syedabbast/skill-scanner) | Zero-dependency `SKILL.md` scanning | Corpus |
| [Prism Scanner](https://github.com/aidongise-cell/prism-scanner) | Skills, plugins and MCP server rules | Corpus |
| [Skill Audit MCP](https://github.com/eltociear/skill-audit-mcp) | Static skills, plugins and MCP signatures | Corpus |
| [Skill Safety Audit](https://github.com/AI272/skill-safety-audit) | Static Codex and Claude Code skill audit | Corpus |
| [Nyuway Skill Scanner](https://github.com/Nyuway-Cybersecurity/nyuwayskillscanner) | Static enterprise-oriented skill-bundle scan | Corpus |
| [OpenClaw Skill Scanner](https://github.com/clawdbrunner/openclaw-skill-scanner) | Multi-stage OpenClaw skill checks | Corpus |
| [Skill Shield](https://github.com/highimpact-dev/skill-shield) | Skill trust scoring and marketplace checks | Corpus |
| [AgentSafety ClawCare](https://github.com/AgentSafety/ClawCare) | Skills and plugins before execution | Corpus |
| [T2I SkillGuard](https://github.com/Tech2Insights/t2i-skillguard) | `SKILL.md` and bundled-code checks | Corpus |

## MCP and configuration scanners

| Project | Declared focus | Evidence |
| --- | --- | --- |
| [Cisco MCP Scanner](https://github.com/cisco-ai-defense/mcp-scanner) | Static and live MCP threat analysis | Corpus |
| [Snyk Agent Scan](https://github.com/snyk/agent-scan) | MCP discovery, execution and remote analysis | README, Corpus |
| [AgentSeal](https://github.com/getagentseal/agentseal) | MCP config, live MCP and machine-wide discovery | README, Corpus |
| [Ramparts](https://github.com/highflame-ai/ramparts) | MCP and skill configuration vulnerabilities | Corpus |
| [claudit-sec](https://github.com/HarmonicSecurity/claudit-sec) | Claude Desktop and Claude Code inventory on macOS | Corpus |
| [SecureMCP](https://github.com/makalin/SecureMCP) | MCP vulnerability and configuration audit | Corpus |
| [mcp-watch](https://github.com/kapilduraphe/mcp-watch) | MCP implementation security checks | Corpus |
| [MCTS](https://github.com/MCP-Audit/MCTS) | Static and live MCP discovery with auditable scores | Corpus |
| [mcp-fence](https://github.com/DaoyuanLi2816/mcp-fence) | Static scanning, protocol inspection, fuzzing and sandbox | Corpus |
| [AgentsID Scanner](https://github.com/AgentsID-dev/agentsid-scanner) | MCP authentication, permissions, injection and tool safety | Corpus |
| [MCPShield](https://github.com/mcpshield/mcpshield) | MCP typosquats, CVEs, secrets and permissions | Corpus |
| [MCP Safeguard](https://github.com/SyedAnas01/mcp-safeguard) | Rule-based MCP server scan | Corpus |
| [MCP Scanner](https://github.com/MK-ScorpioSec/mcp-scanner) | CVE, authentication and tool-poisoning checks | Corpus |
| [Attestral](https://github.com/attestral-labs/attestral) | MCP and agent cloud-reach analysis | Corpus |
| [IntentProbe](https://github.com/mcpware/IntentProbe) | Model-activation probe for poisoned MCP, skills and packages | Corpus |
| [Secure Hulk](https://github.com/AppiumTestDistribution/secure-hulk) | MCP configuration and tool threats | Corpus |
| [mcpwn](https://github.com/ressl/mcpwn) | MCP server security scanning | Corpus |
| [MCP Scanner](https://github.com/Oabraham1/mcp-scanner) | Prompt injection, permissions and tool shadowing | Corpus |
| [Assay](https://github.com/chawdamrunal/assay) | LLM threat modelling for plugins, MCP, hooks and skills | Corpus |
| [MCP Fortress](https://github.com/safedep) | MCP and package-supply-chain checks referenced by the study; exact project URL needs verification | Study |

## Supply-chain and malicious-package tools

These tools overlap dependency evidence but usually target generic
vulnerabilities, registry reputation, or installation policy rather than
campaign-to-repository traceability.

| Project | Declared focus | Relationship | Evidence |
| --- | --- | --- | --- |
| [OSV-Scanner](https://github.com/google/osv-scanner) | Vulnerable dependency scanning from OSV | Complementary SCA; broader ecosystems, different threat model | Study |
| [Grype](https://github.com/anchore/grype) | Filesystem, image and SBOM vulnerability scanning | Complementary SCA and container coverage | Study |
| [Socket](https://socket.dev/) | Malicious package and supply-chain risk | Commercial and broader continuous monitoring | Study |
| [Aikido Safe Chain](https://www.aikido.dev/) | Package installation and supply-chain protection | Overlaps install-time prevention | Study |
| [npm Security Scanner](https://araptus.com/software/npm-security-scanner) | Known malicious npm package scan | Narrow package overlap | Study |
| [SafeDep vet](https://github.com/safedep/vet) | Package vetting and malicious-package intelligence | Potential intelligence and scan integration reference | Study |
| [npq](https://github.com/lirantal/npq) | Pre-install npm package checks | Adjacent install-time gate | Study |
| [Clawdex](https://www.koi.ai/) | Skill and package intelligence associated with ClawHavoc | Threat-intelligence and registry overlap; exact public artifact needs verification | Study |
| [Watchtower](https://marketplace.visualstudio.com/items?itemName=luisfontes19.watchtower) | VS Code workspace threat scanning | IDE-specific pre-trust overlap | Study |
| [Tirith](https://github.com/sheeki03/tirith) | Intercept dangerous terminal and agent actions before execution | Preventive runtime-adjacent complement | Corpus |
| [Runner Guard](https://github.com/Vigilant-LLC/runner-guard) | CI/CD injection and agent-config poisoning | CI-specific overlap | Corpus |

## Adjacent projects worth monitoring

These projects may supply techniques, formats, test corpora, or integration
ideas. They should not drive the core product category.

| Project | Adjacent domain | Evidence |
| --- | --- | --- |
| [DeepSec](https://github.com/vercel-labs/deepsec) | Agent-powered application security harness | Corpus |
| [Cloudflare Security Audit Skill](https://github.com/cloudflare/security-audit-skill) | Agent-driven application audit with machine-readable findings | Corpus |
| [Google Mantis](https://github.com/google/mantis) | Security-review skills for coding agents | Corpus |
| [Agentic Radar](https://github.com/splx-ai/agentic-radar) | Agent workflow security | Corpus |
| [AI Infra Guard](https://github.com/Tencent/AI-Infra-Guard) | Broad AI red-team and infrastructure scanning | Corpus |
| [VulnHunter](https://github.com/capitalone/VulnHunter) | Agentic source-code vulnerability analysis | Corpus |
| [OpenTaint](https://github.com/seqra/opentaint) | Customizable taint analysis | Corpus |
| [Pipelock](https://github.com/luckyPipewrench/pipelock) | Runtime MCP and agent-egress mediation | Corpus |
| [CodeGate](https://github.com/stacklok/codegate) | Agent workflow security proxy | Corpus |
| [ThreatClaw](https://www.threatclaw.ai/company) | AI-focused threat intelligence platform | Study |
| [Claude Code Guide security page](https://cc.bruniaux.com/security/) | Educational threat-intelligence consumer | Study, local integration |
| [Awesome AI Security Tools](https://github.com/scadastrangelove/awesome-ai-security-tools) | Broader ecosystem index | Corpus |
| [Awesome MCP Security](https://github.com/Puliczek/awesome-mcp-security) | MCP security index | Corpus |
| [Awesome LLM Supply Chain Security](https://github.com/ShenaoW/awesome-llm-supply-chain-security) | Research and incident bibliography | Corpus |

## Naming collisions

The name `AgentSec` is not viable for public distribution. It is already used
by multiple projects and products in overlapping categories.

| Name | Existing use | Evidence |
| --- | --- | --- |
| [AgentSec](https://github.com/debu-sinha/agentsec) | Open-source scanner and hardener for agent installations | README, Corpus |
| [AgentSec](https://agentsec.sh/) | Agent skill and MCP security toolkit associated with Semiotic AI | Study |
| [agentsec-cli](https://pypi.org/project/agentsec-cli/) | Python package for coding-agent and MCP scanning | Study |
| [agentsec-ai](https://pypi.org/project/agentsec-ai/) | Python package for agent security analysis | Study |
| [AgentSec Desktop](https://www.agentsec.tech/) | RPA script security product | Study |
| [AgentSec Autonomous DevSecOps](https://www.ashtech.app/) | Repository and cloud DevSecOps product | Study |
| `agentsec.protect` | Cisco AI Defense runtime-protection naming | Study |

The repository, package, import namespace, CLI command, schema identifiers,
generated feed, guide integration, and landing integration all need a planned
rename before publication. Keeping `agentsec` as a public compatibility alias
would preserve the collision and is not recommended before a first release.

## Product gaps exposed by the ecosystem

### Release blockers

- resolve the threat-data licensing gate;
- select and validate the new name across GitHub, package registries, search,
  domains, and obvious trademarks;
- publish a reproducible installation path and signed artifacts;
- demonstrate the full Linux, macOS, and Windows gate on public CI.

### Minimum credible feature set

1. Ship detectors for **three to five independently sourced campaigns**, not
   merely intelligence fiches.
2. Add **SARIF** and a pinned **GitHub Action**.
3. Add `coverage` or equivalent output that maps campaign, IOC, observable
   surfaces, unsupported surfaces, and completion state.
4. Add campaign-specific response playbooks and remediation links.
5. Publish a reproducible positive, near-miss, and negative benchmark corpus.
6. Publish detector and intelligence update provenance.

### Differentiating follow-up

- diff-scoped or baseline-aware review for pull requests;
- mapping between campaign techniques, repository evidence, detector rules,
  and missing host or runtime evidence;
- signed intelligence updates with rollback protection;
- a contribution contract for sources, fiches, IOCs, synthetic fixtures, and
  detectors;
- a measured service-level objective for candidate review and emergency
  detector releases.

### Work to defer

- generic SAST;
- generic CVE scanning;
- secret scanning as a product category;
- antivirus or EDR behavior;
- a multi-tenant governance dashboard;
- live MCP execution inside the repository scanner;
- automatic remediation that rewrites an untrusted repository.

## Recommended operating cadence

The threat-intelligence rhythm should be different from the detector-release
rhythm.

| Activity | Target rhythm | Gate |
| --- | --- | --- |
| Candidate discovery | Daily or event-driven | No automatic promotion |
| Source and event review | Weekly, plus emergency review | Primary source and explicit confidence |
| Detector feasibility decision | During event review | Repository-observable evidence exists |
| Emergency IOC update | As needed | Exact IOC, provenance, schema and regression witness |
| Detector release | Small, independent releases | Positive, near-miss negative, safety tests and full gate |
| Ecosystem review | Monthly | Official README and release verification for closest projects |
| Positioning and naming review | Before each public milestone | Current capabilities only |

An intelligence fiche can ship with `not_detected`. A detector claim cannot
ship until a regression witness proves it. Automated discovery may create a
candidate queue, but it must not publish security claims by itself.

## Hands-on evaluation queue

The first comparative test batch is cloned under
`/Users/florianbruniaux/Sites/divers-test/agent-security-ecosystem`. These are
shallow snapshots. The revision column makes later observations reproducible.

| Project | Local directory | Revision |
| --- | --- | --- |
| Aguara | `aguara` | `819eafb5fa66` |
| patient-zero | `patient-zero` | `331320c152aa` |
| Repo Forensics | `repo-forensics` | `eedd6a5f909a` |
| AgentShield | `agentshield` | `bdad15dd28da` |
| Snyk Agent Scan | `snyk-agent-scan` | `891f0b2cc69c` |
| AgentSeal | `agentseal` | `7c2a22891465` |
| Medusa | `medusa` | `5f217edf8b09` |
| cc-audit | `cc-audit` | `bdb657474624` |
| NVIDIA SkillSpector | `skillspector` | `698e2bf29c7d` |
| Cisco Skill Scanner | `cisco-skill-scanner` | `48f59347a54b` |
| AgentSec by debu-sinha | `agentsec-debu-sinha` | `3e704ade516f` |
| Trust Issues | `trust-issues` | `ca53cd030f78` |
| Sigil | `sigil` | `0f73627236d5` |
| agent-security-scanner-mcp | `agent-security-scanner-mcp` | `79e8779b4eec` |
| Inkog | `inkog` | `85683e73f2db` |
| agent-bom | `agent-bom` | `9ceeb22fff1f` |

Do not execute these projects against a trusted workstation or real repository
as part of cloning. Evaluation needs a separate test plan, pinned revisions,
isolated fixtures, no credentials, and network controls appropriate to each
tool's declared behavior.

## Maintenance checklist

For each monthly update:

1. rerun the read-only corpus queries;
2. review new direct candidates instead of copying every `security` keyword
   match;
3. verify the closest projects against official README and release pages;
4. preserve project claims as claims until benchmarked;
5. update the snapshot date and record material changes in `CHANGELOG.md`;
6. update roadmap priorities only when a competitor changes the actual product
   trade-off.

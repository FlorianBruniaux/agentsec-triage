# AgentShield

Review of the pinned revision only. No AgentShield code was executed.

## Project identity

- Project ID: `agentshield`
- Repository: `https://github.com/affaan-m/agentshield`
- Revision: `bdad15dd28da`
- Review date: `2026-08-24`
- Review scope: tracked TypeScript source, tests, action, license, and documentation

## Declared promise

| Claim | State | Evidence | Notes |
| --- | --- | --- | --- |
| Security auditor for AI agent configuration | `declared` | `README.md:7@bdad15dd28da` | Focuses on Claude setup, hooks, MCP, permissions, and prompts |
| One hundred and two rules across five categories | `declared` | `README.md:115@bdad15dd28da` | Produces a numeric score and grade |
| CLI, GitHub Action, and application integrations | `declared` | `README.md:7@bdad15dd28da` | Includes optional active and LLM-backed modes |

## Observed architecture

| Component | State | Evidence | Responsibility |
| --- | --- | --- | --- |
| CLI | `code_verified` | `src/index.ts:216@bdad15dd28da` | Selects static, sandbox, taint, Opus, baseline, policy, and supply-chain modes |
| Discovery | `code_verified` | `src/scanner/discovery.ts:73@bdad15dd28da` | Finds agent configuration, skills, hooks, and package-manager files |
| Rule engine | `code_verified` | `src/scanner/index.ts:24@bdad15dd28da` | Applies built-in rules and annotates runtime confidence |
| GitHub Action | `code_verified` | `action.yml:1@bdad15dd28da` | Runs the bundled Node action without a package install step |

## Inspected surfaces

| Surface | State | Evidence | Boundary |
| --- | --- | --- | --- |
| Claude, MCP, agent, skill, and hook files | `code_verified` | `src/scanner/discovery.ts:128@bdad15dd28da` | Discovery uses a fixed inventory and skips common generated directories |
| Package-manager configuration | `code_verified` | `src/scanner/discovery.ts:166@bdad15dd28da` | Includes npm, pnpm, and Yarn configuration |
| Source context | `code_verified` | `README.md:199@bdad15dd28da` | Findings distinguish active, optional, example, cache, manifest, and hook-code contexts |

## Safety boundary

| Property | State | Evidence | Consequence |
| --- | --- | --- | --- |
| Target content execution | `code_verified` | `src/scanner/index.ts:24@bdad15dd28da` | Default static mode applies rules only; sandbox and deep modes are separate |
| Target writes | `code_verified` | `src/fixer/index.ts:93@bdad15dd28da` | Default scan reads; fix, baseline, evidence, policy, and runtime commands write explicitly |
| Network access | `code_verified` | `src/index.ts:290@bdad15dd28da` | Online supply-chain and Opus analysis are opt-in |
| Read confinement | `contradicted` | `src/scanner/discovery.ts:426@bdad15dd28da` | Fixed config paths are read without a real-path check, so target symlinks can escape the root |

## Intelligence lifecycle

| Capability | State | Evidence | Update contract |
| --- | --- | --- | --- |
| Built-in CVE and threat rules | `code_verified` | `src/threat-intel/cve-database.ts:1@bdad15dd28da` | Shipped with the package; no independent signed feed was found |
| Optional npm enrichment | `code_verified` | `README.md:173@bdad15dd28da` | Requires an explicit online flag |

## Outputs and integration

| Output or integration | State | Evidence | Contract |
| --- | --- | --- | --- |
| Terminal, JSON, Markdown, HTML, and SARIF | `code_verified` | `src/reporter/index.ts:1@bdad15dd28da` | Human and machine output modules are separate |
| Runtime confidence | `code_verified` | `src/scanner/index.ts:100@bdad15dd28da` | Context affects labels and score weighting |
| GitHub Action gate | `code_verified` | `src/action.ts:138@bdad15dd28da` | Fails on findings by default and exposes policy and supply-chain states |

## Distribution

| Channel | State | Evidence | Verification |
| --- | --- | --- | --- |
| npm package and bundled Node Action | `code_verified` | `package.json:1@bdad15dd28da` | Package exports CLI and Action bundles |

## Tests and fixtures

| Test property | State | Evidence | Limitation |
| --- | --- | --- | --- |
| Rule, reporter, action, and scanner suites | `code_verified` | `package.json:18@bdad15dd28da` | Static review did not execute the suite |
| Source-context regression tests | `code_verified` | `tests/scanner/scanner.test.ts:183@bdad15dd28da` | Covers classification, not root-escape symlinks |

## License

| Item | State | Evidence | Consequence |
| --- | --- | --- | --- |
| MIT License | `code_verified` | `LICENSE:1@bdad15dd28da` | Permissive reuse with copyright notice |

## Contradictions and unknowns

| Claim or question | State | Evidence | Required follow-up |
| --- | --- | --- | --- |
| Config symlink can read outside target | `contradicted` | `src/scanner/discovery.ts:426@bdad15dd28da` | Run a sandboxed symlink witness after owner approval |
| Unreadable discovery entry handling | `not_tested` | `src/scanner/discovery.ts:101@bdad15dd28da` | Inject permission failures and inspect exit and coverage output |
| Active sandbox containment | `not_tested` | `src/sandbox/executor.ts:1@bdad15dd28da` | Trace process, filesystem, and network effects separately from static mode |

## Parity lessons

| Candidate capability | State | Evidence | AgentSec decision question |
| --- | --- | --- | --- |
| Runtime-confidence labels | `code_verified` | `README.md:199@bdad15dd28da` | Add activation confidence without weakening IOC findings |
| Baseline, policy, and evidence packs | `code_verified` | `action.yml:24@bdad15dd28da` | Define which enterprise artifacts belong before the stable CLI contract |
| Package-manager hardening | `code_verified` | `src/rules/package-manager.ts:1@bdad15dd28da` | Add lifecycle and release-age checks beside campaign IOCs |

## Differentiation lessons

| Candidate distinction | State | Evidence | AgentSec decision question |
| --- | --- | --- | --- |
| Versioned external security timeline | `code_verified` | `src/threat-intel/cve-database.ts:1@bdad15dd28da` | Keep AgentSec intelligence independently reviewable and exportable |
| Explicit incomplete-scan coverage | `not_tested` | `src/scanner/discovery.ts:101@bdad15dd28da` | Benchmark unreadable, oversized, and symlink cases |

## Evidence

| Reference | State | Evidence type | Relevance |
| --- | --- | --- | --- |
| `src/scanner/discovery.ts:426@bdad15dd28da` | `code_verified` | Code | Establishes unchecked file reads |
| `src/scanner/index.ts:100@bdad15dd28da` | `code_verified` | Code | Establishes context classification |
| `src/action.ts:138@bdad15dd28da` | `code_verified` | Code | Establishes Action gate defaults |

# NVIDIA SkillSpector

Review of the pinned revision only. No SkillSpector code was executed.

## Project identity

- Project ID: `skillspector`
- Repository: `https://github.com/NVIDIA/SkillSpector`
- Revision: `698e2bf29c7d`
- Review date: `2026-08-24`
- Review scope: tracked Python source, tests, package metadata, license, and documentation

## Declared promise

| Claim | State | Evidence | Notes |
| --- | --- | --- | --- |
| Security scanner for AI agent skills | `declared` | `README.md:1@698e2bf29c7d` | Accepts local and remote skill bundles |
| Static checks with optional LLM analysis | `declared` | `README.md:778@698e2bf29c7d` | LLM analysis sends eligible file content to the selected provider |
| Stable exit and JSON integration contract | `declared` | `README.md:621@698e2bf29c7d` | Distinguishes execution failure from a risk decision |

## Observed architecture

| Component | State | Evidence | Responsibility |
| --- | --- | --- | --- |
| Input resolver | `code_verified` | `src/skillspector/input_handler.py:661@698e2bf29c7d` | Resolves Git, URL, zip, Markdown, and directory inputs |
| Analysis graph | `code_verified` | `src/skillspector/nodes/build_context.py:271@698e2bf29c7d` | Builds bounded context for static and optional model analyzers |
| Inspection ledger | `code_verified` | `src/skillspector/inspection_ledger.py:672@698e2bf29c7d` | Accounts for completed, partial, skipped, and failed work |
| CLI | `code_verified` | `src/skillspector/cli.py:670@698e2bf29c7d` | Writes the report and maps execution, completeness, and risk to exit codes |

## Inspected surfaces

| Surface | State | Evidence | Boundary |
| --- | --- | --- | --- |
| Skill instructions and related files | `code_verified` | `src/skillspector/nodes/build_context.py:271@698e2bf29c7d` | Skips unsafe links and records analysis limitations |
| Nested archives and external references | `code_verified` | `src/skillspector/nested_artifacts.py:1047@698e2bf29c7d` | Applies member, byte, depth, and traversal limits |
| Dependencies and MCP metadata | `code_verified` | `README.md:741@698e2bf29c7d` | OSV and MCP registry checks can require network access |

## Safety boundary

| Property | State | Evidence | Consequence |
| --- | --- | --- | --- |
| Target content execution | `code_verified` | `README.md:301@698e2bf29c7d` | `--no-llm` retains deterministic static analysis; target files are not invoked |
| Target writes | `code_verified` | `src/skillspector/input_handler.py:698@698e2bf29c7d` | Remote inputs use temporary storage; explicit output and baseline commands write reports |
| Network access | `code_verified` | `README.md:778@698e2bf29c7d` | LLM content transfer is optional, but OSV dependency coordinates are sent even with `--no-llm` |
| Read confinement | `code_verified` | `src/skillspector/input_handler.py:267@698e2bf29c7d` | Rejects symlinked inputs and parents and uses no-follow file opens |

## Intelligence lifecycle

| Capability | State | Evidence | Update contract |
| --- | --- | --- | --- |
| OSV vulnerability lookup | `code_verified` | `README.md:764@698e2bf29c7d` | Uses the live service with a bundled offline fallback list |
| Static rule corpus | `code_verified` | `src/skillspector/nodes/analyzers/static_runner.py:1@698e2bf29c7d` | Ships with package releases; no independent signed intelligence feed was found |

## Outputs and integration

| Output or integration | State | Evidence | Contract |
| --- | --- | --- | --- |
| Terminal, JSON, Markdown, and SARIF | `code_verified` | `README.md:621@698e2bf29c7d` | JSON exposes recommendation and analysis completeness |
| Incomplete-scan gate | `code_verified` | `src/skillspector/cli.py:490@698e2bf29c7d` | `--fail-on-incomplete` turns partial relevant analysis into exit `1` |
| Exit codes | `code_verified` | `src/skillspector/cli.py:684@698e2bf29c7d` | Execution failure exits `2`; policy or risk failure exits `1` |

## Distribution

| Channel | State | Evidence | Verification |
| --- | --- | --- | --- |
| PyPI package and container workflow | `code_verified` | `pyproject.toml:5@698e2bf29c7d` | Package requires Python 3.12 through 3.14 |

## Tests and fixtures

| Test property | State | Evidence | Limitation |
| --- | --- | --- | --- |
| Symlink and input-boundary regressions | `code_verified` | `tests/unit/test_input_handler.py:93@698e2bf29c7d` | Static review did not execute the suite |
| Completeness and CLI regressions | `code_verified` | `tests/unit/test_cli.py:3442@698e2bf29c7d` | Runtime behavior remains unobserved in this study |

## License

| Item | State | Evidence | Consequence |
| --- | --- | --- | --- |
| Apache License 2.0 | `code_verified` | `LICENSE:1@698e2bf29c7d` | Permissive reuse with notice and license terms |

## Contradictions and unknowns

| Claim or question | State | Evidence | Required follow-up |
| --- | --- | --- | --- |
| Static-only network isolation | `contradicted` | `README.md:779@698e2bf29c7d` | An offline benchmark must block OSV traffic because `--no-llm` alone does not disable it |
| Completeness exit behavior | `not_tested` | `src/skillspector/cli.py:692@698e2bf29c7d` | Inject unreadable and oversized fixtures in an approved offline run |
| LLM provider subprocess isolation | `not_tested` | `src/skillspector/providers/_agent_cli.py:1@698e2bf29c7d` | Keep model-backed modes outside the first benchmark |

## Parity lessons

| Candidate capability | State | Evidence | AgentSec decision question |
| --- | --- | --- | --- |
| Canonical inspection ledger | `code_verified` | `src/skillspector/inspection_ledger.py:672@698e2bf29c7d` | Replace aggregate diagnostics with per-work accounting in V2 |
| Evidence-bound baselines | `code_verified` | `README.md:616@698e2bf29c7d` | Define when a suppression expires after file or rule changes |
| Nested artifact analysis | `code_verified` | `src/skillspector/nested_artifacts.py:1047@698e2bf29c7d` | Add bounded archive inspection only after the V2 safe-reader contract |

## Differentiation lessons

| Candidate distinction | State | Evidence | AgentSec decision question |
| --- | --- | --- | --- |
| Versioned public campaign intelligence | `code_verified` | `README.md:764@698e2bf29c7d` | Keep source conflicts, corrections, and dated events separate from live OSV enrichment |
| Repository-wide campaign triage | `not_applicable` | `pyproject.toml:8@698e2bf29c7d` | Preserve AgentSec's repository job instead of narrowing to skill packages |

## Evidence

| Reference | State | Evidence type | Relevance |
| --- | --- | --- | --- |
| `src/skillspector/input_handler.py:267@698e2bf29c7d` | `code_verified` | Code | Establishes local read confinement |
| `src/skillspector/inspection_ledger.py:672@698e2bf29c7d` | `code_verified` | Code | Establishes completeness accounting |
| `src/skillspector/cli.py:684@698e2bf29c7d` | `code_verified` | Code | Establishes exit behavior |

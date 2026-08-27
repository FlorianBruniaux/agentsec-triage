# AgentSeal

Review of the pinned revision only. No AgentSeal code was executed.

## Project identity

- Project ID: `agentseal`
- Repository: `https://github.com/getagentseal/agentseal`
- Revision: `7c2a22891465`
- Review date: `2026-08-24`
- Review scope: tracked Python and TypeScript source, tests, action, license, and documentation

## Declared promise

| Claim | State | Evidence | Notes |
| --- | --- | --- | --- |
| AI-agent security toolkit | `declared` | `README.md:7@7c2a22891465` | Combines host guard, prompt probes, MCP runtime scan, and watcher |
| Guard needs no API key or network | `declared` | `README.md:60@7c2a22891465` | The implementation performs registry enrichment by default |
| Six-stage local detection pipeline | `declared` | `README.md:65@7c2a22891465` | Includes semantic similarity, baselines, registry data, and custom rules |

## Observed architecture

| Component | State | Evidence | Responsibility |
| --- | --- | --- | --- |
| Guard orchestrator | `code_verified` | `python/agentseal/guard.py:57@7c2a22891465` | Discovers host components, scans skills, checks MCP config, and tracks baselines |
| Machine discovery | `code_verified` | `python/agentseal/machine_discovery.py:54@7c2a22891465` | Enumerates well-known agent paths and project files |
| Skill scanner | `code_verified` | `python/agentseal/skill_scanner.py:55@7c2a22891465` | Applies patterns, deobfuscation, optional semantic analysis, and size limits |
| Registry client | `code_verified` | `python/agentseal/registry_client.py:56@7c2a22891465` | Sends MCP package slugs to AgentSeal's bulk-check API |

## Inspected surfaces

| Surface | State | Evidence | Boundary |
| --- | --- | --- | --- |
| Twenty-eight agent families | `declared` | `README.md:60@7c2a22891465` | Default guard scans machine-wide well-known locations |
| Skills and agent instruction files | `code_verified` | `python/agentseal/machine_discovery.py:45@7c2a22891465` | Project discovery includes major agent rule formats |
| MCP config and toxic flows | `code_verified` | `python/agentseal/guard.py:130@7c2a22891465` | Static config checks precede optional live connections |

## Safety boundary

| Property | State | Evidence | Consequence |
| --- | --- | --- | --- |
| Target content execution | `code_verified` | `python/agentseal/guard.py:169@7c2a22891465` | Default guard does not connect; `--connect` and scan-mcp spawn configured servers |
| Target writes | `code_verified` | `python/agentseal/baselines.py:213@7c2a22891465` | Guard creates and updates user-home baselines; shield and fix add further writes |
| Network access | `contradicted` | `python/agentseal/cli.py:1249@7c2a22891465` | Default guard enriches MCP results through `agentseal.org` unless registry is disabled |
| Read confinement | `contradicted` | `python/tests/test_edge_cases.py:67@7c2a22891465` | Symlinked skills are intentionally followed and scanned |

## Intelligence lifecycle

| Capability | State | Evidence | Update contract |
| --- | --- | --- | --- |
| Hosted MCP registry | `code_verified` | `python/agentseal/registry_client.py:12@7c2a22891465` | Network errors silently return no enrichment |
| Built-in blocklist and rules | `code_verified` | `python/agentseal/blocklist.py:1@7c2a22891465` | Package release carries local intelligence; provenance signing was not found |
| Baseline change detection | `code_verified` | `python/agentseal/baselines.py:213@7c2a22891465` | Updates stored state during each scan |

## Outputs and integration

| Output or integration | State | Evidence | Contract |
| --- | --- | --- | --- |
| Terminal, JSON, and SARIF | `declared` | `README.md:82@7c2a22891465` | Guard and prompt-scan paths expose machine-readable reports |
| GitHub Docker Action | `code_verified` | `.github/actions/guard/action.yml:1@7c2a22891465` | Defaults to registry enrichment unless `no-registry` is set |
| Trust score and baseline delta | `code_verified` | `python/agentseal/guard.py:182@7c2a22891465` | Combines static findings, runtime data, and stored state |

## Distribution

| Channel | State | Evidence | Verification |
| --- | --- | --- | --- |
| PyPI, npm, and Docker Action | `declared` | `README.md:25@7c2a22891465` | Published artifacts were not downloaded |

## Tests and fixtures

| Test property | State | Evidence | Limitation |
| --- | --- | --- | --- |
| Unreadable, oversized, binary, and symlink files | `code_verified` | `python/tests/test_edge_cases.py:14@7c2a22891465` | Symlink behavior is accepted rather than confined |
| MCP runtime subprocess mocks | `code_verified` | `python/tests/test_mcp_runtime.py:527@7c2a22891465` | Runtime containment is not established by mocked process tests |

## License

| Item | State | Evidence | Consequence |
| --- | --- | --- | --- |
| FSL 1.1 with Apache 2.0 future license | `code_verified` | `LICENSE:1@7c2a22891465` | Competing commercial use is restricted until the change date |

## Contradictions and unknowns

| Claim or question | State | Evidence | Required follow-up |
| --- | --- | --- | --- |
| Guard's no-network claim | `contradicted` | `python/agentseal/cli.py:1249@7c2a22891465` | Observe default traffic and repeat with `--no-registry` |
| Root escape through skill symlinks | `contradicted` | `python/tests/test_edge_cases.py:67@7c2a22891465` | Run a sandboxed outside-root secret witness after approval |
| Failed registry enrichment is invisible | `code_verified` | `python/agentseal/registry_client.py:75@7c2a22891465` | Decide whether missing intelligence changes verdict completeness |

## Parity lessons

| Candidate capability | State | Evidence | AgentSec decision question |
| --- | --- | --- | --- |
| Cross-harness machine discovery | `code_verified` | `python/agentseal/machine_discovery.py:54@7c2a22891465` | Reuse a shared location catalog in an explicit host mode |
| Rug-pull baseline for MCP tools | `code_verified` | `python/agentseal/baselines.py:213@7c2a22891465` | Add history only with immutable evidence and no silent overwrite |
| Toxic-flow analysis | `code_verified` | `python/agentseal/guard.py:137@7c2a22891465` | Correlate capabilities after individual detector evidence is stable |

## Differentiation lessons

| Candidate distinction | State | Evidence | AgentSec decision question |
| --- | --- | --- | --- |
| Offline means no network by default | `contradicted` | `python/agentseal/cli.py:1249@7c2a22891465` | Make AgentSec offline behavior testable and exact |
| Repository confinement | `contradicted` | `python/tests/test_edge_cases.py:67@7c2a22891465` | Keep outside-root reads as blocking coverage errors |
| Permissive competitive reuse | `code_verified` | `LICENSE:28@7c2a22891465` | Explain the practical adoption difference of AgentSec's MIT code |

## Evidence

| Reference | State | Evidence type | Relevance |
| --- | --- | --- | --- |
| `python/agentseal/cli.py:1249@7c2a22891465` | `code_verified` | Code | Establishes default registry enrichment |
| `python/tests/test_edge_cases.py:67@7c2a22891465` | `code_verified` | Test | Establishes deliberate symlink following |
| `LICENSE:28@7c2a22891465` | `code_verified` | License | Establishes competing-use restrictions |

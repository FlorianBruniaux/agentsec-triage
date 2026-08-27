# Sigil

Review of the pinned revision only. No Sigil code was executed.

## Project identity

- Project ID: `sigil`
- Repository: `https://github.com/NOMARJ/sigil`
- Revision: `0f73627236d5`
- Review date: `2026-08-24`
- Review scope: tracked Rust CLI source, scanner, tests, license, and documentation

## Declared promise

| Claim | State | Evidence | Notes |
| --- | --- | --- | --- |
| Quarantine-first scanner for repositories, packages, MCP servers, and skills | `declared` | `README.md:17@0f73627236d5` | Positions approval before installation as the main workflow |
| Eight local scan phases | `declared` | `README.md:342@0f73627236d5` | Combines static rules, dependencies, provenance, and threat intelligence |
| Offline operation keeps local analysis | `declared` | `README.md:238@0f73627236d5` | The default full scan has no matching offline switch |

## Observed architecture

| Component | State | Evidence | Responsibility |
| --- | --- | --- | --- |
| Rust CLI orchestrator | `code_verified` | `cli/src/main.rs:926@0f73627236d5` | Resolves phases, cache, feeds, output, and exit behavior |
| Static scanner | `code_verified` | `cli/src/scanner/mod.rs:191@0f73627236d5` | Walks target files and applies local signatures |
| Approval ledger | `code_verified` | `cli/src/main.rs:981@0f73627236d5` | Reapplies current suppression decisions to cached results |

## Inspected surfaces

| Surface | State | Evidence | Boundary |
| --- | --- | --- | --- |
| Repository files and lockfiles | `code_verified` | `cli/src/main.rs:1006@0f73627236d5` | Static findings are enriched with package intelligence |
| Package and repository acquisition | `declared` | `README.md:17@0f73627236d5` | Content enters a quarantine workflow before approval |
| Optional LLM review | `code_verified` | `cli/src/main.rs:1130@0f73627236d5` | Sends eligible file content to the configured model service |

## Safety boundary

| Property | State | Evidence | Consequence |
| --- | --- | --- | --- |
| Target content execution | `code_verified` | `README.md:17@0f73627236d5` | The documented scan path is static and approval precedes install |
| Network access | `contradicted` | `cli/src/main.rs:1010@0f73627236d5` | A default full scan attempts OSV, npm, PyPI, KEV, and EPSS requests |
| Read completeness | `contradicted` | `cli/src/scanner/mod.rs:263@0f73627236d5` | Binary, oversized, and unreadable files can produce no diagnostic |
| Cache freshness | `code_verified` | `cli/src/main.rs:974@0f73627236d5` | Default scans may reuse results unless `--no-cache` is supplied |

## Intelligence lifecycle

| Capability | State | Evidence | Update contract |
| --- | --- | --- | --- |
| OSV and ecosystem feeds | `code_verified` | `cli/src/main.rs:1006@0f73627236d5` | Network failures are nonfatal and do not mark the scan incomplete |
| KEV and EPSS enrichment | `code_verified` | `cli/src/main.rs:1026@0f73627236d5` | Enrichment is applied after local findings |
| Local cloud signatures | `code_verified` | `cli/src/scanner/mod.rs:242@0f73627236d5` | Missing signatures degrade to an empty result |

## Outputs and integration

| Output or integration | State | Evidence | Contract |
| --- | --- | --- | --- |
| Terminal and structured scan output | `code_verified` | `cli/src/main.rs:983@0f73627236d5` | Cached and fresh results share the same presentation path |
| Severity exit gate | `contradicted` | `cli/src/main.rs:880@0f73627236d5` | Exit status reflects findings, not skipped reads or missing feeds |
| GitHub Action and MCP surfaces | `declared` | `README.md:342@0f73627236d5` | Published artifacts were not downloaded |

## Distribution

| Channel | State | Evidence | Verification |
| --- | --- | --- | --- |
| Rust CLI, GitHub Action, and MCP server | `declared` | `README.md:342@0f73627236d5` | Static repository inspection only |

## Tests and fixtures

| Test property | State | Evidence | Limitation |
| --- | --- | --- | --- |
| Scanner test suite | `code_verified` | `cli/src/scanner/mod.rs:117@0f73627236d5` | Runtime tests were not executed |
| Unreadable input witness | `not_tested` | `cli/src/scanner/mod.rs:263@0f73627236d5` | Requires approved isolated execution |

## License

| Item | State | Evidence | Consequence |
| --- | --- | --- | --- |
| Apache License 2.0 | `code_verified` | `LICENSE:1@0f73627236d5` | Permissive reuse with notice and patent terms |

## Contradictions and unknowns

| Claim or question | State | Evidence | Required follow-up |
| --- | --- | --- | --- |
| Offline scan claim | `contradicted` | `cli/src/main.rs:1010@0f73627236d5` | Block network and observe the default full scan after approval |
| Clean result after skipped reads | `contradicted` | `cli/src/scanner/mod.rs:263@0f73627236d5` | Use unreadable and oversized fixtures in an isolated sandbox |
| Quarantine containment | `not_tested` | `README.md:17@0f73627236d5` | Inspect filesystem writes and subprocesses during acquisition |

## Parity lessons

| Candidate capability | State | Evidence | AgentSec decision question |
| --- | --- | --- | --- |
| Approval ledger tied to content | `code_verified` | `cli/src/main.rs:981@0f73627236d5` | Add reviewed suppressions without hiding later intelligence changes |
| Quarantine-first acquisition | `declared` | `README.md:17@0f73627236d5` | Keep acquisition separate from the scanner's read-only core |
| Fast native CLI | `code_verified` | `cli/Cargo.toml:1@0f73627236d5` | Measure startup and traversal before considering a language rewrite |

## Differentiation lessons

| Candidate distinction | State | Evidence | AgentSec decision question |
| --- | --- | --- | --- |
| Explicit completeness verdict | `contradicted` | `cli/src/scanner/mod.rs:263@0f73627236d5` | Preserve AgentSec's incomplete-scan diagnostics as a product promise |
| Verifiable offline mode | `contradicted` | `cli/src/main.rs:1010@0f73627236d5` | Test zero network access instead of relying on documentation |
| Versioned reviewed threat feed | `code_verified` | `cli/src/main.rs:1006@0f73627236d5` | Explain the difference between live enrichment and curated intelligence |

## Evidence

| Reference | State | Evidence type | Relevance |
| --- | --- | --- | --- |
| `cli/src/main.rs:1010@0f73627236d5` | `code_verified` | Code | Establishes default network enrichment |
| `cli/src/scanner/mod.rs:263@0f73627236d5` | `code_verified` | Code | Establishes silent file omissions |
| `LICENSE:1@0f73627236d5` | `code_verified` | License | Establishes reuse terms |

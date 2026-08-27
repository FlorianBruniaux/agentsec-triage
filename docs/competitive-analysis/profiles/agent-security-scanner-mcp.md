# agent-security-scanner-mcp

Review of the pinned revision only. No project code was executed.

## Project identity

- Project ID: `agent-security-scanner-mcp`
- Repository: `https://github.com/sinewaveai/agent-security-scanner-mcp`
- Revision: `79e8779b4eec`
- Review date: `2026-08-24`
- Review scope: tracked JavaScript and Python source, package metadata, license, and documentation

## Declared promise

| Claim | State | Evidence | Notes |
| --- | --- | --- | --- |
| Scan projects, MCP servers, skills, prompts, packages, and actions | `declared` | `README.md:179@79e8779b4eec` | Broad command set exposed through one npm package |
| Rule-based CLI and MCP scans stay local | `declared` | `README.md:275@79e8779b4eec` | Semantic review uses a separately selected provider |
| Full project scan produces an A to F grade | `declared` | `README.md:179@79e8779b4eec` | Grade does not encode all skipped or failed analysis |

## Observed architecture

| Component | State | Evidence | Responsibility |
| --- | --- | --- | --- |
| Node CLI and MCP entry point | `code_verified` | `index.js:21@79e8779b4eec` | Dispatches project, MCP, skill, prompt, and package scanners |
| Project traversal | `code_verified` | `src/tools/scan-project.js:77@79e8779b4eec` | Collects selected code files with ignore rules |
| Python analyzer bridge | `code_verified` | `src/utils.js:82@79e8779b4eec` | Runs the bundled analyzer in a child process |

## Inspected surfaces

| Surface | State | Evidence | Boundary |
| --- | --- | --- | --- |
| Selected source extensions | `code_verified` | `src/tools/scan-project.js:20@79e8779b4eec` | Project scan excludes several repository instruction and manifest formats |
| Individual file analysis | `code_verified` | `src/tools/scan-security.js:69@79e8779b4eec` | Static and optional semantic engines feed one issue list |
| MCP and skill commands | `declared` | `README.md:179@79e8779b4eec` | Separate command paths exist but were not executed |

## Safety boundary

| Property | State | Evidence | Consequence |
| --- | --- | --- | --- |
| Target content execution | `code_verified` | `src/utils.js:82@79e8779b4eec` | Bundled analyzer code executes, target repository code is not intentionally invoked |
| Read confinement | `contradicted` | `src/tools/scan-project.js:96@79e8779b4eec` | `statSync` follows directory symlinks without a resolved-root check |
| Large file handling | `code_verified` | `src/tools/scan-security.js:78@79e8779b4eec` | Files above 1 MB return zero issues with a skipped flag |
| Network access | `declared` | `README.md:275@79e8779b4eec` | Rule scans are documented local; semantic providers can receive content |

## Intelligence lifecycle

| Capability | State | Evidence | Update contract |
| --- | --- | --- | --- |
| Bundled rule and analyzer release | `code_verified` | `package.json:3@79e8779b4eec` | npm package version 4.5.8 carries the local rules |
| Semantic provider analysis | `code_verified` | `src/tools/scan-security.js:125@79e8779b4eec` | Failures log a warning and static analysis continues |
| External threat feed | `not_tested` | `README.md:275@79e8779b4eec` | No reviewed, versioned threat-feed contract was identified |

## Outputs and integration

| Output or integration | State | Evidence | Contract |
| --- | --- | --- | --- |
| Grade and issue counts | `code_verified` | `src/tools/scan-project.js:270@79e8779b4eec` | Grade is derived from collected issues |
| CLI exit status | `contradicted` | `index.js:456@79e8779b4eec` | Missing totals after failures can evaluate as no findings and exit cleanly |
| MCP server and GitHub workflow | `declared` | `README.md:220@79e8779b4eec` | Distribution surfaces were not executed |

## Distribution

| Channel | State | Evidence | Verification |
| --- | --- | --- | --- |
| npm CLI, MCP server, workflow, and Apify Actor | `declared` | `README.md:220@79e8779b4eec` | Published packages and services were not contacted |

## Tests and fixtures

| Test property | State | Evidence | Limitation |
| --- | --- | --- | --- |
| Local vulnerable demo | `declared` | `README.md:74@79e8779b4eec` | Demo execution remains behind the approval gate |
| Symlink and unreadable witnesses | `not_tested` | `src/tools/scan-project.js:85@79e8779b4eec` | Require isolated filesystem fixtures |

## License

| Item | State | Evidence | Consequence |
| --- | --- | --- | --- |
| MIT License | `code_verified` | `LICENSE:1@79e8779b4eec` | Permissive reuse with copyright notice |

## Contradictions and unknowns

| Claim or question | State | Evidence | Required follow-up |
| --- | --- | --- | --- |
| A grade with unreadable or skipped inputs | `contradicted` | `src/tools/scan-security.js:86@79e8779b4eec` | Verify no-file, oversized, and analyzer-error exit behavior |
| Repository confinement | `contradicted` | `src/tools/scan-project.js:96@79e8779b4eec` | Use an outside-root symlink witness after approval |
| Semantic data boundary | `not_tested` | `README.md:275@79e8779b4eec` | Trace provider payloads without sending real repository content |

## Parity lessons

| Candidate capability | State | Evidence | AgentSec decision question |
| --- | --- | --- | --- |
| One CLI for repository and agent surfaces | `declared` | `README.md:179@79e8779b4eec` | Extend scope only after each detector has a completeness contract |
| Compact grade for first-pass triage | `code_verified` | `src/tools/scan-project.js:270@79e8779b4eec` | Add a summary only if it cannot hide incomplete coverage |
| Optional semantic engine | `code_verified` | `src/tools/scan-security.js:125@79e8779b4eec` | Keep probabilistic analysis separate from deterministic verdicts |

## Differentiation lessons

| Candidate distinction | State | Evidence | AgentSec decision question |
| --- | --- | --- | --- |
| Fail closed on analyzer and read errors | `contradicted` | `src/tools/scan-security.js:86@79e8779b4eec` | Make missing evidence visible in output and exit status |
| Root-confined traversal | `contradicted` | `src/tools/scan-project.js:96@79e8779b4eec` | Retain AgentSec's explicit symlink diagnostics |
| Curated incident intelligence | `not_tested` | `package.json:3@79e8779b4eec` | Lead with reviewed incidents instead of raw rule count |

## Evidence

| Reference | State | Evidence type | Relevance |
| --- | --- | --- | --- |
| `src/tools/scan-project.js:96@79e8779b4eec` | `code_verified` | Code | Establishes symlink-following traversal |
| `src/tools/scan-security.js:86@79e8779b4eec` | `code_verified` | Code | Establishes zero-issue skipped files |
| `LICENSE:1@79e8779b4eec` | `code_verified` | License | Establishes reuse terms |

# patient-zero

Review of the pinned revision only. No patient-zero code was executed.

## Project identity

- Project ID: `patient-zero`
- Repository: `https://github.com/0xSteph/patient-zero`
- Revision: `331320c152aa`
- Review date: `2026-08-24`
- Review scope: tracked source, tests, action, and documentation

## Declared promise

| Claim | State | Evidence | Notes |
| --- | --- | --- | --- |
| Campaign IOC triage for Node, Python, and agent configuration | `declared` | `README.md:1@331320c152aa` | Focused on known supply-chain incidents |
| On-demand, install-blocker, and CI modes | `declared` | `README.md:42@331320c152aa` | Includes local and automation entrypoints |
| Exit `2` means incomplete or operational error | `declared` | `README.md:111@331320c152aa` | This contract is contradicted in combined error cases |

## Observed architecture

| Component | State | Evidence | Responsibility |
| --- | --- | --- | --- |
| CLI orchestrator | `code_verified` | `bin/cli.js:90@331320c152aa` | Loads intelligence and runs five scanners in parallel |
| IOC loader | `code_verified` | `src/ioc-loader.js:23@331320c152aa` | Selects fresh cache, remote data, stale cache, or bundled data |
| Repository walker | `code_verified` | `src/walk.js:31@331320c152aa` | Finds lockfiles recursively |
| GitHub Action wrapper | `code_verified` | `action.yml:53@331320c152aa` | Installs the package, captures output, and evaluates findings |

## Inspected surfaces

| Surface | State | Evidence | Boundary |
| --- | --- | --- | --- |
| Node and Python lockfiles | `code_verified` | `test/scanners-lockfile.test.js:23@331320c152aa` | Parser fixtures cover positive and negative cases |
| MCP configuration | `code_verified` | `src/scanners/mcp.js:34@331320c152aa` | Reads fixed host configuration paths as well as the target |
| Local persistence and processes | `code_verified` | `src/scanners/local-files.js:16@331320c152aa` | Extends beyond repository confinement into the user host |
| GitHub repositories | `code_verified` | `src/scanners/github.js:1@331320c152aa` | Remote scan is opt-in |

## Safety boundary

| Property | State | Evidence | Consequence |
| --- | --- | --- | --- |
| Target content execution | `code_verified` | `src/scanners/install-tree.js:1@331320c152aa` | Package-manager subprocesses resolve dependency trees with install scripts disabled |
| Target writes | `code_verified` | `src/hook-installer.js:1@331320c152aa` | The scan reads targets; a separate command writes Git hooks and configuration |
| Network access | `contradicted` | `src/ioc-loader.js:23@331320c152aa` | Network refresh is the default unless offline mode is selected |
| Read confinement | `contradicted` | `src/scanners/local-files.js:16@331320c152aa` | Default scope includes home persistence and host agent configuration |

## Intelligence lifecycle

| Capability | State | Evidence | Update contract |
| --- | --- | --- | --- |
| Hourly remote IOC refresh with fallback | `code_verified` | `src/ioc-loader.js:23@331320c152aa` | Fetches the main branch without signature or digest verification, then falls back silently |
| Schema compatibility | `code_verified` | `src/ioc-loader.js:91@331320c152aa` | Checks only the schema major version |

## Outputs and integration

| Output or integration | State | Evidence | Contract |
| --- | --- | --- | --- |
| CLI and SARIF | `code_verified` | `bin/cli.js:130@331320c152aa` | Findings and scanner errors are aggregated |
| Exit status | `contradicted` | `bin/cli.js:158@331320c152aa` | Errors become exit `2` only when no findings exist; low findings plus errors can exit `0` |
| GitHub Action | `contradicted` | `action.yml:83@331320c152aa` | The wrapper ignores scanner exit `2` and can pass when output parsing fails |

## Distribution

| Channel | State | Evidence | Verification |
| --- | --- | --- | --- |
| npm package and GitHub Action | `code_verified` | `package.json:1@331320c152aa` | Package metadata declares the CLI and bundled data |
| Action install | `code_verified` | `action.yml:69@331320c152aa` | Uses `npx` and a configurable version whose default is not pinned to a digest |

## Tests and fixtures

| Test property | State | Evidence | Limitation |
| --- | --- | --- | --- |
| Lockfile positive and negative fixtures | `code_verified` | `test/scanners-lockfile.test.js:23@331320c152aa` | Static review did not execute the suite |
| MCP, local file, process, and GitHub cases | `code_verified` | `test/scanners-other.test.js:24@331320c152aa` | No cited regression for the Action fail-open path |

## License

| Item | State | Evidence | Consequence |
| --- | --- | --- | --- |
| MIT License | `code_verified` | `LICENSE:1@331320c152aa` | Permissive reuse with copyright notice |

## Contradictions and unknowns

| Claim or question | State | Evidence | Required follow-up |
| --- | --- | --- | --- |
| Documented incomplete exit contract | `contradicted` | `bin/cli.js:158@331320c152aa` | Add witnesses for scanner error plus low, medium, and high findings |
| CI can pass on scanner failure | `contradicted` | `action.yml:83@331320c152aa` | Run the Action in an isolated fixture after owner approval |
| Remote IOC authenticity | `contradicted` | `src/ioc-loader.js:23@331320c152aa` | Verify whether releases provide an external signed channel not present here |

## Parity lessons

| Candidate capability | State | Evidence | AgentSec decision question |
| --- | --- | --- | --- |
| Named campaign response playbooks | `declared` | `README.md:121@331320c152aa` | Link each AgentSec finding to a concise containment path |
| Install-blocker workflow | `declared` | `README.md:42@331320c152aa` | Offer a safe pre-install gate without executing package lifecycle scripts |

## Differentiation lessons

| Candidate distinction | State | Evidence | AgentSec decision question |
| --- | --- | --- | --- |
| Fail-closed incomplete coverage | `contradicted` | `bin/cli.js:158@331320c152aa` | Make incomplete scans a stable, machine-readable AgentSec state |
| Signed and versioned intelligence | `contradicted` | `src/ioc-loader.js:23@331320c152aa` | Preserve feed provenance and avoid fetching a mutable branch by default |
| Repository-only default scope | `contradicted` | `src/scanners/local-files.js:16@331320c152aa` | Keep host inspection explicit and separate from repository triage |

## Evidence

| Reference | State | Evidence type | Relevance |
| --- | --- | --- | --- |
| `bin/cli.js:130@331320c152aa` | `code_verified` | Code | Establishes aggregation and exit behavior |
| `action.yml:83@331320c152aa` | `code_verified` | Workflow | Establishes the Action fail-open path |
| `src/ioc-loader.js:23@331320c152aa` | `code_verified` | Code | Establishes mutable remote intelligence behavior |

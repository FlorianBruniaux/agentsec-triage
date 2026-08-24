# Snyk Agent Scan

Review of the pinned revision only. No Snyk Agent Scan code was executed.

## Project identity

- Project ID: `snyk-agent-scan`
- Repository: `https://github.com/snyk/agent-scan`
- Revision: `891f0b2cc69c`
- Review date: `2026-08-24`
- Review scope: tracked Python source, tests, release guidance, license, and documentation

## Declared promise

| Claim | State | Evidence | Notes |
| --- | --- | --- | --- |
| Discover and scan installed agent components | `declared` | `README.md:7@891f0b2cc69c` | Covers harnesses, MCP servers, and skills across host scopes |
| Prompt-injection and vulnerability analysis | `declared` | `README.md:48@891f0b2cc69c` | Uses local discovery plus Snyk analysis APIs |
| Experimental CLI output | `declared` | `README.md:14@891f0b2cc69c` | Production consumers are warned against depending on fields and codes |

## Observed architecture

| Component | State | Evidence | Responsibility |
| --- | --- | --- | --- |
| CLI and consent gate | `code_verified` | `src/agent_scan/cli.py:763@891f0b2cc69c` | Controls interactive and non-interactive MCP startup |
| Agent discovery adapters | `code_verified` | `src/agent_scan/agents/base.py:82@891f0b2cc69c` | Enumerate well-known host and project locations |
| MCP client | `code_verified` | `src/agent_scan/mcp_client.py:78@891f0b2cc69c` | Connects to HTTP, SSE, and stdio servers |
| Analysis client | `code_verified` | `src/agent_scan/verify_api.py:489@891f0b2cc69c` | Authenticates and sends redacted component data to Snyk |

## Inspected surfaces

| Surface | State | Evidence | Boundary |
| --- | --- | --- | --- |
| Host agent configuration | `code_verified` | `README.md:153@891f0b2cc69c` | Covers system, user, project, workspace, extension, and plugin scopes |
| MCP tool descriptions | `code_verified` | `src/agent_scan/mcp_client.py:129@891f0b2cc69c` | Requires connecting to each server |
| Skill directories and files | `code_verified` | `src/agent_scan/skill_client.py:241@891f0b2cc69c` | Recursive traversal sends text after secret redaction |

## Safety boundary

| Property | State | Evidence | Consequence |
| --- | --- | --- | --- |
| Target content execution | `code_verified` | `README.md:53@891f0b2cc69c` | Scanning stdio MCP configuration executes its command after consent |
| Target writes | `code_verified` | `README.md:308@891f0b2cc69c` | Scan state defaults to a user-home file; Guard installation has separate writes |
| Network access | `code_verified` | `README.md:276@891f0b2cc69c` | Component information is sent to the analysis API; remote MCP is also contacted |
| Read confinement | `code_verified` | `README.md:153@891f0b2cc69c` | Product scope is intentionally host-wide, not repository-confined |

## Intelligence lifecycle

| Capability | State | Evidence | Update contract |
| --- | --- | --- | --- |
| Hosted risk analysis | `code_verified` | `README.md:276@891f0b2cc69c` | Backend content and change cadence are outside this repository |
| Versioned API models | `code_verified` | `src/agent_scan/models/api/v20260710.py:1@891f0b2cc69c` | Client models pin a dated API shape |

## Outputs and integration

| Output or integration | State | Evidence | Contract |
| --- | --- | --- | --- |
| Human and JSON reports | `code_verified` | `README.md:292@891f0b2cc69c` | Schema is explicitly experimental |
| CI mode | `code_verified` | `src/agent_scan/cli.py:815@891f0b2cc69c` | CI refuses to start without the dangerous MCP execution override |
| Declined-server diagnostic | `code_verified` | `README.md:265@891f0b2cc69c` | Declined servers remain visible as `user_declined` |

## Distribution

| Channel | State | Evidence | Verification |
| --- | --- | --- | --- |
| PyPI through uvx and standalone binaries | `declared` | `README.md:68@891f0b2cc69c` | Releases document SBOM, checksums, and signed checksums |
| GPG checksum verification | `declared` | `README.md:205@891f0b2cc69c` | Release assets were not downloaded in this static review |

## Tests and fixtures

| Test property | State | Evidence | Limitation |
| --- | --- | --- | --- |
| Consent and CI behavior | `code_verified` | `tests/e2e/test_scan.py:427@891f0b2cc69c` | Static review did not run the end-to-end suite |
| MCP and skill fixtures | `code_verified` | `tests/e2e/test_inspect.py:107@891f0b2cc69c` | Many tests deliberately execute local fixture servers |

## License

| Item | State | Evidence | Consequence |
| --- | --- | --- | --- |
| Apache License 2.0 | `code_verified` | `LICENSE:1@891f0b2cc69c` | Permissive CLI reuse with notice and patent terms |

## Contradictions and unknowns

| Claim or question | State | Evidence | Required follow-up |
| --- | --- | --- | --- |
| Hosted detector implementation | `not_tested` | `README.md:276@891f0b2cc69c` | Treat coverage and scoring as opaque until supported by service evidence |
| Skill content redaction completeness | `not_tested` | `src/agent_scan/skill_client.py:241@891f0b2cc69c` | Use synthetic secrets and capture the outgoing request after approval |
| Safe comparable mode | `not_tested` | `README.md:53@891f0b2cc69c` | Benchmark only a fixture skill with a test token and isolated network capture |

## Parity lessons

| Candidate capability | State | Evidence | AgentSec decision question |
| --- | --- | --- | --- |
| Cross-harness host inventory | `code_verified` | `README.md:153@891f0b2cc69c` | Add an explicit host-audit mode after repository mode is stable |
| Consent before server execution | `code_verified` | `src/agent_scan/cli.py:1122@891f0b2cc69c` | If AgentSec ever probes MCP runtime, require per-command consent and a sandbox |
| Dated API contract | `code_verified` | `src/agent_scan/models/api/v20260710.py:1@891f0b2cc69c` | Version public feed and report schemas independently |

## Differentiation lessons

| Candidate distinction | State | Evidence | AgentSec decision question |
| --- | --- | --- | --- |
| Fully local repository triage | `code_verified` | `README.md:276@891f0b2cc69c` | Keep AgentSec usable without credentials or content upload |
| Stable machine-readable contract | `declared` | `README.md:14@891f0b2cc69c` | Make AgentSec JSON compatibility a release gate |
| No target execution | `code_verified` | `README.md:53@891f0b2cc69c` | Keep pre-trust scanning static and separate from runtime MCP analysis |

## Evidence

| Reference | State | Evidence type | Relevance |
| --- | --- | --- | --- |
| `README.md:53@891f0b2cc69c` | `code_verified` | Documentation and code-correlated warning | Establishes target command execution |
| `src/agent_scan/mcp_client.py:78@891f0b2cc69c` | `code_verified` | Code | Establishes server connections |
| `src/agent_scan/cli.py:815@891f0b2cc69c` | `code_verified` | Code | Establishes the CI execution gate |

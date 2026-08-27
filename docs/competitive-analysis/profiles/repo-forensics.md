# Repo Forensics

Review of the pinned revision only. No Repo Forensics code was executed.

## Project identity

- Project ID: `repo-forensics`
- Repository: `https://github.com/alexgreensh/repo-forensics`
- Revision: `eedd6a5f909a`
- Review date: `2026-08-24`
- Review scope: tracked source, hooks, workflow, tests, license, and documentation

## Declared promise

| Claim | State | Evidence | Notes |
| --- | --- | --- | --- |
| Pre-trust, local repository forensics | `declared` | `README.md:7@eedd6a5f909a` | Presented as zero telemetry and suitable before opening a repository |
| Twenty-seven scanners and cross-scanner correlation | `declared` | `README.md:20@eedd6a5f909a` | Includes campaign IOCs, CVE data, and behavior rules |
| Signed rule feed and offline scanning | `declared` | `README.md:189@eedd6a5f909a` | Seven Ed25519-signed rule packs are documented |

## Observed architecture

| Component | State | Evidence | Responsibility |
| --- | --- | --- | --- |
| Shell orchestrator | `code_verified` | `run_forensics.sh:307@eedd6a5f909a` | Runs scanner subprocesses and aggregates their reports |
| Result aggregator | `code_verified` | `aggregate_json.py:70@eedd6a5f909a` | Parses scanner output, correlates findings, and computes coverage |
| Dynamic hook scanner | `code_verified` | `scan_dast.py:177@eedd6a5f909a` | Resolves and executes discovered target hook scripts |
| Claude hooks | `code_verified` | `hooks/hooks.json:1@eedd6a5f909a` | Registers pre-tool, post-tool, and session-start commands |

## Inspected surfaces

| Surface | State | Evidence | Boundary |
| --- | --- | --- | --- |
| Repository content and agent configuration | `code_verified` | `run_forensics.sh:363@eedd6a5f909a` | Full mode invokes a broad scanner set |
| Target hook behavior | `code_verified` | `scan_dast.py:115@eedd6a5f909a` | Hook scripts can be executed dynamically |
| Host and update state | `declared` | `README.md:113@eedd6a5f909a` | Session scheduling and feed monitoring extend beyond one scan |

## Safety boundary

| Property | State | Evidence | Consequence |
| --- | --- | --- | --- |
| Target content execution | `contradicted` | `scan_dast.py:253@eedd6a5f909a` | Full scan executes target hooks even when no supported sandbox exists |
| Target writes | `not_tested` | `run_forensics.sh:307@eedd6a5f909a` | Scanner subprocess write locations require runtime tracing |
| Network access | `not_tested` | `README.md:189@eedd6a5f909a` | Offline scan is documented, but update and hook behavior need network tracing |
| Read confinement | `not_tested` | `run_forensics.sh:363@eedd6a5f909a` | Broad host and repository readers require isolated observation |

## Intelligence lifecycle

| Capability | State | Evidence | Update contract |
| --- | --- | --- | --- |
| Signed rule packs | `code_verified` | `.github/workflows/verify-checksums.yml:16@eedd6a5f909a` | Workflow verifies a signed checksum manifest |
| Campaign and CVE corpus | `declared` | `README.md:198@eedd6a5f909a` | Update provenance and correction workflow were not fully traced |

## Outputs and integration

| Output or integration | State | Evidence | Contract |
| --- | --- | --- | --- |
| Aggregated JSON and exit codes | `code_verified` | `aggregate_json.py:320@eedd6a5f909a` | Parse errors exit `99`; severity drives `1` or `2` |
| Coverage diagnostics | `code_verified` | `aggregate_json.py:332@eedd6a5f909a` | Missing scanner output becomes a blocking coverage gap |
| SARIF and YARA | `code_verified` | `export_sarif.py:21@eedd6a5f909a` | SARIF paths are normalized and confined |
| GitHub Action | `code_verified` | `action.yml:37@eedd6a5f909a` | Propagates the scanner exit status |

## Distribution

| Channel | State | Evidence | Verification |
| --- | --- | --- | --- |
| Source repository and GitHub Action | `code_verified` | `action.yml:37@eedd6a5f909a` | Workflow setup is visible; release artifacts were not downloaded |

## Tests and fixtures

| Test property | State | Evidence | Limitation |
| --- | --- | --- | --- |
| Large documented test corpus | `declared` | `README.md:231@eedd6a5f909a` | The stated count was not independently executed |
| Coverage-gap aggregation | `code_verified` | `aggregate_json.py:320@eedd6a5f909a` | Static control flow supports fail-closed aggregation |

## License

| Item | State | Evidence | Consequence |
| --- | --- | --- | --- |
| PolyForm Noncommercial 1.0.0 | `code_verified` | `LICENSE:1@eedd6a5f909a` | Commercial use and product reuse require separate permission |

## Contradictions and unknowns

| Claim or question | State | Evidence | Required follow-up |
| --- | --- | --- | --- |
| Pre-trust scan executes untrusted hooks | `contradicted` | `run_forensics.sh:416@eedd6a5f909a` | Never run full mode outside a disposable sandbox |
| Missing sandbox does not stop execution | `contradicted` | `scan_dast.py:253@eedd6a5f909a` | Verify an exact safe mode that excludes DAST before benchmarking |
| Scanner write and network footprint | `not_tested` | `run_forensics.sh:307@eedd6a5f909a` | Trace syscalls and network in a disposable environment after approval |

## Parity lessons

| Candidate capability | State | Evidence | AgentSec decision question |
| --- | --- | --- | --- |
| Cross-detector correlation | `code_verified` | `aggregate_json.py:70@eedd6a5f909a` | Correlate weak signals without obscuring their original evidence |
| Coverage as a first-class result | `code_verified` | `aggregate_json.py:332@eedd6a5f909a` | Expand AgentSec coverage categories and failure reasons |
| SARIF path confinement | `code_verified` | `export_sarif.py:59@eedd6a5f909a` | Add output-path escape fixtures to AgentSec |

## Differentiation lessons

| Candidate distinction | State | Evidence | AgentSec decision question |
| --- | --- | --- | --- |
| Never execute target content | `contradicted` | `scan_dast.py:253@eedd6a5f909a` | State and test AgentSec's static-only pre-trust boundary |
| Permissive open-source adoption | `contradicted` | `LICENSE:48@eedd6a5f909a` | Keep AgentSec usable in commercial CI under MIT |

## Evidence

| Reference | State | Evidence type | Relevance |
| --- | --- | --- | --- |
| `scan_dast.py:253@eedd6a5f909a` | `code_verified` | Code | Establishes unsandboxed target execution |
| `aggregate_json.py:320@eedd6a5f909a` | `code_verified` | Code | Establishes fail-closed aggregation |
| `LICENSE:48@eedd6a5f909a` | `code_verified` | License | Establishes the noncommercial restriction |

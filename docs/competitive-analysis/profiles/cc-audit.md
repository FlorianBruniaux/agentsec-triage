# cc-audit

Review of the pinned revision only. No cc-audit code was executed.

## Project identity

- Project ID: `cc-audit`
- Repository: `https://github.com/ryo-ebata/cc-audit`
- Revision: `bdb657474624`
- Review date: `2026-08-24`
- Review scope: tracked Rust source, tests, action, license, and documentation

## Declared promise

| Claim | State | Evidence | Notes |
| --- | --- | --- | --- |
| Pre-install audit of Claude artifacts | `declared` | `README.md:16@bdb657474624` | Covers local and remote inputs |
| Broad scanner, CVE, baseline, pinning, and autofix features | `declared` | `README.md:138@bdb657474624` | Also documents proxy, watch, and SBOM modes |
| JSON, SARIF, HTML, and Markdown reports | `declared` | `README.md:138@bdb657474624` | Multiple CI and human outputs |

## Observed architecture

| Component | State | Evidence | Responsibility |
| --- | --- | --- | --- |
| CLI dispatcher | `code_verified` | `src/main.rs:22@bdb657474624` | Routes commands and returns an exit code |
| Scan handler | `code_verified` | `src/handlers/scan.rs:19@bdb657474624` | Validates output and input paths, then builds the scan |
| Scan runner | `code_verified` | `src/run/scanner.rs:37@bdb657474624` | Loads configuration and fans out to scanners |
| Engine scanner | `code_verified` | `src/engine/scanner.rs:67@bdb657474624` | Handles size limits, parse failures, and rule matching |

## Inspected surfaces

| Surface | State | Evidence | Boundary |
| --- | --- | --- | --- |
| Claude agent files and repository configuration | `code_verified` | `src/lib.rs:121@bdb657474624` | Multiple scanner and reporter modules are compiled into the CLI |
| Explicit files and directories | `code_verified` | `src/handlers/scan.rs:57@bdb657474624` | Explicit symlink inputs are accepted with a warning |
| Custom rules and malware or CVE databases | `code_verified` | `src/run/scanner.rs:62@bdb657474624` | Project and global configuration can influence the scan |

## Safety boundary

| Property | State | Evidence | Consequence |
| --- | --- | --- | --- |
| Target content execution | `code_verified` | `src/engine/scanner.rs:164@bdb657474624` | Reviewed core scan parses content rather than executing it |
| Target writes | `not_tested` | `src/handlers/scan.rs:19@bdb657474624` | Output, baseline, fix, and other commands require separate write tracing |
| Network access | `not_tested` | `README.md:138@bdb657474624` | Remote scan, proxy, and update modes need explicit offline configuration |
| Read confinement | `contradicted` | `src/handlers/scan.rs:57@bdb657474624` | An explicit symlink path can refer outside the requested root |

## Intelligence lifecycle

| Capability | State | Evidence | Update contract |
| --- | --- | --- | --- |
| Built-in and custom malware or CVE data | `code_verified` | `src/run/scanner.rs:399@bdb657474624` | Custom database failure warns and falls back to built-in data |
| Target-owned configuration | `code_verified` | `src/run/scanner.rs:62@bdb657474624` | Project configuration loads before scanning and must be excluded for hostile targets |

## Outputs and integration

| Output or integration | State | Evidence | Contract |
| --- | --- | --- | --- |
| CLI exit status | `code_verified` | `src/handlers/scan.rs:259@bdb657474624` | Missing result exits `2`; policy findings can exit `1` |
| Scanner fanout | `contradicted` | `src/run/scanner.rs:141@bdb657474624` | Individual scanner failures are warnings if another scanner succeeds |
| GitHub Action and SARIF upload | `code_verified` | `action.yml:175@bdb657474624` | Produces and uploads SARIF when configured |

## Distribution

| Channel | State | Evidence | Verification |
| --- | --- | --- | --- |
| Cargo, source, and GitHub Action | `code_verified` | `Cargo.toml:4@bdb657474624` | Crate metadata and action installer are present |
| Action installation | `contradicted` | `action.yml:77@bdb657474624` | Default installation is latest and is not pinned to a release digest |

## Tests and fixtures

| Test property | State | Evidence | Limitation |
| --- | --- | --- | --- |
| Engine size and parse diagnostics | `code_verified` | `src/engine/scanner.rs:67@bdb657474624` | Oversized and unparsable inputs produce findings in the core engine |
| Full suite behavior | `not_tested` | `Cargo.toml:4@bdb657474624` | Static review did not compile or run the Rust suite |

## License

| Item | State | Evidence | Consequence |
| --- | --- | --- | --- |
| MIT License | `code_verified` | `LICENSE:1@bdb657474624` | Permissive reuse with copyright notice |

## Contradictions and unknowns

| Claim or question | State | Evidence | Required follow-up |
| --- | --- | --- | --- |
| Partial scanner failure can still yield a result | `contradicted` | `src/run/scanner.rs:141@bdb657474624` | Inject one failing scanner and check output completeness metadata |
| Action argument construction uses shell strings | `contradicted` | `action.yml:120@bdb657474624` | Test crafted path and input values in a disposable workflow |
| Explicit symlink path escapes root | `contradicted` | `src/handlers/scan.rs:57@bdb657474624` | Run a read-confinement witness after owner approval |

## Parity lessons

| Candidate capability | State | Evidence | AgentSec decision question |
| --- | --- | --- | --- |
| Broad report formats and SBOM | `declared` | `README.md:138@bdb657474624` | Prioritize SARIF first, then justify any extra format with a consumer |
| Oversized and parse diagnostics | `code_verified` | `src/engine/scanner.rs:67@bdb657474624` | Preserve explicit coverage gaps at every parser boundary |
| Baseline and pinning workflows | `declared` | `README.md:138@bdb657474624` | Add only after severity and intelligence identity are stable |

## Differentiation lessons

| Candidate distinction | State | Evidence | AgentSec decision question |
| --- | --- | --- | --- |
| Strict root confinement | `contradicted` | `src/handlers/scan.rs:57@bdb657474624` | Keep AgentSec's refusal to traverse symlinked repository paths |
| Complete detector accounting | `contradicted` | `src/run/scanner.rs:141@bdb657474624` | Report every disabled, failed, and executed detector |
| Safe CI argument handling | `contradicted` | `action.yml:120@bdb657474624` | Use structured arguments and pinned installation in AgentSec Actions |

## Evidence

| Reference | State | Evidence type | Relevance |
| --- | --- | --- | --- |
| `src/run/scanner.rs:141@bdb657474624` | `code_verified` | Code | Establishes partial scanner failure handling |
| `src/handlers/scan.rs:57@bdb657474624` | `code_verified` | Code | Establishes explicit symlink acceptance |
| `action.yml:120@bdb657474624` | `code_verified` | Workflow | Establishes shell string argument construction |

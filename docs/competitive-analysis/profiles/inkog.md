# Inkog

Review of the pinned revision only. No Inkog code or hosted service was executed.

## Project identity

- Project ID: `inkog`
- Repository: `https://github.com/inkog-io/inkog`
- Revision: `85683e73f2db`
- Review date: `2026-08-24`
- Review scope: tracked Go client source, contracts, license, and documentation

## Declared promise

| Claim | State | Evidence | Notes |
| --- | --- | --- | --- |
| Pre-flight static analysis for AI agents | `declared` | `README.md:5@85683e73f2db` | Covers agent logic, MCP, skills, and common code risks |
| Local redaction before remote analysis | `declared` | `cmd/inkog/main.go:1632@85683e73f2db` | Source content still leaves the machine after redaction |
| Open CLI with proprietary analysis engine | `declared` | `README.md:103@85683e73f2db` | Meaningful detector behavior cannot be fully inspected locally |

## Observed architecture

| Component | State | Evidence | Responsibility |
| --- | --- | --- | --- |
| Go CLI | `code_verified` | `cmd/inkog/main.go:28@85683e73f2db` | Collects inputs, resolves credentials, and calls the hosted API |
| Hybrid scanner | `code_verified` | `pkg/cli/scanner.go:307@85683e73f2db` | Finds local secrets, redacts files, and uploads the remaining content |
| HTTP client | `code_verified` | `pkg/cli/client.go:56@85683e73f2db` | Sends multipart scan requests to the configured server |

## Inspected surfaces

| Surface | State | Evidence | Boundary |
| --- | --- | --- | --- |
| Source files | `code_verified` | `pkg/cli/scanner.go:402@85683e73f2db` | Selected extensions are collected up to a file and upload cap |
| Agent skills | `code_verified` | `pkg/cli/skill_collector.go:28@85683e73f2db` | Skill contents and package metadata are prepared for upload |
| Hosted detectors | `declared` | `README.md:50@85683e73f2db` | Detector implementation and claimed ecosystem measurements are not in this repository |

## Safety boundary

| Property | State | Evidence | Consequence |
| --- | --- | --- | --- |
| Target content execution | `code_verified` | `pkg/cli/scanner.go:307@85683e73f2db` | Collection reads files and does not intentionally run target code |
| Source upload | `code_verified` | `pkg/cli/scanner.go:335@85683e73f2db` | Redacted file bodies are sent to the Inkog API |
| File limits | `code_verified` | `pkg/cli/scanner.go:493@85683e73f2db` | More than 500 eligible files are truncated by default |
| Read completeness | `code_verified` | `pkg/cli/scanner.go:428@85683e73f2db` | Unreadable files are silently skipped during collection |

## Intelligence lifecycle

| Capability | State | Evidence | Update contract |
| --- | --- | --- | --- |
| Hosted proprietary detectors | `declared` | `README.md:103@85683e73f2db` | Server releases can change without a pinned local detector version |
| Local secret redaction | `code_verified` | `pkg/cli/scanner.go:558@85683e73f2db` | Applied to collected files before upload |
| Server coverage diagnostics | `code_verified` | `pkg/contract/contract.go:144@85683e73f2db` | Response contract includes skipped and failed file counts |

## Outputs and integration

| Output or integration | State | Evidence | Contract |
| --- | --- | --- | --- |
| Terminal and SARIF output | `declared` | `README.md:85@85683e73f2db` | Findings originate from the hosted engine |
| GitHub Action | `declared` | `README.md:85@85683e73f2db` | Requires the hosted service for substantive analysis |
| Anonymous preview | `code_verified` | `pkg/cli/client.go:292@85683e73f2db` | Returns at most two findings without an API key |

## Distribution

| Channel | State | Evidence | Verification |
| --- | --- | --- | --- |
| Go CLI and GitHub Action | `declared` | `README.md:74@85683e73f2db` | Hosted API access was not attempted |

## Tests and fixtures

| Test property | State | Evidence | Limitation |
| --- | --- | --- | --- |
| Client-side collector tests | `code_verified` | `pkg/cli/scanner.go:402@85683e73f2db` | Hosted detector accuracy is outside the repository evidence |
| Server scan behavior | `not_tested` | `README.md:103@85683e73f2db` | Requires owner-approved external data transfer and account use |

## License

| Item | State | Evidence | Consequence |
| --- | --- | --- | --- |
| Apache License 2.0 for the client | `code_verified` | `LICENSE:1@85683e73f2db` | The hosted detector engine is not covered by the inspected source |

## Contradictions and unknowns

| Claim or question | State | Evidence | Required follow-up |
| --- | --- | --- | --- |
| Hosted detector implementation | `not_tested` | `README.md:103@85683e73f2db` | Treat accuracy and coverage claims as unverified until independently benchmarked |
| Default 500-file truncation | `code_verified` | `pkg/cli/scanner.go:497@85683e73f2db` | Verify how truncation affects CI verdict and SARIF metadata |
| Absolute path disclosure | `code_verified` | `pkg/cli/scanner.go:623@85683e73f2db` | Confirm server retention and redaction policy before real-repository use |

## Parity lessons

| Candidate capability | State | Evidence | AgentSec decision question |
| --- | --- | --- | --- |
| Local credential redaction | `code_verified` | `pkg/cli/scanner.go:558@85683e73f2db` | Redact diagnostics and exports without weakening local detection |
| Hosted deep analysis lane | `declared` | `README.md:103@85683e73f2db` | Keep local deterministic scanning primary before any optional remote lane |
| Explicit server failure counts | `code_verified` | `pkg/contract/contract.go:144@85683e73f2db` | Include per-detector and per-file completeness in machine output |

## Differentiation lessons

| Candidate distinction | State | Evidence | AgentSec decision question |
| --- | --- | --- | --- |
| Fully local inspectable verdict | `code_verified` | `pkg/cli/scanner.go:335@85683e73f2db` | Position AgentSec around local evidence and reproducible rules |
| No account required | `declared` | `README.md:74@85683e73f2db` | Preserve a useful scanner without API keys or hosted dependencies |
| Versioned public intelligence | `not_tested` | `README.md:103@85683e73f2db` | Make intelligence provenance inspectable instead of service-opaque |

## Evidence

| Reference | State | Evidence type | Relevance |
| --- | --- | --- | --- |
| `pkg/cli/scanner.go:335@85683e73f2db` | `code_verified` | Code | Establishes redacted source upload |
| `pkg/contract/contract.go:144@85683e73f2db` | `code_verified` | Code | Establishes server coverage fields |
| `LICENSE:1@85683e73f2db` | `code_verified` | License | Establishes client reuse terms |

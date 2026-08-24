# Aguara

Review of the pinned revision only. No Aguara code was executed.

## Project identity

- Project ID: `aguara`
- Repository: `https://github.com/garagon/aguara`
- Revision: `819eafb5fa66`
- Review date: `2026-08-24`
- Review scope: tracked source, tests, workflows, and documentation

## Declared promise

| Claim | State | Evidence | Notes |
| --- | --- | --- | --- |
| Local, deterministic pre-trust scanning | `declared` | `README.md:4@819eafb5fa66` | Covers packages, lockfiles, install scripts, MCP, agent instructions, and CI |
| No SaaS, telemetry, or LLM dependency | `declared` | `README.md:36@819eafb5fa66` | The default path is presented as local and offline |
| Signed threat intelligence updates | `declared` | `README.md:146@819eafb5fa66` | Embedded intelligence is the default; updates are opt-in |

## Observed architecture

| Component | State | Evidence | Responsibility |
| --- | --- | --- | --- |
| CLI scan command | `code_verified` | `cmd/aguara/commands/scan.go:90@819eafb5fa66` | Builds the scanner and selects report formats |
| Public scan API | `code_verified` | `aguara.go:119@819eafb5fa66` | Disables target-owned suppressions by default |
| Scanner engine | `code_verified` | `internal/scanner/scanner.go:218@819eafb5fa66` | Loads content and invokes analyzers |
| Intelligence verifier | `code_verified` | `internal/intel/bundle/verify.go:72@819eafb5fa66` | Verifies bundle identity and transparency metadata |

## Inspected surfaces

| Surface | State | Evidence | Boundary |
| --- | --- | --- | --- |
| Repository files and dependency metadata | `code_verified` | `README.md:4@819eafb5fa66` | Binary extensions and oversized files are excluded |
| Changed files | `code_verified` | `cmd/aguara/commands/scan.go:495@819eafb5fa66` | Symlinked changed paths are skipped |
| Target configuration and suppressions | `code_verified` | `README.md:135@819eafb5fa66` | CI and public API ignore them unless policy allows them |

## Safety boundary

| Property | State | Evidence | Consequence |
| --- | --- | --- | --- |
| Target content execution | `code_verified` | `README.md:36@819eafb5fa66` | No LLM or target-script execution was found in the reviewed scan path |
| Target writes | `code_verified` | `cmd/aguara/commands/update.go:95@819eafb5fa66` | Intelligence updates write only after verification; scan writes depend on requested report output |
| Network access | `code_verified` | `cmd/aguara/commands/update.go:25@819eafb5fa66` | Default scan uses embedded data; update and fresh modes are explicit |
| Read confinement | `contradicted` | `internal/scanner/target.go:92@819eafb5fa66` | Directory symlinks are skipped, but unreadable and oversized inputs are silently omitted |

## Intelligence lifecycle

| Capability | State | Evidence | Update contract |
| --- | --- | --- | --- |
| Embedded and signed intelligence | `code_verified` | `internal/intel/bundle/verify.go:72@819eafb5fa66` | Sigstore verification, expected identity, schema checks, and zero-record refusal |
| Manual, OSV, and OpenSSF sources | `declared` | `README.md:146@819eafb5fa66` | Provenance is documented; correction latency was not measured |

## Outputs and integration

| Output or integration | State | Evidence | Contract |
| --- | --- | --- | --- |
| Terminal, JSON, SARIF, and Markdown | `code_verified` | `cmd/aguara/commands/scan.go:538@819eafb5fa66` | Multiple machine and human report formats |
| Exit status | `code_verified` | `cmd/aguara/main.go:11@819eafb5fa66` | Threshold finding exits `1`; operational error exits `2` |
| CI baseline | `code_verified` | `README.md:225@819eafb5fa66` | Malformed baselines fail closed; compromised-package findings cannot be baselined |

## Distribution

| Channel | State | Evidence | Verification |
| --- | --- | --- | --- |
| Source, Homebrew, container, and release binaries | `declared` | `README.md:244@819eafb5fa66` | The README states digest, SBOM, and provenance support; artifacts were not downloaded |

## Tests and fixtures

| Test property | State | Evidence | Limitation |
| --- | --- | --- | --- |
| Changed-file symlink regression | `code_verified` | `cmd/aguara/commands/scan_test.go:207@819eafb5fa66` | Covers changed-file mode, not an explicit single-file symlink target |
| SARIF and exit threshold tests | `code_verified` | `cmd/aguara/commands/scan_test.go:352@819eafb5fa66` | Static review did not execute the suite |

## License

| Item | State | Evidence | Consequence |
| --- | --- | --- | --- |
| Apache License 2.0 | `code_verified` | `LICENSE:1@819eafb5fa66` | Permissive reuse with notice and patent terms |

## Contradictions and unknowns

| Claim or question | State | Evidence | Required follow-up |
| --- | --- | --- | --- |
| Clean output can omit unreadable files | `contradicted` | `internal/scanner/scanner.go:218@819eafb5fa66` | Run an isolated unreadable-file witness and inspect result diagnostics |
| Files larger than 50 MB are silent skips | `contradicted` | `internal/scanner/target.go:14@819eafb5fa66` | Compare the verdict and coverage metadata with AgentSec |
| Explicit single-file symlink confinement | `not_tested` | `internal/scanner/scanner.go:151@819eafb5fa66` | Run a sandboxed path-escape witness after owner approval |

## Parity lessons

| Candidate capability | State | Evidence | AgentSec decision question |
| --- | --- | --- | --- |
| Signed, opt-in intelligence update | `code_verified` | `cmd/aguara/commands/update.go:25@819eafb5fa66` | Add signing and rollback metadata to AgentSec feeds |
| CI-safe suppression policy | `code_verified` | `aguara.go:119@819eafb5fa66` | Separate local convenience from untrusted-target policy |
| SARIF and baseline workflow | `code_verified` | `README.md:225@819eafb5fa66` | Prioritize interoperable CI adoption without hiding critical campaigns |

## Differentiation lessons

| Candidate distinction | State | Evidence | AgentSec decision question |
| --- | --- | --- | --- |
| Explicit incomplete-scan diagnostics | `contradicted` | `internal/scanner/target.go:92@819eafb5fa66` | Keep AgentSec coverage gaps visible and verdict-affecting |
| Versioned public intelligence feed | `code_verified` | `README.md:146@819eafb5fa66` | Explain AgentSec as scanner plus auditable security timeline, not only rules |

## Evidence

| Reference | State | Evidence type | Relevance |
| --- | --- | --- | --- |
| `internal/scanner/target.go:92@819eafb5fa66` | `code_verified` | Code | Establishes the silent-skip behavior |
| `internal/intel/bundle/verify.go:72@819eafb5fa66` | `code_verified` | Code | Establishes signed update verification |
| `cmd/aguara/commands/scan_test.go:207@819eafb5fa66` | `code_verified` | Test | Establishes changed-file symlink coverage |

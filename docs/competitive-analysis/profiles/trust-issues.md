# Trust Issues

Review of the pinned revision only. No Trust Issues code was executed.

## Project identity

- Project ID: `trust-issues`
- Repository: `https://github.com/howshannon/trust-issues`
- Revision: `ca53cd030f78`
- Review date: `2026-08-24`
- Review scope: tracked Bash scanner, skill workflow, fixtures, benchmark result, license, and documentation

## Declared promise

| Claim | State | Evidence | Notes |
| --- | --- | --- | --- |
| Pre-install attacker-minded review for repositories, skills, MCP, and packages | `declared` | `README.md:20@ca53cd030f78` | Produces a human or agent verdict |
| Read-only 14-category scanner plus five-persona review | `declared` | `README.md:26@ca53cd030f78` | Manual reasoning is the primary decision layer |
| Public fixture benchmark with recall and false positives | `declared` | `README.md:36@ca53cd030f78` | README claims 10 of 11 malicious fixtures in the correct category |

## Observed architecture

| Component | State | Evidence | Responsibility |
| --- | --- | --- | --- |
| Bash triage scanner | `code_verified` | `scripts/triage_scan.sh:1@ca53cd030f78` | Applies grep, find, file, wc, and awk checks across 14 categories |
| Agent skill workflow | `code_verified` | `SKILL.md:47@ca53cd030f78` | Directs acquisition, research, scanning, manual review, and verdict writing |
| Benchmark harness | `code_verified` | `benchmark/run_benchmark.sh:21@ca53cd030f78` | Copies inert fixtures to a temporary directory and scans them |

## Inspected surfaces

| Surface | State | Evidence | Boundary |
| --- | --- | --- | --- |
| Source, manifests, prompts, CI, secrets, and binaries | `code_verified` | `scripts/triage_scan.sh:96@ca53cd030f78` | Signature scan excludes common vendor and generated trees |
| Current threat research | `code_verified` | `SKILL.md:59@ca53cd030f78` | Performed by the reviewing agent or human, not by the Bash scanner |
| Manual intent review | `code_verified` | `SKILL.md:88@ca53cd030f78` | Requires reading every executable entrypoint, agent document, workflow, and network call |

## Safety boundary

| Property | State | Evidence | Consequence |
| --- | --- | --- | --- |
| Target content execution | `code_verified` | `scripts/triage_scan.sh:65@ca53cd030f78` | Scanner reads via standard utilities and does not invoke target entrypoints |
| Target writes | `code_verified` | `scripts/triage_scan.sh:28@ca53cd030f78` | Scanner has no target write path; the benchmark uses temporary copies |
| Network access | `code_verified` | `scripts/triage_scan.sh:11@ca53cd030f78` | Bash scanner is offline; the full workflow mandates web research |
| Read confinement | `code_verified` | `scripts/triage_scan.sh:40@ca53cd030f78` | Canonicalizes the root and uses non-following traversal |

## Intelligence lifecycle

| Capability | State | Evidence | Update contract |
| --- | --- | --- | --- |
| Per-run web research | `code_verified` | `SKILL.md:59@ca53cd030f78` | Reviewer folds current advisories into manual analysis without a structured feed |
| Local threat catalog | `code_verified` | `SKILL.md:71@ca53cd030f78` | Versioned with the skill and updated through source changes |

## Outputs and integration

| Output or integration | State | Evidence | Contract |
| --- | --- | --- | --- |
| Human triage report | `code_verified` | `scripts/triage_scan.sh:206@ca53cd030f78` | Informational only; scanner exits `0` after a completed triage regardless of hits |
| GO, GO WITH MITIGATIONS, or NO-GO | `code_verified` | `SKILL.md:127@ca53cd030f78` | Verdict comes from the manual or LLM reasoning workflow |
| Structured machine output | `not_applicable` | `scripts/triage_scan.sh:93@ca53cd030f78` | Scanner prints human text and has no JSON or SARIF contract |

## Distribution

| Channel | State | Evidence | Verification |
| --- | --- | --- | --- |
| Git repository and installable agent skill | `code_verified` | `README.md:73@ca53cd030f78` | Bash scanner can also run standalone |

## Tests and fixtures

| Test property | State | Evidence | Limitation |
| --- | --- | --- | --- |
| Inert malicious and benign fixtures | `code_verified` | `benchmark/README.md:21@ca53cd030f78` | Corpus is small and project-authored |
| Checked-in benchmark result | `contradicted` | `benchmark/RESULTS.md:3@ca53cd030f78` | Result reports zero malicious cases despite eleven tracked malicious fixtures and the README claim |

## License

| Item | State | Evidence | Consequence |
| --- | --- | --- | --- |
| MIT License | `code_verified` | `LICENSE:1@ca53cd030f78` | Permissive reuse with copyright notice |

## Contradictions and unknowns

| Claim or question | State | Evidence | Required follow-up |
| --- | --- | --- | --- |
| README benchmark equals the versioned result | `contradicted` | `README.md:40@ca53cd030f78` | Re-run the harness only in the approved offline benchmark and compare regenerated output |
| Unreadable-file completeness | `contradicted` | `scripts/triage_scan.sh:68@ca53cd030f78` | Read and traversal errors are redirected away, and the informational scan can still exit `0` |
| Full workflow resistance to prompt injection | `not_tested` | `SKILL.md:88@ca53cd030f78` | Review the workflow with an inert prompt-injection fixture without granting secrets or network |

## Parity lessons

| Candidate capability | State | Evidence | AgentSec decision question |
| --- | --- | --- | --- |
| Explicit pre-trust verdict language | `code_verified` | `SKILL.md:127@ca53cd030f78` | Add a concise action recommendation without overstating safety |
| Published benign and malicious fixture corpus | `code_verified` | `benchmark/README.md:1@ca53cd030f78` | Publish only original inert witnesses with expected semantic findings |
| Human reasoning handoff | `code_verified` | `scripts/triage_scan.sh:206@ca53cd030f78` | Generate a bounded investigation checklist from structured evidence |

## Differentiation lessons

| Candidate distinction | State | Evidence | AgentSec decision question |
| --- | --- | --- | --- |
| Reproducible machine contract | `not_applicable` | `scripts/triage_scan.sh:26@ca53cd030f78` | Keep JSON schema, explicit coverage, and exit semantics central |
| Curated versioned intelligence | `code_verified` | `SKILL.md:59@ca53cd030f78` | Replace ad hoc search-only updates with reviewed sources, dated events, and corrections |

## Evidence

| Reference | State | Evidence type | Relevance |
| --- | --- | --- | --- |
| `scripts/triage_scan.sh:65@ca53cd030f78` | `code_verified` | Code | Establishes read-only static behavior |
| `benchmark/RESULTS.md:3@ca53cd030f78` | `contradicted` | Fixture result | Establishes benchmark drift |
| `SKILL.md:127@ca53cd030f78` | `code_verified` | Workflow | Establishes decision output |

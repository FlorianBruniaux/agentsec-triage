# Cisco Skill Scanner

Review of the pinned revision only. No Cisco Skill Scanner code was executed.

## Project identity

- Project ID: `cisco-skill-scanner`
- Repository: `https://github.com/cisco-ai-defense/skill-scanner`
- Revision: `48f59347a54b`
- Review date: `2026-08-24`
- Review scope: tracked Python source, tests, package metadata, license, and documentation

## Declared promise

| Claim | State | Evidence | Notes |
| --- | --- | --- | --- |
| Best-effort security scanner for AI agent skills | `declared` | `README.md:12@48f59347a54b` | Explicitly says a clean scan does not prove safety |
| Pattern, bytecode, pipeline, behavioral, model, and cloud engines | `declared` | `README.md:22@48f59347a54b` | Networked engines are optional |
| CI output and severity gates | `declared` | `README.md:24@48f59347a54b` | Includes SARIF and reusable workflows |

## Observed architecture

| Component | State | Evidence | Responsibility |
| --- | --- | --- | --- |
| Loader | `code_verified` | `skill_scanner/core/loader.py:43@48f59347a54b` | Parses skill metadata and inventories text and binary files |
| Scanner orchestrator | `code_verified` | `skill_scanner/core/scanner.py:107@48f59347a54b` | Runs core and optional analyzers in two phases |
| CLI | `code_verified` | `skill_scanner/cli/cli.py:376@48f59347a54b` | Selects engines, formats reports, and applies a severity threshold |
| Repository fetcher | `code_verified` | `skill_scanner/core/repo_fetcher.py:40@48f59347a54b` | Accepts GitHub HTTPS references and shallow-clones to a temporary directory |

## Inspected surfaces

| Surface | State | Evidence | Boundary |
| --- | --- | --- | --- |
| Skill Markdown, scripts, references, and assets | `code_verified` | `skill_scanner/core/loader.py:43@48f59347a54b` | Strict mode requires `SKILL.md`; lenient mode can synthesize from Markdown |
| Static, bytecode, and pipeline behavior | `code_verified` | `skill_scanner/cli/cli.py:724@48f59347a54b` | Core engines run by default without cloud credentials |
| Archives | `code_verified` | `skill_scanner/core/extractors/content_extractor.py:180@48f59347a54b` | Detects zip links and bounds nested extraction |

## Safety boundary

| Property | State | Evidence | Consequence |
| --- | --- | --- | --- |
| Target content execution | `code_verified` | `skill_scanner/core/scanner.py:202@48f59347a54b` | Default analyzers inspect data; no target entrypoint invocation was found |
| Target writes | `code_verified` | `skill_scanner/core/extractors/content_extractor.py:260@48f59347a54b` | Archive extraction uses temporary directories; output files require explicit flags |
| Network access | `code_verified` | `skill_scanner/cli/cli.py:944@48f59347a54b` | LLM, VirusTotal, AI Defense, and OSV are explicit opt-ins |
| Read confinement | `code_verified` | `skill_scanner/core/loader.py:297@48f59347a54b` | Skips symlinks and resolved paths outside the skill root |

## Intelligence lifecycle

| Capability | State | Evidence | Update contract |
| --- | --- | --- | --- |
| Built-in policies, YARA, and taxonomy | `code_verified` | `skill_scanner/data/default_policy.yaml:1@48f59347a54b` | Ships with package releases and supports local custom packs |
| Optional OSV and cloud intelligence | `code_verified` | `skill_scanner/cli/cli.py:946@48f59347a54b` | Requires explicit networked flags and external service availability |

## Outputs and integration

| Output or integration | State | Evidence | Contract |
| --- | --- | --- | --- |
| Summary, JSON, Markdown, table, SARIF, and HTML | `code_verified` | `skill_scanner/cli/cli.py:896@48f59347a54b` | Supports multiple formats in one run |
| Severity gate | `code_verified` | `skill_scanner/cli/cli.py:456@48f59347a54b` | Returns `1` at or above the selected threshold |
| Multi-skill skipped list | `code_verified` | `skill_scanner/core/models.py:320@48f59347a54b` | JSON includes skipped skills when present |

## Distribution

| Channel | State | Evidence | Verification |
| --- | --- | --- | --- |
| PyPI package and source workflow | `code_verified` | `pyproject.toml:5@48f59347a54b` | Package supports Python 3.10 and newer |

## Tests and fixtures

| Test property | State | Evidence | Limitation |
| --- | --- | --- | --- |
| API, analyzer, path, policy, and output suites | `code_verified` | `tests/test_path_traversal_and_redaction.py:109@48f59347a54b` | Static review did not execute the suite |
| Archive symlink regression | `code_verified` | `tests/test_api_deep.py:277@48f59347a54b` | Covers uploaded zip links, not every filesystem race |

## License

| Item | State | Evidence | Consequence |
| --- | --- | --- | --- |
| Apache License 2.0 | `code_verified` | `LICENSE:1@48f59347a54b` | Permissive reuse with notice and license terms |

## Contradictions and unknowns

| Claim or question | State | Evidence | Required follow-up |
| --- | --- | --- | --- |
| Multi-skill scan fails when a skill is skipped | `contradicted` | `skill_scanner/cli/cli.py:499@48f59347a54b` | The report records skips, but exit `0` remains possible when another skill scanned and no threshold finding exists |
| Unreadable non-metadata file coverage | `not_tested` | `skill_scanner/core/loader.py:329@48f59347a54b` | Inject an unreadable file and determine if it becomes binary-only or incomplete evidence |
| Model and cloud analyzer failure policy | `not_tested` | `skill_scanner/cli/cli.py:446@48f59347a54b` | Keep all networked analyzers outside the first benchmark |

## Parity lessons

| Candidate capability | State | Evidence | AgentSec decision question |
| --- | --- | --- | --- |
| Skill-specific semantic and dataflow analysis | `code_verified` | `skill_scanner/core/scanner.py:216@48f59347a54b` | Add only the techniques that improve campaign evidence without model dependence |
| Custom policy and rule packs | `code_verified` | `skill_scanner/data/default_policy.yaml:1@48f59347a54b` | Define a stable local extension contract after the built-in detector API |
| Multi-format output | `code_verified` | `skill_scanner/cli/cli.py:896@48f59347a54b` | Decide whether HTML belongs outside the core CLI |

## Differentiation lessons

| Candidate distinction | State | Evidence | AgentSec decision question |
| --- | --- | --- | --- |
| Fail-closed repository coverage | `contradicted` | `skill_scanner/cli/cli.py:580@48f59347a54b` | Keep incomplete coverage independent from finding severity |
| Campaign-to-evidence explanation | `not_applicable` | `pyproject.toml:8@48f59347a54b` | Preserve sourced incident context instead of competing on skill rules alone |

## Evidence

| Reference | State | Evidence type | Relevance |
| --- | --- | --- | --- |
| `skill_scanner/core/loader.py:297@48f59347a54b` | `code_verified` | Code | Establishes file discovery and confinement |
| `skill_scanner/core/scanner.py:754@48f59347a54b` | `code_verified` | Code | Establishes skipped-skill behavior |
| `skill_scanner/cli/cli.py:580@48f59347a54b` | `code_verified` | Code | Establishes multi-skill exit policy |

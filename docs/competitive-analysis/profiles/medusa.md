# Medusa

Review of the pinned revision only. No Medusa code was executed.

## Project identity

- Project ID: `medusa`
- Repository: `https://github.com/Pantheon-Security/medusa`
- Revision: `5f217edf8b09`
- Review date: `2026-08-24`
- Review scope: tracked Python source, rules, tests, license, and documentation

## Declared promise

| Claim | State | Evidence | Notes |
| --- | --- | --- | --- |
| AI-first multi-language security scanner | `declared` | `pyproject.toml:8@5f217edf8b09` | Claims 79 analyzers and more than 40,000 patterns |
| AI repository-poisoning coverage | `declared` | `README.md:475@5f217edf8b09` | Covers agent instructions, MCP, skills, IDE config, CVEs, and languages |
| Local built-in rules with optional external linters | `declared` | `README.md:535@5f217edf8b09` | External tools are auto-detected when installed |

## Observed architecture

| Component | State | Evidence | Responsibility |
| --- | --- | --- | --- |
| Click CLI | `code_verified` | `medusa/cli.py:1316@5f217edf8b09` | Selects local, Git clone, cache, report, and screening behavior |
| Parallel scan engine | `code_verified` | `medusa/core/parallel.py:419@5f217edf8b09` | Loads project configuration and dispatches scanners |
| Scanner registry | `code_verified` | `medusa/scanners/__init__.py:1@5f217edf8b09` | Registers language, agent, MCP, CVE, and external-tool adapters |
| YAML rule corpus | `code_verified` | `medusa/rules/agent_security/agentic_attacks_2026.yaml:1@5f217edf8b09` | Stores a large pattern and metadata set in-repo |

## Inspected surfaces

| Surface | State | Evidence | Boundary |
| --- | --- | --- | --- |
| Agent and IDE configuration | `code_verified` | `tests/test_git_scan.py:197@5f217edf8b09` | Fixtures cover Claude hooks, agents, skills, MCP, and other instruction formats |
| General source languages and infrastructure | `declared` | `README.md:552@5f217edf8b09` | Scope extends far beyond AgentSec's agent-security focus |
| Host chat histories and credentials | `code_verified` | `medusa/core/chat_history_discovery.py:1@5f217edf8b09` | Separate secret scanning reaches user-home data |

## Safety boundary

| Property | State | Evidence | Consequence |
| --- | --- | --- | --- |
| Target content execution | `not_tested` | `medusa/cli.py:1100@5f217edf8b09` | Scanner adapters invoke external tools; their handling of target-owned configs needs tracing |
| Target writes | `code_verified` | `medusa/core/parallel.py:127@5f217edf8b09` | Default cache and reports write outside or beside scan results; purge and init are separate mutation paths |
| Network access | `code_verified` | `medusa/cli.py:1807@5f217edf8b09` | Remote-repository mode clones over Git; local scan dependencies include request clients |
| Read confinement | `contradicted` | `medusa/core/parallel.py:419@5f217edf8b09` | Target-owned `medusa.yml` controls exclusions and scanner selection |

## Intelligence lifecycle

| Capability | State | Evidence | Update contract |
| --- | --- | --- | --- |
| In-repository YAML rules and CVEs | `code_verified` | `medusa/rules/cve/cveminer_cves.yaml:1@5f217edf8b09` | Rules update with package releases; signed feed and correction ledger were not found |
| False-positive filter corpus | `code_verified` | `medusa/core/fp_patterns/_universal.yaml:1@5f217edf8b09` | Large suppressor set influences output after detection |

## Outputs and integration

| Output or integration | State | Evidence | Contract |
| --- | --- | --- | --- |
| JSON, HTML, Markdown, SARIF, JUnit, and text | `declared` | `README.md:585@5f217edf8b09` | Broad reporting surface for CI and humans |
| Severity threshold | `code_verified` | `medusa/cli.py:1286@5f217edf8b09` | `--fail-on` selects build failure threshold |
| Cache | `code_verified` | `tests/test_security_hardening.py:630@5f217edf8b09` | HMAC envelope rejects tampering and stale rule versions |

## Distribution

| Channel | State | Evidence | Verification |
| --- | --- | --- | --- |
| PyPI source distribution | `code_verified` | `pyproject.toml:5@5f217edf8b09` | Package metadata declares Python 3.10 and later |

## Tests and fixtures

| Test property | State | Evidence | Limitation |
| --- | --- | --- | --- |
| Malicious agent-repository fixtures | `code_verified` | `tests/test_git_scan.py:197@5f217edf8b09` | Positive and safe-file assertions exist |
| Cache and host-boundary hardening | `code_verified` | `tests/test_security_hardening.py:630@5f217edf8b09` | External scanner execution remains outside these fixtures |

## License

| Item | State | Evidence | Consequence |
| --- | --- | --- | --- |
| AGPL 3.0 or later | `code_verified` | `LICENSE:1@5f217edf8b09` | Modified network services have source-availability obligations |

## Contradictions and unknowns

| Claim or question | State | Evidence | Required follow-up |
| --- | --- | --- | --- |
| Hostile target can tune scan config | `contradicted` | `medusa/core/parallel.py:419@5f217edf8b09` | Benchmark with a target config that disables relevant scanners and exclusions |
| External tools may load target config or plugins | `not_tested` | `medusa/cli.py:1100@5f217edf8b09` | Trace subprocess argv, environment, filesystem, and network in a container |
| Rule count and false-positive claims | `not_tested` | `pyproject.toml:8@5f217edf8b09` | Count active unique rules and measure against the common corpus |

## Parity lessons

| Candidate capability | State | Evidence | AgentSec decision question |
| --- | --- | --- | --- |
| Priority scan for agent files | `code_verified` | `tests/test_git_scan.py:197@5f217edf8b09` | Offer a fast agent-surface mode without weakening full coverage accounting |
| Cache integrity | `code_verified` | `tests/test_security_hardening.py:630@5f217edf8b09` | Sign cache identity with database and detector versions |
| Broad report formats | `declared` | `README.md:585@5f217edf8b09` | Add formats only when a real consumer requires them |

## Differentiation lessons

| Candidate distinction | State | Evidence | AgentSec decision question |
| --- | --- | --- | --- |
| Narrow agent-security verdict | `code_verified` | `pyproject.toml:8@5f217edf8b09` | Position AgentSec against generic SAST breadth and rule-count marketing |
| Target config distrust | `contradicted` | `medusa/core/parallel.py:419@5f217edf8b09` | Ignore repository-owned exclusions in CI and public API modes |
| Auditable intelligence lifecycle | `code_verified` | `medusa/rules/cve/cveminer_cves.yaml:1@5f217edf8b09` | Keep source, event date, coverage, and correction state beside each event |

## Evidence

| Reference | State | Evidence type | Relevance |
| --- | --- | --- | --- |
| `medusa/core/parallel.py:419@5f217edf8b09` | `code_verified` | Code | Establishes target configuration loading |
| `tests/test_security_hardening.py:630@5f217edf8b09` | `code_verified` | Test | Establishes cache integrity controls |
| `tests/test_git_scan.py:197@5f217edf8b09` | `code_verified` | Test | Establishes agent-repository fixture coverage |

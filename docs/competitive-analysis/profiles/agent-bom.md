# agent-bom

Review of the pinned revision only. No agent-bom code was executed.

## Project identity

- Project ID: `agent-bom`
- Repository: `https://github.com/msaad00/agent-bom`
- Revision: `9ceeb22fff1f`
- Review date: `2026-08-24`
- Review scope: tracked Python source, tests, packaging, license, and documentation

## Declared promise

| Claim | State | Evidence | Notes |
| --- | --- | --- | --- |
| Open scanner and self-hosted control plane for AI, MCP, cloud, and supply chain | `declared` | `README.md:19@9ceeb22fff1f` | Scope extends well beyond local repository triage |
| Incomplete evidence cannot return a clean CI result | `declared` | `README.md:121@9ceeb22fff1f` | Implementation records scan outcome and forces exit 1 |
| Discovery and analysis do not mutate scanned targets | `declared` | `README.md:240@9ceeb22fff1f` | Optional integrations have separate operational boundaries |

## Observed architecture

| Component | State | Evidence | Responsibility |
| --- | --- | --- | --- |
| Click CLI and scan pipeline | `code_verified` | `src/agent_bom/cli/agents/scan_cmd.py:277@9ceeb22fff1f` | Orchestrates discovery, scanners, reports, and integrations |
| Project manifest parser | `code_verified` | `src/agent_bom/parsers/__init__.py:804@9ceeb22fff1f` | Discovers packages across supported ecosystems with root checks |
| Vulnerability scanner | `code_verified` | `src/agent_bom/scanners/package_scan.py:1315@9ceeb22fff1f` | Uses local databases and online fallbacks under explicit scan options |
| Evidence outcome model | `code_verified` | `src/agent_bom/cli/agents/_post.py:472@9ceeb22fff1f` | Converts degraded collection into a nonzero scan verdict |

## Inspected surfaces

| Surface | State | Evidence | Boundary |
| --- | --- | --- | --- |
| Repository manifests and lockfiles | `code_verified` | `src/agent_bom/parsers/__init__.py:847@9ceeb22fff1f` | Parses multiple package ecosystems to inventory direct and transitive dependencies |
| Agents, MCP clients, skills, and AI components | `declared` | `README.md:49@9ceeb22fff1f` | Combines local configuration, source, and package evidence |
| Cloud and runtime control plane | `declared` | `README.md:237@9ceeb22fff1f` | Operational surfaces are adjacent to repository scanning |

## Safety boundary

| Property | State | Evidence | Consequence |
| --- | --- | --- | --- |
| Target content execution | `declared` | `README.md:240@9ceeb22fff1f` | Read-first analysis is the documented default |
| Network-offline mode | `code_verified` | `src/agent_bom/cli/agents/scan_cmd.py:783@9ceeb22fff1f` | Sets both scanner and transport layers offline |
| Symlink confinement | `code_verified` | `src/agent_bom/parsers/__init__.py:840@9ceeb22fff1f` | Default skips symlinks; optional following remains inside the resolved root |
| Permission failures | `contradicted` | `src/agent_bom/parsers/__init__.py:909@9ceeb22fff1f` | A denied directory can be skipped without adding a project warning |

## Intelligence lifecycle

| Capability | State | Evidence | Update contract |
| --- | --- | --- | --- |
| Local vulnerability database | `code_verified` | `src/agent_bom/scanners/package_scan.py:1565@9ceeb22fff1f` | Missing offline coverage raises an incomplete-scan error |
| OSV and ecosystem enrichment | `code_verified` | `src/agent_bom/scanners/package_scan.py:1540@9ceeb22fff1f` | Online mode queries gaps not covered by local data |
| Broad control-plane intelligence | `declared` | `README.md:126@9ceeb22fff1f` | Database update commands cover advisory and exploitation feeds |

## Outputs and integration

| Output or integration | State | Evidence | Contract |
| --- | --- | --- | --- |
| Console, JSON, SARIF, and compliance artifacts | `declared` | `README.md:49@9ceeb22fff1f` | One report model supports developer and governance workflows |
| Fail-closed scan outcome | `code_verified` | `src/agent_bom/cli/agents/_post.py:472@9ceeb22fff1f` | Any non-complete effective outcome forces exit 1 |
| MCP server with 84 tools | `declared` | `README.md:240@9ceeb22fff1f` | Very broad agent interface increases product and security surface |

## Distribution

| Channel | State | Evidence | Verification |
| --- | --- | --- | --- |
| PyPI, container, Action, API, Helm, MCP, and SDK | `declared` | `README.md:237@9ceeb22fff1f` | Published artifacts and hosted paths were not exercised |

## Tests and fixtures

| Test property | State | Evidence | Limitation |
| --- | --- | --- | --- |
| Project-mode symlink tests | `code_verified` | `tests/test_project_mode.py:82@9ceeb22fff1f` | Establishes expected inside-root behavior |
| Offline incomplete coverage tests | `code_verified` | `tests/test_local_db_scan.py:527@9ceeb22fff1f` | Tests were inspected but not run |
| Demo corpus | `declared` | `README.md:95@9ceeb22fff1f` | Runtime behavior remains behind the approval gate |

## License

| Item | State | Evidence | Consequence |
| --- | --- | --- | --- |
| Apache License 2.0 | `code_verified` | `pyproject.toml:10@9ceeb22fff1f` | Permissive reuse with notice and patent terms |

## Contradictions and unknowns

| Claim or question | State | Evidence | Required follow-up |
| --- | --- | --- | --- |
| Permission-denied traversal accounting | `contradicted` | `src/agent_bom/parsers/__init__.py:909@9ceeb22fff1f` | Verify whether another collector records the omission in final scan evidence |
| Full offline network isolation | `not_tested` | `src/agent_bom/cli/agents/scan_cmd.py:783@9ceeb22fff1f` | Observe network-denied execution after approval |
| Breadth versus repository precision | `not_tested` | `README.md:19@9ceeb22fff1f` | Compare narrow fixture recall and diagnostics before copying product scope |

## Parity lessons

| Candidate capability | State | Evidence | AgentSec decision question |
| --- | --- | --- | --- |
| Structured scan-run evidence | `code_verified` | `src/agent_bom/cli/agents/_post.py:472@9ceeb22fff1f` | Expand AgentSec diagnostics into a stable machine-readable completeness contract |
| Explicit local database coverage | `code_verified` | `src/agent_bom/scanners/package_scan.py:1565@9ceeb22fff1f` | Report covered ecosystems, freshness, and missing intelligence |
| Inventory plus reachable impact | `declared` | `README.md:110@9ceeb22fff1f` | Add relationships only after repository facts remain traceable |

## Differentiation lessons

| Candidate distinction | State | Evidence | AgentSec decision question |
| --- | --- | --- | --- |
| Narrow repository-trust decision | `declared` | `README.md:19@9ceeb22fff1f` | Keep AgentSec focused instead of becoming a general control plane |
| Curated agent-attack intelligence | `not_tested` | `README.md:126@9ceeb22fff1f` | Compare incident provenance and detector mapping directly |
| Simpler local operational model | `code_verified` | `pyproject.toml:7@9ceeb22fff1f` | Make one-command adoption a deliberate contrast to a broad platform |

## Evidence

| Reference | State | Evidence type | Relevance |
| --- | --- | --- | --- |
| `src/agent_bom/cli/agents/_post.py:472@9ceeb22fff1f` | `code_verified` | Code | Establishes fail-closed scan outcome |
| `src/agent_bom/parsers/__init__.py:840@9ceeb22fff1f` | `code_verified` | Code | Establishes symlink confinement |
| `pyproject.toml:10@9ceeb22fff1f` | `code_verified` | Package metadata | Establishes reuse terms |

# Project name

Review only the pinned revision recorded in
`data/competitive-projects.yaml`. Replace each placeholder and keep unsupported
claims marked `not_tested`.

## Project identity

- Project ID: `project-id`
- Repository: `https://github.com/owner/repository`
- Revision: `0123456789ab`
- Review date: `YYYY-MM-DD`
- Review scope: static tracked files or isolated observation identifier

## Declared promise

| Claim | State | Evidence | Notes |
| --- | --- | --- | --- |
| Replace with an official product claim | `declared` | `README.md:line@revision` | Preserve the documented scope |

## Observed architecture

| Component | State | Evidence | Responsibility |
| --- | --- | --- | --- |
| Replace with an entrypoint or subsystem | `code_verified` | `path:line@revision` | Describe the data flow |

## Inspected surfaces

| Surface | State | Evidence | Boundary |
| --- | --- | --- | --- |
| Replace with a supported input | `code_verified` | `path:line@revision` | Record exclusions and limits |

## Safety boundary

| Property | State | Evidence | Consequence |
| --- | --- | --- | --- |
| Target content execution | `not_tested` | `path:line@revision` or run ID | Record subprocess and interpreter use |
| Target writes | `not_tested` | `path:line@revision` or run ID | Record every writable location |
| Network access | `not_tested` | `path:line@revision` or run ID | Record destinations and consent |
| Read confinement | `not_tested` | `path:line@revision` or run ID | Record symlink and metadata handling |

## Intelligence lifecycle

| Capability | State | Evidence | Update contract |
| --- | --- | --- | --- |
| Rule or IOC updates | `not_tested` | `path:line@revision` | Record provenance, signing, rollback, and corrections |

## Outputs and integration

| Output or integration | State | Evidence | Contract |
| --- | --- | --- | --- |
| Replace with CLI, JSON, SARIF, CI, or API | `not_tested` | `path:line@revision` | Record exit codes and incomplete behavior |

## Distribution

| Channel | State | Evidence | Verification |
| --- | --- | --- | --- |
| Replace with source, package, binary, image, or action | `not_tested` | `path:line@revision` | Record pinning and signatures |

## Tests and fixtures

| Test property | State | Evidence | Limitation |
| --- | --- | --- | --- |
| Replace with applicable regression evidence | `code_verified` | `path:line@revision` | Record positive, negative, and safety coverage |

## License

| Item | State | Evidence | Consequence |
| --- | --- | --- | --- |
| Repository license | `code_verified` | `LICENSE:line@revision` | Record SPDX identifier or exact custom terms |

## Contradictions and unknowns

| Claim or question | State | Evidence | Required follow-up |
| --- | --- | --- | --- |
| Replace with a conflict or unresolved behavior | `not_tested` | `path:line@revision` | State the static or runtime check needed |

## Parity lessons

| Candidate capability | State | Evidence | AgentSec decision question |
| --- | --- | --- | --- |
| Replace with an expected market capability | `code_verified` | `path:line@revision` | Match, reject, or defer |

## Differentiation lessons

| Candidate distinction | State | Evidence | AgentSec decision question |
| --- | --- | --- | --- |
| Replace with an observed gap or trade-off | `code_verified` | `path:line@revision` | Test the proposed advantage |

## Evidence

| Reference | State | Evidence type | Relevance |
| --- | --- | --- | --- |
| `path:line@revision` | `code_verified` | Code, test, fixture, workflow, or documentation | Link the reference to one claim above |

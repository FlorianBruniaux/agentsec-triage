# Repository Guidance and Security Intelligence Design

**Date:** 2026-08-07  
**Status:** Approved direction, pending implementation plan  
**Scope:** AgentSec Triage repository documentation and intelligence publishing

## 1. Goal

Make the repository understandable to humans and coding agents, while adding a
structured, attributable record of relevant security research and dated security
events. The implementation must not create another manually maintained copy of
the threat database or imply that the project tracks every vulnerability in
existence.

## 2. Repository guidance files

The repository root will contain these five entry points:

- `AGENTS.md`: canonical cross-agent development instructions, repository map,
  security invariants, test gates, threat-data rules, and release restrictions.
- `CLAUDE.md`: Claude Code adapter that imports `@AGENTS.md` and contains only
  Claude-specific navigation and workflow notes.
- `README.md`: user-facing product scope, installation, CLI examples, limitations,
  and links to the roadmap and intelligence documents.
- `CHANGELOG.md`: implementation and release history. It does not contain threat
  events.
- `ROADMAP.md`: prioritized product direction, explicit non-goals, release gates,
  and acceptance criteria for the next milestones.

`AGENTS.md` is canonical so agent instructions do not drift. `CLAUDE.md` must not
duplicate those instructions.

## 3. Intelligence data model

Human-readable documents will be generated from structured authoring data:

```text
data/intelligence/
├── sources.yaml
├── events.yaml
└── intelligence.schema.json

docs/
├── SECURITY-INTELLIGENCE.md
└── SECURITY-TIMELINE.md

src/agentsec/resources/
└── security-intelligence.json
```

### 3.1 Sources

`sources.yaml` is a curated bibliography. Each source has a stable ID, title,
publisher, URL, publication date when known, source type, topics, the claim for
which it is cited, review date, and status. A source being listed does not mean
AgentSec endorses every statement it contains.

### 3.2 Events

`events.yaml` is a dated event ledger. Each event has a stable ID, event type,
title, summary, affected ecosystem or product, relevant occurrence/disclosure/
update dates, status, confidence, source IDs, related campaign/CVE/technique IDs,
and detector coverage.

Supported statuses include `confirmed`, `contested`, `corrected`, `retracted`,
and `monitoring`. Corrections append history; they do not silently rewrite a
previous claim.

The timeline says “events tracked by AgentSec,” never “all security flaws.”
Publication date and incident date remain separate when both are known.

## 4. Generation and validation

`scripts/build_intelligence_docs.py` will:

1. load YAML with duplicate-key rejection;
2. validate both documents against the JSON Schema;
3. reject duplicate stable IDs and missing source references;
4. generate deterministic Markdown documents;
5. generate a deterministic JSON artifact for future consumers;
6. write no timestamps that would change without a data change.

CI and the local release gate will regenerate the artifacts and require a clean
diff. Unit tests cover schema failures, ordering, unresolved references,
contested/corrected events, and deterministic output.

## 5. Relationship with the threat database

The threat database remains the current canonical security-data source in the
guide during migration. AgentSec's imported `data/threat-db.yaml` remains the
detector input for V0.1.

The new intelligence files add editorial context and chronology; they do not
duplicate IOC payloads. Events may reference stable campaign, CVE, and technique
IDs from the threat database. Sources may be shared by ID after the threat-data
normalization work is complete.

AgentSec becomes the technical source of truth only after a licensed, tagged
release passes schema, detector, integration, and provenance gates.

## 6. Landing integration

The first implementation produces the JSON artifact but does not modify the
separate landing repository. A later landing change will consume a pinned
AgentSec release artifact at build time and verify its checksum. The landing
must not maintain manually copied versions, dates, counts, or source paths.

The intended flow is:

```text
AgentSec authoring YAML
  -> validated release JSON
  -> guide explanations
  -> landing timeline and source browser
```

No runtime network fetch is required for repository scans or for rendering a
previously built landing.

## 7. Initial content

The first source and event records cover the August 2026 Shai-Hulud/Keyv npm
campaign already used by the V0.1 detector. Confirmed and contested claims stay
separate and preserve their existing Aikido, JFrog, SafeDep, Socket, and related
attribution.

Historical backfill from the guide threat database is a roadmap item. It must be
reviewed record by record rather than generated from aggregate counts.

## 8. Documentation updates

Implementation will:

- add `AGENTS.md`, `CLAUDE.md`, and `ROADMAP.md`;
- add the structured intelligence data, schema, generator, generated documents,
  and tests;
- link the roadmap and intelligence documents from `README.md`;
- document the work under `[Unreleased]` in `CHANGELOG.md`;
- add the generation checks to `CONTRIBUTING.md` and CI.

## 9. Release and tag gate

The implementation branch may be merged locally into `main` after all tests and
review gates pass. The natural prerelease identifier is `v0.1.0-alpha`, matching
the Python version `0.1.0a0`.

No tag, GitHub release, source archive, or PyPI publication is allowed while
`LICENSE-DECISION.md` remains unresolved. Licensing code and threat data is a
separate prerequisite, not a documentation checkbox.

## 10. Acceptance criteria

- All five requested root documents exist and have distinct responsibilities.
- `CLAUDE.md` imports rather than duplicates `AGENTS.md`.
- Structured source and event data validate against a schema.
- Generated Markdown and JSON are deterministic and checked in CI.
- Every event references at least one known source.
- Contested intelligence is visibly marked and never promoted to confirmed.
- README and CHANGELOG expose the new capability and its limits.
- Existing 336 tests plus new tests pass; Ruff and mypy pass.
- The branch is clean and ready for a local merge.
- Tagging remains blocked until the recorded licensing decision is resolved.

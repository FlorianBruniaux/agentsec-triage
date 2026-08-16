# Adding Security Intelligence

AgentSec separates evidence sources, dated events, detector rules, and public
integration data. Adding an article does not automatically create a detector or
prove that a repository is compromised.

## Choose the right record

| Change | Authoring file |
| --- | --- |
| Article, advisory, maintainer notice, database, or social context | `data/intelligence/sources.yaml` |
| Incident, campaign, disclosure, correction, retraction, or intelligence update | `data/intelligence/events.yaml` |
| Exact package version, hash, domain, or detector IOC | `data/threat-db.yaml` |
| New repository behavior that performs detection | `src/agentsec/detectors/` plus fixtures and tests |

## Add a source

Append a record to `data/intelligence/sources.yaml`. Use a stable lowercase ID
that will not change when the article title changes.

```yaml
  - id: vendor-campaign-2026
    title: Technical analysis of the campaign
    publisher: Vendor Security Research
    url: https://example.com/research/campaign
    source_type: research
    published_date: "2026-08-16"
    topics: [supply-chain, npm]
    supports:
      - The exact claim this source supports, without extending its scope.
    reviewed_date: "2026-08-16"
    status: active
```

Use `social` for community warnings. A social post can establish that a warning
circulated, but it is not an independent authority for an IOC.

## Add a fiche

Append one event to `data/intelligence/events.yaml`. A fiche must reference at
least one declared source and must state detector coverage even when no detector
exists.

```yaml
  - id: evt-2026-08-example-campaign
    event_type: campaign
    title: Example supply-chain campaign disclosed
    summary: >-
      Reviewed sources reported a package compromise. This summary states only
      the shared, attributed finding.
    ecosystems: [npm, developer-tools]
    disclosed_date: "2026-08-16"
    status: confirmed
    confidence: confirmed
    source_ids: [vendor-campaign-2026]
    related:
      campaign_ids: [example-campaign-2026-08]
      cve_ids: []
      technique_ids: [npm.compromised-version]
    detector_coverage:
      status: not_detected
      detector_ids: []
      notes: >-
        The event is tracked, but no AgentSec detector covers it yet.
```

Use the actual occurrence, disclosure, or update date. Do not estimate an
unknown date. A contested fiche must use both `status: contested` and
`confidence: contested`.

## Regenerate and synchronize

Update the top-level `updated` field in each edited authoring document, then run:

```bash
.venv/bin/python scripts/build_intelligence_docs.py
.venv/bin/python scripts/build_security_feed.py
.venv/bin/python scripts/sync_security_feed.py --write
```

From a worktree or a nonstandard checkout layout, pass the consumer roots:

```bash
.venv/bin/python scripts/sync_security_feed.py --write \
  --guide-root /absolute/path/to/claude-code-ultimate-guide \
  --landing-root /absolute/path/to/claude-code-ultimate-guide-landing
```

Verify that the committed mirrors match:

```bash
.venv/bin/python scripts/sync_security_feed.py --check \
  --guide-root /absolute/path/to/claude-code-ultimate-guide \
  --landing-root /absolute/path/to/claude-code-ultimate-guide-landing
```

Review these generated outputs before committing:

- `docs/SECURITY-INTELLIGENCE.md`;
- `docs/SECURITY-TIMELINE.md`;
- `src/agentsec/resources/security-intelligence.json`;
- `exports/security-feed.v1.json`;
- the guide and landing feed mirrors.

## Publication boundary

The public feed contains project metadata, factual counts, detector contracts,
reviewed event summaries, and source references. It excludes exact package IOCs,
payload hashes, domains, malicious-skill records, minimum-safe-version data, and
third-party notes. The complete threat database and AgentSec package remain
blocked by `LICENSE-DECISION.md`.

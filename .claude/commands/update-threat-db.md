# Update AgentSec Threat Intelligence

Update AgentSec as the canonical technical source. Do not edit the guide or
landing first. Do not publish, tag, or push until the local gates pass and the
data-license decision permits the requested action.

## Required context

Read these files before research or edits:

1. `AGENTS.md`
2. `CONTRIBUTING.md`
3. `docs/intelligence-authoring.md`
4. `LICENSE-DECISION.md`
5. `data/intelligence/sources.yaml`
6. `data/intelligence/events.yaml`
7. `data/threat-db.yaml`

Run `git status --short --branch`. Preserve unrelated changes and create an
isolated worktree when the current checkout is dirty.

## Research window

Use the latest recorded `updated` date as the lower bound. Search through the
current date. Prefer vendor advisories, maintainer notices, NVD, CVE records,
and primary research. Secondary news and social posts may add context but do
not independently confirm an IOC, affected version, victim, or remediation.

For each candidate, record:

- stable source URL, publisher, publication date, and review date;
- exact claim supported by that source;
- affected component, ecosystem, version range, and patched floor;
- confidence and status supported by the schema;
- detector coverage: `detected`, `partial`, `not_detected`, or
  `not_applicable`;
- redistribution or attribution constraint when known.

Reject duplicates and aliases. Preserve corrections, contested claims, and
retractions as new events. Do not silently rewrite history.

## Researcher IOC dumps (CSV or gist)

A researcher list is a lead list with per-row evidence, not a verified set.

- Read the source file yourself and record the gist or file URL, its created
  and updated timestamps, and the check date.
- Keep each row's own confidence. Never raise a row to `confirmed` because its
  neighbours are.
- Separate build-confirmed IOCs (local hash, sandbox report) from
  campaign-level ones (IPs, contracts, domains reported for other builds).
  Abused legitimate services such as geolocation APIs, CDNs, and public RPC
  endpoints never go into `malicious_domains`.
- Defang repository URLs (`hxxps://github[.]com/owner/repo`) and record
  `live` or `gone` with the check date. Route repository and path IOCs to
  `iocs.github_repos`, hashes to `iocs.malware_hashes`, IPs to `iocs.c2_ips`.
- Give each hash a `campaign_id` and a `detector_projection` (`exact-hash` or
  `none`). A hash without `campaign_id` lands in the shared map that
  `shai-hulud-keyv` reads. Project only hashes whose confidence supports a
  `critical / confirmed` verdict, and withhold generic runtime binaries.
- Keep IOCs out of event summaries and source `supports` text.
- Judge detector coverage on where the payload lives: the README, committed
  archives, agent configuration directories. A source saying that `SKILL.md`
  and settings files are clean means a SKILL.md or settings check does not
  cover it.

## Promotion rules

Route each accepted record to one owner:

- Evidence source: `data/intelligence/sources.yaml`
- Dated fiche: `data/intelligence/events.yaml`
- Exact IOC or version floor: `data/threat-db.yaml`
- New executable detection: detector code, positive fixture, near-miss fixture,
  and a red-first regression test

Use `status: monitoring` with `confidence: review` for a credible claim that
still lacks enough primary evidence. The schema has no `candidate` status.
Never mark a fiche detected unless an existing test demonstrates that exact
coverage.

## Test-first sequence

1. Add the smallest regression test for the first verified record.
2. Run it and capture the expected failure.
3. Add the minimum source, event, and detector data needed to pass.
4. Run the focused test again.
5. Expand the reviewed batch one record at a time.

Configuration-only and prose-only changes still require schema, builder, and
style checks even when no executable behavior changes.

## Build and validate

Run:

```bash
.venv/bin/python scripts/build_threat_db.py
.venv/bin/python scripts/build_intelligence_docs.py
.venv/bin/python scripts/build_security_feed.py
.venv/bin/python scripts/check_markdown_style.py .
.venv/bin/ruff check src tests scripts
.venv/bin/mypy src scripts
PIP_NO_INDEX=1 .venv/bin/pytest --cov=agentsec --cov-report=term-missing --cov-fail-under=85
```

Run every builder a second time and require no generated drift. Inspect the
public feed to confirm it contains no exact IOC, hash, domain, malicious-skill
record, minimum-safe-version value, or third-party notes.

## Synchronize consumers

Only after AgentSec passes locally:

```bash
.venv/bin/python scripts/sync_security_feed.py --write \
  --guide-root /absolute/path/to/claude-code-ultimate-guide \
  --landing-root /absolute/path/to/claude-code-ultimate-guide-landing

.venv/bin/python scripts/sync_security_feed.py --check \
  --guide-root /absolute/path/to/claude-code-ultimate-guide \
  --landing-root /absolute/path/to/claude-code-ultimate-guide-landing
```

Run the guide and landing integration tests after synchronization. A matching
version string alone is insufficient; the mirrors must match AgentSec byte for
byte.

## Report

Return:

- research window and reviewed primary sources;
- accepted, monitoring, rejected, corrected, and retracted records;
- detector coverage added and remaining blind spots;
- database, source, event, and feed counts;
- focused and full validation commands with results;
- consumer synchronization state;
- commit, push, tag, and publication state.

Update `CHANGELOG.md` under `[Unreleased]`. Do not create a tag or public
release while `LICENSE-DECISION.md` remains unresolved.

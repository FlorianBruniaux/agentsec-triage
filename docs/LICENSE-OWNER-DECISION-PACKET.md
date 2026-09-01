# Owner License Decision Packet

## Purpose

This file lists the owner decisions still required before a package, tag,
source archive, GitHub release, or gated-data publication. It does not select a
license, grant rights, or replace legal review.

## Already recorded

- Project-owned source code and original documentation: MIT, selected by the
  owner on 2026-08-15.
- Copyright notice: Florian Bruniaux, 2026.
- Public integration feed: narrow CC BY-SA 4.0 authorization recorded in
  `LICENSE-DATA.md`.
- Package and gated-data publication: blocked by `LICENSE-DECISION.md`.

## Exact owner choices still required

### 1. Data license and scope

Choose and record one outcome:

- approve CC BY-SA 4.0 for the reviewed project-owned data scope;
- choose a different data license after compatibility review;
- keep the gated data private and exclude it from every distributed artifact.

For the chosen outcome, approve the exact authoring paths, generated paths,
database-right treatment, copyright notice, attribution, adaptation notice,
and exclusions. Do not approve a path that still contains an `UNKNOWN` prose
classification.

### 2. Third-party expression

For every `UNKNOWN` row in `docs/LICENSE-PROSE-INVENTORY.json`, choose one
disposition:

- document independent authorship from reviewed facts;
- obtain and record redistribution permission;
- replace the field with an independently written factual summary;
- remove the field from distributed sources and generated artifacts.

The deterministic inventory covers all `notes:` or `description:` keys in the
authoring database: 430 as reviewed on 2026-08-31 in the 2.27.0 database, and
433 as of 2026-09-01 after two subsequent threat-intelligence records added
three fields (see `docs/LICENSE-INVENTORY.md` and `docs/LICENSE-PROSE-REVIEW.md`
for the update notes). Local provenance is verified for the historical 28-field
scanning-tool subset only; the remaining 405 fields are unreviewed, and every
legal classification remains `UNKNOWN`. The 93-locator, 77-field resolution
figure describes the 2026-08-31 review and has not been recomputed for the
three newest fields; a locator supports review but does not prove authorship,
permission, or attribution sufficiency. The Aguara note also needs a factual
rewrite.

### 3. Attribution and packaging

Approve the final artifact policy:

- exact attribution and adaptation notices;
- license files included in wheel, source archive, and repository;
- final SPDX expression for the combined package without implying that MIT
  covers the gated data;
- whether generated intelligence Markdown and JSON are distributed in the
  package, source archive, both, or neither.

### 4. Release authorization

After the reviews, notices, metadata, package inspection, and cross-platform
gates pass, explicitly authorize or reject each action independently:

- annotated `v0.1.0-alpha` tag;
- GitHub release and attached artifacts;
- source archive redistribution;
- Python package publication.

Public repository visibility is not authorization for these actions.

## Evidence required with the decision

Record the decision date, owner identity, approved paths, excluded paths,
license identifiers, attribution text, adaptation statement, legal-review
reference if one exists, and the commit containing the reviewed data snapshot.
Until all required evidence is committed, `LICENSE-DECISION.md` remains closed.

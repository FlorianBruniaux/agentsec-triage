# AgentSec License Evidence Inventory

## Status and scope

This document is a factual decision aid, not a legal conclusion or a data
license grant. It records evidence available in the local repositories through
2026-08-31 and the owner's code-license decision from 2026-08-15. The source
repository became publicly visible on 2026-08-30. That visibility is not a data
license grant. Tagging, release archives, and PyPI publication remain blocked
by [`LICENSE-DECISION.md`](../LICENSE-DECISION.md).

## Threat-data provenance

The AgentSec authoring database was imported byte for byte from the canonical
Claude Code Ultimate Guide file:

```text
/Users/florianbruniaux/Sites/perso/claude-code-ultimate-guide/examples/commands/resources/threat-db.yaml
```

The imported version is `2.26.0`. The source snapshot digest recorded and
verified at import is:

```text
86c0f786498a60970bd4b1f7d3969289df666dedc1d893090b06310ac3236365
```

The copy method, date, source path, and digest are recorded in
[`data/IMPORT_PROVENANCE.md`](../data/IMPORT_PROVENANCE.md).

The current AgentSec authoring file is no longer byte-identical to that imported
snapshot. Commit `cbacb93` added the explicit contested status required by the
runtime confidence model. Its 2026-08-11 SHA-256 is:

```text
727043f80fddcff83ab83adc7e5f2dca8ad084ab1a518dc0c146df9a659b180b
```

The imported digest proves the origin of the baseline; it is not a digest of the
current adapted AgentSec file.

## Observed Git authorship

The canonical guide file had 26 commits in its `--follow` history at the time of
review. Every commit carried the same Git author identity:

```text
Florian BRUNIAUX <florian@bruniaux.com>
```

The imported file has two commits in the AgentSec repository, with that same
identity. This single Git author identity reduces the contributor-permission
question, but Git metadata alone does not prove exclusive rights to copied or
adapted third-party expression.

Reproduce the author-history checks from the relevant repository:

```bash
git log --follow --format='%h %an <%ae>' -- examples/commands/resources/threat-db.yaml
git log --follow --format='%h %an <%ae>' -- data/threat-db.yaml
```

## Third-party sources and prose review

The database cites public advisories, incident reports, vendor research, and
community material. Facts and indicators can have different legal treatment
from original prose, selection, arrangement, and database rights.

The earlier inventory count of 28 was incomplete. It matches the
`scanning_tools[].notes` subset, not the complete database. A recursive count
finds 419 `notes:` or `description:` keys in the imported 2.26.0 snapshot and
430 in the current 2.27.0 authoring database.

The generated [`LICENSE-PROSE-INVENTORY.json`](LICENSE-PROSE-INVENTORY.json)
now records all 430 current prose fields with their field path, full value
digest, locally resolvable source locators where available, classification,
review state, and required action. The historical 28-field
`scanning_tools[].notes` subset has review state `LOCAL_PROVENANCE_VERIFIED`;
the other 402 fields are `UNREVIEWED`. Every classification remains `UNKNOWN`.
The inventory resolves 93 locators across 77 fields from a sibling `url`, a
sibling `sources` list, or an exact top-level source match, and leaves 353
fields with an empty locator list rather than infer a source. The review also
found that the Aguara note contains a stale observatory claim.

Update 2026-09-01: three subsequent threat-intelligence records (CVE-2026-82233,
CVE-2026-53965) added three more `description:`/`mitigation:`/`notes:` fields,
bringing the generated inventory to 433 fields in the 2.28.0 authoring database.
The three new fields have not been through the locator-resolution or
classification pass described above; they remain `UNREVIEWED` and `UNKNOWN`
pending the same review this section requires for the rest of the database.
The 419/2.26.0, 430/2.27.0, 93-locator, 77-field, and 353-empty-locator figures
above describe the state at the time of that review and are left unchanged
rather than recomputed here.

Every prose field must be reviewed against its cited source and classified as
one of:

1. independently written factual summary;
2. short attributed quotation with a recorded justification;
3. third-party expression requiring permission or replacement;
4. information whose source or ownership is unresolved.

The review must record the source URL, reviewed field path, classification,
reviewer, review date, and required rewrite or attribution. Unresolved fields
must be rewritten independently from verified facts, covered by recorded
permission, or removed before the data is redistributed. Local Git attribution
does not prove independent authorship or redistribution rights.

## Code-license decision

The owner selected MIT on 2026-08-15 for project-owned source code and original
documentation. [`LICENSE`](../LICENSE) records:

- license: MIT;
- copyright holder: Florian Bruniaux;
- copyright year: 2026;
- excluded data scope: the paths recorded in
  [`LICENSE-DATA.md`](../LICENSE-DATA.md).

This decision resolves the code-license question. It does not grant rights over
imported data or third-party expression.

## Data-license candidate

CC BY-SA 4.0 is the current candidate for:

- `data/threat-db.yaml` after the prose and rights review;
- `data/intelligence/` authoring records owned or validly licensed by the
  project;
- generated runtime and documentation data to the extent those artifacts
  reproduce protected selection, arrangement, or expression from the authoring
  data.

Creative Commons states that its licenses are non-exclusive, so a rights holder
may offer the same material under another licensing arrangement. It also warns
licensors to secure all rights needed for included material and to identify
material not covered by the license.

Primary references:

- <https://creativecommons.org/faq/index.html>
- <https://creativecommons.org/licenses/by-sa/4.0/legalcode>

The exact choices still required from the owner are separated from this
evidence inventory in
[`LICENSE-OWNER-DECISION-PACKET.md`](LICENSE-OWNER-DECISION-PACKET.md).

## Distribution work required after the decisions

After the reviewed data scope is explicitly approved:

1. add the exact data license text and attribution notices;
2. add the final SPDX expression and package metadata without implying that one
   license covers both code and data;
3. add copyright and attribution notices;
4. include the required data license and notices in wheel and source artifacts;
5. document which paths and generated artifacts each license covers;
6. rerun the offline build and inspect wheel and sdist metadata and contents;
7. rerun the complete cross-platform CI matrix before creating a tag.

## Unresolved decisions

| Decision | Current evidence | Required owner action |
| --- | --- | --- |
| Code license | MIT selected on 2026-08-15 | Resolved |
| Code copyright notice | Florian Bruniaux, 2026 | Resolved |
| Data license | CC BY-SA 4.0 is the candidate | Approve after prose review |
| Third-party prose | 433 fields are inventoried (430 as of the 2.27.0 review plus 3 added 2026-09-01, see the update note above); 28 have `LOCAL_PROVENANCE_VERIFIED`, 405 are `UNREVIEWED`, and all classifications are `UNKNOWN` | Complete source comparison, independent rewrite, permission, or removal |
| Attribution packaging | Not implemented | Define notices and artifact inclusion |
| Package and gated-data release | Blocked | Open only after every item above is complete |

Until the remaining data decisions and reviews are recorded, package, tag,
archive, and gated-data publication remain blocked.

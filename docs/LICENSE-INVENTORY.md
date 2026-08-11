# AgentSec License Evidence Inventory

## Status and scope

This document is a factual decision aid, not a legal conclusion or a license
grant. It records evidence available in the local repositories on 2026-08-11.
Public distribution, tagging, release archives, and PyPI publication remain
blocked by [`LICENSE-DECISION.md`](../LICENSE-DECISION.md).

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

The 2026-08-11 source contains 28 `notes:` or `description:` fields. Each field
must be reviewed against its cited source and classified as one of:

1. independently written factual summary;
2. short attributed quotation with a recorded justification;
3. third-party expression requiring permission or replacement;
4. information whose source or ownership is unresolved.

The review must record the source URL, reviewed field path, classification,
reviewer, review date, and required rewrite or attribution. Unresolved fields
must be rewritten independently from verified facts or removed before the data
is redistributed.

## Code-license candidates

No code license has been selected.

### Apache-2.0

- explicit patent grant and patent-termination terms;
- requires preservation of the license and applicable notices;
- longer and more explicit than MIT.

### MIT

- short and widely understood permission notice;
- requires preservation of copyright and permission notices;
- does not contain Apache-2.0's explicit patent grant.

The owner must choose one candidate and record the copyright holder and year.
This inventory does not make that choice.

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

## Distribution work required after the decisions

After the code license and reviewed data scope are explicitly approved:

1. add the exact code and data license texts in separately named files;
2. add SPDX expressions and package metadata without implying that one license
   covers both code and data;
3. add copyright and attribution notices;
4. include the required data license and notices in wheel and source artifacts;
5. document which paths and generated artifacts each license covers;
6. rerun the offline build and inspect wheel and sdist metadata and contents;
7. rerun the complete cross-platform CI matrix before creating a tag.

## Unresolved decisions

| Decision | Current evidence | Required owner action |
| --- | --- | --- |
| Code license | MIT and Apache-2.0 are candidates | Select one explicitly |
| Code copyright notice | One project owner is recorded | Confirm holder name and year |
| Data license | CC BY-SA 4.0 is the candidate | Approve after prose review |
| Third-party prose | 28 fields require classification | Complete and record the review |
| Attribution packaging | Not implemented | Define notices and artifact inclusion |
| Public release | Blocked | Open only after every item above is complete |

Until these decisions and reviews are recorded, publication remains blocked.

# Data license review required before package release

## Status

**Package release is blocked.** Do not publish this package to PyPI, create a
package or source release artifact, or redistribute a source archive. Do not tag
`v0.1.0-alpha` while this decision is unresolved.

The source repository became publicly visible on 2026-08-30. That owner action
does not grant a separate license for the gated data paths and does not clear
the package, tag, archive, or GitHub release gate.

The generated integration feed has one narrow publication exception recorded in
`LICENSE-DATA.md`. That exception does not clear the package, tag, archive, or
GitHub release gate.

The project owner selected MIT for project-owned source code and original
documentation on 2026-08-15. The grant and its scope are recorded in
[`LICENSE`](LICENSE). This resolves the code-license choice. It does not
license the data paths listed in [`LICENSE-DATA.md`](LICENSE-DATA.md).

The verified evidence, candidate licenses, prose-review scope, and remaining
owner decisions are tracked in [`docs/LICENSE-INVENTORY.md`](docs/LICENSE-INVENTORY.md).
That inventory is a decision aid, not permission to publish.

`pyproject.toml` deliberately retains
`License decision pending before package release` for the distribution package.
The built package contains data whose review is incomplete, so declaring the
whole distribution MIT would be inaccurate. The placeholder is a release gate,
not permission to redistribute the package.

## Why the gate exists

The authoring threat database was imported byte for byte from the Codex Ultimate
Guide at version 2.26.0. The exact source, date, digest, and copy method are
recorded in [`data/IMPORT_PROVENANCE.md`](data/IMPORT_PROVENANCE.md).

The guide is distributed under CC BY-SA 4.0, but the ownership and compatibility
of its threat-data contribution history have not been reviewed for this separate
repository and package. The database contains factual indicators plus selection,
organization, descriptions, and source references. It is not safe to assume that
all of those elements have the same copyright or licensing treatment.

The MIT code license does not resolve the data license, attribution, contributor
rights, or share-alike questions.

## Required review and recorded decision

Before package, archive, GitHub release, or tag distribution:

1. Inventory the imported database's relevant contribution history and identify
   the owners of code, schema, data selection, descriptions, and later edits.
2. Confirm what the guide's CC BY-SA 4.0 notice covers. Record any additional
   terms attached to imported or contributed material.
3. Review attribution, notice, adaptation, database-right, and share-alike
   obligations for source and generated threat-data artifacts.
4. Obtain missing permissions or remove and independently recreate material
   that cannot be distributed under CC BY-SA 4.0.
5. Record the final data-license scope, copyright notices, attribution,
   adaptation notices, and provenance.
6. Add the data license to package metadata and use the final SPDX expression
   for the combined distribution.
7. Rerun the complete release gate, commit the data-license decision, and only
   then create an annotated `v0.1.0-alpha` tag or publish release artifacts.

Until these steps are completed, local review in the authorized working copy
does not establish a right to publish or redistribute it.

## Packaging metadata guard

`LICENSE-DECISION.md` is a blocking decision record, not a granted license. Its
filename must not produce a `License-File` field in wheel metadata. The project
therefore sets `license-files = []`, and the offline packaging test parses the
built wheel's `METADATA` and requires no `License-File` header.

When the data review is resolved, replace the placeholder package license,
select the final SPDX expression, include the MIT and data-license files, update
this guard, and rerun the complete release gate. Until then, absence of a
`License-File` header prevents a false package-wide grant; it does not
authorize publication.

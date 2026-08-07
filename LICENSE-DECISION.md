# License decision required before public release

## Status

**Public release is blocked.** Do not publish this package to PyPI, create a
public release artifact, or redistribute a source archive. Do not tag
`v0.1.0-alpha` while this decision is unresolved.

No `LICENSE` file is present and `pyproject.toml` deliberately says
`License decision pending before public release`. That text is a release gate,
not an open-source license and not permission to redistribute the project.

## Why the gate exists

The authoring threat database was imported byte for byte from the Codex Ultimate
Guide at version 2.26.0. The exact source, date, digest, and copy method are
recorded in [`data/IMPORT_PROVENANCE.md`](data/IMPORT_PROVENANCE.md).

The guide is distributed under CC BY-SA 4.0, but the ownership and compatibility
of its threat-data contribution history have not been reviewed for this separate
repository and package. The database contains factual indicators plus selection,
organization, descriptions, and source references. It is not safe to assume that
all of those elements have the same copyright or licensing treatment.

An OSS code license must not be guessed. A code license also does not, by itself,
resolve the data license, attribution, contributor rights, or share-alike
questions.

## Required review and recorded decision

Before public distribution or tagging:

1. Inventory the imported database's relevant contribution history and identify
   the owners of code, schema, data selection, descriptions, and later edits.
2. Confirm what the guide's CC BY-SA 4.0 notice covers and whether imported or
   contributed material has additional terms.
3. Review attribution, notice, adaptation, database-right, and share-alike
   obligations for source and generated threat-data artifacts.
4. Select compatible licenses for code and data separately. Obtain missing
   permissions or remove and independently recreate material that cannot be
   distributed compatibly.
5. Record the decision, scope, copyright notices, attribution, and provenance.
   Add the corresponding license files and SPDX expressions.
6. Rerun the complete Task 12 gate, commit the license decision, and only then
   consider an annotated `v0.1.0-alpha` tag and public package publication.

Until these steps are completed, local review in the authorized working copy
does not establish a right to publish or redistribute it.

## Packaging metadata guard

`LICENSE-DECISION.md` is a blocking decision record, not a granted license. Its
filename must not produce a `License-File` field in wheel metadata. The project
therefore sets `license-files = []`, and the offline packaging test parses the
built wheel's `METADATA` and requires no `License-File` header.

When the licensing review is resolved, replace the placeholder license text,
select explicit license files and SPDX expressions, update this guard, and rerun
the complete release gate. Until then, absence of a `License-File` header prevents
a false grant; it does not authorize publication.

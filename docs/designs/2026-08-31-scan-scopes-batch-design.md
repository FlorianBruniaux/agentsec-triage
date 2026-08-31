# Scan Scopes and Batch Triage Design

**Status:** Approved for implementation on 2026-08-31
**Owner:** AgentSec Triage
**Target:** Alpha CLI and scan-result schema v2

## Problem

The current scanner walks every regular file below one repository root. This
preserves broad hash coverage, but installed dependency trees, generated files,
large media, and symlink aliases make normal application repositories
incomplete. The first MSDS pilot inspected 256,364 files and 1.22 GB across
four repositories without a finding, but all four scans were incomplete.

Two diagnostics are misleading:

- a root `.git` marker makes the scan incomplete even though Git history is a
  declared unsupported capability;
- every skipped large regular file invalidates the detector even when the
  operator requested a source-focused triage.

The CLI also accepts only one root, so operators must build their own batch
wrapper and aggregate exit codes without a public contract.

## Goals

- Make the default scan useful for source-focused repository triage.
- Keep exclusions explicit and measurable.
- Preserve a strict full-repository scope for broad payload hash coverage.
- Keep installed dependency inspection available as an explicit scope.
- Stop treating declared out-of-scope Git history as an execution failure.
- Deduplicate safe internal symlink aliases without following them.
- Add deterministic, bounded batch scans for explicit repository roots.
- Publish machine-readable scan and batch contracts.

## Non-goals

- Reproduce `git ls-files` or claim that source scope means Git-tracked files.
- Invoke Git or interpret the Git index from an untrusted target.
- Follow a symlink, reparse point, external gitdir, or object alternate.
- Auto-discover repositories below a broad directory.
- Scan host state, remote repositories, remote CI, containers, or Git history.
- Claim that an excluded scope or a completed detector proves a repository is
  clean.

## CLI contract

### Single repository

```text
agentsec scan ROOT --scope {source,dependencies,repository}
```

`source` is the default.

| Scope | Selected inputs | Explicit exclusions |
| --- | --- | --- |
| `source` | project-authored text and configuration candidates, lockfiles, startup configuration, and regular files within the source boundary | installed dependency trees, generated/cache trees, known binary assets, VCS metadata |
| `dependencies` | supported lockfiles and files below installed `node_modules` trees | project source outside supported lockfiles and installed dependency trees, VCS metadata |
| `repository` | every regular file below the requested root except VCS metadata and nested repositories | VCS metadata only; applicable unreadable, unsafe, oversized, or budget-exceeding input remains blocking |

The words `tracked`, `committed`, and `gitignore` must not describe `source`.
The implementation does not invoke Git and does not honor ignore files.

### Batch

```text
agentsec batch ROOT [ROOT ...] --scope source --format {human,json}
agentsec batch --from-file PATH --scope source --format {human,json}
```

Positional roots and `--from-file` are mutually exclusive. A path file is
UTF-8, contains one path per non-empty line, and has a maximum of 10,000 lines
and 1 MiB. Duplicate roots are rejected after strict resolution. Batch does not
search below a supplied directory for repositories.

Batch exit codes aggregate child results:

- `0`: every child completed and no child reported a finding;
- `1`: every child completed and at least one child reported a finding;
- `2`: input validation failed or at least one child was incomplete.

All child scans share one loaded bundled database and the selected detector
set. Each child receives independent file, byte, entry, directory, and
diagnostic budgets. `--redact` applies before either human or JSON output.

## Scope classification

Scope classification is lexical and deterministic. It never reads target file
content and never trusts a repository-owned ignore file.

### Always excluded

- VCS metadata directories: `.git`, `.hg`, `.svn`.
- A nested directory containing its own `.git` marker. The nested repository
  produces a warning and must be scanned as a separate explicit root.

### Source dependency trees

Source scope prunes directories named:

```text
node_modules .pnpm-store .yarn/cache .venv venv __pypackages__
```

The reason ID is `installed_dependencies`.

### Source generated and cache trees

Source scope prunes directories named:

```text
.cache .next .nuxt .output .parcel-cache .pytest_cache .mypy_cache
.ruff_cache .tox .nox .turbo build coverage dist htmlcov out target
```

The reason ID is `generated_or_cache`.

### Source binary assets

Source scope excludes regular files with a case-insensitive extension in this
initial set:

```text
.7z .avi .bmp .bz2 .db .dmg .eot .flac .gif .gz .ico .jpeg .jpg .m4a
.mov .mp3 .mp4 .otf .pdf .png .sqlite .sqlite3 .tar .tgz .ttf .wav
.webm .webp .woff .woff2 .xz .zip
```

The reason ID is `binary_asset`. A supported lockfile or startup configuration
name wins over extension classification. Repository scope never applies this
extension exclusion.

### Dependency scope

Dependency scope selects supported lockfile names anywhere below the root and
all regular files below a directory named `node_modules`. It prunes other
directories unless they can contain a nested supported lockfile. The first
implementation may traverse the repository to locate lockfiles, but it must
not read unrelated files.

The excluded-source reason ID is `outside_dependency_scope`.

## Symlink policy

AgentSec never opens file content through a symlink or reparse point.

After normal discovery, a skipped link may be classified as a redundant
internal alias only when all of these conditions hold:

1. the link target resolves lexically inside the resolved scan root;
2. the target exists at classification time;
3. the target is represented by a non-link regular file or directory already
   covered through its canonical path;
4. no read is attempted through the alias.

Such an alias increments exclusion reason `internal_symlink_alias` and does not
make the scan incomplete. Broken links, external links, directory aliases whose
canonical subtree was not covered, and links that change or cannot be
classified safely remain blocking errors. Windows reparse points remain
blocking until equivalent alias evidence is available without following them.

## Large and unreadable files

Applicability depends on both scope and detector input type.

- A file excluded by the selected scope is outside that run and cannot make
  the run incomplete. The exclusion remains visible in coverage.
- A selected structured input such as a supported lockfile, installed package
  manifest, or startup configuration that exceeds its applicable parser or
  reader limit is blocking.
- A selected arbitrary regular file in `repository` scope remains applicable
  to exact payload hashing. If it exceeds `max_file_bytes`, the detector is
  incomplete.
- Read errors, identity changes, budget exhaustion, unsupported authoritative
  formats, and diagnostics truncation remain blocking for applicable input.

## Scan-result schema v2

Schema v2 replaces the flat aggregate coverage object with discovery coverage
and per-detector coverage. It prevents multiple detectors from multiplying the
same discovery count.

Required top-level fields:

```text
schema_version tool_version database_version root scope complete elapsed_ms
discovery detectors not_scanned diagnostics findings
```

`schema_version` is the constant string `2`.

`discovery` contains:

```json
{
  "entries_seen": 0,
  "directories_opened": 0,
  "files_selected": 0,
  "exclusions": [
    {"reason": "generated_or_cache", "paths": 1, "subtrees": 1}
  ]
}
```

Exclusion rows are sorted by reason and omit zero counts.

`detectors` contains one row per selected detector:

```json
{
  "detector_id": "shai-hulud-keyv",
  "applicability": "applicable",
  "files_seen": 12,
  "files_inspected": 12,
  "bytes_inspected": 4096,
  "not_scanned": ["git.history"]
}
```

Top-level diagnostics and findings remain flattened and deterministically
sorted. Existing severity, confidence, remediation URL, redaction, and exit-code
semantics remain unchanged.

The v1 schema and digest remain in the repository as historical contracts.
The package ships both v1 and v2 schemas, but new CLI output uses v2. `doctor`
validates the v2 artifact and digest.

## Batch-result schema v1

Batch JSON uses a separate `batch-result-v1` schema. Required top-level fields:

```text
schema_version tool_version database_version scope complete elapsed_ms
summary results
```

`summary` contains repository totals by child exit class, findings, selected
files, inspected files, inspected bytes, errors, and warnings. `results` embeds
complete scan-result v2 objects in input order. JSON size is bounded indirectly
by the root limit, per-scan diagnostic limit, and existing deterministic
finding output. The CLI does not write a report file on behalf of the user.

## Human output

Single-scan output adds:

```text
Scope: source
Discovery: files_selected=... entries_seen=... directories_opened=...
Exclusions:
  generated_or_cache: paths=... subtrees=...
```

Detector coverage is printed per detector. Batch human output uses one compact
row per root followed by aggregate totals. It does not duplicate every child
finding or diagnostic; operators use JSON for the full embedded reports.

## Architecture

- `agentsec.scopes` owns scope enums, lexical classification, reason IDs, and
  immutable exclusion counters.
- `agentsec.engine.discovery` owns confined traversal and returns a structured
  `DiscoveryResult` instead of an unlabelled tuple.
- `agentsec.engine.runner` receives a scope, builds one immutable `ScanContext`,
  and preserves detector isolation.
- `agentsec.batch` owns path-file parsing, root validation, child aggregation,
  and batch models. It calls `run_scan` directly and never shells out.
- `agentsec.output` owns versioned scan and batch rendering.
- Schemas and digests remain generated, packaged resources.

No third-party runtime dependency is added.

## Testing

Each behavior follows red-green-refactor.

Required witnesses:

- source, dependencies, and repository scope selection;
- lockfile precedence over binary classification;
- Git history remains `not_scanned` without an error;
- internal alias with canonical coverage, external link, broken link, changed
  link, and Windows reparse behavior;
- large binary asset excluded in source but blocking in repository scope;
- oversized structured input remains blocking in every applicable scope;
- batch root ordering, duplicate rejection, bounded path files, redaction,
  aggregate exit codes, JSON schemas, and human summary;
- multiple detectors do not multiply discovery counters;
- package contains v1, v2, batch schema, and matching digests;
- CLI and module entry points behave identically.

The final gate is the repository gate in `AGENTS.md`, plus replay of the two
earlier personal repositories and four MSDS pilot repositories using `source`
scope. A pilot result may contain findings, but it must not be called complete
unless every applicable selected input completed.

## Compatibility and release

This is an alpha breaking change. Human output and new JSON output change
together. The changelog must state that v1 consumers need to pin the earlier
CLI or migrate to v2. No package, tag, archive, GitHub release, or PyPI
publication is authorized by this work.

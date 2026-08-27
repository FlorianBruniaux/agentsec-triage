# Sigil image status

Status: **blocked before build**

The pinned revision `0f73627236d5` has `cli/Cargo.toml` but no tracked
`Cargo.lock`. Resolving dependencies during the build would make the result
depend on mutable registry state and would violate the first-cohort lockfile
contract.

Do not build or execute Sigil in this benchmark until one of these inputs is
approved:

- an upstream lockfile at a newly reviewed revision;
- an upstream release artifact with a verified checksum and matching source;
- a separately reviewed derived lockfile whose origin and digest are recorded.

This is a build-provenance limitation, not a scanner-quality result.

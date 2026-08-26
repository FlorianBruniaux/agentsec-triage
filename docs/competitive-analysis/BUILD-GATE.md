# Competitor image build gate

Status: **toolchain-aligned recipe ready for renewed build approval**

Recipe bundle digest:
`d5997fa44ea05afc9b4789222b9608c36b1dc5bea996912fe65337eb71988c4b`

This gate covers image construction only. It does not authorize a competitor
scan. Runtime plans receive separate approval after every local image ID is
known.

## Decision

Seven recipes are ready. Sigil is blocked because its pinned source has no
tracked `Cargo.lock`. Resolving its Rust graph today would create a result tied
to mutable registry state instead of the reviewed revision.

| Project | Full source commit | Build status | Runtime entry point |
| --- | --- | --- | --- |
| Aguara | `819eafb5fa6623f16ed26e4de344de6420fb5250` | ready | `aguara` |
| patient-zero | `331320c152aa296630d1c6bf02e03d3dbbda1471` | ready | `node /app/bin/cli.js` |
| AgentShield | `bdad15dd28da548a0586d6ca989cb5aa35a67ad6` | ready | `node /app/dist/index.js` |
| cc-audit | `bdb6574746246bf1c1dba722b2b50744d58e390d` | ready | `cc-audit` |
| NVIDIA SkillSpector | `698e2bf29c7d32aa8211ada677382460c01900d7` | ready | `skillspector` |
| Cisco Skill Scanner | `48f59347a54b93606dd1e31c41989ebfd0fcc84d` | ready | `skill-scanner` |
| Sigil | `0f73627236d5d9e152d3ab88b6eb71d74eb5538c` | blocked | none |
| agent-bom | `9ceeb22fff1f156ce9c2ce8b122ba31743fc47c7` | ready | `agent-bom` |

All eight clones were clean and at the listed commit when this gate was
prepared on 2026-08-26.

## First build attempt

The build authorized with the previous bundle digest stopped at the first
failure, as required. No competitor CLI or fixture scan ran.

| Project | Result | Local image ID or evidence |
| --- | --- | --- |
| Aguara | built | `sha256:38c057adf78bec20c8e9b084501d8fd686e22dea46705b11c178d90827b0469c` |
| patient-zero | built | `sha256:f62c6fa1523e3fc5cd95440f7d7923d872a3c01e0f1560249a04cff0e85c2080` |
| AgentShield | built with dependency warnings | `sha256:010bc7821650cd613e835804ceec627498cc0eb395e7f214dd490fbd88a59278` |
| cc-audit | failed before source compilation | `cargo fetch --locked` could not find the declared `scan_benchmark` target |
| NVIDIA SkillSpector | not attempted | stopped after the `cc-audit` failure |
| Cisco Skill Scanner | not attempted | stopped after the `cc-audit` failure |
| agent-bom | not attempted | stopped after the `cc-audit` failure |

AgentShield's locked dependency install reported deprecated
`node-domexception@1.0.0` and `glob@11.1.0` packages. The benchmark recipe does
not alter competitor dependencies, so these warnings remain build evidence.

The first correction made the `cc-audit` dependency stage copy its tracked
`benches/scan_benchmark.rs` target before `cargo fetch --locked`. A regression
test enforces the ordering.

The second attempt passed dependency resolution, then stopped before source
compilation because the source's tracked `rust-toolchain.toml` requires Rust
`1.93.0` while the recipe used Rust 1.90. Rustup could not install the missing
toolchain in the network-disabled source-build step. No image was produced and
the three later builds were not attempted.

The recipe now uses the immutable official Rust 1.93 image that matches the
tracked toolchain. A second regression test locks that alignment. This renewed
gate authorizes only the `cc-audit` retry and the three builds not yet
attempted. The three existing image IDs are retained and must be inspected
again before runtime-plan generation.

## Build boundary

Each ready recipe has these properties:

- every base image uses an immutable multi-platform SHA-256 digest;
- dependency manifests and lockfiles enter the image before project source;
- dependency retrieval may use the network;
- npm lifecycle scripts are disabled;
- the source-present Go, Rust, and Python build step declares
  `RUN --network=none`;
- the build context comes from `git archive <full-commit>`, not the working
  tree, `.git`, ignored files, or untracked files;
- no build secret, SSH agent, host home, Docker socket mount, or real
  repository enters the build context;
- the image is loaded locally and identified by its immutable
  `sha256:<64-hex>` image ID. It is not pushed to a registry.

The Node recipes do not compile project source. patient-zero runs its tracked
JavaScript files. AgentShield runs the tracked `dist/index.js`. Both install
locked production dependencies with `npm ci --ignore-scripts`.

## Resolved base inputs

The Docker Registry API resolved the Node, Rust, Debian, and uv image indexes
on 2026-08-26. Aguara, SkillSpector, and agent-bom also supplied pinned base
digests in their reviewed Dockerfiles.

| Input | Immutable index digest |
| --- | --- |
| `node:22-bookworm-slim` | `sha256:83f487e0a63425e5b4d146fb5e5be574bcbe1b7b843d3ebafdd95eaf7767a7e5` |
| `rust:1.93-bookworm` | `sha256:7c4ae649a84014c467d79319bbf17ce2632ae8b8be123ac2fb2ea5be46823f31` |
| `debian:bookworm-slim` | `sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171` |
| `python:3.12-slim-bookworm` | `sha256:8a7e7cc04fd3e2bd787f7f24e22d5d119aa590d429b50c95dfe12b3abe52f48b` |
| `ghcr.io/astral-sh/uv:0.10.9` | `sha256:10902f58a1606787602f303954cea099626a4adb02acbac4c69920fe9d278f82` |
| `golang:1.25-alpine` | `sha256:5caaf1cca9dc351e13deafbc3879fd4754801acba8653fa9540cea125d01a71f` |
| `alpine:3.24` | `sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b` |

The recipes pin `hatchling`, `hatch-vcs`, `setuptools`, and `wheel` before the
network-disabled local project install. Project runtime resolution still comes
from each committed lockfile.

## Exact build procedure

Run the validator first:

```bash
.venv/bin/python scripts/check_competitive_images.py
```

For one approved recipe, create an empty temporary context, archive the exact
commit, build for the declared platform, and record the local image ID:

```bash
BUILD_DIR="$(mktemp -d /private/tmp/agentsec-competitive-build.XXXXXX)"
mkdir -p "$BUILD_DIR/context"
git -C <pinned-clone> archive --format=tar --output="$BUILD_DIR/source.tar" <full-commit>
tar -xf "$BUILD_DIR/source.tar" -C "$BUILD_DIR/context"
docker buildx build \
  --platform linux/arm64 \
  --pull \
  --load \
  --progress=plain \
  --file <absolute-recipe-Dockerfile> \
  --tag <manifest-tag> \
  --iidfile "$BUILD_DIR/image.id" \
  "$BUILD_DIR/context"
docker image inspect --format '{{.Id}}' <manifest-tag>
```

The placeholders must be replaced with the exact values in
`research/competitive-images/manifest.yaml`. The build stops on the first
nonzero command. Temporary contexts are retained until image IDs and logs are
reviewed, then removed by explicit path.

## Network and execution effects

An approved build may contact the pinned base registries and the package
registries referenced by each committed lockfile. Build backends and compiler
steps execute inside BuildKit containers. The reviewed source is present only
during network-disabled project build steps, except for Node projects where no
project build step runs.

No competitor CLI or fixture scan runs in this gate. After the seven builds,
the next review records:

- the seven local image IDs;
- build success or failure and Dockerfile digest;
- the exact fixture plan and command array per image;
- the runtime approval digest generated by
  `scripts/run_competitive_benchmark.py validate`.

Only that second approval can start `docker run` against a fixture.

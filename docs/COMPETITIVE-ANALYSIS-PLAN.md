# Competitive Analysis Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> `superpowers:subagent-driven-development` or `superpowers:executing-plans`
> to execute this plan task by task. Steps use checkbox syntax for tracking.

**Goal:** Determine which capabilities the renamed project must match, which
product contract it can own, and which work should be excluded from the next
three public milestones.

**Architecture:** Use a three-level funnel. Review 16 pinned repositories
statically, execute at most eight tools in a controlled benchmark, then perform
three deep teardowns. Keep declared claims, code evidence, and observed runtime
behavior separate. Do not change production scanner behavior until the product
decision gate is approved.

**Tech stack:** Markdown, YAML, Python 3.11 for validation and benchmark
orchestration, JSON Lines for raw observations, Docker or a disposable virtual
machine for third-party execution, and the existing pytest toolchain for any
new local validator.

**Spec:** `docs/ECOSYSTEM.md`

## Execution status on 2026-08-26

- Tasks 1 through 10 are complete: isolated worktree, methodology, 16 static
  profiles, comparison matrix, approved cohort, 12 inert fixtures, and the
  host-side benchmark runner.
- Task 11 is at its renewed safety gate. Aguara, patient-zero, and AgentShield
  images are built. The first attempt stopped when `cc-audit` omitted a
  manifest-declared benchmark target from its dependency stage. A second retry
  exposed a Rust 1.90 versus tracked Rust 1.93 toolchain mismatch before source
  compilation. A third attempt proved the minor-version image did not provide a
  toolchain installed under the exact tracked `1.93.0` name. The exact-patch
  image then exposed missing declared components from its minimal rustup
  profile. The dependency stage now resolves the tracked toolchain components
  before source copy. All three recipe defects have regression tests; its retry
  and three pending builds await a new digest approval. Sigil remains blocked
  because the pinned revision has no tracked `Cargo.lock`.
- No competitor CLI has scanned a fixture.
- Runtime observations, deep teardowns, product decisions, naming, roadmap
  changes, and main-branch integration remain pending.

## Global constraints

- Treat every cloned competitor repository as untrusted.
- Do not run an installer, hook, package script, MCP server, or binary on the
  host workstation.
- Use synthetic inert fixtures. Do not copy malware, leaked credentials, or
  victim data.
- Do not copy competitor source, rules, fixtures, prose, or databases into the
  product. Record ideas, then build any resulting feature independently.
- Pin every observation to a Git revision and record the command and date.
- Record a capability as `declared`, `code_verified`, `observed`,
  `contradicted`, `not_applicable`, or `not_tested`.
- Do not convert a missing finding into proof that a tool cannot detect a
  technique until the documented configuration and supported input are
  verified.
- Do not rank incomparable tools with a single synthetic score.
- Keep AgentSec's current user-owned worktree changes out of analysis commits.
- Use a clean worktree for plan execution if the main checkout remains dirty.
- Update `CHANGELOG.md` for each tracked research or product-decision artifact.
- No public naming, release, or package decision bypasses the unresolved data
  licensing gate.

---

## Strategy and decision funnel

Three approaches were considered:

| Approach | Benefit | Failure mode | Decision |
| --- | --- | --- | --- |
| README comparison only | Fast and safe | Repeats marketing claims and misses behavior | Reject |
| Execute all identified tools | Broad runtime data | Unsafe, slow, and dominated by immature projects | Reject |
| 16 static reviews, 8 controlled runs, 3 deep teardowns | Balances breadth, proof, and time | Requires a strict methodology | **Use this approach** |

The work stops at four explicit gates:

1. **Static gate:** select no more than eight tools for controlled execution.
2. **Safety gate:** approve each exact command, container policy, and network
   requirement before it runs.
3. **Product gate:** choose parity work and differentiation bets from observed
   evidence.
4. **Naming gate:** select a new name only after the product promise is fixed.

## File map

| Path | Responsibility |
| --- | --- |
| `docs/competitive-analysis/METHODOLOGY.md` | Scope, evidence levels, safety model, comparison fields, and selection gates |
| `data/competitive-projects.yaml` | Pinned project metadata and analysis status |
| `data/competitive-projects.schema.json` | Validation contract for the project index |
| `scripts/check_competitive_projects.py` | Dependency-free schema and cross-file checks |
| `tests/unit/test_competitive_projects.py` | Validator regression tests |
| `docs/competitive-analysis/profiles/*.md` | One evidence-backed static profile per project |
| `docs/competitive-analysis/STATIC-MATRIX.md` | Cross-project static findings derived from profiles |
| `research/competitive-fixtures/` | Inert synthetic inputs used only for comparative research |
| `research/competitive-runs/README.md` | Raw-run format and privacy boundary; raw local results remain ignored |
| `research/competitive-runs/.gitignore` | Prevents third-party output and machine paths from entering Git |
| `docs/competitive-analysis/BENCHMARK-DESIGN.md` | Fixture truth table, commands, isolation policy, and metrics |
| `docs/competitive-analysis/BUILD-GATE.md` | Pinned image recipes, build boundary, blockers, and approval digest |
| `research/competitive-images/manifest.yaml` | Exact build status, runtime commands, and fixture subsets for the selected cohort |
| `scripts/check_competitive_images.py` | Recipe, base-image pin, and source-build network validator |
| `docs/competitive-analysis/BENCHMARK-RESULTS.md` | Redacted observations and reproducible result summary |
| `docs/competitive-analysis/PRODUCT-DECISIONS.md` | Parity features, differentiation bets, rejected work, and evidence |
| `docs/NAMING.md` | Naming brief, candidates, collision checks, and decision record |
| `ROADMAP.md` | Evidence-backed milestones after the product gate |
| `README.md` | Links to final public research documents only |
| `CHANGELOG.md` | Research and product-decision history |

Raw competitor clones remain outside the repository at
`/Users/florianbruniaux/Sites/divers-test/agent-security-ecosystem`.

## Evaluation model

### Evidence dimensions

Every profile must answer the same questions:

1. What user job does the project claim to solve?
2. Which files, ecosystems, agent clients, and host surfaces does it inspect?
3. Does it execute target content, invoke package managers, contact a service,
   write into the target, or inspect outside the requested root?
4. How are rules, IOCs, sources, updates, corrections, and confidence modeled?
5. What outputs, exit codes, schemas, remediation, coverage states, and CI
   integrations exist?
6. Which claims are backed by code, tests, fixtures, releases, signatures, or
   published benchmarks?
7. What would AgentSec need to match, deliberately reject, or outperform?

### Result vocabulary

| Status | Meaning |
| --- | --- |
| `pass` | Observed behavior satisfies the declared criterion |
| `partial` | Some supported inputs or paths satisfy it |
| `fail` | Observed behavior contradicts the criterion |
| `not_applicable` | Criterion is outside the project's declared job |
| `not_tested` | No safe or reproducible observation was made |

Do not use a single total score. Publish matrices by job and safety property.

### Product comparison axes

- **Pre-trust repository scan:** useful before opening or installing a clone.
- **Campaign response:** useful immediately after a security disclosure.
- **Pull-request gate:** useful without hiding incomplete coverage.
- **Incident explanation:** connects evidence to sources and next actions.
- **Safety:** confines reads and avoids target execution and hidden network use.
- **Coverage honesty:** distinguishes no finding from incomplete or unsupported.
- **Intelligence lifecycle:** supports source attribution, conflicts,
  corrections, and versioned updates.
- **Distribution:** installs reproducibly and integrates with common CI.
- **Maintainability:** exposes stable rules, tests, schemas, and contribution
  paths.

---

### Task 1: Isolate the research work

**Files:**

- Inspect: repository worktree status
- Create at execution time: isolated worktree and `codex/competitive-analysis`

**Produces:** A clean branch where analysis files cannot stage or overwrite the
existing CLI color-output work.

- [ ] **Step 1: Inspect the current state**

  Run `rtk git status --short --branch` from the AgentSec repository.

- [ ] **Step 2: Confirm the dirty paths are user-owned**

  Require the existing `CHANGELOG.md`, `src/agentsec/cli.py`,
  `src/agentsec/output/human.py`, `tests/integration/test_cli.py`, and
  `tests/unit/test_human_output.py` changes to remain untouched.

- [ ] **Step 3: Create an isolated worktree**

  Use the `superpowers:using-git-worktrees` skill. Base the worktree on the
  current committed `main`, not on the dirty checkout.

- [ ] **Step 4: Verify isolation**

  Run `rtk git status --short --branch` in both checkouts. The research
  worktree must be clean and the original checkout must retain its changes.

### Task 2: Define the methodology and machine-readable index

**Files:**

- Create: `docs/competitive-analysis/METHODOLOGY.md`
- Create: `data/competitive-projects.yaml`
- Create: `data/competitive-projects.schema.json`
- Create: `scripts/check_competitive_projects.py`
- Test: `tests/unit/test_competitive_projects.py`
- Modify: `CHANGELOG.md`

**Produces:** A validated index with project ID, name, URL, local path,
revision, category, evidence state, execution tier, license, and profile path.

- [ ] **Step 1: Write validator tests for required project fields**

  Cover missing revision, duplicate project ID, invalid URL, missing local
  directory, unknown evidence status, unknown execution tier, and profile path
  escape.

- [ ] **Step 2: Run the targeted test and observe failure**

  Run `.venv/bin/pytest tests/unit/test_competitive_projects.py -q`.

- [ ] **Step 3: Add the schema and minimal validator**

  Accept execution tiers `static_only`, `offline_sandbox`,
  `networked_sandbox`, and `manual_review`. Reject unknown fields.

- [ ] **Step 4: Seed all 16 pinned projects**

  Copy the exact revisions recorded in `docs/ECOSYSTEM.md`. Do not resolve a
  moving branch name during validation.

- [ ] **Step 5: Write the methodology**

  Include the global constraints, evidence vocabulary, comparison axes,
  selection gates, and citation format `path:line@revision`.

- [ ] **Step 6: Run validator and Markdown checks**

  Run `.venv/bin/python scripts/check_competitive_projects.py --clone-root
  /Users/florianbruniaux/Sites/divers-test/agent-security-ecosystem`,
  `.venv/bin/pytest tests/unit/test_competitive_projects.py -q`, and
  `.venv/bin/python scripts/check_markdown_style.py .`.

- [ ] **Step 7: Commit the methodology unit**

  Commit explicit paths with
  `docs(research): define competitor evaluation protocol`.

### Task 3: Create the static profile template

**Files:**

- Create: `docs/competitive-analysis/profiles/TEMPLATE.md`
- Modify: `scripts/check_competitive_projects.py`
- Test: `tests/unit/test_competitive_projects.py`

**Produces:** One mandatory structure for every static audit.

- [ ] **Step 1: Add a failing test for missing profile sections**

  Require project identity, declared promise, observed architecture, surfaces,
  safety boundary, intelligence, outputs, distribution, tests, license,
  contradictions, parity lessons, differentiation lessons, and evidence.

- [ ] **Step 2: Run the targeted test and observe failure**

  Run `.venv/bin/pytest tests/unit/test_competitive_projects.py -q`.

- [ ] **Step 3: Add the profile template and section validator**

  Require every factual row to include `declared`, `code_verified`,
  `observed`, `contradicted`, `not_applicable`, or `not_tested`.

- [ ] **Step 4: Run tests and Markdown validation**

  Run the targeted pytest file and the Markdown checker.

- [ ] **Step 5: Commit the template unit**

  Commit with `docs(research): standardize competitor profiles`.

### Task 4: Audit the four closest campaign and repository tools

**Files:**

- Create profiles for `aguara`, `patient-zero`, `repo-forensics`, and
  `cc-audit`
- Modify: `data/competitive-projects.yaml`

**Produces:** Static evidence for the closest product and safety competitors.

- [ ] **Step 1: Inspect only tracked files at each pinned revision**

  Read README, license, security policy, package metadata, entrypoints,
  detector/rule directories, output model, updater, CI workflows, tests, and
  representative fixtures.

- [ ] **Step 2: Trace three high-value claims per project into code**

  Prioritize campaign coverage, repository confinement, intelligence updates,
  incomplete-scan behavior, SARIF, and CI.

- [ ] **Step 3: Record contradictions and unknowns**

  Do not infer that an undocumented behavior is absent. Mark it `not_tested`
  until code evidence or a controlled run exists.

- [ ] **Step 4: Validate all four profiles**

  Run the competitive-project validator and Markdown checker.

- [ ] **Step 5: Commit the batch**

  Commit with `docs(research): audit campaign triage competitors`.

### Task 5: Audit the four agent configuration and host tools

**Files:**

- Create profiles for `agentshield`, `snyk-agent-scan`, `agentseal`, and
  `agentsec-debu-sinha`
- Modify: `data/competitive-projects.yaml`

**Produces:** Static evidence for agent discovery, configuration, execution,
host scope, and the naming collision.

- [ ] **Step 1: Inspect the same canonical files as Task 4**

- [ ] **Step 2: Trace MCP execution and network behavior**

  Record whether configured servers are started, which data leaves the host,
  whether consent exists, and which mode is safe for an untrusted repository.

- [ ] **Step 3: Trace distribution and enterprise integration claims**

  Verify binary signing, package installation, GitHub Action, background mode,
  and output stability from official files.

- [ ] **Step 4: Validate and commit**

  Run the documentation gates and commit with
  `docs(research): audit agent configuration competitors`.

### Task 6: Audit the four broad and reasoning-driven tools

**Files:**

- Create profiles for `medusa`, `trust-issues`, `sigil`, and
  `agent-security-scanner-mcp`
- Modify: `data/competitive-projects.yaml`

**Produces:** Static evidence for broad feature claims, LLM reasoning,
quarantine workflows, and large rule catalogues.

- [ ] **Step 1: Inspect architecture, rules, prompts, tests, and output paths**

- [ ] **Step 2: Separate deterministic findings from model-generated findings**

- [ ] **Step 3: Verify whether advertised features exist in released code**

  Mark unpublished, stubbed, example-only, or externally hosted surfaces
  explicitly.

- [ ] **Step 4: Validate and commit**

  Commit with `docs(research): audit broad agent security competitors`.

### Task 7: Audit the final four ecosystem and governance tools

**Files:**

- Create profiles for `skillspector`, `cisco-skill-scanner`, `inkog`, and
  `agent-bom`
- Modify: `data/competitive-projects.yaml`

**Produces:** Static evidence for skill analysis, governance, SBOM, and
control-plane approaches.

- [ ] **Step 1: Inspect supported formats and analysis engines**

- [ ] **Step 2: Trace optional online, model, OSV, and enterprise components**

- [ ] **Step 3: Record techniques worth integrating and platform work to defer**

- [ ] **Step 4: Validate and commit**

  Commit with `docs(research): audit skill and governance competitors`.

### Task 8: Build the static comparison matrix and select eight tools

**Files:**

- Create: `docs/competitive-analysis/STATIC-MATRIX.md`
- Modify: `data/competitive-projects.yaml`
- Modify: `CHANGELOG.md`

**Produces:** A matrix of code-verified capabilities and a justified execution
shortlist of at most eight projects.

- [ ] **Step 1: Build matrices by product job**

  Create separate tables for pre-trust, campaign response, CI, incident
  explanation, safety, coverage honesty, intelligence, distribution, and
  maintainability.

- [ ] **Step 2: List contradictions independently**

  Do not bury README-to-code contradictions inside a total score.

- [ ] **Step 3: Select execution candidates**

  Require meaningful overlap, runnable pinned code, a safe isolation path, and
  a question that static inspection cannot answer.

- [ ] **Step 4: Assign execution tiers**

  Use `offline_sandbox` for tools that can run without network or credentials,
  `networked_sandbox` for tools requiring APIs or updates, and `manual_review`
  for tools that execute MCP servers or cannot be safely automated.

- [ ] **Step 5: Review the static gate**

  Obtain explicit owner approval for the shortlist and exclusion reasons before
  running third-party code.

- [ ] **Step 6: Validate and commit**

  Commit with `docs(research): select controlled benchmark cohort`.

### Task 9: Define the inert fixture corpus

**Files:**

- Create: `research/competitive-fixtures/manifest.yaml`
- Create: `research/competitive-fixtures/clean-control/`
- Create: `research/competitive-fixtures/shai-hulud-confirmed/`
- Create: `research/competitive-fixtures/keyv-contested/`
- Create: `research/competitive-fixtures/lifecycle-near-miss/`
- Create: `research/competitive-fixtures/renamed-payload-hash/`
- Create: `research/competitive-fixtures/claude-hook-review/`
- Create: `research/competitive-fixtures/vscode-startup-review/`
- Create: `research/competitive-fixtures/skill-delayed-instruction/`
- Create: `research/competitive-fixtures/mcp-inline-fetch-exec/`
- Create: `research/competitive-fixtures/ci-untrusted-trigger/`
- Create: `research/competitive-fixtures/unsupported-binary-lock/`
- Create: `research/competitive-fixtures/confinement-symlink/`
- Test: `tests/unit/test_competitive_fixtures.py`

**Produces:** Twelve inert, source-attributed fixture classes with expected
surface, expected evidence, applicable tools, and near-miss controls.

- [ ] **Step 1: Write manifest validation tests**

  Require fixture ID, technique, expected evidence, source URL, applicable tool
  classes, absence of secrets, and `inert: true`.

- [ ] **Step 2: Observe validator failure**

  Run `.venv/bin/pytest tests/unit/test_competitive_fixtures.py -q`.

- [ ] **Step 3: Add inert fixtures one class at a time**

  Use non-routable domains, dummy commands stored as text, synthetic hashes,
  and fake package identities where exact real IOCs are not required to test
  the parser contract.

- [ ] **Step 4: Add near-miss controls**

  Each positive heuristic fixture needs a structurally close benign control.

- [ ] **Step 5: Prove no fixture is executable by the test suite**

  Reject executable permission bits, archive files, binaries other than the
  intentionally inert unsupported-lock placeholder, and recognized
  secret-shaped strings.

- [ ] **Step 6: Validate and commit**

  Commit with `test(research): add inert competitor benchmark corpus`.

### Task 10: Design the controlled benchmark

**Files:**

- Create: `docs/competitive-analysis/BENCHMARK-DESIGN.md`
- Create: `research/competitive-runs/README.md`
- Create: `research/competitive-runs/.gitignore`
- Create: `scripts/run_competitive_benchmark.py`
- Test: `tests/unit/test_competitive_benchmark.py`

**Produces:** A host-side runner that records observations without allowing a
third-party tool to write results into the product repository.

- [ ] **Step 1: Write tests for command allowlisting and output redaction**

  Reject shell strings, unresolved revisions, host home mounts, writable
  fixture mounts, missing timeouts, unapproved network, and output containing
  absolute user paths or secret-shaped values.

- [ ] **Step 2: Observe test failure**

  Run `.venv/bin/pytest tests/unit/test_competitive_benchmark.py -q`.

- [ ] **Step 3: Implement the host-side result envelope**

  Record project ID, revision, fixture ID, exact argument vector, image digest,
  network policy, exit code, timeout, duration, maximum RSS when available,
  stdout digest, stderr digest, normalized findings, files written, and network
  attempts.

- [ ] **Step 4: Enforce sandbox defaults**

  Use a disposable container or virtual machine, non-root user, empty home,
  read-only fixture mount, read-only competitor source mount, writable scratch
  mount, dropped capabilities, process and memory limits, and network disabled.

- [ ] **Step 5: Keep raw results local**

  Store raw JSON Lines below `research/competitive-runs/local/`, ignored by
  Git. Only redacted aggregate observations may enter documentation.

- [ ] **Step 6: Validate the runner without a competitor tool**

  Use a local inert echo fixture to prove argument handling, timeout, write
  inventory, network policy, and redaction.

- [ ] **Step 7: Commit the benchmark infrastructure**

  Commit with `test(research): add isolated competitor benchmark runner`.

### Task 11: Run the controlled benchmark

**Files:**

- Local only: `research/competitive-runs/local/*.jsonl`
- Modify: `docs/competitive-analysis/BENCHMARK-RESULTS.md`
- Modify: `data/competitive-projects.yaml`

**Produces:** Repeated observations for supported fixtures and explicit
`not_applicable` or `not_tested` cells for the rest.

- [ ] **Step 1: Review every exact command before execution**

  Confirm the pinned revision, documented mode, sandbox image digest or local
  image ID, fixture subset, network policy, and timeout. A tool that cannot
  meet the build-provenance contract is recorded as blocked and is not run.

- [ ] **Step 2: Run clean and near-miss controls first**

  Stop a tool's batch if it writes outside scratch, attempts undeclared network,
  executes fixture content, or cannot be confined.

- [ ] **Step 3: Run applicable positive fixtures**

  Do not penalize a tool for a surface it explicitly excludes.

- [ ] **Step 4: Repeat deterministic tools three times**

  Compare exit code, normalized finding IDs, paths, severities, and output
  digests. Record nondeterminism rather than averaging it away.

- [ ] **Step 5: Capture operational behavior**

  Record installation friction, first useful command, diagnostics, incomplete
  behavior, remediation, format validity, and cleanup.

- [ ] **Step 6: Publish redacted results**

  Include commands, revisions, fixture truth, observations, limitations, and
  contradictions. Do not publish raw third-party output containing paths or
  copied rule text.

- [ ] **Step 7: Validate and commit**

  Commit with `docs(research): publish controlled competitor observations`.

### Task 12: Deep teardown of the top three competitors

**Files:**

- Modify the selected three profiles
- Modify: `docs/competitive-analysis/BENCHMARK-RESULTS.md`

**Produces:** Architecture and product lessons from the three tools with the
highest combination of overlap, maturity, and observed effectiveness.

- [ ] **Step 1: Select three projects from evidence**

  The expected candidates are Aguara, patient-zero, and Repo Forensics, but the
  benchmark result controls the choice.

- [ ] **Step 2: Trace one finding end to end per project**

  Follow source or rule input, parser, analyzer, confidence, output model,
  remediation, test, release artifact, and update path.

- [ ] **Step 3: Trace one incomplete or unsupported input**

  Observe the tool's behavior: fail closed, emit a warning, skip silently, or
  return a success status.

- [ ] **Step 4: Inspect contribution economics**

  Measure how many files, schemas, fixtures, tests, and docs a new campaign or
  rule requires. Record maintainability, not just runtime detection.

- [ ] **Step 5: Commit the teardown evidence**

  Commit with `docs(research): trace competitor detection pipelines`.

### Task 13: Make product decisions

**Files:**

- Create: `docs/competitive-analysis/PRODUCT-DECISIONS.md`
- Modify: `docs/ECOSYSTEM.md`
- Modify: `CHANGELOG.md`

**Produces:** A bounded product thesis based on observed trade-offs.

- [ ] **Step 1: Identify parity requirements**

  Select no more than five capabilities users reasonably expect. Current
  candidates are reproducible installation, SARIF, GitHub Action, more than one
  campaign detector, and a clear explain or coverage command.

- [ ] **Step 2: Identify differentiation bets**

  Select no more than three. Preferred candidates are campaign-to-detector
  traceability, fail-closed coverage semantics, and campaign-specific response
  playbooks.

- [ ] **Step 3: Record explicit rejections**

  Keep generic SAST, generic SCA, EDR, broad host scanning, live MCP execution,
  auto-remediation, and multi-tenant governance outside the next three
  milestones unless evidence overturns the decision.

- [ ] **Step 4: Define measurable proof for each bet**

  Each decision needs a user job, required input, expected output, test witness,
  safety boundary, completion gate, and competitor evidence.

- [ ] **Step 5: Review the product gate**

  Obtain owner approval before changing the scanner or starting naming work.

- [ ] **Step 6: Validate and commit**

  Commit with `docs(product): select evidence-backed product wedge`.

### Task 14: Select the new name

**Files:**

- Create: `docs/NAMING.md`
- Modify after decision: package, import, CLI, schemas, feed, guide, landing,
  repository metadata, README, and documentation paths in a separate rename
  implementation plan

**Produces:** One selected name and two fallbacks. This task records the
decision but does not perform the rename.

- [ ] **Step 1: Write the naming brief from the approved product thesis**

  Require repository focus, campaign evidence, neutral international
  pronunciation, a short CLI command, and room for multiple ecosystems.

- [ ] **Step 2: Generate candidates in three semantic families**

  Use repository plus trace, campaign plus evidence, and pre-trust plus signal.
  Eliminate names that imply antivirus, certification, continuous monitoring,
  generic SAST, or a single campaign.

- [ ] **Step 3: Run collision checks**

  Check GitHub, PyPI, npm, crates.io, Homebrew formulae, common search engines,
  relevant domains, and obvious trademark databases. Record date and URL for
  each check.

- [ ] **Step 4: Test comprehension**

  Ask at least five developers or AppSec practitioners what the top candidates
  do based only on name and one-line descriptor. Record misunderstandings.

- [ ] **Step 5: Select one name and two fallbacks**

  Prefer comprehension and collision safety over cleverness.

- [ ] **Step 6: Review the naming gate and commit**

  Commit with `docs(brand): select public project name`.

### Task 15: Rebase the roadmap on evidence

**Files:**

- Modify: `ROADMAP.md`
- Modify: `README.md`
- Modify: `CHANGELOG.md`
- Create: separate rename implementation plan

**Produces:** Three milestones with acceptance criteria and no unsupported
marketing claim.

- [ ] **Step 1: Define Milestone 0, identity and release safety**

  Include rename, data-license resolution, signed source artifacts, clean
  cross-platform CI, reproducible installation, and public repository readiness.

- [ ] **Step 2: Define Milestone 1, credible campaign triage**

  Include three to five campaign detectors, campaign playbooks, explain or
  coverage output, and public positive, near-miss, and negative witnesses.

- [ ] **Step 3: Define Milestone 2, developer workflow integration**

  Include SARIF, pinned GitHub Action, documented CI policy, and fail-closed
  incomplete behavior.

- [ ] **Step 4: Define Milestone 3, durable intelligence**

  Include signed updates, rollback protection, correction propagation,
  contribution workflow, and measured update cadence.

- [ ] **Step 5: Remove or defer unsupported breadth**

  Do not keep broad ecosystem and host-scanning items solely because a
  competitor advertises them.

- [ ] **Step 6: Validate consistency**

  Check that README describes only shipped behavior, ROADMAP describes future
  behavior, and CHANGELOG describes completed documentation decisions.

- [ ] **Step 7: Run the documentation gate and commit**

  Commit with `docs(roadmap): prioritize campaign evidence and distribution`.

## Suggested calendar

| Working days | Outcome |
| --- | --- |
| 1 to 2 | Isolation, methodology, schema, validator, and template |
| 3 to 6 | Sixteen static profiles in four comparable batches |
| 7 | Static matrix and eight-tool selection gate |
| 8 to 9 | Inert fixture corpus and benchmark runner |
| 10 to 11 | Controlled benchmark and repeated observations |
| 12 | Three deep teardowns |
| 13 | Product decision gate |
| 14 | Naming research and comprehension tests |
| 15 | Roadmap rewrite and rename implementation plan |

The schedule assumes one focused owner. Do not compress the safety or product
gates to meet the calendar.

## Acceptance criteria

The competitive-analysis program is complete only when:

- all 16 profiles cite pinned code or official documentation;
- every matrix cell distinguishes declared, code-verified, and observed state;
- no more than eight tools are run and every run has an approved isolation
  record;
- the fixture corpus contains clean, positive, and near-miss witnesses without
  executable malware or credentials;
- deterministic tools have three-run consistency evidence;
- safety violations, hidden network, target writes, and incomplete behavior are
  reported independently from detection results;
- five or fewer parity requirements and three or fewer differentiation bets are
  selected;
- the product decision names at least five explicit non-goals;
- one public name and two fallbacks pass recorded collision checks;
- `ROADMAP.md` contains testable milestone gates;
- `README.md` still describes only implemented behavior;
- the Markdown checker, competitive-data validator, targeted tests, and
  `git diff --check` pass;
- competitor code, rules, output, and threat data are not copied into the
  product;
- commits remain independent and production code remains unchanged until the
  product and naming gates are approved.

## Rollback and review

Each task ends in an independent documentation or research-infrastructure
commit. A reviewer can revert one competitor batch, the benchmark harness, the
product decision, or the naming decision without reverting scanner behavior.
The external shallow clones are disposable research inputs and are never added
to the AgentSec Git history.

Stop execution and request owner review when:

- a competitor requires host credentials, privileged execution, or an
  unconfined MCP command;
- a tool's license restricts the intended observation or publication;
- a fixture would require real malware or personal data;
- benchmark results change the selected product category;
- the preferred name has an unresolved package, domain, or trademark collision.

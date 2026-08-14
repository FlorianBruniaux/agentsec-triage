# Agent instruction documentation design

Date: 2026-08-14
Status: approved, expanded to all tracked Markdown

## Objective

Improve the repository instructions without duplicating the same rules in two
files. `AGENTS.md` remains the canonical contract for coding agents.
`CLAUDE.md` imports that contract and adds only Claude Code navigation and
orchestration guidance.

The rewrite applies the style checks from the owner's `ANTI_AI.md` during this
change. The repository will not depend on that user-local file because other
contributors cannot rely on the same absolute path.

## Scope

This change reviews and corrects every tracked `*.md` file in the repository.
The inventory contains 19 files at approval time: root documentation, import and
license records, generated intelligence pages, and historical plans and specs.
Scanner behavior, detector coverage, threat facts, licensing decisions, and
release state stay unchanged.

Generated Markdown must still come from its structured input or builder. The
change may therefore edit `scripts/build_intelligence_docs.py` and focused tests
before regenerating `docs/SECURITY-INTELLIGENCE.md` and
`docs/SECURITY-TIMELINE.md`. No generated file may receive a manual-only fix.

The existing local `.gitignore` modification belongs to the user. This work
must preserve it and exclude it from every commit.

## Canonical responsibilities

`AGENTS.md` will keep the product contract, repository map, TDD workflow,
security invariants, data ownership, generation rules, verification commands,
and release gate. The revision will add the schema digest command,
authoring-to-runtime projection semantics, both supported CLI entry points, and
explicit dirty-worktree handling.

`CLAUDE.md` will stay short enough to avoid drift. It will define the reading
order, when Plan Mode is warranted, how delegated work must preserve AgentSec's
security invariants, which generated files must never be edited by hand, and
which final checks Claude Code must run itself.

The other 17 Markdown files retain their technical meaning and historical
record. Edits remove identified style markers without changing dates, hashes,
commands, source titles, threat claims, exit codes, or prior design decisions.

## Writing rules

Both files will use concrete nouns, active verbs, and commands that exist in the
repository. The revision will remove em dashes, generic buzzwords, mechanical
transitions, decorative triads, empty reminders, and duplicated negative
contrasts. Lists remain appropriate for paths, commands, invariants, and ordered
workflows.

Claims will name the relevant file, command, exit code, version, or decision.
The text will not describe AgentSec as a complete security scanner or imply that
redaction, a completed detector run, or a passing self-scan certifies safety.

## Verification

The documentation change must pass these checks:

1. Scan all 19 tracked Markdown files for the automatic markers listed in
   `ANTI_AI.md`, followed by a manual review for cadence and empty prose.
2. Run documentation tests, then the complete local release gate required by
   `AGENTS.md`.
3. Confirm that generated artifacts remain unchanged.
4. Confirm that Git reports only the user's pre-existing `.gitignore` change
   after the documentation commit.

## Acceptance criteria

All tracked Markdown passes the automatic marker scan and a manual prose review.
Technical facts, commands, URLs, hashes, dates, source titles, and historical
decisions remain intact. An agent can identify the correct source file, test
sequence, generated-file workflow, exit-code contract, and publication gate
without reading duplicated or contradictory instructions. Claude Code receives
concrete orchestration rules, while every security and release rule still comes
from `AGENTS.md`.

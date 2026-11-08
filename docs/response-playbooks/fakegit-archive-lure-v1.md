# FakeGit archive lure response

Version: `1.0.0`.

Detector: `fakegit-archive-lure`.

This playbook is manual-only. Destructive automation is forbidden. Preserve
evidence before an authorized person changes repository state.

Mapped rules:

- `archive-in-agent-config-directory`
- `known-fakegit-archive-hash`
- `readme-links-committed-archive`

## Confidence guidance

### `confirmed`

Treat an exact SHA-256 match against a confirmed FakeGit archive or component hash as incident-response evidence within the inspected repository scope. Preserve the file before changing the repository, and do not extract or run it.

### `high`

No rule of this detector reports high confidence. Keep the label for a future rule that pairs a README link with a sourced indicator.

### `review`

Treat a README link to a committed archive, or an archive inside an agent configuration directory, as a hunt lead. Legitimate projects also commit installers, so check who owns the repository and what the archive contains before using campaign language.

### `contested`

No rule of this detector reports contested intelligence. Preserve the label and the conflicting source scopes if a future correction narrows the sourced hash set.

## Evidence collection

1. Preserve the redacted AgentSec report, completion state, diagnostics, detector confidence, and the exact relative paths and line numbers before editing the repository.
1. Copy the flagged README and archive into an approved evidence location, then record cryptographic hashes without extracting, opening, or running the archive.
1. Record the repository owner, the account age, the clone or install source, the commit that added the archive, and any evidence that a person or an agent followed the README instructions. Mark unknown facts as unknown.

## Manual containment

1. With repository-owner approval, stop people and agents from following the README installer steps for the affected checkout while preserving the original files.
1. With CI-owner approval, prevent new jobs from consuming the affected repository or its archive. Do not delete files or rewrite history automatically.
1. Escalate suspected archive execution, credential exposure, scheduled-task persistence, or account activity to the responsible incident team because AgentSec does not inspect those surfaces.

## Remediation

1. After evidence preservation and explicit approval, prepare a reviewed change that removes the committed archive and the README link, or replaces them with a separately verified release source.
1. Review the commit history for README-only changes that re-pointed a download link, because AgentSec does not read Git history.
1. Route credential rotation, host cleanup, and account recovery to their system owners. Those actions are not performed or verified by AgentSec.

## Verification

1. Run AgentSec again on the explicit repository root, with --scope repository when the archive lives under a directory that the source scope prunes, and require a complete scan with no remaining mapped finding.
1. Review the final repository diff and confirm that no README or agent configuration still points at an installer archive within the inspected repository scope.
1. Verify host, identity, and remote-release recovery with the responsible tools and owners. A clear AgentSec rescan does not verify those systems or certify the repository as clean.

## Outside AgentSec scope

- AgentSec does not extract, execute, or detonate any archive, launcher, or script.
- AgentSec does not read GitHub Release assets, remote downloads, Git history, repository ownership, or account age.
- AgentSec does not inspect host processes, scheduled tasks, credentials, browser data, or remote CI state.
- This playbook does not replace the incident owner's evidence-retention, legal, privacy, or notification procedures.

## Sources

- [Agent Lure Stealer IOC list (Thomas Roccia)](https://gist.github.com/fr0gger/3d0288bf0fee3b8df7b618e7c10334d7) (accessed `2026-11-05`).
- [AgentBaiting: How 800+ Fake AI Skills and MCP Servers Delivered Malware](https://www.island.io/blog/agentbaiting-how-800-fake-ai-skills-and-mcp-servers-delivered-malware) (accessed `2026-11-05`).
- [Cloned, Loaded, and Stolen: How 109 Fake GitHub Repositories Delivered SmartLoader and StealC](https://hexastrike.com/resources/blog/threat-intelligence/cloned-loaded-and-stolen-how-109-fake-github-repositories-delivered-smartloader-and-stealc/) (accessed `2026-11-05`).

Source links support the campaign context and detector boundary. The
response wording in this file is AgentSec-authored and does not reproduce
third-party prose.

# ClawHavoc skill response

Version: `1.0.0`.

Detector: `clawhavoc-skill`.

This playbook is manual-only. Destructive automation is forbidden. Preserve
evidence before an authorized person changes repository state.

Mapped rules:

- `delegated-known-malicious-domain`
- `known-malicious-skill-domain`

## Confidence guidance

### `confirmed`

Use confirmed only when separate evidence establishes the sourced campaign indicator and its repository context. Preserve the evidence before changing the skill.

### `high`

Treat an exact bundled campaign-domain match as high-priority review evidence. It does not by itself prove payload execution, credential theft, or host compromise.

### `review`

Keep a review signal as a hunt lead. Do not relabel it as campaign activity without a sourced indicator or independent evidence.

### `contested`

Preserve the contested label, the conflicting source scopes, and the original evidence. Do not apply confirmed-incident language until the conflict is resolved.

## Evidence collection

1. Preserve the redacted AgentSec report, completion state, diagnostics, detector confidence, and the exact relative paths and line numbers before editing files.
1. Copy the relevant SKILL.md and explicitly delegated setup Markdown into an approved evidence location, then record cryptographic hashes without opening links or executing instructions.
1. Record where the skill came from, the installed or pinned version when known, and any evidence that a human or agent followed the referenced setup instructions. Mark unknown facts as unknown.

## Manual containment

1. With repository-owner approval, stop agents and automation from loading the affected skill while preserving the original files for investigation.
1. With CI-owner approval, prevent new jobs from consuming the affected skill or delegated setup instructions. Do not delete files or rewrite configuration automatically.
1. Escalate suspected host execution, credential exposure, registry compromise, or account activity to the responsible incident team because AgentSec does not inspect those surfaces.

## Remediation

1. After evidence preservation and explicit approval, prepare a reviewed repository change that removes the campaign-domain reference and the untrusted skill source or replaces it with a separately verified source.
1. Review every same-skill setup file and delegated instruction reached from SKILL.md. Do not assume that removing one visible line removes all related instructions.
1. Route credential rotation, host cleanup, registry action, and account recovery to their system owners. Those actions are not performed or verified by AgentSec.

## Verification

1. Run AgentSec again on the explicit repository root and require a complete scan with no remaining finding for the mapped ClawHavoc rules.
1. Review the final repository diff and confirm that the affected skill is no longer loaded by local agent configuration or CI within the inspected repository scope.
1. Verify host, identity, registry, and remote-CI recovery with the responsible tools and owners. A clear AgentSec rescan does not verify those systems or certify the repository as clean.

## Outside AgentSec scope

- AgentSec does not execute, fetch, or detonate the referenced skill or payload.
- AgentSec does not inspect host processes, credentials, caches, accounts, registry history, remote payloads, or remote CI state.
- AgentSec does not delete skills, edit configuration, rotate credentials, revoke tokens, or recover accounts.
- This playbook does not replace the incident owner's evidence-retention, legal, privacy, or notification procedures.

## Sources

- [ClawHavoc: 341 malicious ClawedBot skills found](https://www.koi.ai/blog/clawhavoc-341-malicious-clawedbot-skills-found-by-the-bot-they-were-targeting) (accessed `2026-08-31`).
- [OpenClaw skills used to distribute Atomic macOS Stealer](https://www.trendmicro.com/en_us/research/26/b/openclaw-skills-used-to-distribute-atomic-macos-stealer.html) (accessed `2026-08-31`).

Source links support the campaign context and detector boundary. The
response wording in this file is AgentSec-authored and does not reproduce
third-party prose.

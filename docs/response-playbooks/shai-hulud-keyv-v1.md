# Shai-Hulud and Keyv response

Version: `1.0.0`.

Detector: `shai-hulud-keyv`.

This playbook is manual-only. Destructive automation is forbidden. Preserve
evidence before an authorized person changes repository state.

Mapped rules:

- `campaign-lifecycle-script`
- `campaign-startup-hook`
- `compromised-installed-version`
- `compromised-lockfile-version`
- `known-payload-hash`
- `startup-hook`
- `suspicious-lifecycle-script`

## Confidence guidance

### `confirmed`

Treat an exact confirmed package-version or payload-hash match as incident-response evidence within the inspected repository scope. Preserve it before changing dependencies or files.

### `high`

Treat a campaign-correlated lifecycle or startup invocation as strong review evidence. Confirm whether it executed and whether the referenced file matches sourced campaign evidence before expanding the claim.

### `review`

Treat a generic startup hook or suspicious lifecycle script as a hunt lead, not proof of Shai-Hulud activity or compromise.

### `contested`

Keep disputed package scope labeled contested and retain the source disagreement. Do not merge it into the confirmed package set without a sourced correction.

## Evidence collection

1. Preserve the redacted AgentSec report, completion state, diagnostics, detector confidence, package name and version, relative path, and reported hash before editing the repository.
1. Copy affected lockfiles, installed package manifests, lifecycle scripts, startup configuration, and matched payload files into an approved evidence location, then record cryptographic hashes without executing repository content.
1. Record the package-manager command history and CI or developer install window when available. Keep execution, credential exposure, and host impact unknown until independently verified.

## Manual containment

1. With repository-owner approval, pause dependency installation, builds, and repository startup hooks for the affected checkout while retaining evidence.
1. With CI-owner approval, stop new jobs from consuming the affected dependency state. Do not delete files, rewrite lockfiles, or change hooks automatically.
1. Escalate suspected payload execution, credential exposure, package-registry compromise, or host persistence to the responsible incident team because AgentSec does not inspect those surfaces.

## Remediation

1. After evidence preservation and explicit approval, prepare a reviewed dependency change that replaces sourced affected versions and removes campaign-linked lifecycle or startup entries from the repository.
1. Recreate dependency state only in a controlled clean environment using independently verified package sources and project-specific package-manager procedures.
1. Route credential rotation, host cleanup, registry action, and remote-CI recovery to their system owners. AgentSec neither performs nor verifies those actions.

## Verification

1. Run AgentSec again with the scope required to inspect the affected lockfiles and installed dependency metadata. Require a complete scan with no remaining mapped Shai-Hulud finding.
1. Review the final dependency and configuration diff, then verify the resolved package tree with the project's package manager in the controlled environment.
1. Verify host, identity, package-registry, and remote-CI recovery with the responsible tools and owners. A clear AgentSec rescan does not verify those systems or certify the repository as clean.

## Outside AgentSec scope

- AgentSec does not execute or detonate payloads, lifecycle scripts, startup hooks, or package-manager commands.
- AgentSec does not inspect host processes, credentials, caches, accounts, registry state, network traffic, or remote CI.
- AgentSec does not delete files, update dependencies, rewrite lockfiles, edit hooks, rotate credentials, revoke tokens, or recover accounts.
- This playbook does not replace the incident owner's evidence-retention, legal, privacy, or notification procedures.

## Sources

- [Keyv npm supply-chain compromise](https://safedep.io/keyv-npm-supply-chain-compromise/) (accessed `2026-08-31`).
- [Keyv and friends compromised in npm supply-chain attack](https://www.aikido.dev/blog/keyv-and-friends-compromised-in-npm-supply-chain-attack) (accessed `2026-08-31`).
- [Shai-Hulud is back](https://research.jfrog.com/post/shai-hulud-is-back-august/) (accessed `2026-08-31`).
- [Popular npm packages Keyv and cacheable compromised](https://socket.dev/blog/popular-npm-packages-keyv-and-cacheable-compromised) (accessed `2026-08-31`).

Source links support the campaign context and detector boundary. The
response wording in this file is AgentSec-authored and does not reproduce
third-party prose.

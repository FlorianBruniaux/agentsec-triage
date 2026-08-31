# Response playbooks

These versioned playbooks turn an AgentSec finding into bounded manual
response steps. They do not execute target content, delete files, rewrite
configuration, rotate credentials, or certify that a repository is clean.

| Detector | Version | Rules | Playbook |
| --- | --- | ---: | --- |
| `clawhavoc-skill` | `1.0.0` | 2 | [ClawHavoc skill response](clawhavoc-skill-v1.md) |
| `shai-hulud-keyv` | `1.0.0` | 7 | [Shai-Hulud and Keyv response](shai-hulud-keyv-v1.md) |

## Confidence boundary

Each playbook preserves `confirmed`, `high`, `review`, and `contested`
as distinct states. Follow the guidance for the confidence emitted by the
finding. Never upgrade a review or contested signal without new evidence.

## Machine-readable mapping

The authoring source is `data/response-playbooks.json`. The deterministic
packaged index is `src/agentsec/resources/response-playbooks.json`.
`scripts/build_response_playbooks.py` validates exact coverage of every
active detector rule and rejects missing, duplicate, or unknown mappings.

Findings continue to use the existing stable security-page remediation URL.
A future deployment may route those findings to individual playbook pages
only after the public URLs exist and are checked. The repository does not
publish speculative or broken remediation links.

Updated: `2026-08-31`.

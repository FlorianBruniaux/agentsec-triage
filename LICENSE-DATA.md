# AgentSec Data License Status

## Current status

**Public redistribution of the data listed below is not authorized yet, except
for the narrow integration feed described below.**

The source repository has been publicly visible since 2026-08-30. Public
repository visibility does not grant a separate license for the data paths
listed in this file and does not authorize package, source-archive, or release
redistribution.

The intended license is [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/)
after the documented prose, attribution, ownership, and database-rights review
is complete. This file records that intent and the affected paths. It is not a
license grant.

## Data scope

| Path | Content |
| --- | --- |
| `data/threat-db.yaml` | Authoring threat database |
| `data/intelligence/` | Source bibliography and security-event authoring records |
| `src/agentsec/resources/threat-db.json` | Generated runtime threat database |
| `src/agentsec/resources/security-intelligence.json` | Generated intelligence resource |
| `docs/SECURITY-INTELLIGENCE.md` | Generated source catalogue |
| `docs/SECURITY-TIMELINE.md` | Generated security-event chronology |

The scope includes protected selection, arrangement, descriptions, notes, and
other expression reproduced from these authoring sources in a generated
artifact. Facts, indicators, and public-domain material may have different
legal treatment, but this project does not infer that treatment automatically.

## Narrow public-feed authorization

On 2026-08-16, the project owner authorized publication of
`exports/security-feed.v1.json` under CC BY-SA 4.0 for synchronization with the
Claude Code Ultimate Guide and `cc.bruniaux.com/security/`.

The feed contains project metadata, factual counts, AgentSec detector contracts,
reviewed AgentSec event summaries, and source references. Its generator rejects
the gated IOC and prose fields listed below:

- package-version IOC collections;
- payload hashes and domains;
- malicious-skill records;
- minimum-safe-version records;
- source `supports` claims and third-party database notes.

This exception does not authorize publication of the complete threat database,
the source intelligence corpus, the AgentSec package, a source archive, or a
GitHub release.

## Required review

Before granting CC BY-SA 4.0 for the gated data or publishing package and
source-archive artifacts:

1. Resolve the 28 `UNKNOWN` entries in the reviewed 28-field scanning-tool
   subset and classify the 402 current prose keys outside that subset, as
   recorded in [the prose review](docs/LICENSE-PROSE-REVIEW.md).
2. Confirm ownership or permission for every protected contribution.
3. Rewrite or remove third-party expression that cannot be redistributed.
4. Record the required attribution and adaptation notices.
5. Include the final data license and notices in source and package artifacts.
6. Rebuild the package and inspect its license metadata and contents.

Until that review is complete, the MIT grant in [`LICENSE`](LICENSE) does not
cover these paths. [`LICENSE-DECISION.md`](LICENSE-DECISION.md) remains the
package and gated-data publication gate.

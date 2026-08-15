# AgentSec Data License Status

## Current status

**Public redistribution of the data listed below is not authorized yet.**

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

## Required review

Before applying CC BY-SA 4.0 or making the repository public:

1. Classify the 28 imported `notes:` and `description:` fields recorded in
   [the license evidence inventory](docs/LICENSE-INVENTORY.md).
2. Confirm ownership or permission for every protected contribution.
3. Rewrite or remove third-party expression that cannot be redistributed.
4. Record the required attribution and adaptation notices.
5. Include the final data license and notices in source and package artifacts.
6. Rebuild the package and inspect its license metadata and contents.

Until that review is complete, the MIT grant in [`LICENSE`](LICENSE) does not
cover these paths. [`LICENSE-DECISION.md`](LICENSE-DECISION.md) remains the
publication gate.

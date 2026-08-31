# Naming brief

Status: **provisional shortlist; no rename authorized**

Last screening: 2026-08-31 (UTC). This is a naming-collision screen, not a
trademark clearance or legal opinion. A 404 is only evidence that the queried
registry endpoint returned no record at that time. It neither reserves a name
nor proves that use is safe.

## Naming job

The name should help a developer understand that the tool inspects a repository
before trust or installation and reports campaign-linked evidence with explicit
coverage limits. It must not imply antivirus protection, host monitoring, a
clean certification, automatic remediation, or complete vulnerability
coverage.

## Product promise to preserve

Input: one explicit local repository or a bounded list of roots.

Output: sourced findings, diagnostics, inspected and skipped coverage,
unsupported capabilities, and remediation links.

Boundary: offline, read-only, no target execution, and fail-closed when an
applicable input cannot be inspected.

## Status vocabulary

| Status | Meaning |
| --- | --- |
| `verified_absence` | An official queried endpoint returned 404 for the stated exact string. |
| `collision` | An official queried endpoint returned a record for the exact string, or a material same-name use was directly observed. |
| `ambiguity` | A non-exact use, category meaning, or prior result could confuse the audience but is not an exact registry collision. |
| `verification_unavailable` | The endpoint could not return a usable result. It is not an absence. |

## Candidate screening

All package checks cover both the concatenated and hyphenated form. GitHub
repository search uses GitHub's documented
[`in:name` qualifier](https://docs.github.com/en/search-github/searching-on-github/searching-for-repositories).
It narrows the search to repository names, but it is not a namespace
reservation check. All URLs below were fetched on 2026-08-31 UTC.

| Candidate | Product meaning and risk | GitHub repositories | PyPI exact names | npm exact names | crates.io exact names | `.com` RDAP | `.dev` RDAP | Current result |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| **RepoVigil** | Repository inspection and vigilance. `Vigil` can imply continuous monitoring. | `verified_absence`: the `in:name` API query returned `total_count=0`. | `verified_absence`: `repovigil`, `repo-vigil` returned 404. | `verified_absence`: `repovigil`, `repo-vigil` returned 404. | `verification_unavailable`: official API returned 403. | `verified_absence`: `repovigil.com` returned 404. | `verified_absence`: `repovigil.dev` returned 404. | Provisional first choice, pending comprehension and trademark review. |
| **BeforeTrust** | Pre-trust timing. It does not itself identify repositories or security. | `ambiguity`: one non-exact cybersecurity-awareness repository, [`beforetrust-game`](https://github.com/mnegrinho/beforetrust-game), matched the query. | `verified_absence`: `beforetrust`, `before-trust` returned 404. | `verified_absence`: `beforetrust`, `before-trust` returned 404. | `verification_unavailable`: official API returned 403. | `verified_absence`: `beforetrust.com` returned 404. | `verified_absence`: `beforetrust.dev` returned 404. | Fallback only. The category meaning and same-stem cybersecurity use are ambiguities. |
| **CampaignScope** | Campaign evidence and explicit scope. `Campaign` is ambiguous with marketing. | `collision`: [`jh22d/CampaignScope`](https://github.com/jh22d/CampaignScope) is an exact GitHub repository name for marketing-campaign analysis. | `verified_absence`: `campaignscope`, `campaign-scope` returned 404. | `verified_absence`: `campaignscope`, `campaign-scope` returned 404. | `verification_unavailable`: official API returned 403. | `collision`: `campaignscope.com` returned an active RDAP record, registered 2022-07-08 and expiring 2027-07-08. | `verified_absence`: `campaignscope.dev` returned 404. | Blocked. GitHub and domain collisions remain. |

### Source endpoints and observed result

| Surface | Official source | Result on 2026-08-31 UTC |
| --- | --- | --- |
| GitHub repositories | [RepoVigil `in:name` query](https://api.github.com/search/repositories?q=RepoVigil+in%3Aname), [BeforeTrust `in:name` query](https://api.github.com/search/repositories?q=BeforeTrust+in%3Aname), [CampaignScope `in:name` query](https://api.github.com/search/repositories?q=CampaignScope+in%3Aname) | `200`: RepoVigil `total_count=0`; BeforeTrust `total_count=1` for [`mnegrinho/beforetrust-game`](https://github.com/mnegrinho/beforetrust-game); CampaignScope `total_count=1` for exact [`jh22d/CampaignScope`](https://github.com/jh22d/CampaignScope). |
| PyPI | RepoVigil: [`repovigil`](https://pypi.org/pypi/repovigil/json), [`repo-vigil`](https://pypi.org/pypi/repo-vigil/json). BeforeTrust: [`beforetrust`](https://pypi.org/pypi/beforetrust/json), [`before-trust`](https://pypi.org/pypi/before-trust/json). CampaignScope: [`campaignscope`](https://pypi.org/pypi/campaignscope/json), [`campaign-scope`](https://pypi.org/pypi/campaign-scope/json). | Every linked endpoint returned `404`. |
| npm | RepoVigil: [`repovigil`](https://registry.npmjs.org/repovigil), [`repo-vigil`](https://registry.npmjs.org/repo-vigil). BeforeTrust: [`beforetrust`](https://registry.npmjs.org/beforetrust), [`before-trust`](https://registry.npmjs.org/before-trust). CampaignScope: [`campaignscope`](https://registry.npmjs.org/campaignscope), [`campaign-scope`](https://registry.npmjs.org/campaign-scope). | Every linked endpoint returned `404`. |
| crates.io | RepoVigil: [`repovigil`](https://crates.io/api/v1/crates/repovigil), [`repo-vigil`](https://crates.io/api/v1/crates/repo-vigil). BeforeTrust: [`beforetrust`](https://crates.io/api/v1/crates/beforetrust), [`before-trust`](https://crates.io/api/v1/crates/before-trust). CampaignScope: [`campaignscope`](https://crates.io/api/v1/crates/campaignscope), [`campaign-scope`](https://crates.io/api/v1/crates/campaign-scope). | Every linked endpoint returned `403`. No absence conclusion. |
| `.com` | [Verisign RDAP for RepoVigil](https://rdap.verisign.com/com/v1/domain/repovigil.com), [BeforeTrust](https://rdap.verisign.com/com/v1/domain/beforetrust.com), [CampaignScope](https://rdap.verisign.com/com/v1/domain/campaignscope.com) | RepoVigil and BeforeTrust returned `404`; CampaignScope returned `200` with a registered record. |
| `.dev` | [Google Registry RDAP for RepoVigil](https://www.registry.google/rdap/domain/repovigil.dev), [BeforeTrust](https://www.registry.google/rdap/domain/beforetrust.dev), [CampaignScope](https://www.registry.google/rdap/domain/campaignscope.dev) | Each endpoint returned `404`. |

## Obvious trademark screening

The official public interfaces were reached on 2026-08-31 UTC, but none
yielded a reproducible candidate-level result in this non-interactive check.
They are recorded as `verification_unavailable`, not as no conflict:

| Register | Official interface | Status | Reason |
| --- | --- | --- | --- |
| EUIPO | [eSearch plus](https://euipo.europa.eu/eSearch/) | `verification_unavailable` | The public landing page loaded, but this session could not submit and preserve a candidate query. |
| INPI France | [Data INPI trademarks](https://data.inpi.fr/marques) | `verification_unavailable` | The listed public endpoint returned 404. |
| USPTO | [Trademark Search](https://tmsearch.uspto.gov/) | `verification_unavailable` | The JavaScript search application did not expose a query result to this check. |
| WIPO | [Global Brand Database](https://branddb.wipo.int/) | `verification_unavailable` | The official site required an interactive challenge before search. |

Before a rename, an authorized person must run and preserve candidate, class,
territory, date, and result for relevant software and security classes in these
official registers. Counsel should determine whether any result is legally
material. This repository makes no trademark availability conclusion.

## Rejected candidates

- `ScopeTrace`: several GitHub projects already use the name, including an AI
  governance platform and developer tracing tools.
- `EvidenceGate`: several evidence-first code and AI verification projects use
  the exact name.
- `TrustLedger`: many identity, finance, blockchain, and agent projects use the
  exact name.

## Provisional selection

**RepoVigil** remains the current first choice only as a provisional shortlist
entry. It does not become the selected name until it passes the unaided human
comprehension gate in
[the test kit](naming-comprehension-test-kit.md), crates.io is rechecked
without an access failure, and the trademark-review record is complete.

Fallback status:

1. **BeforeTrust**, if participants correctly identify the repository-security
   job from the name alone.
2. **CampaignScope** is blocked and is not a fallback while its GitHub and
   domain collisions remain. An owner must record one of these outcomes before
   it can be reconsidered: acquire and control `campaignscope.com`, then repeat
   the domain and registry screen; accept a documented no-domain risk and use a
   different domain, with fresh confusion and trademark evidence; or reject the
   candidate. An owner decision alone does not resolve the collision.

## Migration surface

A final rename affects:

- GitHub repository name, About text, topics, issue links, and clone URLs;
- Python distribution, import module, console command, version output, and
  generated schemas;
- `action.yml`, workflow examples, SARIF driver and rule metadata;
- threat database, public feed, guide mirror, landing mirror, and security CTA;
- README, examples, prompts, `llms.txt`, changelog, roadmap, and security policy;
- existing `agentsec` command users, who need a documented compatibility alias
  and removal policy.

Do not rename the repository, package, module, CLI, feed schema, or detector
IDs until the owner approves the final name and the remaining checks are
recorded.

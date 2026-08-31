# Naming brief

Status: **provisional shortlist; no rename authorized**

Screening date: 2026-08-31

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

## Candidate screening

| Candidate | What it communicates | Main ambiguity | GitHub name search | PyPI, npm, crates.io exact names | `.com` / `.dev` RDAP |
| --- | --- | --- | --- | --- | --- |
| **RepoVigil** | Repository inspection and vigilance | May imply continuous monitoring | No result for `RepoVigil` | `repovigil` and `repo-vigil` returned 404 | Both returned 404 |
| **BeforeTrust** | The pre-trust moment | Does not identify repositories or security alone | One cybersecurity awareness game using `beforetrust-game` | `beforetrust` and `before-trust` returned 404 | Both returned 404 |
| **CampaignScope** | Campaign evidence and explicit scope | "Campaign" can mean marketing | One marketing-analysis repository | `campaignscope` and `campaign-scope` returned 404 | `.com` exists; `.dev` returned 404 |

HTTP 404 means no record was returned by the queried endpoint at screening
time. It does not reserve a package or domain and does not establish trademark
clearance.

## Rejected candidates

- `ScopeTrace`: several GitHub projects already use the name, including an AI
  governance platform and developer tracing tools.
- `EvidenceGate`: several evidence-first code and AI verification projects use
  the exact name.
- `TrustLedger`: many identity, finance, blockchain, and agent projects use the
  exact name.

## Provisional selection

**RepoVigil** is the current first choice. It names the repository boundary and
is the least collision-prone candidate in this screening. The continuous
monitoring interpretation must be tested before adoption.

Fallbacks:

1. **BeforeTrust**, if users understand the repository-security job from one
   sentence of context.
2. **CampaignScope**, if campaign-linked evidence proves more valuable than
   immediate category comprehension.

## Unaided comprehension gate

Show only each candidate name, without the README or tagline, to target users.
Ask:

1. What do you think this tool inspects?
2. When would you run it?
3. What result do you expect?
4. Does the name imply continuous protection or a clean certification?

Reject a candidate if the dominant interpretation is host antivirus,
continuous monitoring, marketing campaigns, or generic AI-code validation.
Record the answers before selecting the final name.

## Checks still required

- EUIPO, INPI, USPTO, and WIPO trademark searches in relevant software and
  security classes;
- package-name registration immediately before the rename;
- registrar confirmation for the selected domain;
- social handle and search-result review;
- unaided comprehension evidence from target users.

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

Do not rename the repository, package, module, CLI, feed schema, or detector IDs
until the owner approves the final name and the remaining checks are recorded.

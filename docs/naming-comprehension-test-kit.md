# Unaided naming-comprehension test kit

Status: **required evidence before a name can leave the provisional shortlist**

This kit tests the name only. It does not test the current product, a tagline,
the README, or an explanation from the facilitator. It must not be used to
claim trademark clearance, market demand, security effectiveness, or release
readiness.

## Decision question

Can target users infer that a candidate is a repository-focused, pre-trust
inspection tool without inferring host antivirus, continuous monitoring, clean
certification, or automatic remediation?

## Participants and sampling

Recruit at least seven people before deciding. At least five must be developers
or AppSec practitioners who might inspect third-party repositories, packages,
skills, or setup instructions. Record participant role and experience band, not
employer, email address, repository names, or other unnecessary personal data.

The facilitator must give no explanation before every unaided response is
recorded. Do not recruit only project contributors or people who have seen the
AgentSec README.

## Facilitator procedure

1. Create a random candidate-to-code mapping independently for each
   participant, such as `A = RepoVigil`, `B = BeforeTrust`, and
   `C = CampaignScope`. Keep the mapping outside the participant sheet until
   scoring.
2. Show one code and its candidate name only. Do not show a descriptor, logo,
   product category, repository, documentation, or the other candidates.
3. Ask the four prompts verbatim. Do not clarify terms or react to an answer.
4. Record the answer verbatim, then repeat for the remaining two names in a
   different random order.
5. Score only after all participants finish. A second scorer independently
   scores at least 20 percent of responses, including every failing candidate.
   Resolve disagreements by retaining the lower score and recording why.

## Participant prompts

For each displayed name, ask:

1. What do you think this tool inspects?
2. At what point would you use it?
3. What kind of result would you expect it to give you?
4. Does the name make you expect any of these: continuous monitoring, host
   antivirus, a clean certification, or automatic remediation? Explain briefly.

Do not add a one-line descriptor. The purpose is unaided comprehension.

## Scoring grid

Score each dimension once per participant and candidate. A response may receive
zero on every dimension. Preserve the raw response so later reviewers can
audit the classification.

| Dimension | 1 point | 0 points | Critical misconception |
| --- | --- | --- | --- |
| Repository target | Names a repository, codebase, package source, local project, dependency manifest, or agent configuration. | Names only a computer, network, account, cloud service, marketing audience, or gives no target. | N/A |
| Pre-trust timing | States before installing, trusting, adopting, executing, or reviewing third-party repository content. | Gives only ongoing, post-incident, or no timing. | N/A |
| Evidence-oriented result | Expects findings, suspicious artifacts, a report, diagnostics, or scoped coverage. | Expects a generic score, unspecified protection, or no outcome. | N/A |
| Safety-boundary inference | Explicitly rejects all four prohibited expectations when answering prompt 4. | Leaves the four expectations unaddressed. | Expects continuous monitoring, host antivirus, a clean certificate, or automatic remediation. |

The maximum is four points. The fourth row is both a point and a safety check:
any listed expectation is a critical misconception even if other answers score
well.

## Recording sheet

| Participant ID | Role / experience band | Candidate code | Display order | Q1 raw answer | Q2 raw answer | Q3 raw answer | Q4 raw answer | Target | Timing | Result | Boundary | Critical misconception | Scorer | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- | ---: | ---: | ---: | ---: | --- | --- | --- |
| P01 | Developer, 5+ years | A | 2 |  |  |  |  |  |  |  |  |  |  |  |

Store the candidate-code mapping and raw responses with the study record. Do
not publish participant identifiers or free-text answers without their consent.

## Decision rule

A candidate may advance from provisional to owner review only when all of the
following are true for at least seven completed participant records:

- at least 70 percent score the repository target point;
- at least 70 percent score the pre-trust timing point;
- at least 70 percent score the evidence-oriented result point;
- no more than one participant has a critical misconception;
- the mean total score is at least 3.0 out of 4.0;
- no unresolved `collision` or `verification_unavailable` entry remains for
  required registries and trademark checks in [the naming brief](NAMING.md).

Otherwise retain the candidate as provisional or reject it. Do not average away
a critical misconception. Report counts, denominator, the candidate-code map,
raw-response storage location, scoring disagreements, and the dated collision
screen with the decision.

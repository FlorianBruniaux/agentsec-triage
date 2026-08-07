# Security policy

AgentSec Triage is alpha software. Reports about the scanner and corrections to
its threat data are different workflows. Pick the section that matches the
problem and do not attach secrets, live credentials, private repository content,
or unredacted personal paths to a public report.

No private intake address is asserted in this repository yet. The temporary
private-disclosure procedure below is intentionally conservative until the
project owner configures and documents a verified channel.

## Scanner vulnerabilities

A scanner vulnerability is a flaw in AgentSec itself, including target-repository
code execution, a scan-root escape, unsafe symlink or reparse-point traversal,
unintended network access, secret disclosure, or a denial of service that defeats
the documented bounds.

Do not open a public issue when exploitation details or a proof of concept could
put users at risk. Follow **Private disclosure**. Include the affected commit or
version, platform, Python version, minimal reproduction, observed impact, and
whether the reproduction contains sensitive data.

## False positives

A false positive is a finding on benign evidence. A public issue may use this
template after all sensitive material is removed:

```text
Title: False positive: <detector ID>/<rule ID>
AgentSec version and database version:
Platform and Python version:
Command, including limits and --redact use:
Minimal benign fixture or public repository link:
Finding severity, confidence, path, and redacted evidence:
Why the evidence is benign:
Expected behavior:
```

Do not remove a confirmed IOC solely because one environment considers it benign.
The underlying source and scope must be reviewed.

## False negatives

A false negative is documented in-scope attack evidence that an otherwise
complete scan misses. If the evidence is already public and disclosure creates
no new risk, a public issue may use:

```text
Title: False negative: <campaign or technique>
AgentSec version and database version:
Platform and Python version:
Minimal safe fixture:
Primary source URL and access date:
Exact source claim the fixture represents:
Expected detector, rule, severity, and confidence:
Actual exit code, completion status, diagnostics, and findings:
```

If the evidence is unpublished, weaponizable, or contains a live indicator that
could identify a victim, use **Private disclosure** instead.

## IOC corrections

Use a public issue only for public, non-sensitive corrections. Include:

```text
Title: IOC correction: <record or campaign>
Database version and affected field:
Current value:
Proposed value or retraction:
Primary source URL, publication date, and access date:
Exact supporting or contradicting claim:
Confidence and status change requested:
Source license or redistribution note, if known:
```

Do not submit raw stolen data, credentials, victim identifiers, or a source that
cannot legally be redistributed. Corrections require traceable evidence and a
regression fixture when they affect detector behavior.

## Private disclosure

Until this repository documents a verified private reporting channel, do not
send sensitive details to a guessed email address and do not open a public issue.
Contact the project owner through an existing private channel you have already
verified and ask for the current security intake method without including the
vulnerability details. If no verified channel exists, retain the report and only
publish a minimal request for a private contact method that reveals no exploit or
victim information.

Once a private channel is established, send the affected version, impact,
reproduction steps, safe proof of concept, suggested mitigation, and a contact
for follow-up. Encrypt sensitive attachments using a key confirmed through that
channel. No response-time promise is made for this alpha.


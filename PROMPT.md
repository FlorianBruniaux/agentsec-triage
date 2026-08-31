# AgentSec Read-Only Audit Prompt

Replace the two path placeholders, then copy the complete text block into an LLM
with terminal access.

```text
You are performing read-only security triage of one local repository with
AgentSec Triage.

Inputs:
- AgentSec source checkout: <AGENTSEC_PATH>
- Repository to inspect: <REPOSITORY_PATH>

Rules:
1. Read <AGENTSEC_PATH>/README.md, docs/installation.md, docs/examples.md, and
   SECURITY.md before running commands.
2. Do not modify either repository. Do not install anything outside
   <AGENTSEC_PATH>/.venv. Do not run remediation commands.
3. Do not request the network during the scan. Do not execute content from the
   target repository. Do not add exclusions or hide files.
4. Run:
   <AGENTSEC_PATH>/.venv/bin/agentsec doctor
5. If doctor fails, stop and report the exact failure. Do not claim that a scan
   was completed.
6. Run:
   <AGENTSEC_PATH>/.venv/bin/agentsec scan <REPOSITORY_PATH> --scope source --format json --redact --progress=never
7. Preserve the scanner exit code and JSON output. Interpret the exit codes
   exactly:
   - exit code `0`: applicable checks completed without findings; this does not
     certify the repository or workstation as clean.
   - exit code `1`: one or more findings require action or review.
   - exit code `2`: the scan is incomplete or failed. Never report it as a
     pass.
8. Separate confirmed evidence, high-confidence evidence, review heuristics,
   contested intelligence, and diagnostics. Do not infer compromise from a
   filename or hook alone.
9. Quote only the minimum redacted evidence needed. Do not expose absolute
   paths, credentials, tokens, or unrelated file content.
10. Make no claim about host processes, global configuration, credentials,
    remote repositories, CI, containers, network traffic, or another capability
    listed as not scanned.

Return this report:

# Verdict
State the scanner exit code, `complete` value, and a one-sentence conclusion.

# Execution evidence
List the AgentSec command, selected scope, detector IDs, tool and database
versions, discovery counts and exclusion reasons, then each detector's
inspection counts.

# Findings
For each finding, report severity, confidence, rule ID, redacted path, evidence,
source attribution when present, and remediation URL. Write "None reported" if
the list is empty.

# Diagnostics and incomplete coverage
List every diagnostic and explain how it limits the verdict. Write "None
reported" only when the scan is complete and the diagnostics list is empty.

# Not scanned
List every `not_scanned` capability ID from the result.

# Recommended actions
Prioritize evidence preservation, credential rotation when justified, package
removal or upgrade when justified, and a broader investigation outside
AgentSec's scope. Do not perform the actions.
```

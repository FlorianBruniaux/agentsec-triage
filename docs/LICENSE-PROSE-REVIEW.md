# Third-Party Prose Evidence Review

## Scope and result

This is a factual local-evidence review, not a copyright conclusion or a
license grant. Reviewer: Codex local evidence review. Review date:
`2026-08-31`.

The earlier inventory described 28 imported `notes:` or `description:` fields.
That count was not the complete database count. It corresponds exactly to the
28 `scanning_tools[].notes` fields. The deterministic
[`LICENSE-PROSE-INVENTORY.json`](LICENSE-PROSE-INVENTORY.json) artifact records
all 430 current prose fields in the 2.27.0 authoring database. It contains the
field path, full SHA-256 value digest, locally resolvable source locators,
classification, review state, and required action for every entry.

The inventory resolves 93 source locators across 77 fields from a sibling
`url`, a sibling `sources` list, or an exact match against the database's
top-level `sources` list. Eight fields have more than one locator. The other
353 fields retain an empty `source_locators` list. A resolved local URL links a
field to a cited record; it does not prove that the prose is independently
written, correctly attributed, or redistributable.

Local Git establishes that all 28 strings first appeared in the canonical
guide under the author identity `Florian BRUNIAUX <florian@bruniaux.com>` and
were later imported byte for byte into AgentSec. Git attribution does not prove
independent authorship, permission, or the absence of copied expression.

Result for the current 430-field inventory:

- provenance: 28 `scanning_tools[].notes` fields have review state
  `LOCAL_PROVENANCE_VERIFIED` against local Git history; the other 402 fields
  have review state `UNREVIEWED`;
- classification: all 430 fields are **UNKNOWN** because no local source
  snapshot, drafting record, or permission record establishes independent
  authorship, justified quotation, or authorized third-party expression;
- factual drift: the Aguara note is contradicted by the pinned README, which
  states that the prior public observatory is stale and unsupported;
- publication: still blocked until every `UNKNOWN` classification is resolved
  by source comparison, independent rewrite, permission, or removal.

Update 2026-09-01 (not part of the original 2026-08-31 review above): two
subsequent threat-intelligence records (CVE-2026-82233, CVE-2026-53965) added
three more prose fields, bringing the inventory to 433 fields. These three
fields were freshly authored this session from public NVD and GitHub Security
Advisory text, not imported from the canonical guide, so they are outside the
28-field historically-verified subset below. They carry review state
`UNREVIEWED` and classification `UNKNOWN` under the same rule stated above and
require the same source comparison before publication.

`VERIFIED` means the stated local evidence was observed. `UNKNOWN` means the
available local evidence is insufficient. Neither state grants redistribution
rights. `LOCAL_PROVENANCE_VERIFIED` is a review state, not an authorship or
rights classification. `UNREVIEWED` records that no local provenance review has
been entered for that field. The historical state is emitted only when both the
field path and its full digest match the recorded 28-field subset; changing the
field value returns it to `UNREVIEWED`.

## Historically verified local-provenance subset

The digest is the first 16 hexadecimal characters of SHA-256 over the exact
UTF-8 field value. The origin column records the first matching canonical-guide
commit and its author date. Every origin commit carries the author identity
recorded above.

| Field | Digest | Origin | Source locator | Classification | Local evidence | Required action |
| --- | --- | --- | --- | --- | --- | --- |
| `scanning_tools[name=mcp-scan].notes` | `e02ebb57fc41ad6a` | `deb518ce`, 2026-02-11 | [mcp-scan](https://github.com/invariantlabs-ai/mcp-scan) | **UNKNOWN** | The text is project-specific, but local Git attribution does not prove independent drafting. | Confirm independent drafting or rewrite from reviewed facts. |
| `scanning_tools[name=Ferrok].notes` | `8d093ba27a32cefe` | `9ea6e487`, 2026-03-30 | [Ferrok](https://lobehub.com/mcp/rfounds-ferrok-scan) | **UNKNOWN** | No local source snapshot or permission record supports classification 1, 2, or 3. | Compare the source, then rewrite independently, obtain permission, or remove. |
| `scanning_tools[name=GitHub Security Lab Taskflow Agent].notes` | `ba7e2bb3f7096d2a` | `b0698bfb`, 2026-03-13 | [Taskflow Agent](https://github.blog/security/how-to-scan-for-vulnerabilities-with-github-security-labs-open-source-ai-powered-framework/) | **UNKNOWN** | No local source snapshot or permission record supports classification 1, 2, or 3. | Compare the source, then rewrite independently, obtain permission, or remove. |
| `scanning_tools[name=OpenAI Codex Security].notes` | `2a9f24ff1975a1ff` | `b0698bfb`, 2026-03-13 | [OpenAI Codex Security](https://openai.com/index/codex-security-now-in-research-preview/) | **UNKNOWN** | No local source snapshot or permission record supports classification 1, 2, or 3. | Compare the source, then rewrite independently, obtain permission, or remove. |
| `scanning_tools[name=Jozu Agent Guard].notes` | `4ae5d650dc8dd5d3` | `44818a3f`, 2026-03-18 | [Jozu Agent Guard](https://www.helpnetsecurity.com/2026/03/17/jozu-agent-guard-targets-ai-agents-that-evade-controls/) | **UNKNOWN** | No local source snapshot or permission record supports classification 1, 2, or 3. | Compare the source, then rewrite independently, obtain permission, or remove. |
| `scanning_tools[name=Cisco AI Agent Security Scanner for IDEs].notes` | `00ab7da8001bd803` | `0f6f2385`, 2026-05-03 | [Cisco IDE scanner](https://blogs.cisco.com/ai/introducing-the-ai-agent-security-scanner-for-ides-verify-your-agents) | **UNKNOWN** | No local source snapshot or permission record supports classification 1, 2, or 3. | Compare the source, then rewrite independently, obtain permission, or remove. |
| `scanning_tools[name=MCP Sentinel].notes` | `a8ef3e8fb5617010` | `44818a3f`, 2026-03-18 | [MCP Sentinel](https://www.youtube.com/watch?v=l00ZoeYhBwg) | **UNKNOWN** | No local source snapshot or permission record supports classification 1, 2, or 3. | Compare the source, then rewrite independently, obtain permission, or remove. |
| `scanning_tools[name=AquilaX AI Agent Configuration Scanner].notes` | `f412e44144900af3` | `e9499e3d`, 2026-03-23 | [AquilaX](https://aquilax.ai/blog/mcp-security-shadow-ai-agents) | **UNKNOWN** | No local source snapshot or permission record supports classification 1, 2, or 3. | Compare the source, then rewrite independently, obtain permission, or remove. |
| `scanning_tools[name=Cisco DefenseClaw].notes` | `0fecd298e102691b` | `146848ca`, 2026-03-27 | [Cisco DefenseClaw](https://github.com/cisco-ai-defense/defenseclaw) | **UNKNOWN** | No local source snapshot or permission record supports classification 1, 2, or 3. | Compare the source, then rewrite independently, obtain permission, or remove. |
| `scanning_tools[name=hackmyagent].notes` | `6ca6a4bcd6fa15b8` | `146848ca`, 2026-03-27 | [hackmyagent](https://github.com/opena2a-org/hackmyagent) | **UNKNOWN** | No local source snapshot or permission record supports classification 1, 2, or 3. | Compare the source, then rewrite independently, obtain permission, or remove. |
| `scanning_tools[name=ClawNet].notes` | `f37ec4a1d3bdb63f` | `146848ca`, 2026-03-27 | [ClawNet](https://www.silverfort.com/blog/clawhub-vulnerability-enables-attackers-to-manipulate-rankings-to-become-the-number-one-skill/) | **UNKNOWN** | No local source snapshot or permission record supports classification 1, 2, or 3. | Compare the source, then rewrite independently, obtain permission, or remove. |
| `scanning_tools[name=ESET AI Skills Checker].notes` | `f5c099f6b0b20351` | `146848ca`, 2026-03-27 | [ESET AI Skills Checker](https://www.eset.com/us/home/ai-skills-checker/) | **UNKNOWN** | No local source snapshot or permission record supports classification 1, 2, or 3. | Compare the source, then rewrite independently, obtain permission, or remove. |
| `scanning_tools[name=SandyClaw].notes` | `5784b9347c04ea29` | `05be712a`, 2026-04-06 | [SandyClaw](https://permiso.io/blog/introducing-sandyclaw-dynamic-sandbox-ai-agent-skills) | **UNKNOWN** | No local source snapshot or permission record supports classification 1, 2, or 3. | Compare the source, then rewrite independently, obtain permission, or remove. |
| `scanning_tools[name=Semgrep MCP].notes` | `7515151969f23652` | `05be712a`, 2026-04-06 | [Semgrep MCP](https://semgrep.dev/docs/mcp) | **UNKNOWN** | No local source snapshot or permission record supports classification 1, 2, or 3. | Compare the source, then rewrite independently, obtain permission, or remove. |
| `scanning_tools[name=ClawArmor].notes` | `745998ce567676c7` | `d225a5b7`, 2026-04-11 | [ClawArmor](https://accuknox.com/blog/introducing-clawarmor-for-openclaw-instances) | **UNKNOWN** | No local source snapshot or permission record supports classification 1, 2, or 3. | Compare the source, then rewrite independently, obtain permission, or remove. |
| `scanning_tools[name=ClawSec].notes` | `e998581ce9ecbedd` | `d225a5b7`, 2026-04-11 | [ClawSec](https://github.com/prompt-security/clawsec) | **UNKNOWN** | No local source snapshot or permission record supports classification 1, 2, or 3. | Compare the source, then rewrite independently, obtain permission, or remove. |
| `scanning_tools[name=Snyk Agent Scan].notes` | `523bab9815c00d05` | `2c52b29b`, 2026-04-20 | [Snyk Agent Scan](https://github.com/snyk/agent-scan) | **UNKNOWN** | The pinned profile verifies vendor and behavior, not the April 2026 date. | Compare the source, then rewrite independently, obtain permission, or remove. |
| `scanning_tools[name=Straiker MCP Security Platform].notes` | `cce37ef259c8ed37` | `2c52b29b`, 2026-04-20 | [Straiker](https://www.straiker.ai/solution/mcp-security) | **UNKNOWN** | No local source snapshot or permission record supports classification 1, 2, or 3. | Compare the source, then rewrite independently, obtain permission, or remove. |
| `scanning_tools[name=Aguara].notes` | `2c10155615c99a2a` | `1e416368`, 2026-05-27 | [Aguara](https://aguarascan.com/) | **UNKNOWN** | Pinned `README.md:435@819eafb5fa66` says the prior observatory is stale and unsupported. | Rewrite the stale observatory claim, then re-review. |
| `scanning_tools[name=SkillRisk].notes` | `3b1381282cb24ff7` | `1e416368`, 2026-05-27 | [SkillRisk](https://skillrisk.org/) | **UNKNOWN** | No local source snapshot or permission record supports classification 1, 2, or 3. | Compare the source, then rewrite independently, obtain permission, or remove. |
| `scanning_tools[name=Golf Scanner].notes` | `ad467f118bbc42d2` | `c034d78d`, 2026-06-04 | [Golf Scanner](https://github.com/golf-mcp/golf-scanner) | **UNKNOWN** | No local source snapshot or permission record supports classification 1, 2, or 3. | Compare the source, then rewrite independently, obtain permission, or remove. |
| `scanning_tools[name=Microsoft MDASH].notes` | `ac724d29b3d16c61` | `c034d78d`, 2026-06-04 | [Microsoft MDASH](https://www.microsoft.com/en-us/security/blog/2026/05/12/defense-at-ai-speed-microsofts-new-multi-model-agentic-security-system-tops-leading-industry-benchmark/) | **UNKNOWN** | No local source snapshot or permission record supports classification 1, 2, or 3. | Compare the source, then rewrite independently, obtain permission, or remove. |
| `scanning_tools[name=NVIDIA SkillSpector].notes` | `a602040740824e5b` | `b43cf217`, 2026-06-10 | [NVIDIA SkillSpector](https://github.com/NVIDIA/SkillSpector) | **UNKNOWN** | The pinned profile verifies least-privilege rules, not the date or the "first" claim. | Compare the source, then rewrite independently, obtain permission, or remove. |
| `scanning_tools[name=VIPER-MCP].notes` | `039a66d5d4600392` | `b43cf217`, 2026-06-10 | [VIPER-MCP](https://arxiv.org/abs/2605.21392) | **UNKNOWN** | No local source snapshot or permission record supports classification 1, 2, or 3. | Compare the source, then rewrite independently, obtain permission, or remove. |
| `scanning_tools[name=SkillScan Security].notes` | `3681387e291b85ee` | `5395214b`, 2026-07-12 | [SkillScan Security](https://github.com/kurtpayne/skillscan-security) | **UNKNOWN** | No local source snapshot or permission record supports classification 1, 2, or 3. | Compare the source, then rewrite independently, obtain permission, or remove. |
| `scanning_tools[name=AI-Infra-Guard (A.I.G)].notes` | `b042d384c5cf7912` | `5395214b`, 2026-07-12 | [AI-Infra-Guard](https://github.com/Tencent/AI-Infra-Guard) | **UNKNOWN** | No local source snapshot or permission record supports classification 1, 2, or 3. | Compare the source, then rewrite independently, obtain permission, or remove. |
| `scanning_tools[name=mcp-spec-check].notes` | `22bf48b0e41e9a35` | `752edfe5`, 2026-08-06 | [mcp-spec-check](https://blog.modelcontextprotocol.io/posts/2026-07-28-release-candidate/) | **UNKNOWN** | The text is project-specific, but local Git attribution does not prove independent drafting. | Confirm independent drafting or rewrite from reviewed facts. |
| `scanning_tools[name=SkillDetonate].notes` | `6591809cf5c5171a` | `752edfe5`, 2026-08-06 | [SkillDetonate](https://www.cybersecurityinstitute.com/blog/?p=5483) | **UNKNOWN** | No local source snapshot or permission record supports classification 1, 2, or 3. | Compare the source, then rewrite independently, obtain permission, or remove. |

## Reproduction

Rebuild the complete machine-verifiable inventory twice and compare the byte
output:

```bash
python scripts/build_license_prose_inventory.py
python scripts/build_license_prose_inventory.py --output /tmp/license-prose-inventory.json
cmp docs/LICENSE-PROSE-INVENTORY.json /tmp/license-prose-inventory.json
python scripts/build_license_prose_inventory.py --check
```

The imported baseline is available at commit `54c7d45`. Its complete file
digest is recorded in `data/IMPORT_PROVENANCE.md`. Reproduce a field origin in
the canonical guide with the exact field value:

```bash
git log --reverse --format='%H|%ad|%an|%ae' --date=short \
  -S '<exact field value>' -- examples/commands/resources/threat-db.yaml
```

Recalculate a field digest as SHA-256 over the exact UTF-8 scalar value. A
changed digest invalidates the corresponding row and requires a new review.

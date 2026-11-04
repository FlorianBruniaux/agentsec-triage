"""Guard scanning-tool install commands against names their vendors do not publish.

Readers copy these commands. On 2026-11-04 three of them fetched code that the
named vendor does not publish: `npx @snyk/agent-scan` (Snyk publishes no npm
package for Agent Scan), `npx ferrok-scan` (Ferrok ships a GitHub Action and the
npm name is unregistered) and `npx mcp-scan` (the npm name belongs to an
unrelated author; Invariant's scanner was renamed to the PyPI package
snyk-agent-scan).
"""

from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).parents[2]


def _tools() -> dict[str, dict[str, str]]:
    database = yaml.safe_load((ROOT / "data/threat-db.yaml").read_text(encoding="utf-8"))
    return {tool["name"]: tool for tool in database["scanning_tools"]}


@pytest.mark.parametrize(
    "name,command,url",
    [
        ("mcp-scan", "uvx snyk-agent-scan@latest", "https://github.com/snyk/agent-scan"),
        ("Snyk Agent Scan", "uvx snyk-agent-scan@latest", "https://github.com/snyk/agent-scan"),
        ("Ferrok", "uses: rfounds/ferrok-scan@v1", "https://github.com/rfounds/ferrok-scan"),
    ],
)
def test_scanning_tool_command_matches_vendor_distribution(name: str, command: str, url: str):
    tool = _tools()[name]
    assert tool["command"] == command
    assert tool["url"] == url


@pytest.mark.parametrize("unpublished", ["npx @snyk/agent-scan", "npx ferrok-scan", "npx mcp-scan"])
def test_no_scanning_tool_runs_a_name_its_vendor_does_not_publish(unpublished: str):
    assert all(tool.get("command") != unpublished for tool in _tools().values())

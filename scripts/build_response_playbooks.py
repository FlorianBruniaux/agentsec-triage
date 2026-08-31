from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import cast

from jsonschema import Draft202012Validator, FormatChecker  # type: ignore[import-untyped]

from agentsec.detectors.registry import get_detectors

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SOURCE = PROJECT_ROOT / "data" / "response-playbooks.json"
DEFAULT_SCHEMA = PROJECT_ROOT / "schemas" / "response-playbooks-v1.schema.json"
DEFAULT_RESOURCE = (
    PROJECT_ROOT / "src" / "agentsec" / "resources" / "response-playbooks.json"
)
DEFAULT_DOCS_ROOT = PROJECT_ROOT / "docs" / "response-playbooks"


class ResponsePlaybookBuildError(Exception):
    """Raised when response playbooks violate their public contract."""


class DuplicateJsonKeyError(ValueError):
    """Raised when a JSON object contains an ambiguous duplicate key."""


def _reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateJsonKeyError
        result[key] = value
    return result


def _load_json(path: Path, label: str) -> dict[str, object]:
    try:
        loaded = cast(
            object,
            json.loads(
                path.read_text(encoding="utf-8"),
                object_pairs_hook=_reject_duplicate_json_keys,
            ),
        )
    except DuplicateJsonKeyError as exc:
        raise ResponsePlaybookBuildError(
            f"{label} load failed: duplicate JSON object key"
        ) from exc
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ResponsePlaybookBuildError(f"{label} load failed") from exc
    if not isinstance(loaded, dict) or not all(isinstance(key, str) for key in loaded):
        raise ResponsePlaybookBuildError(f"{label} root must be an object")
    return cast(dict[str, object], loaded)


def _playbooks(document: Mapping[str, object]) -> list[dict[str, object]]:
    value = document.get("playbooks")
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise ResponsePlaybookBuildError("playbooks must be an array")
    if not all(isinstance(item, Mapping) for item in value):
        raise ResponsePlaybookBuildError("playbook entries must be objects")
    return [cast(dict[str, object], item) for item in value]


def _strings(value: object, label: str) -> list[str]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise ResponsePlaybookBuildError(f"{label} must be an array")
    if not all(isinstance(item, str) and item for item in value):
        raise ResponsePlaybookBuildError(f"{label} must contain strings")
    return list(cast(Sequence[str], value))


def _string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ResponsePlaybookBuildError(f"{label} must be a non-empty string")
    return value


def _mapping(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise ResponsePlaybookBuildError(f"{label} must be an object")
    return cast(dict[str, object], value)


def validate_rule_coverage(
    document: Mapping[str, object], detector_rules: Mapping[str, frozenset[str]]
) -> None:
    """Require one playbook mapping for every active detector rule and no extras."""
    actual: list[tuple[str, str]] = []
    playbook_ids: list[str] = []
    document_paths: list[str] = []
    for playbook in _playbooks(document):
        playbook_ids.append(_string(playbook.get("id"), "playbook id"))
        document_paths.append(
            _string(playbook.get("document_path"), "playbook document_path")
        )
        detector_id = _string(playbook.get("detector_id"), "playbook detector_id")
        actual.extend(
            (detector_id, rule_id)
            for rule_id in _strings(playbook.get("rule_ids"), "playbook rule_ids")
        )
    expected = sorted(
        (detector_id, rule_id)
        for detector_id, rule_ids in detector_rules.items()
        for rule_id in rule_ids
    )
    if sorted(actual) != expected or len(actual) != len(set(actual)):
        raise ResponsePlaybookBuildError(
            "active detector rule coverage mismatch"
        )
    if playbook_ids != sorted(set(playbook_ids)):
        raise ResponsePlaybookBuildError("playbook ids must be sorted and unique")
    if len(document_paths) != len(set(document_paths)):
        raise ResponsePlaybookBuildError("playbook document paths must be unique")
    for playbook in _playbooks(document):
        rules = _strings(playbook.get("rule_ids"), "playbook rule_ids")
        if rules != sorted(set(rules)):
            raise ResponsePlaybookBuildError(
                "playbook rule ids must be sorted and unique"
            )


def load_document(source: Path, schema_path: Path) -> dict[str, object]:
    document = _load_json(source, "playbook source")
    schema = _load_json(schema_path, "playbook schema")
    try:
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema, format_checker=FormatChecker())
    except Exception as exc:
        raise ResponsePlaybookBuildError("playbook schema is invalid") from exc
    errors = sorted(
        validator.iter_errors(document),
        key=lambda error: (
            tuple(str(part) for part in error.absolute_path),
            error.message,
        ),
    )
    if errors:
        raise ResponsePlaybookBuildError(
            f"playbook validation failed at {errors[0].json_path}"
        )
    validate_rule_coverage(
        document,
        {
            detector.id: frozenset(detector.rule_ids)
            for detector in get_detectors()
        },
    )
    return document


def render_resource(document: Mapping[str, object]) -> str:
    return json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def render_index(document: Mapping[str, object]) -> str:
    lines = [
        "# Response playbooks",
        "",
        "These versioned playbooks turn an AgentSec finding into bounded manual",
        "response steps. They do not execute target content, delete files, rewrite",
        "configuration, rotate credentials, or certify that a repository is clean.",
        "",
        "| Detector | Version | Rules | Playbook |",
        "| --- | --- | ---: | --- |",
    ]
    for playbook in _playbooks(document):
        document_path = _string(playbook.get("document_path"), "document_path")
        filename = Path(document_path).name
        lines.append(
            "| `{}` | `{}` | {} | [{}]({}) |".format(
                _string(playbook.get("detector_id"), "detector_id"),
                _string(playbook.get("version"), "version"),
                len(_strings(playbook.get("rule_ids"), "rule_ids")),
                _string(playbook.get("title"), "title"),
                filename,
            )
        )
    lines.extend(
        [
            "",
            "## Confidence boundary",
            "",
            "Each playbook preserves `confirmed`, `high`, `review`, and `contested`",
            "as distinct states. Follow the guidance for the confidence emitted by the",
            "finding. Never upgrade a review or contested signal without new evidence.",
            "",
            "## Machine-readable mapping",
            "",
            "The authoring source is `data/response-playbooks.json`. The deterministic",
            "packaged index is `src/agentsec/resources/response-playbooks.json`.",
            "`scripts/build_response_playbooks.py` validates exact coverage of every",
            "active detector rule and rejects missing, duplicate, or unknown mappings.",
            "",
            "Findings continue to use the existing stable security-page remediation URL.",
            "A future deployment may route those findings to individual playbook pages",
            "only after the public URLs exist and are checked. The repository does not",
            "publish speculative or broken remediation links.",
            "",
            f"Updated: `{_string(document.get('updated'), 'updated')}`.",
            "",
        ]
    )
    return "\n".join(lines)


def render_playbook(playbook: Mapping[str, object]) -> str:
    lines = [
        f"# {_string(playbook.get('title'), 'title')}",
        "",
        f"Version: `{_string(playbook.get('version'), 'version')}`.",
        "",
        f"Detector: `{_string(playbook.get('detector_id'), 'detector_id')}`.",
        "",
        "This playbook is manual-only. Destructive automation is forbidden. Preserve",
        "evidence before an authorized person changes repository state.",
        "",
        "Mapped rules:",
        "",
    ]
    lines.extend(
        f"- `{rule_id}`"
        for rule_id in _strings(playbook.get("rule_ids"), "rule_ids")
    )
    lines.extend(["", "## Confidence guidance", ""])
    guidance = _mapping(playbook.get("confidence_guidance"), "confidence_guidance")
    for confidence in ("confirmed", "high", "review", "contested"):
        lines.extend(
            [
                f"### `{confidence}`",
                "",
                _string(guidance.get(confidence), f"guidance {confidence}"),
                "",
            ]
        )
    for phase in cast(list[dict[str, object]], playbook.get("phases")):
        lines.extend(
            [
                f"## {_string(phase.get('title'), 'phase title')}",
                "",
            ]
        )
        lines.extend(
            f"1. {action}"
            for action in _strings(phase.get("actions"), "phase actions")
        )
        lines.append("")
    lines.extend(["## Outside AgentSec scope", ""])
    lines.extend(
        f"- {item}"
        for item in _strings(playbook.get("out_of_scope"), "out_of_scope")
    )
    lines.extend(["", "## Sources", ""])
    for source in cast(list[dict[str, object]], playbook.get("sources")):
        lines.append(
            "- [{}]({}) (accessed `{}`).".format(
                _string(source.get("title"), "source title"),
                _string(source.get("url"), "source url"),
                _string(source.get("accessed"), "source accessed"),
            )
        )
    lines.extend(
        [
            "",
            "Source links support the campaign context and detector boundary. The",
            "response wording in this file is AgentSec-authored and does not reproduce",
            "third-party prose.",
            "",
        ]
    )
    return "\n".join(lines)


def build(
    source: Path,
    schema: Path,
    resource: Path,
    docs_root: Path,
) -> None:
    document = load_document(source, schema)
    resource.parent.mkdir(parents=True, exist_ok=True)
    resource.write_text(render_resource(document), encoding="utf-8")
    docs_root.mkdir(parents=True, exist_ok=True)
    (docs_root / "README.md").write_text(render_index(document), encoding="utf-8")
    for playbook in _playbooks(document):
        document_path = PROJECT_ROOT / _string(
            playbook.get("document_path"), "document_path"
        )
        try:
            output = docs_root / document_path.relative_to(DEFAULT_DOCS_ROOT)
        except ValueError as exc:
            raise ResponsePlaybookBuildError(
                "playbook document_path is outside the response-playbooks directory"
            ) from exc
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(render_playbook(playbook), encoding="utf-8")


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build versioned response playbooks")
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA)
    parser.add_argument("--resource", type=Path, default=DEFAULT_RESOURCE)
    parser.add_argument("--docs-root", type=Path, default=DEFAULT_DOCS_ROOT)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        build(args.source, args.schema, args.resource, args.docs_root)
    except ResponsePlaybookBuildError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

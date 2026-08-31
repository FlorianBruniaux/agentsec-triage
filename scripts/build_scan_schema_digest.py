from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from hashlib import sha256
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PAIRS = tuple(
    (
        PROJECT_ROOT / "schemas" / name,
        PROJECT_ROOT / "schemas" / name.replace(".json", ".sha256"),
    )
    for name in (
        "scan-result-v1.schema.json",
        "scan-result-v2.schema.json",
        "batch-result-v1.schema.json",
    )
)


def _expected_digest(schema: Path) -> str:
    content = schema.read_bytes().replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    return f"{sha256(content).hexdigest()}\n"


def _write_digest(output: Path, content: str) -> None:
    temporary = output.with_name(f".{output.name}.tmp")
    try:
        output.parent.mkdir(parents=True, exist_ok=True)
        temporary.write_text(content, encoding="ascii")
        temporary.replace(output)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate or verify the AgentSec scan-result schema digest"
    )
    parser.add_argument("--schema", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--check", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if (args.schema is None) != (args.output is None):
        print("error: --schema and --output must be provided together", file=sys.stderr)
        return 1
    pairs = (
        ((args.schema, args.output),)
        if args.schema is not None and args.output is not None
        else DEFAULT_PAIRS
    )
    try:
        validated: list[tuple[Path, str]] = []
        for schema, output in pairs:
            expected = _expected_digest(schema)
            if args.check:
                try:
                    current = output.read_text(encoding="ascii")
                except FileNotFoundError:
                    current = ""
                if current != expected:
                    suffix = f": {schema.name}" if len(pairs) > 1 else ""
                    print(f"error: schema digest is stale{suffix}", file=sys.stderr)
                    return 1
            else:
                _write_digest(output, expected)
            validated.append((schema, expected))
    except (OSError, UnicodeError) as exc:
        print(f"error: schema digest failed: {exc}", file=sys.stderr)
        return 1
    for schema, expected in validated:
        print(f"schema digest valid {schema.name} sha256={expected.strip()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

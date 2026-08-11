from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from hashlib import sha256
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SCHEMA = PROJECT_ROOT / "schemas" / "scan-result-v1.schema.json"
DEFAULT_OUTPUT = PROJECT_ROOT / "schemas" / "scan-result-v1.schema.sha256"


def _expected_digest(schema: Path) -> str:
    return f"{sha256(schema.read_bytes()).hexdigest()}\n"


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
    parser.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--check", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        expected = _expected_digest(args.schema)
        if args.check:
            try:
                current = args.output.read_text(encoding="ascii")
            except FileNotFoundError:
                current = ""
            if current != expected:
                print("error: schema digest is stale", file=sys.stderr)
                return 1
        else:
            _write_digest(args.output, expected)
    except (OSError, UnicodeError) as exc:
        print(f"error: schema digest failed: {exc}", file=sys.stderr)
        return 1
    print(f"schema digest valid sha256={expected.strip()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

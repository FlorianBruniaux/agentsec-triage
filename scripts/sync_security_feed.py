from __future__ import annotations

import argparse
import hashlib
import sys
from collections.abc import Sequence
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_FEED = PROJECT_ROOT / "exports" / "security-feed.v1.json"
DEFAULT_GUIDE_ROOT = PROJECT_ROOT.parent / "claude-code-ultimate-guide"
DEFAULT_LANDING_ROOT = PROJECT_ROOT.parent / "claude-code-ultimate-guide-landing"
GUIDE_DESTINATION = Path("machine-readable/agentsec-security-feed.v1.json")
LANDING_DESTINATION = Path("src/data/agentsec-security-feed.v1.json")


def _read(path: Path, label: str) -> bytes:
    try:
        return path.read_bytes()
    except OSError as exc:
        raise ValueError(f"cannot read {label}: {path}") from exc


def _write(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_bytes(content)
    temporary.replace(path)


def _destinations(guide_root: Path, landing_root: Path) -> tuple[tuple[str, Path], ...]:
    return (
        ("guide", guide_root / GUIDE_DESTINATION),
        ("landing", landing_root / LANDING_DESTINATION),
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Synchronize the AgentSec public feed with guide and landing mirrors."
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    parser.add_argument("--feed", type=Path, default=DEFAULT_FEED)
    parser.add_argument("--guide-root", type=Path, default=DEFAULT_GUIDE_ROOT)
    parser.add_argument("--landing-root", type=Path, default=DEFAULT_LANDING_ROOT)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    try:
        canonical = _read(arguments.feed, "canonical feed")
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    destinations = _destinations(arguments.guide_root, arguments.landing_root)
    if arguments.write:
        for _, destination in destinations:
            _write(destination, canonical)
        digest = hashlib.sha256(canonical).hexdigest()
        print(f"synchronized security feed sha256={digest}")
        return 0

    differences: list[str] = []
    for label, destination in destinations:
        try:
            mirrored = _read(destination, f"{label} feed")
        except ValueError:
            differences.append(f"{label} feed differs: missing {destination}")
            continue
        if mirrored != canonical:
            differences.append(f"{label} feed differs: {destination}")
    if differences:
        for difference in differences:
            print(f"error: {difference}", file=sys.stderr)
        return 1
    print(f"security feed mirrors match sha256={hashlib.sha256(canonical).hexdigest()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

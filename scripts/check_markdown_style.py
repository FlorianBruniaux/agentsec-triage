#!/usr/bin/env python3
"""Report automatically detectable style markers in repository Markdown."""

from __future__ import annotations

import re
import sys
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path

SKIPPED_DIRECTORIES = frozenset(
    {
        ".git",
        ".mypy_cache",
        ".package-check",
        ".pytest_cache",
        ".ruff_cache",
        ".venv",
        ".worktrees",
        "build",
        "dist",
    }
)


@dataclass(frozen=True, slots=True)
class Marker:
    name: str
    pattern: re.Pattern[str]


@dataclass(frozen=True, slots=True)
class Violation:
    path: Path
    line: int
    marker: str
    excerpt: str


def _compile(expression: str, *, multiline: bool = False) -> re.Pattern[str]:
    flags = re.IGNORECASE
    if multiline:
        flags |= re.MULTILINE
    return re.compile(expression, flags)


MARKERS = (
    Marker("em-dash", re.compile(chr(0x2014))),
    Marker(
        "stereotyped-opening",
        _compile(
            r"\b(?:Il est important de noter que|Dans le paysage(?: numérique| actuel)?|"
            r"À l'ère du numérique|Au cœur de cette problématique|En conclusion|"
            r"Pour résumer|Globalement|In today's digital world|At its core|"
            r"Let's delve into|It's worth noting)\b"
        ),
    ),
    Marker(
        "mechanical-transition",
        _compile(
            r"^[ \t]*(?:Par ailleurs|En outre|De plus|Tout d'abord|Ensuite|Enfin|"
            r"Furthermore|Moreover|Additionally|Overall)\b",
            multiline=True,
        ),
    ),
    Marker(
        "buzzword",
        _compile(
            r"\b(?:enjeux|complexité|défis|potentiel|robuste|essentiel|fondamental|"
            r"robust|pivotal|crucial|innovative|seamless|game[- ]changer|landscape)\b"
        ),
    ),
    Marker(
        "empty-evidence",
        _compile(
            r"\b(?:des études montrent|les experts s'accordent|la recherche démontre|"
            r"studies show|experts agree|research shows)\b"
        ),
    ),
    Marker(
        "rhetorical-transition",
        _compile(
            r"\b(?:Le hic|Le plus beau|Le résultat|Mais voilà le vrai sujet|"
            r"The catch|The best part)\s*\?"
        ),
    ),
    Marker(
        "redundant-pair",
        _compile(r"\b(?:simple et efficace|clair et précis|clear and precise)\b"),
    ),
    Marker(
        "negative-parallel",
        _compile(
            r"\b(?:Ce n'est pas\b[^.!?\n]{1,160}\bc'est|"
            r"Il ne s'agit pas\b[^.!?\n]{1,160}\bmais|"
            r"Non seulement\b[^.!?\n]{1,160}\bmais aussi|"
            r"Not only\b[^.!?\n]{1,160}\bbut also|"
            r"Not\b[^.!?\n]{1,160}\bbut)\b"
        ),
    ),
    Marker(
        "whether-or",
        _compile(r"\b(?:que ce soit|qu'il s'agisse de|whether)\b[^.!?\n]{1,160}\bor\b"),
    ),
    Marker("chevron-quote", re.compile(r"[«»]")),
)


INLINE_CODE = re.compile(r"`[^`\n]*`")


def _mask_code(text: str) -> str:
    masked_lines: list[str] = []
    fence: str | None = None
    for line in text.splitlines(keepends=True):
        stripped = line.lstrip()
        candidate = stripped[:3]
        if candidate in {"```", "~~~"}:
            fence = None if fence == candidate else candidate
            masked_lines.append("\n" if line.endswith("\n") else "")
            continue
        if fence is not None:
            masked_lines.append("\n" if line.endswith("\n") else "")
            continue
        masked_lines.append(INLINE_CODE.sub(lambda match: " " * len(match.group()), line))
    return "".join(masked_lines)


def iter_markdown_files(root: Path) -> Iterator[Path]:
    paths = []
    for path in root.rglob("*.md"):
        relative = path.relative_to(root)
        if any(part in SKIPPED_DIRECTORIES for part in relative.parts[:-1]):
            continue
        if path.is_file():
            paths.append(path)
    yield from sorted(paths, key=lambda item: item.relative_to(root).as_posix())


def find_violations(path: Path, text: str) -> list[Violation]:
    masked = _mask_code(text)
    original_lines = text.splitlines()
    violations: list[Violation] = []
    for marker in MARKERS:
        for match in marker.pattern.finditer(masked):
            line = masked.count("\n", 0, match.start()) + 1
            excerpt = original_lines[line - 1].strip()
            violations.append(Violation(path, line, marker.name, excerpt))
    return sorted(violations, key=lambda item: (item.line, item.marker, item.excerpt))


def _run(root: Path) -> int:
    if not root.is_dir():
        print("markdown root is not a directory", file=sys.stderr)
        return 2

    resolved_root = root.resolve()
    violations: list[Violation] = []
    for path in iter_markdown_files(resolved_root):
        text = path.read_text(encoding="utf-8")
        violations.extend(find_violations(path, text))

    for violation in sorted(
        violations,
        key=lambda item: (
            item.path.relative_to(resolved_root).as_posix(),
            item.line,
            item.marker,
        ),
    ):
        relative = violation.path.relative_to(resolved_root).as_posix()
        print(f"{relative}:{violation.line}: {violation.marker}: {violation.excerpt}")
    return 1 if violations else 0


def main(arguments: Sequence[str] | None = None) -> int:
    values = list(sys.argv[1:] if arguments is None else arguments)
    if len(values) > 1:
        print("usage: check_markdown_style.py [ROOT]", file=sys.stderr)
        return 2
    root = Path(values[0]) if values else Path.cwd()
    return _run(root)


if __name__ == "__main__":
    raise SystemExit(main())

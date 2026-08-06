"""Repository-scoped Shai-Hulud Keyv/cacheable campaign detector."""

from __future__ import annotations

import hashlib
import re
import stat
from pathlib import Path

from agentsec.analyzers.git_history import GitIndicator, inspect_git_history
from agentsec.analyzers.lockfiles import ResolvedPackage, parse_lockfile_content
from agentsec.analyzers.packages import (
    InstalledPackage,
    inspect_package_manifest_content,
)
from agentsec.analyzers.safe_io import safe_read_regular_file
from agentsec.analyzers.startup import StartupHook, inspect_startup_config_content
from agentsec.detectors.base import ScanContext
from agentsec.engine.discovery import DiscoveredFile
from agentsec.models import (
    Applicability,
    Confidence,
    Coverage,
    DetectorResult,
    Diagnostic,
    DiagnosticKind,
    Finding,
    Severity,
    ThreatDatabase,
)

_CAMPAIGN_ID = "shai-hulud-keyv-2026-08"
_LOCKFILE_NAMES = frozenset(
    {
        "package-lock.json",
        "npm-shrinkwrap.json",
        "pnpm-lock.yaml",
        "pnpm-lock.yml",
        "yarn.lock",
        "bun.lock",
        "bun.lockb",
    }
)
_CAMPAIGN_FILENAMES = frozenset({"setup.mjs", "math_symbol.js", "math_init.js"})
_SCRIPT_INTERPRETERS = frozenset({"node", "node.exe", "bun", "bun.exe", "deno", "deno.exe"})
_VALID_KEYV_PACKAGE_SEGMENT = re.compile(r"^[a-z0-9_~-][a-z0-9._~-]*$")
_ENVIRONMENT_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=.*$")
_MAX_NPM_PACKAGE_NAME_LENGTH = 214
_MAX_COMMAND_LENGTH = 1024 * 1024
_MAX_ENV_SPLIT_DEPTH = 4
_MAX_GIT_COMMITS = 100_000


class ShaiHuludDetector:
    """Compose bounded analyzers into deterministic campaign findings."""

    id = "shai-hulud-keyv"
    version = "1"

    def applies(self, context: ScanContext) -> bool:
        return bool(context.files) or _git_metadata_state(context.root)[0]

    def run(self, context: ScanContext) -> DetectorResult:
        findings: list[Finding] = []
        diagnostics: list[Diagnostic] = []
        inspected_files = 0
        inspected_bytes = 0

        for item in context.files:
            category = _file_category(item.relative_path)
            safety_error = _file_safety_error(item, context)
            if safety_error is not None:
                diagnostics.append(safety_error)
                continue

            content, analyzer_diagnostics = safe_read_regular_file(
                item.absolute_path,
                context.limits.max_file_bytes,
            )
            diagnostics.extend(analyzer_diagnostics)
            if content is None:
                continue
            inspected_files += 1
            inspected_bytes += len(content)

            digest = hashlib.sha256(content).hexdigest()
            if digest in context.database.hashes:
                findings.append(
                    _finding(
                        rule_id="known-payload-hash",
                        severity=Severity.CRITICAL,
                        confidence=Confidence.CONFIRMED,
                        path=item.relative_path,
                        evidence=(f"sha256:{digest} ({context.database.hashes[digest]})"),
                    )
                )

            if category == "lockfile":
                packages, analyzer_diagnostics = parse_lockfile_content(content, item.absolute_path)
                diagnostics.extend(analyzer_diagnostics)
                for resolved_package in packages:
                    if _is_compromised(
                        resolved_package.name,
                        resolved_package.version,
                        context.database,
                    ):
                        findings.append(_lockfile_finding(resolved_package, item.relative_path))
                continue

            if category == "manifest":
                installed_package, analyzer_diagnostics = inspect_package_manifest_content(
                    content,
                    item.absolute_path,
                )
                diagnostics.extend(analyzer_diagnostics)
                if installed_package is not None:
                    findings.extend(
                        _installed_package_findings(
                            installed_package,
                            item.relative_path,
                            context.database,
                        )
                    )
                continue

            if category == "startup":
                hooks, analyzer_diagnostics = inspect_startup_config_content(
                    content, item.absolute_path
                )
                diagnostics.extend(analyzer_diagnostics)
                findings.extend(_startup_findings(hooks, item.relative_path))

        has_git, git_diagnostic = _git_metadata_state(context.root)
        if git_diagnostic is not None:
            diagnostics.append(git_diagnostic)
        elif has_git:
            indicators, analyzer_diagnostics = inspect_git_history(
                context.root,
                max_commits=min(context.limits.max_files, _MAX_GIT_COMMITS),
            )
            diagnostics.extend(analyzer_diagnostics)
            findings.extend(_git_findings(indicators, context.database))

        return DetectorResult(
            detector_id=self.id,
            applicability=Applicability.APPLICABLE,
            findings=_deduplicate_findings(findings),
            diagnostics=_bounded_diagnostics(
                diagnostics,
                root=context.root,
                limit=context.limits.max_diagnostics,
            ),
            coverage=Coverage(
                files_seen=len(context.files),
                files_inspected=inspected_files,
                bytes_inspected=inspected_bytes,
            ),
        )


def _file_category(path: Path) -> str | None:
    if path.name in _LOCKFILE_NAMES:
        return "lockfile"
    parts = path.parts
    if path.name == "package.json" and "node_modules" in parts[:-1]:
        return "manifest"
    if path.parent == Path(".claude") and path.name in {"settings.json", "settings.local.json"}:
        return "startup"
    if path == Path(".vscode/tasks.json"):
        return "startup"
    return None


def _file_safety_error(item: DiscoveredFile, context: ScanContext) -> Diagnostic | None:
    if item.symlink:
        return Diagnostic(
            DiagnosticKind.ERROR,
            item.absolute_path,
            "Refusing to inspect symlinked repository file",
        )
    if item.size < 0 or item.size > context.limits.max_file_bytes:
        return Diagnostic(
            DiagnosticKind.ERROR,
            item.absolute_path,
            f"File exceeds max_file_bytes={context.limits.max_file_bytes}; scan incomplete",
        )
    return None


def _is_compromised(name: str, version: str, database: ThreatDatabase) -> bool:
    if version in database.package_versions.get(name, frozenset()):
        return True
    return any(
        prefix == "@keyv/"
        and _is_valid_keyv_wildcard_package(name)
        and version in versions
        for prefix, versions in database.wildcard_package_versions.items()
    )


def _is_valid_keyv_wildcard_package(name: str) -> bool:
    if len(name) > _MAX_NPM_PACKAGE_NAME_LENGTH or not name.startswith("@keyv/"):
        return False
    segment = name.removeprefix("@keyv/")
    return (
        bool(segment)
        and not segment.startswith(".")
        and _VALID_KEYV_PACKAGE_SEGMENT.fullmatch(segment) is not None
    )


def _lockfile_finding(package: ResolvedPackage, path: Path) -> Finding:
    return _finding(
        rule_id="compromised-lockfile-version",
        severity=Severity.CRITICAL,
        confidence=Confidence.CONFIRMED,
        path=path,
        evidence=f"{package.name}@{package.version}",
    )


def _installed_package_findings(
    package: InstalledPackage,
    path: Path,
    database: ThreatDatabase,
) -> tuple[Finding, ...]:
    compromised = _is_compromised(package.name, package.version, database)
    package_evidence = f"{package.name}@{package.version}"
    findings: list[Finding] = []
    if compromised:
        findings.append(
            _finding(
                rule_id="compromised-installed-version",
                severity=Severity.CRITICAL,
                confidence=Confidence.CONFIRMED,
                path=path,
                evidence=package_evidence,
            )
        )
    if package.preinstall is not None and _is_campaign_invocation(package.preinstall):
        findings.append(
            _finding(
                rule_id=(
                    "campaign-lifecycle-script" if compromised else "suspicious-lifecycle-script"
                ),
                severity=Severity.CRITICAL if compromised else Severity.MEDIUM,
                confidence=Confidence.HIGH if compromised else Confidence.REVIEW,
                path=path,
                evidence=f"{package_evidence} preinstall: {package.preinstall}",
            )
        )
    return tuple(findings)


def _startup_findings(hooks: tuple[StartupHook, ...], path: Path) -> tuple[Finding, ...]:
    findings = []
    for hook in hooks:
        campaign_correlated = _is_campaign_invocation(hook.command)
        findings.append(
            _finding(
                rule_id="campaign-startup-hook" if campaign_correlated else "startup-hook",
                severity=Severity.HIGH if campaign_correlated else Severity.MEDIUM,
                confidence=Confidence.HIGH if campaign_correlated else Confidence.REVIEW,
                path=path,
                evidence=f"{hook.kind} {hook.event}: {hook.command}",
            )
        )
    return tuple(findings)


def _is_campaign_invocation(command: str) -> bool:
    return _command_invokes_campaign_file(command, split_depth=0)


def _command_invokes_campaign_file(command: str, *, split_depth: int) -> bool:
    if len(command) > _MAX_COMMAND_LENGTH:
        return False
    segments = _tokenize_command_segments(command)
    return any(
        _segment_invokes_campaign_file(segment, split_depth=split_depth)
        for segment in segments
    )


def _tokenize_command_segments(command: str) -> tuple[tuple[str, ...], ...]:
    segments: list[tuple[str, ...]] = []
    tokens: list[str] = []
    token: list[str] = []
    token_started = False
    quote: str | None = None
    index = 0

    def finish_token() -> None:
        nonlocal token_started
        if token_started:
            tokens.append("".join(token))
            token.clear()
            token_started = False

    def finish_segment() -> None:
        finish_token()
        if tokens:
            segments.append(tuple(tokens))
            tokens.clear()

    while index < len(command):
        character = command[index]
        if quote is not None:
            if character == quote:
                quote = None
            elif character == "\\" and index + 1 < len(command) and command[index + 1] == quote:
                token.append(command[index + 1])
                index += 1
            else:
                token.append(character)
            index += 1
            continue

        if character in {'"', "'"}:
            quote = character
            token_started = True
        elif character == "\\" and index + 1 < len(command) and (
            command[index + 1].isspace() or command[index + 1] in "\"';|&\\"
        ):
            token.append(command[index + 1])
            token_started = True
            index += 1
        elif character == "#" and not token_started:
            finish_token()
            while index < len(command) and command[index] not in "\r\n":
                index += 1
            continue
        elif character in "\r\n;|&":
            finish_segment()
        elif character.isspace():
            finish_token()
        else:
            token.append(character)
            token_started = True
        index += 1

    if quote is not None:
        return ()
    finish_segment()
    return tuple(segments)


def _segment_invokes_campaign_file(
    tokens: tuple[str, ...], *, split_depth: int
) -> bool:
    if not tokens:
        return False
    command_tokens, split_string = _resolve_environment_command(tokens)
    if split_string is not None:
        value, trailing_tokens = split_string
        return _split_string_invokes_campaign_file(
            value,
            trailing_tokens,
            split_depth=split_depth,
        )
    if not command_tokens:
        return False
    executable = _command_basename(command_tokens[0])
    if executable in _CAMPAIGN_FILENAMES:
        return True
    if executable not in _SCRIPT_INTERPRETERS:
        return False
    return _runtime_entrypoint_is_campaign(executable, command_tokens[1:])


def _resolve_environment_command(
    tokens: tuple[str, ...],
) -> tuple[tuple[str, ...], tuple[str, tuple[str, ...]] | None]:
    index = 0
    while index < len(tokens) and _ENVIRONMENT_ASSIGNMENT.fullmatch(tokens[index]):
        index += 1
    if index >= len(tokens) or _command_basename(tokens[index]) != "env":
        return tokens[index:], None

    index += 1
    while index < len(tokens):
        token = tokens[index]
        if _ENVIRONMENT_ASSIGNMENT.fullmatch(token):
            index += 1
            continue
        if token in {"-S", "--split-string"}:
            if index + 1 >= len(tokens):
                return (), None
            return (), (tokens[index + 1], tokens[index + 2 :])
        if token.startswith("--split-string="):
            return (), (token.partition("=")[2], tokens[index + 1 :])
        if token in {"-u", "--unset", "-C", "--chdir"}:
            if index + 1 >= len(tokens):
                return (), None
            index += 2
            continue
        if token.startswith("-"):
            index += 1
            continue
        break
    return tokens[index:], None


def _split_string_invokes_campaign_file(
    value: str,
    trailing_tokens: tuple[str, ...],
    *,
    split_depth: int,
) -> bool:
    if split_depth >= _MAX_ENV_SPLIT_DEPTH or len(value) > _MAX_COMMAND_LENGTH:
        return False
    segments = _tokenize_command_segments(value)
    for index, segment in enumerate(segments):
        combined = segment + trailing_tokens if index == len(segments) - 1 else segment
        if _segment_invokes_campaign_file(combined, split_depth=split_depth + 1):
            return True
    return False


def _runtime_entrypoint_is_campaign(executable: str, arguments: tuple[str, ...]) -> bool:
    deno_run_pending = executable in {"deno", "deno.exe"}
    for token in arguments:
        lowered = token.lower()
        if lowered in {"-e", "--eval", "-p", "--print"} or lowered.startswith(
            ("--eval=", "--print=")
        ):
            return False
        if token == "--" or token.startswith("-"):
            continue
        if deno_run_pending and lowered == "run":
            deno_run_pending = False
            continue
        return _command_basename(token) in _CAMPAIGN_FILENAMES
    return False


def _command_basename(token: str) -> str:
    return token.replace("\\", "/").rsplit("/", 1)[-1].lower()


def _git_findings(
    indicators: tuple[GitIndicator, ...], database: ThreatDatabase
) -> tuple[Finding, ...]:
    expected = {
        (item["author"], item["email"], item["subject"]) for item in database.commit_indicators
    }
    return tuple(
        _finding(
            rule_id="campaign-git-identity",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            path=Path("."),
            evidence=f"{indicator.author} <{indicator.email}>: {indicator.subject}",
        )
        for indicator in indicators
        if (indicator.author, indicator.email, indicator.subject) in expected
    )


def _git_metadata_state(root: Path) -> tuple[bool, Diagnostic | None]:
    metadata = root / ".git"
    try:
        metadata_stat = metadata.lstat()
    except FileNotFoundError:
        return False, None
    except (OSError, ValueError):
        return True, Diagnostic(
            DiagnosticKind.ERROR,
            metadata,
            "Unable to inspect local Git metadata",
        )

    attributes = getattr(metadata_stat, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    if stat.S_ISLNK(metadata_stat.st_mode) or attributes & reparse_flag:
        return True, Diagnostic(
            DiagnosticKind.ERROR,
            metadata,
            "Refusing unsafe local Git metadata path",
        )
    if not (stat.S_ISDIR(metadata_stat.st_mode) or stat.S_ISREG(metadata_stat.st_mode)):
        return True, Diagnostic(
            DiagnosticKind.ERROR,
            metadata,
            "Unsupported local Git metadata type",
        )
    return True, None


def _finding(
    *,
    rule_id: str,
    severity: Severity,
    confidence: Confidence,
    path: Path,
    evidence: str,
) -> Finding:
    return Finding(
        detector_id="shai-hulud-keyv",
        rule_id=rule_id,
        severity=severity,
        confidence=confidence,
        path=path,
        evidence=evidence,
        campaign_ids=(_CAMPAIGN_ID,),
    )


def _deduplicate_findings(findings: list[Finding]) -> tuple[Finding, ...]:
    unique = {(finding.rule_id, finding.path, finding.evidence): finding for finding in findings}
    return tuple(
        unique[key]
        for key in sorted(
            unique,
            key=lambda item: (item[0], item[1].as_posix(), item[2]),
        )
    )


def _bounded_diagnostics(
    diagnostics: list[Diagnostic], *, root: Path, limit: int
) -> tuple[Diagnostic, ...]:
    unique = {(item.kind, item.path, item.message): item for item in diagnostics}
    ordered = [
        unique[key]
        for key in sorted(
            unique,
            key=lambda item: (item[0], item[1].as_posix(), item[2]),
        )
    ]
    if len(ordered) <= limit:
        return tuple(ordered)
    return (
        *ordered[:limit],
        Diagnostic(
            DiagnosticKind.ERROR,
            root,
            f"diagnostics truncated at max_diagnostics={limit}; detector scan incomplete",
        ),
    )

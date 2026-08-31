"""Repository-scoped Shai-Hulud Keyv/cacheable campaign detector."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from itertools import chain, islice
from pathlib import Path

from agentsec.analyzers.lockfiles import ResolvedPackage, parse_lockfile_content
from agentsec.analyzers.packages import (
    InstalledPackage,
    inspect_package_manifest_content,
)
from agentsec.analyzers.safe_io import safe_read_regular_file
from agentsec.analyzers.startup import StartupHook, inspect_startup_config_content
from agentsec.detectors.base import DetectorMetadata, DetectorRuleMetadata, ScanContext
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
_SHELL_ENVIRONMENT_ASSIGNMENT = re.compile(
    r"^[A-Za-z_][A-Za-z0-9_]*(?:\[[^\]\x00]+\])?\+?=[^\x00]*$"
)
_MAX_NPM_PACKAGE_NAME_LENGTH = 214
_MAX_COMMAND_LENGTH = 1024 * 1024
_MAX_ENV_SPLIT_DEPTH = 4
_REMEDIATION_URL = "https://cc.bruniaux.com/security/"
_TECHNIQUE_IDS = (
    "npm.compromised-version",
    "npm.lifecycle-script",
    "payload.sha256",
    "repository.startup-hook",
)
_TECHNIQUES_BY_RULE = {
    "known-payload-hash": ("payload.sha256",),
    "compromised-lockfile-version": ("npm.compromised-version",),
    "compromised-installed-version": ("npm.compromised-version",),
    "campaign-lifecycle-script": ("npm.lifecycle-script",),
    "suspicious-lifecycle-script": ("npm.lifecycle-script",),
    "campaign-startup-hook": ("repository.startup-hook",),
    "startup-hook": ("repository.startup-hook",),
}


@dataclass(frozen=True, slots=True)
class PackageIntelligence:
    severity: Severity
    confidence: Confidence
    sources: tuple[str, ...]


class ShaiHuludDetector:
    """Compose bounded analyzers into deterministic campaign findings."""

    id = "shai-hulud-keyv"
    version = "1"
    rule_ids: tuple[str, ...] = tuple(sorted(_TECHNIQUES_BY_RULE))
    metadata = DetectorMetadata(
        description=(
            "Detect repository-local indicators associated with the August 2026 "
            "Shai-Hulud Keyv/cacheable npm campaign."
        ),
        supported_inputs=(
            "all discovered regular files (SHA-256)",
            "bun.lock",
            "node_modules/**/package.json",
            "npm-shrinkwrap.json",
            "package-lock.json",
            "pnpm-lock.yaml",
            "pnpm-lock.yml",
            "repository .claude/settings.json and .claude/settings.local.json",
            "repository .vscode/tasks.json",
            "yarn.lock",
        ),
        campaign_ids=(_CAMPAIGN_ID,),
        technique_ids=_TECHNIQUE_IDS,
        source_references=(
            "https://safedep.io/keyv-npm-supply-chain-compromise/",
            "https://www.aikido.dev/blog/keyv-and-friends-compromised-in-npm-supply-chain-attack",
            "https://research.jfrog.com/post/shai-hulud-is-back-august/",
            "https://socket.dev/blog/popular-npm-packages-keyv-and-cacheable-compromised",
        ),
        limitations=(
            "Binary bun.lockb is unsupported.",
            "Only repository-local files are inspected.",
            "Package manifests and startup configuration have parser-specific 1 MiB caps.",
            "Threat intelligence is bundled and is not refreshed during a scan.",
        ),
        remediation_url=_REMEDIATION_URL,
        not_scanned=("git.history",),
        applicability="at_least_one_discovered_file",
        rules=tuple(
            DetectorRuleMetadata(id=rule_id, technique_ids=technique_ids)
            for rule_id, technique_ids in sorted(_TECHNIQUES_BY_RULE.items())
        ),
    )

    def applies(self, context: ScanContext) -> bool:
        return bool(context.files)

    def run(self, context: ScanContext) -> DetectorResult:
        findings: list[Finding] = []
        diagnostics: list[Diagnostic] = []
        inspected_files = 0
        inspected_bytes = 0
        oversized_files = 0

        for item in context.files:
            category = _file_category(item.relative_path)
            if item.size > context.limits.max_file_bytes:
                oversized_files += 1
                continue
            safety_error = _file_safety_error(item, context)
            if safety_error is not None:
                diagnostics.append(safety_error)
                continue
            remaining_bytes = context.limits.max_total_bytes - inspected_bytes
            if item.size > remaining_bytes:
                diagnostics.append(
                    Diagnostic(
                        DiagnosticKind.ERROR,
                        item.absolute_path,
                        "Aggregate byte budget reached at "
                        f"max_total_bytes={context.limits.max_total_bytes}; scan incomplete",
                    )
                )
                break

            content, analyzer_diagnostics = safe_read_regular_file(
                item.absolute_path,
                min(context.limits.max_file_bytes, remaining_bytes),
            )
            diagnostics.extend(analyzer_diagnostics)
            if content is None:
                break
            inspected_files += 1
            inspected_bytes += len(content)
            if context.progress is not None and inspected_files % 1_000 == 0:
                context.progress(inspected_files, inspected_bytes)

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
                    intelligence = _match_package_intelligence(
                        resolved_package.name,
                        resolved_package.version,
                        context.database,
                    )
                    if intelligence is not None:
                        findings.append(
                            _lockfile_finding(
                                resolved_package,
                                item.relative_path,
                                intelligence,
                            )
                        )
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

        if context.progress is not None and inspected_files % 1_000 != 0:
            context.progress(inspected_files, inspected_bytes)
        if oversized_files:
            noun = "file" if oversized_files == 1 else "files"
            diagnostics.append(
                Diagnostic(
                    DiagnosticKind.ERROR,
                    context.root,
                    "Refusing to inspect "
                    f"{oversized_files} {noun} larger than "
                    f"max_file_bytes={context.limits.max_file_bytes}; scan incomplete",
                )
            )

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
    if path.name == "package.json" and _is_installed_package_manifest(path):
        return "manifest"
    if path.parent == Path(".claude") and path.name in {"settings.json", "settings.local.json"}:
        return "startup"
    if path == Path(".vscode/tasks.json"):
        return "startup"
    return None


def _is_installed_package_manifest(path: Path) -> bool:
    parts = path.parts
    node_modules_index = max(
        (index for index, part in enumerate(parts) if part == "node_modules"),
        default=-1,
    )
    if node_modules_index < 0:
        return False
    tail = parts[node_modules_index + 1 :]
    if len(tail) == 2:
        package, filename = tail
        return filename == "package.json" and not package.startswith("@")
    if len(tail) == 3:
        scope, package, filename = tail
        return (
            scope.startswith("@")
            and bool(package)
            and filename == "package.json"
        )
    return False


def _file_safety_error(item: DiscoveredFile, context: ScanContext) -> Diagnostic | None:
    if item.symlink:
        return Diagnostic(
            DiagnosticKind.ERROR,
            item.absolute_path,
            "Refusing to inspect symlinked repository file",
        )
    if item.size < 0:
        return Diagnostic(
            DiagnosticKind.ERROR,
            item.absolute_path,
            "File reports an invalid negative size; scan incomplete",
        )
    return None


def _match_package_intelligence(
    name: str, version: str, database: ThreatDatabase
) -> PackageIntelligence | None:
    if version in database.package_versions.get(name, frozenset()):
        return _package_intelligence(
            database,
            package_key=name,
            version=version,
            severity=Severity.CRITICAL,
            confidence=Confidence.CONFIRMED,
        )
    if version in database.contested_package_versions.get(name, frozenset()):
        return _package_intelligence(
            database,
            package_key=name,
            version=version,
            severity=Severity.HIGH,
            confidence=Confidence.CONTESTED,
        )
    if not _is_valid_keyv_wildcard_package(name):
        return None
    for package_key, versions, confidence, severity in (
        *(
            (prefix, versions, Confidence.CONFIRMED, Severity.CRITICAL)
            for prefix, versions in database.wildcard_package_versions.items()
        ),
        *(
            (prefix, versions, Confidence.CONTESTED, Severity.HIGH)
            for prefix, versions in database.contested_wildcard_package_versions.items()
        ),
    ):
        if package_key == "@keyv/" and version in versions:
            return _package_intelligence(
                database,
                package_key=package_key,
                version=version,
                severity=severity,
                confidence=confidence,
            )
    return None


def _package_intelligence(
    database: ThreatDatabase,
    *,
    package_key: str,
    version: str,
    severity: Severity,
    confidence: Confidence,
) -> PackageIntelligence:
    sources = database.package_version_sources.get(package_key, {}).get(version, ())
    return PackageIntelligence(severity, confidence, sources)


def _is_valid_keyv_wildcard_package(name: str) -> bool:
    if len(name) > _MAX_NPM_PACKAGE_NAME_LENGTH or not name.startswith("@keyv/"):
        return False
    segment = name.removeprefix("@keyv/")
    return (
        bool(segment)
        and not segment.startswith(".")
        and _VALID_KEYV_PACKAGE_SEGMENT.fullmatch(segment) is not None
    )


def _package_evidence(
    name: str, version: str, intelligence: PackageIntelligence
) -> str:
    evidence = f"{name}@{version}"
    if intelligence.confidence is not Confidence.CONTESTED:
        return evidence
    sources = ", ".join(intelligence.sources) or "unattributed"
    return f"{evidence} (contested intelligence; sources: {sources})"


def _lockfile_finding(
    package: ResolvedPackage, path: Path, intelligence: PackageIntelligence
) -> Finding:
    return _finding(
        rule_id="compromised-lockfile-version",
        severity=intelligence.severity,
        confidence=intelligence.confidence,
        path=path,
        evidence=_package_evidence(package.name, package.version, intelligence),
    )


def _installed_package_findings(
    package: InstalledPackage,
    path: Path,
    database: ThreatDatabase,
) -> tuple[Finding, ...]:
    intelligence = _match_package_intelligence(package.name, package.version, database)
    package_evidence = f"{package.name}@{package.version}"
    findings: list[Finding] = []
    if intelligence is not None:
        findings.append(
            _finding(
                rule_id="compromised-installed-version",
                severity=intelligence.severity,
                confidence=intelligence.confidence,
                path=path,
                evidence=_package_evidence(
                    package.name,
                    package.version,
                    intelligence,
                ),
            )
        )
    if package.preinstall is not None and _is_campaign_invocation(package.preinstall):
        campaign_correlated = (
            intelligence is not None
            and intelligence.confidence is not Confidence.CONTESTED
        )
        findings.append(
            _finding(
                rule_id=(
                    "campaign-lifecycle-script"
                    if campaign_correlated
                    else "suspicious-lifecycle-script"
                ),
                severity=Severity.CRITICAL if campaign_correlated else Severity.MEDIUM,
                confidence=Confidence.HIGH if campaign_correlated else Confidence.REVIEW,
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
    index = 0
    while index < len(tokens) and _is_shell_environment_assignment(tokens[index]):
        index += 1
    return _argv_invokes_campaign_file(tokens, start=index, split_depth=split_depth)


def _argv_invokes_campaign_file(
    tokens: tuple[str, ...], *, start: int, split_depth: int
) -> bool:
    resolved = _unwrap_environment_argv(tokens, start=start, split_depth=split_depth)
    if resolved is None:
        return False
    command_tokens, command_start, _ = resolved
    if command_start >= len(command_tokens):
        return False
    executable = _command_basename(command_tokens[command_start])
    if executable in _CAMPAIGN_FILENAMES:
        return True
    if executable not in _SCRIPT_INTERPRETERS:
        return False
    return _runtime_entrypoint_is_campaign(
        executable,
        command_tokens,
        start=command_start + 1,
    )


def _unwrap_environment_argv(
    tokens: tuple[str, ...], *, start: int, split_depth: int
) -> tuple[tuple[str, ...], int, int] | None:
    command_tokens = tokens
    command_start = start
    current_depth = split_depth
    while command_start < len(command_tokens) and _command_basename(
        command_tokens[command_start]
    ) == "env":
        resolved = _parse_environment_arguments(
            command_tokens,
            start=command_start + 1,
            split_depth=current_depth,
        )
        if resolved is None:
            return None
        command_tokens, command_start, current_depth = resolved
    return command_tokens, command_start, current_depth


def _parse_environment_arguments(
    arguments: tuple[str, ...], *, start: int, split_depth: int
) -> tuple[tuple[str, ...], int, int] | None:
    index = start
    options_allowed = True

    while index < len(arguments):
        token = arguments[index]
        if not options_allowed:
            if _is_environment_assignment(token):
                index += 1
                continue
            return arguments, index, split_depth
        if token == "--":
            options_allowed = False
            index += 1
            continue
        if token == "-":
            index += 1
            continue
        if token.startswith("--"):
            parsed = _parse_long_environment_option(
                arguments,
                index,
            )
        elif token.startswith("-"):
            parsed = _parse_short_environment_options(
                arguments,
                index,
            )
        elif _is_environment_assignment(token):
            options_allowed = False
            index += 1
            continue
        else:
            return arguments, index, split_depth
        if parsed is None:
            return None
        consumed, split_value = parsed
        if split_value is None:
            index += consumed
            continue
        return _expand_environment_split_string(
            arguments,
            next_index=index + consumed,
            value=split_value,
            split_depth=split_depth,
        )

    return arguments, len(arguments), split_depth


def _parse_long_environment_option(
    arguments: tuple[str, ...], index: int
) -> tuple[int, str | None] | None:
    token = arguments[index]
    if token in {"--ignore-environment", "--debug"}:
        return 1, None
    if token == "--null":
        return None
    if token in {"--help", "--version"}:
        return None
    if token == "--unset":
        if index + 1 >= len(arguments) or not _is_valid_environment_name(
            arguments[index + 1]
        ):
            return None
        return 2, None
    if token.startswith("--unset="):
        return (1, None) if _is_valid_environment_name(token.partition("=")[2]) else None
    if token == "--chdir":
        if index + 1 >= len(arguments) or "\0" in arguments[index + 1]:
            return None
        return 2, None
    if token.startswith("--chdir="):
        return (1, None) if "\0" not in token.partition("=")[2] else None
    if token == "--split-string":
        if index + 1 >= len(arguments):
            return None
        return 2, arguments[index + 1]
    if token.startswith("--split-string="):
        return 1, token.partition("=")[2]
    return None


def _parse_short_environment_options(
    arguments: tuple[str, ...], index: int
) -> tuple[int, str | None] | None:
    token = arguments[index]
    position = 1
    while position < len(token):
        option = token[position]
        if option in "iv":
            position += 1
            continue
        if option == "0":
            return None
        if option in "CPu":
            consumed = 1 if position + 1 < len(token) else 2
            if consumed == 2 and index + 1 >= len(arguments):
                return None
            value = token[position + 1 :] if consumed == 1 else arguments[index + 1]
            if "\0" in value or (option == "u" and not _is_valid_environment_name(value)):
                return None
            return consumed, None
        if option == "S":
            attached = token[position + 1 :]
            consumed = 1 if attached else 2
            if consumed == 2:
                if index + 1 >= len(arguments):
                    return None
                value = arguments[index + 1]
            else:
                value = attached
            return consumed, value
        return None
    return 1, None


def _expand_environment_split_string(
    arguments: tuple[str, ...],
    next_index: int,
    value: str,
    *,
    split_depth: int,
) -> tuple[tuple[str, ...], int, int] | None:
    if (
        split_depth >= _MAX_ENV_SPLIT_DEPTH
        or len(value) > _MAX_COMMAND_LENGTH
        or "\0" in value
    ):
        return None
    expanded = _parse_environment_split_string(value)
    if expanded is None:
        return None
    combined = tuple(chain(expanded, islice(arguments, next_index, None)))
    return _parse_environment_arguments(
        combined,
        start=0,
        split_depth=split_depth + 1,
    )


def _is_environment_assignment(token: str) -> bool:
    separator = token.find("=")
    return separator > 0 and "\0" not in token


def _is_shell_environment_assignment(token: str) -> bool:
    return _SHELL_ENVIRONMENT_ASSIGNMENT.fullmatch(token) is not None


def _is_valid_environment_name(name: str) -> bool:
    return bool(name) and "=" not in name and "\0" not in name


def _parse_environment_split_string(value: str) -> tuple[str, ...] | None:
    arguments: list[str] = []
    argument: list[str] = []
    argument_started = False
    quote: str | None = None
    index = 0

    def finish_argument() -> None:
        nonlocal argument_started
        if argument_started:
            arguments.append("".join(argument))
            argument.clear()
            argument_started = False

    while index < len(value):
        character = value[index]
        if quote == "'":
            if character == "'":
                quote = None
            elif character == "\\" and index + 1 < len(value) and value[index + 1] in {
                "'",
                "\\",
            }:
                argument.append(value[index + 1])
                index += 1
            else:
                argument.append(character)
            index += 1
            continue

        if character in {'"', "'"}:
            if quote is None:
                quote = character
            elif quote == character:
                quote = None
            else:
                argument.append(character)
            argument_started = True
            index += 1
            continue
        if character == "\\":
            if index + 1 >= len(value):
                return None
            escaped = value[index + 1]
            if escaped == "c":
                if quote == '"':
                    return None
                finish_argument()
                return tuple(arguments)
            if escaped == "_":
                if quote == '"':
                    argument.append(" ")
                    argument_started = True
                else:
                    finish_argument()
                index += 2
                continue
            escape_values = {
                "f": "\f",
                "n": "\n",
                "r": "\r",
                "t": "\t",
                "v": "\v",
                "#": "#",
                "$": "$",
                '"': '"',
                "'": "'",
                "\\": "\\",
                " ": " ",
                "\t": "\t",
            }
            if escaped not in escape_values:
                return None
            argument.append(escape_values[escaped])
            argument_started = True
            index += 2
            continue
        if quote is None and character in " \t":
            finish_argument()
            index += 1
            continue
        if quote is None and character == "#" and not argument:
            break
        argument.append(character)
        argument_started = True
        index += 1

    if quote is not None:
        return None
    finish_argument()
    return tuple(arguments)


def _runtime_entrypoint_is_campaign(
    executable: str, arguments: tuple[str, ...], *, start: int
) -> bool:
    deno_run_pending = executable in {"deno", "deno.exe"}
    for index in range(start, len(arguments)):
        token = arguments[index]
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
        technique_ids=_TECHNIQUES_BY_RULE[rule_id],
        remediation_url=_REMEDIATION_URL,
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

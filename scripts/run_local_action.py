"""Run the repository-local composite action without installing AgentSec."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import TextIO, cast

_VALID_SCOPES = frozenset({"source", "dependencies", "repository"})
_VALID_REDACTION = frozenset({"true", "false"})


def main() -> int:
    workspace = Path(os.environ.get("GITHUB_WORKSPACE", os.getcwd())).resolve()
    action_root = Path(os.environ.get("GITHUB_ACTION_PATH", Path(__file__).parents[1])).resolve()
    runner_temp = Path(os.environ.get("RUNNER_TEMP", tempfile.gettempdir())).resolve()
    scope = os.environ.get("AGENTSEC_SCOPE", "source")
    redact = os.environ.get("AGENTSEC_REDACT", "true").lower()
    target_input = os.environ.get("AGENTSEC_PATH", ".")
    output_input = os.environ.get("AGENTSEC_SARIF_FILE", "")

    if scope not in _VALID_SCOPES:
        return _fail(f"invalid scope: {scope}")
    if redact not in _VALID_REDACTION:
        return _fail("redact must be true or false")
    if "\n" in output_input or "\r" in output_input:
        return _fail("SARIF output path must stay on one line")

    target = _resolve_from(workspace, target_input)
    output = (
        _resolve_from(workspace, output_input)
        if output_input
        else runner_temp / "agentsec.sarif"
    )
    if "\n" in str(output) or "\r" in str(output):
        return _fail("SARIF output path must stay on one line")
    if output.is_relative_to(target):
        return _fail("SARIF output must stay outside the scanned repository")

    source_root = action_root / "src"
    if not (source_root / "agentsec" / "__init__.py").is_file():
        return _fail(f"AgentSec source unavailable below {action_root}")

    try:
        runner_temp.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=".agentsec-action-",
            suffix=".sarif",
            dir=runner_temp,
        )
        os.close(descriptor)
    except OSError as error:
        return _fail(f"cannot create temporary SARIF file: {error}")

    temporary = Path(temporary_name)
    try:
        status = _scan(
            action_root=action_root,
            source_root=source_root,
            target=target,
            scope=scope,
            redact=redact == "true",
            stream_path=temporary,
        )
        if status not in (0, 1, 2):
            return _fail(f"unexpected AgentSec exit code: {status}")
        if not _valid_sarif(temporary, expected_exit=status):
            return _fail("AgentSec did not produce a valid fail-closed SARIF report")
        try:
            output.parent.mkdir(parents=True, exist_ok=True)
            temporary.replace(output)
        except OSError as error:
            return _fail(f"cannot publish SARIF report: {error}")
        _write_outputs(sarif_file=output, exit_code=status)
        return status
    finally:
        temporary.unlink(missing_ok=True)


def _resolve_from(base: Path, value: str) -> Path:
    path = Path(value)
    return (path if path.is_absolute() else base / path).resolve()


def _scan(
    *,
    action_root: Path,
    source_root: Path,
    target: Path,
    scope: str,
    redact: bool,
    stream_path: Path,
) -> int:
    command = [
        sys.executable,
        "-m",
        "agentsec",
        "scan",
        str(target),
        "--scope",
        scope,
        "--format",
        "sarif",
        "--progress=never",
    ]
    if redact:
        command.append("--redact")
    environment = os.environ.copy()
    existing_pythonpath = environment.get("PYTHONPATH")
    environment["PYTHONPATH"] = (
        f"{source_root}{os.pathsep}{existing_pythonpath}"
        if existing_pythonpath
        else str(source_root)
    )
    with stream_path.open("w", encoding="utf-8", newline="\n") as stream:
        completed = subprocess.run(
            command,
            cwd=action_root,
            env=environment,
            check=False,
            shell=False,
            stdout=cast(TextIO, stream),
        )
    return completed.returncode


def _valid_sarif(path: Path, *, expected_exit: int) -> bool:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        run = payload["runs"][0]
        reported_exit = run["invocations"][0]["exitCode"]
        complete = run["properties"]["agentsec.complete"]
    except (IndexError, KeyError, OSError, TypeError, UnicodeError, json.JSONDecodeError):
        return False
    return (
        payload.get("version") == "2.1.0"
        and reported_exit == expected_exit
        and isinstance(complete, bool)
        and complete is (expected_exit != 2)
    )


def _write_outputs(*, sarif_file: Path | None = None, exit_code: int) -> None:
    output_file = os.environ.get("GITHUB_OUTPUT")
    if not output_file:
        return
    try:
        with Path(output_file).open("a", encoding="utf-8", newline="\n") as stream:
            if sarif_file is not None:
                stream.write(f"sarif-file={sarif_file.resolve()}\n")
            stream.write(f"exit-code={exit_code}\n")
    except OSError as error:
        print(f"agentsec action: cannot write GitHub outputs: {error}", file=sys.stderr)


def _fail(message: str) -> int:
    print(f"agentsec action: {message}", file=sys.stderr)
    _write_outputs(exit_code=2)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

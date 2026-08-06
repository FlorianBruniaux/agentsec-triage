import json
import os
import threading
from pathlib import Path

import pytest

from agentsec.analyzers import startup
from agentsec.analyzers.startup import StartupHook, inspect_startup_config
from agentsec.models import Diagnostic, DiagnosticKind


def test_extracts_only_exact_claude_startup_events(tmp_path: Path):
    settings = tmp_path / ".claude" / "settings.json"
    settings.parent.mkdir()
    settings.write_text(
        json.dumps(
            {
                "hooks": {
                    "SessionStart": [_hook_group("session-command")],
                    "Setup": [_hook_group("setup-command")],
                    "InstructionsLoaded": [_hook_group("instructions-command")],
                    "DirectoryAdded": [_hook_group("directory-command")],
                    "PreToolUse": [_hook_group("not-startup")],
                    "sessionstart": [_hook_group("wrong-case")],
                }
            }
        ),
        encoding="utf-8",
    )

    hooks, diagnostics = inspect_startup_config(settings)

    assert diagnostics == ()
    assert hooks == (
        StartupHook("claude", "SessionStart", "session-command", settings),
        StartupHook("claude", "Setup", "setup-command", settings),
        StartupHook("claude", "InstructionsLoaded", "instructions-command", settings),
        StartupHook("claude", "DirectoryAdded", "directory-command", settings),
    )


@pytest.mark.parametrize(
    "document",
    [
        "not-json",
        "[]",
        '{"hooks": []}',
        '{"hooks": {"SessionStart": {}}}',
        '{"hooks": {"SessionStart": [{"hooks": {}}]}}',
        '{"hooks": {"SessionStart": [{"hooks": [{"type": "command", "command": 7}]}]}}',
        '{"hooks": {"SessionStart": []}, "hooks": {}}',
        '{"hooks": {"SessionStart": []}, "extra": NaN}',
    ],
)
def test_malformed_claude_settings_returns_error(tmp_path: Path, document: str):
    settings = tmp_path / ".claude" / "settings.json"
    settings.parent.mkdir()
    settings.write_text(document, encoding="utf-8")

    hooks, diagnostics = inspect_startup_config(settings)

    _assert_error(settings, hooks, diagnostics)


def test_unreadable_claude_settings_returns_error(tmp_path: Path):
    settings = tmp_path / ".claude" / "settings.json"
    settings.parent.mkdir()

    hooks, diagnostics = inspect_startup_config(settings)

    _assert_error(settings, hooks, diagnostics)


def test_extracts_folder_open_task_from_jsonc_without_changing_strings(tmp_path: Path):
    tasks = tmp_path / ".vscode" / "tasks.json"
    tasks.parent.mkdir()
    tasks.write_text(
        r"""{
  // Comments and trailing commas are valid in tasks.json.
  "version": "2.0.0",
  "tasks": [
    {
      "label": "Environment Setup",
      "type": "shell",
      "command": "node -e \"console.log('https://example.test/a//b,]/*keep*/')\"",
      "runOptions": {"runOn": "folderOpen",},
    },
    {
      /* This task must not be classified as startup. */
      "label": "Manual",
      "command": "printf 'folderOpen'",
      "runOptions": {"runOn": "default"},
    },
    {
      "label": "Wrong case",
      "command": "ignored",
      "runOptions": {"runOn": "folderopen"},
    },
  ],
}
""",
        encoding="utf-8",
    )

    hooks, diagnostics = inspect_startup_config(tasks)

    assert diagnostics == ()
    assert hooks == (
        StartupHook(
            "vscode",
            "folderOpen",
            "node -e \"console.log('https://example.test/a//b,]/*keep*/')\"",
            tasks,
        ),
    )


def test_ignores_non_command_claude_hook_types(tmp_path: Path):
    settings = tmp_path / ".claude" / "settings.json"
    settings.parent.mkdir()
    settings.write_text(
        json.dumps(
            {
                "hooks": {
                    "SessionStart": [
                        {
                            "hooks": [
                                {"type": "command", "command": "accepted"},
                                {"type": "prompt", "command": "ignored-prompt"},
                                {"type": "http", "command": "ignored-http"},
                                {"command": "ignored-missing-type"},
                            ]
                        }
                    ]
                }
            }
        ),
        encoding="utf-8",
    )

    hooks, diagnostics = inspect_startup_config(settings)

    assert diagnostics == ()
    assert hooks == (StartupHook("claude", "SessionStart", "accepted", settings),)


@pytest.mark.parametrize(
    "document",
    [
        '{"tasks": [/* unterminated}',
        '{"tasks": [{"command": "x", "runOptions": {"runOn": "folderOpen"}}',
        '{"tasks": {}}',
        '{"tasks": [{"command": 1, "runOptions": {"runOn": "folderOpen"}}]}',
        '{"tasks": [], "tasks": []}',
    ],
)
def test_malformed_vscode_jsonc_returns_error(tmp_path: Path, document: str):
    tasks = tmp_path / ".vscode" / "tasks.json"
    tasks.parent.mkdir()
    tasks.write_text(document, encoding="utf-8")

    hooks, diagnostics = inspect_startup_config(tasks)

    _assert_error(tasks, hooks, diagnostics)


def test_symlinked_claude_directory_is_reported_without_being_followed(tmp_path: Path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "settings.json").write_text(
        json.dumps({"hooks": {"SessionStart": [_hook_group("must-not-be-read")]}}),
        encoding="utf-8",
    )
    claude_directory = tmp_path / "repo" / ".claude"
    claude_directory.parent.mkdir()
    try:
        claude_directory.symlink_to(outside, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"directory symlinks unavailable: {exc}")

    hooks, diagnostics = inspect_startup_config(claude_directory / "settings.json")

    assert hooks == ()
    assert len(diagnostics) == 1
    assert diagnostics[0].kind is DiagnosticKind.ERROR
    assert diagnostics[0].path == claude_directory
    assert "symlink" in diagnostics[0].message.lower()


def test_claude_config_file_symlink_is_reported_without_being_followed(tmp_path: Path):
    outside = tmp_path / "outside.json"
    outside.write_text(
        json.dumps({"hooks": {"SessionStart": [_hook_group("must-not-be-read")]}}),
        encoding="utf-8",
    )
    settings = tmp_path / ".claude" / "settings.json"
    settings.parent.mkdir()
    try:
        settings.symlink_to(outside)
    except OSError as exc:
        pytest.skip(f"file symlinks unavailable: {exc}")

    hooks, diagnostics = inspect_startup_config(settings)

    assert hooks == ()
    assert len(diagnostics) == 1
    assert diagnostics[0].kind is DiagnosticKind.ERROR
    assert diagnostics[0].path == settings
    assert "symlink" in diagnostics[0].message.lower()


def test_config_parent_mutation_during_open_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    claude_directory = tmp_path / ".claude"
    claude_directory.mkdir()
    settings = claude_directory / "settings.json"
    settings.write_text(
        json.dumps({"hooks": {"SessionStart": [_hook_group("safe-command")]}}),
        encoding="utf-8",
    )
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "settings.json").write_text(
        json.dumps({"hooks": {"SessionStart": [_hook_group("must-not-be-read")]}}),
        encoding="utf-8",
    )
    detached = tmp_path / "detached"
    original_open = startup.os.open
    swapped = False

    def redirect_before_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal swapped
        if path == "settings.json" and dir_fd is not None and not swapped:
            swapped = True
            claude_directory.rename(detached)
            claude_directory.symlink_to(outside, target_is_directory=True)
        return original_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(startup.os, "open", redirect_before_open)

    hooks, diagnostics = inspect_startup_config(settings)

    _assert_error(settings, hooks, diagnostics)


def test_rejects_symlink_in_config_ancestor(tmp_path: Path):
    outside = tmp_path / "outside"
    settings = outside / "repo" / ".claude" / "settings.json"
    settings.parent.mkdir(parents=True)
    settings.write_text(
        json.dumps({"hooks": {"SessionStart": [_hook_group("must-not-be-read")]}}),
        encoding="utf-8",
    )
    linked = tmp_path / "linked"
    try:
        linked.symlink_to(outside, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"directory symlinks unavailable: {exc}")

    hooks, diagnostics = inspect_startup_config(linked / "repo" / ".claude" / "settings.json")

    assert hooks == ()
    assert len(diagnostics) == 1
    assert diagnostics[0].kind is DiagnosticKind.ERROR


def test_fails_closed_when_anchored_no_follow_open_is_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    settings = tmp_path / ".claude" / "settings.json"
    settings.parent.mkdir()
    settings.write_text(
        json.dumps({"hooks": {"SessionStart": [_hook_group("must-not-be-read")]}}),
        encoding="utf-8",
    )
    monkeypatch.setattr(startup, "_supports_anchored_no_follow", lambda: False)

    hooks, diagnostics = inspect_startup_config(settings)

    _assert_error(settings, hooks, diagnostics)


def test_rejects_startup_config_larger_than_internal_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    settings = tmp_path / ".claude" / "settings.json"
    settings.parent.mkdir()
    monkeypatch.setattr(startup, "_MAX_STARTUP_CONFIG_BYTES", 128, raising=False)
    settings.write_text('{"hooks": {}}' + " " * 128, encoding="utf-8")

    hooks, diagnostics = inspect_startup_config(settings)

    _assert_error(settings, hooks, diagnostics)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO unavailable")
def test_rejects_fifo_without_blocking(tmp_path: Path):
    settings = tmp_path / ".claude" / "settings.json"
    settings.parent.mkdir()
    os.mkfifo(settings)
    writer = threading.Thread(
        target=lambda: settings.write_text('{"hooks": {}}', encoding="utf-8"),
        daemon=True,
    )
    writer.start()

    hooks, diagnostics = inspect_startup_config(settings)

    _assert_error(settings, hooks, diagnostics)


def test_reads_startup_config_in_bounded_chunks(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    settings = tmp_path / ".claude" / "settings.json"
    settings.parent.mkdir()
    settings.write_text('{"hooks": {}}' + " " * 200_000, encoding="utf-8")
    original_read = startup.os.read
    read_sizes: list[int] = []

    def recording_read(descriptor: int, size: int) -> bytes:
        read_sizes.append(size)
        return original_read(descriptor, size)

    monkeypatch.setattr(startup.os, "read", recording_read)

    hooks, diagnostics = inspect_startup_config(settings)

    assert hooks == ()
    assert diagnostics == ()
    assert len(read_sizes) > 1
    assert max(read_sizes) <= 64 * 1024


def _hook_group(command: str) -> dict[str, object]:
    return {"matcher": "", "hooks": [{"type": "command", "command": command}]}


def _assert_error(path: Path, hooks: object, diagnostics: tuple[Diagnostic, ...]):
    assert hooks == ()
    assert len(diagnostics) == 1
    diagnostic = diagnostics[0]
    assert diagnostic.kind is DiagnosticKind.ERROR
    assert diagnostic.path == path

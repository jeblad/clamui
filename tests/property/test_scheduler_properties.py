"""
Property-based tests for scheduler target validation and command serialization.

The scheduler emits target paths into both systemd ExecStart lines and cron
commands.  These tests parse those generated representations without executing
them, so a missing quote or backend-specific escape changes the observed argv.
"""

from __future__ import annotations

import shlex
import string
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from hypothesis import example, given
from hypothesis import strategies as st

from src.core import scheduler as scheduler_module
from src.core.scheduler import ScheduleFrequency, Scheduler, _validate_target_paths

pytestmark = pytest.mark.property


CLI_COMMAND = ["flatpak", "run", "--command=clamui-scheduled-scan", "org.example.ClamUI"]
ACCEPTED_PATH_ALPHABET = (
    string.ascii_letters + string.digits + "/._- " + "'\"$`;&|()<>[]{}*?!#~=%+,:@\\" + "éΩ中🙂"
)
PATH_SUFFIX = st.text(alphabet=ACCEPTED_PATH_ALPHABET, max_size=45)
ACCEPTED_TARGET_PATH = st.builds(lambda suffix: f"/scan/{suffix}", PATH_SUFFIX)
NEWLINE_TARGET_PATH = st.builds(
    lambda prefix, newline, suffix: f"/scan/{prefix}{newline}{suffix}",
    PATH_SUFFIX,
    st.sampled_from(("\n", "\r")),
    PATH_SUFFIX,
)
NULL_TARGET_PATH = st.builds(
    lambda prefix, suffix: f"/scan/{prefix}\x00{suffix}",
    PATH_SUFFIX,
    PATH_SUFFIX,
)


def _target_is_accepted_by_contract(target: str) -> bool:
    """Independent input oracle for the scheduler's documented rejection set."""
    return "\n" not in target and "\r" not in target and "\x00" not in target


def _expected_argv(targets: list[str]) -> list[str]:
    argv = [*CLI_COMMAND, "--skip-on-battery", "--auto-quarantine"]
    for target in targets:
        argv.extend(("--target", target))
    return argv


def _assert_systemd_literals_are_escaped(command: str) -> None:
    """Reject systemd variable/specifier expansion before decoding literals."""
    index = 0
    while index < len(command):
        character = command[index]
        if character in "$%":
            assert index + 1 < len(command)
            assert command[index + 1] == character
            index += 2
            continue
        index += 1


def _parse_systemd_execstart(unit: str) -> list[str]:
    """Parse the generated ExecStart words after systemd's literal escapes."""
    execstart_lines = [line for line in unit.splitlines() if line.startswith("ExecStart=")]
    assert len(execstart_lines) == 1
    command = execstart_lines[0].removeprefix("ExecStart=")
    _assert_systemd_literals_are_escaped(command)
    return [word.replace("$$", "$").replace("%%", "%") for word in shlex.split(command)]


def _cron_command_before_shell(command: str) -> str:
    """Model Cronie's do_command.c escaped-percent preprocessing before the shell."""
    shell_command: list[str] = []
    index = 0
    while index < len(command):
        character = command[index]
        if character == "\\":
            backslash_start = index
            while index < len(command) and command[index] == "\\":
                index += 1
            backslash_count = index - backslash_start
            if index < len(command) and command[index] == "%":
                if backslash_count % 2 == 0:
                    raise AssertionError("unescaped cron percent would become stdin")
                shell_command.extend("\\" * (backslash_count - 1))
                shell_command.append("%")
                index += 1
                continue
            shell_command.extend("\\" * backslash_count)
            continue
        if character == "%":
            raise AssertionError("unescaped cron percent would become stdin")
        shell_command.append(character)
        index += 1
    return "".join(shell_command)


def _assert_shell_metacharacters_are_inert(command: str) -> None:
    """Reject shell-active control, glob, and expansion syntax outside safe quotes."""
    state = "unquoted"
    index = 0
    while index < len(command):
        character = command[index]
        if state == "single":
            if character == "'":
                state = "unquoted"
            index += 1
            continue
        if state == "double":
            if character == '"':
                state = "unquoted"
            elif character == "\\" and index + 1 < len(command) and command[index + 1] in '\\"$`\n':
                index += 1
            elif character in "$`":
                raise AssertionError("shell expansion remains active inside double quotes")
            index += 1
            continue

        if character == "'":
            state = "single"
        elif character == '"':
            state = "double"
        elif character == "\\":
            assert index + 1 < len(command)
            index += 1
        elif character in "$`;|&()<>*?[]{}~#":
            raise AssertionError("shell metacharacter remains active")
        index += 1
    assert state == "unquoted"


def _capture_generated_crontab(targets: list[str]) -> str:
    """Capture cron's generated input with a per-example subprocess boundary."""
    scheduler = object.__new__(Scheduler)
    scheduler._get_cli_command_path = lambda: list(CLI_COMMAND)
    written_crontabs: list[str] = []

    def fake_run(_command: list[str], **kwargs: object) -> SimpleNamespace:
        crontab_input = kwargs.get("input")
        if crontab_input is None:
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        assert isinstance(crontab_input, str)
        written_crontabs.append(crontab_input)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    with patch.object(scheduler_module.subprocess, "run", side_effect=fake_run):
        success, error = scheduler._enable_cron_schedule(
            ScheduleFrequency.DAILY,
            "02:00",
            targets,
            day_of_week=0,
            day_of_month=1,
            skip_on_battery=True,
            auto_quarantine=True,
        )

    assert success is True
    assert error is None
    assert len(written_crontabs) == 1
    return written_crontabs[0]


def _parse_generated_cron_argv(crontab: str) -> list[str]:
    """Parse the generated cron shell command without running it."""
    lines = crontab.splitlines()
    marker_index = lines.index(Scheduler.CRON_MARKER)
    fields = lines[marker_index + 1].split(maxsplit=5)
    assert len(fields) == 6
    command = _cron_command_before_shell(fields[5])
    _assert_shell_metacharacters_are_inert(command)
    return shlex.split(command)


@given(
    st.lists(
        st.one_of(ACCEPTED_TARGET_PATH, NEWLINE_TARGET_PATH, NULL_TARGET_PATH),
        min_size=1,
        max_size=5,
    )
)
@example(["/scan/valid\ninjected-cron-line"])
@example(["/scan/valid\rinjected-cron-line"])
@example(["/scan/valid\x00truncated"])
def test_batch_validation_matches_independent_target_contract(targets: list[str]) -> None:
    """Only newline, carriage return, and NUL determine batch acceptance."""
    expected_acceptance = all(_target_is_accepted_by_contract(target) for target in targets)
    assert (_validate_target_paths(targets) is None) is expected_acceptance


@given(PATH_SUFFIX, PATH_SUFFIX)
def test_first_invalid_target_selects_its_distinct_error(
    first_suffix: str, second_suffix: str
) -> None:
    """A preceding newline error wins over a later NUL error, and vice versa."""
    newline_target = f"/first-{first_suffix}\nnewline"
    null_target = f"/second-{second_suffix}\x00null"

    newline_error = _validate_target_paths([newline_target])
    null_error = _validate_target_paths([null_target])

    assert newline_error is not None
    assert null_error is not None
    assert newline_error != null_error
    assert _validate_target_paths([newline_target, null_target]) == newline_error
    assert _validate_target_paths([null_target, newline_target]) == null_error


@given(st.lists(ACCEPTED_TARGET_PATH, min_size=1, max_size=4))
@example(["/scan/quotes'\";$(not-a-command)|&`*?[]{}%$HOME"])
@example(["/scan/$HOME/%h/$(not-a-command)/`not-a-command`/*?[]{};|&<>"])
def test_systemd_generated_execstart_preserves_target_argv(targets: list[str]) -> None:
    """Systemd escaping preserves every accepted target as one argv value."""
    assert all(_target_is_accepted_by_contract(target) for target in targets)
    unit = object.__new__(Scheduler)._generate_service_file(
        CLI_COMMAND,
        targets,
        skip_on_battery=True,
        auto_quarantine=True,
    )
    assert _parse_systemd_execstart(unit) == _expected_argv(targets)


@given(st.lists(ACCEPTED_TARGET_PATH, min_size=1, max_size=4))
@example(["/scan/quotes'\";$(not-a-command)|&`*?[]{}%$HOME"])
@example(["/scan/$HOME/%h/$(not-a-command)/`not-a-command`/*?[]{};|&<>"])
@example([r"/scan/backslash\%literal"])
@example(["/scan/a'b%c"])
def test_cron_generated_command_preserves_target_argv(targets: list[str]) -> None:
    """Cron serialization keeps injection-looking targets in target argv values."""
    assert all(_target_is_accepted_by_contract(target) for target in targets)
    crontab = _capture_generated_crontab(targets)
    assert _parse_generated_cron_argv(crontab) == _expected_argv(targets)

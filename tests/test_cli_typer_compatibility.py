"""Regression tests for the CLI boundary affected by Typer upgrades."""

import json
import re
from pathlib import Path
from unittest.mock import Mock

import pytest
from typer.testing import CliRunner

from skillforge.cli import app

runner = CliRunner()
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


@pytest.mark.parametrize(
    "command", [[], ["validate"], ["audit"], ["run-sandboxed"], ["firewall-mcp"]]
)
def test_help_renders_without_running_commands(command: list[str]) -> None:
    result = runner.invoke(app, [*command, "--help"])
    plain_output = _ANSI_RE.sub("", result.output)

    assert result.exit_code == 0, result.output
    assert "Usage" in plain_output
    assert "--help" in plain_output


@pytest.mark.parametrize(
    ("options", "timeout", "script_args"),
    [
        ([], 5.0, None),
        (["--timeout", "0.25"], 0.25, None),
        (["-t", "2.5"], 2.5, None),
        (["--", "--verbose", "two words"], 5.0, ["--verbose", "two words"]),
    ],
)
def test_sandbox_parameter_conversion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    options: list[str], timeout: float, script_args: list[str] | None,
) -> None:
    # Stub execution so these tests exercise parsing without launching a process.
    execute = Mock()
    execute.return_value.passed = True
    execute.return_value.to_dict.return_value = {"passed": True}
    monkeypatch.setattr("skillforge.sandbox_runner.run_in_sandbox", execute)
    script = tmp_path / "directory with spaces" / "script.py"

    result = runner.invoke(app, ["run-sandboxed", "--json", str(script), *options])

    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout) == {"passed": True}
    execute.assert_called_once_with(script, script_args=script_args, timeout_sec=timeout)


@pytest.mark.parametrize(
    "arguments",
    [[], ["script.py", "--timeout", "invalid"], ["script.py", "--timeout"],
     ["script.py", "--unknown-option"]],
)
def test_sandbox_usage_errors_do_not_execute(
    monkeypatch: pytest.MonkeyPatch, arguments: list[str],
) -> None:
    execute = Mock()
    monkeypatch.setattr("skillforge.sandbox_runner.run_in_sandbox", execute)

    result = runner.invoke(app, ["run-sandboxed", *arguments])

    assert result.exit_code == 2, result.output
    assert result.stderr
    execute.assert_not_called()


@pytest.mark.parametrize(
    ("options", "allowed_tools", "redact_secrets"),
    [
        ([], None, True),
        (["--allow-tool", "read", "-a", "write"], {"read", "write"}, True),
        (["--no-redact"], None, False),
    ],
)
def test_firewall_optional_lists_and_boolean_flags(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    options: list[str], allowed_tools: set[str] | None, redact_secrets: bool,
) -> None:
    firewall = Mock()
    firewall.return_value.run_stdio_proxy.return_value = 0
    monkeypatch.setattr("skillforge.mcp_firewall.MCPFirewall", firewall)
    log = tmp_path / "audit log.jsonl"

    result = runner.invoke(
        app, ["firewall-mcp", "--audit-log", str(log), *options,
              "--", "python", "-m", "example_server"],
    )

    assert result.exit_code == 0, result.output
    firewall.assert_called_once_with(
        allowed_tools=allowed_tools, audit_log_path=log, redact_secrets=redact_secrets,
    )
    firewall.return_value.run_stdio_proxy.assert_called_once_with(
        ["python", "-m", "example_server"]
    )

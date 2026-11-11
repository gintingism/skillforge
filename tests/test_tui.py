"""Tests for Terminal User Interface (TUI) Dashboard."""

from pathlib import Path

from typer.testing import CliRunner

from skillforge.cli import app
from skillforge.tui import create_token_bar, render_dashboard


def test_create_token_bar() -> None:
    bar_empty = create_token_bar(0, 1000, 10)
    assert "[----------] 0%" in bar_empty

    bar_half = create_token_bar(500, 1000, 10)
    assert "[=====-----] 50%" in bar_half

    bar_full = create_token_bar(1000, 1000, 10)
    assert "[==========] 100%" in bar_full


def test_render_dashboard_layout() -> None:
    layout = render_dashboard(Path("."))
    assert layout is not None
    assert len(layout.children) >= 3


def test_cli_tui_static() -> None:
    runner = CliRunner()
    res = runner.invoke(app, ["tui", "--static"])
    assert res.exit_code == 0
    assert "SKILLFORGE" in res.output
    assert "Context Token Budget" in res.output
    assert "Security & Integrity" in res.output

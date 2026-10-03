from pathlib import Path

import pytest

from skillforge.adapters import ClaudeAdapter, CopilotAdapter, detect_adapters
from skillforge.errors import AdapterError
from skillforge.skill import Skill


def test_copilot_adapter_installs_instruction_file(tmp_path: Path) -> None:
    skill = Skill("demo", "A demo", "# Demo\n")
    path = CopilotAdapter().install(skill, tmp_path)
    assert path == tmp_path / ".github" / "copilot-instructions.md"
    assert "name: demo" in path.read_text(encoding="utf-8")


def test_claude_adapter_installs_skill_directory(tmp_path: Path) -> None:
    skill = Skill("demo", "A demo", "# Demo\n")
    path = ClaudeAdapter().install(skill, tmp_path)
    assert path == tmp_path / ".claude" / "skills" / "demo" / "SKILL.md"
    assert path.exists()


def test_detect_adapters(tmp_path: Path) -> None:
    (tmp_path / ".claude").mkdir()
    assert [type(a).__name__ for a in detect_adapters(tmp_path)] == ["ClaudeAdapter"]


def test_detect_adapters_finds_both_targets(tmp_path: Path) -> None:
    (tmp_path / ".github").mkdir()
    (tmp_path / ".claude").mkdir()
    assert [type(a).__name__ for a in detect_adapters(tmp_path)] == [
        "CopilotAdapter",
        "ClaudeAdapter",
    ]


def test_claude_adapter_wraps_filesystem_errors(tmp_path: Path) -> None:
    (tmp_path / ".claude" / "skills").mkdir(parents=True)
    (tmp_path / ".claude" / "skills" / "demo").write_text("not a directory", encoding="utf-8")
    with pytest.raises(AdapterError, match="Unable to install"):
        ClaudeAdapter().install(Skill("demo", "A demo", ""), tmp_path)

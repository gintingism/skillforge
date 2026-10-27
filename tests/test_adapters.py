from pathlib import Path

import pytest

from skillforge.adapters import (
    AgentsMarkdownAdapter,
    AntigravityAdapter,
    ClaudeAdapter,
    ClineAdapter,
    CopilotAdapter,
    CursorAdapter,
    WindsurfAdapter,
    detect_adapters,
)
from skillforge.errors import AdapterError
from skillforge.skill import Skill, SkillPackage


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


def test_antigravity_adapter_installs_skill(tmp_path: Path) -> None:
    skill = Skill("antigravity-test", "Antigravity skill", "# Test\n")
    path = AntigravityAdapter().install(skill, tmp_path)
    assert path == tmp_path / ".gemini" / "config" / "skills" / "antigravity-test" / "SKILL.md"
    assert path.exists()


def test_windsurf_adapter_installs_skill(tmp_path: Path) -> None:
    skill = Skill("windsurf-test", "Windsurf skill", "# Test\n")
    path = WindsurfAdapter().install(skill, tmp_path)
    assert path == tmp_path / ".windsurf" / "skills" / "windsurf-test" / "SKILL.md"
    assert path.exists()


def test_agents_markdown_adapter_updates_catalog(tmp_path: Path) -> None:
    skill = Skill("super-tool", "Does everything", "# Instructions\nRun carefully.\n")
    path = AgentsMarkdownAdapter().install(skill, tmp_path)
    assert path == tmp_path / "AGENTS.md"
    content = path.read_text(encoding="utf-8")
    assert "<!-- skillforge:super-tool:start -->" in content
    assert "### Skill: super-tool" in content
    assert "Run carefully." in content


def test_adapter_installs_full_package(tmp_path: Path) -> None:
    skill = Skill("package-demo", "Demo package", "# Package\n")
    package = SkillPackage(
        skill=skill,
        scripts={"run.py": "print('hello')\n"},
        references={"guide.md": "# Deep Guide\n"},
    )
    path = CursorAdapter().install(package, tmp_path)
    assert path == tmp_path / ".cursor" / "skills" / "package-demo" / "SKILL.md"
    assert (tmp_path / ".cursor" / "skills" / "package-demo" / "scripts" / "run.py").exists()
    assert (tmp_path / ".cursor" / "skills" / "package-demo" / "references" / "guide.md").exists()


def test_detect_adapters(tmp_path: Path) -> None:
    (tmp_path / ".claude").mkdir()
    assert [type(a).__name__ for a in detect_adapters(tmp_path)] == ["ClaudeCodeAdapter"]


def test_detect_adapters_finds_multiple_targets(tmp_path: Path) -> None:
    (tmp_path / ".github").mkdir()
    (tmp_path / ".gemini").mkdir()
    assert [type(a).__name__ for a in detect_adapters(tmp_path)] == [
        "CopilotAdapter",
        "AntigravityAdapter",
    ]


def test_claude_adapter_wraps_filesystem_errors(tmp_path: Path) -> None:
    (tmp_path / ".claude" / "skills").mkdir(parents=True)
    (tmp_path / ".claude" / "skills" / "demo").write_text("not a directory", encoding="utf-8")
    with pytest.raises(AdapterError, match="Unable to install"):
        ClaudeAdapter().install(Skill("demo", "A demo", ""), tmp_path)

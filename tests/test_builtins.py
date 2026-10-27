from pathlib import Path

from skillforge.adapters import ClaudeCodeAdapter, CopilotAdapter, CursorAdapter, detect_adapters
from skillforge.registry import BuiltinRegistry, CompositeRegistry, LocalRegistry


def test_builtin_registry_lists_and_loads_all_builtin_skills() -> None:
    registry = BuiltinRegistry()
    skills = registry.search("")
    assert {skill.name for skill in skills} == {
        "caveman",
        "self-improving-agent",
        "summarize",
        "tavily-search",
        "spec-driven-development",
        "agent-observability",
        "human-in-the-loop",
        "systematic-debugging",
        "antislop-code",
        "mcp-tool-designer",
        "context-compactor",
        "blast-radius-containment",
        "flaky-test-isolation",
        "zero-downtime-migration",
        "runtime-api-verification",
        "cognitive-loop-breaker",
    }
    assert registry.get("caveman").description
    assert registry.get("systematic-debugging").description
    assert registry.get("antislop-code").description
    assert registry.get("blast-radius-containment").description
    assert registry.get("flaky-test-isolation").description
    assert registry.get("zero-downtime-migration").description
    assert registry.get("runtime-api-verification").description
    assert registry.get("cognitive-loop-breaker").description


def test_builtin_registry_install_writes_skill(tmp_path: Path) -> None:
    target = BuiltinRegistry().install("caveman", tmp_path / "staging")
    assert target.read_text(encoding="utf-8").startswith("---\n")


def test_composite_registry_preserves_local_precedence(tmp_path: Path) -> None:
    local = tmp_path / "registry"
    local.mkdir()
    (local / "caveman").mkdir()
    (local / "caveman" / "SKILL.md").write_text(
        "---\nname: caveman\ndescription: Local override\n---\n\nLocal.\n",
        encoding="utf-8",
    )
    registry = CompositeRegistry((LocalRegistry(local), BuiltinRegistry()))
    assert registry.get("caveman").description == "Local override"


def test_detect_adapters_finds_cursor_and_claude_code(tmp_path: Path) -> None:
    (tmp_path / ".cursor").mkdir()
    (tmp_path / ".claude").mkdir()
    adapters = detect_adapters(tmp_path)
    assert [type(adapter).__name__ for adapter in adapters] == [
        "ClaudeCodeAdapter",
        "CursorAdapter",
    ]


def test_adapters_install_builtin_skill(tmp_path: Path) -> None:
    skill = BuiltinRegistry().get("caveman")
    assert (ClaudeCodeAdapter().install(skill, tmp_path)).exists()
    assert (CursorAdapter().install(skill, tmp_path)).exists()

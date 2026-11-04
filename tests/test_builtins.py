from pathlib import Path

from skillforge.adapters import ClaudeCodeAdapter, CopilotAdapter, CursorAdapter, detect_adapters
from skillforge.registry import BuiltinRegistry, CompositeRegistry, LocalRegistry
from skillforge.security import SkillAuditor


def test_builtin_registry_lists_and_loads_all_builtin_skills() -> None:
    registry = BuiltinRegistry()
    skills = registry.search("")
    assert {skill.name for skill in skills} == {
        "agent-observability",
        "antislop-code",
        "blast-radius-containment",
        "caveman",
        "code-review",
        "cognitive-loop-breaker",
        "context-compactor",
        "contract-test-generator",
        "dependency-upgrade",
        "flaky-test-isolation",
        "git-workflow",
        "human-in-the-loop",
        "mcp-tool-designer",
        "performance-profiler",
        "runtime-api-verification",
        "secret-sanitizer",
        "security-threat-modeler",
        "self-improving-agent",
        "skill-architect",
        "spec-driven-development",
        "summarize",
        "supply-chain-sentinel",
        "systematic-debugging",
        "tavily-search",
        "test-driven-development",
        "zero-downtime-migration",
    }
    auditor = SkillAuditor()
    for skill in skills:
        pkg = registry.get_package(skill.name)
        report = auditor.audit_package(pkg)
        assert report.passed is True, f"{skill.name} failed audit: {report.findings}"
        assert report.score == 100, f"{skill.name} had findings: {report.findings}"

    architect_pkg = registry.get_package("skill-architect")
    assert "mechanics.md" in architect_pkg.references


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

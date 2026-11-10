from pathlib import Path

from skillforge.adapters import ClaudeCodeAdapter, CopilotAdapter, CursorAdapter, detect_adapters
from skillforge.evals import run_evals
from skillforge.registry import BuiltinRegistry, CompositeRegistry, LocalRegistry
from skillforge.security import SkillAuditor


def test_builtin_registry_lists_and_loads_all_builtin_skills() -> None:
    registry = BuiltinRegistry()
    skills = registry.search("")
    assert {skill.name for skill in skills} == {
        "agent-observability",
        "antislop-code",
        "architecture-griller",
        "atomic-rollback-guard",
        "attention-anchor-ledger",
        "blast-radius-containment",
        "browser-qa-verifier",
        "caveman",
        "code-review",
        "cognitive-loop-breaker",
        "context-compactor",
        "contract-test-generator",
        "database-query-safety",
        "dependency-upgrade",
        "flaky-test-isolation",
        "git-workflow",
        "git-worktree-isolation",
        "human-in-the-loop",
        "lethal-trifecta-guard",
        "mcp-least-privilege-sentinel",
        "mcp-tool-designer",
        "memory-hygiene-sentinel",
        "performance-profiler",
        "runtime-api-verification",
        "secret-sanitizer",
        "security-threat-modeler",
        "self-improving-agent",
        "skill-architect",
        "spec-driven-development",
        "summarize",
        "supply-chain-lockfile-guard",
        "supply-chain-sentinel",
        "systematic-debugging",
        "tavily-search",
        "test-driven-development",
        "traceback-postmortem",
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

    for name_with_evals in ("architecture-griller", "browser-qa-verifier", "database-query-safety"):
        pkg = registry.get_package(name_with_evals)
        assert pkg.references, f"{name_with_evals} should bundle progressive disclosure references/"
        assert pkg.source_dir is not None
        eval_report = run_evals(pkg.source_dir)
        assert eval_report.passed is True, f"{name_with_evals} evals failed: {eval_report.results}"


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

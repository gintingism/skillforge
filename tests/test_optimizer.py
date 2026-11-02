import json
from pathlib import Path

from typer.testing import CliRunner

from skillforge.cli import app
from skillforge.optimizer import optimize_skill
from skillforge.skill import Skill, SkillPackage

runner = CliRunner()


def test_optimize_already_under_budget(tmp_path: Path) -> None:
    skill_dir = tmp_path / "compact-skill"
    skill_dir.mkdir()
    skill = Skill(
        name="compact-skill",
        description="A concise skill",
        body="# Compact Skill\n\n## Overview\nSimple workflow.\n",
    )
    pkg = SkillPackage(skill=skill)
    pkg.save(skill_dir)

    result = optimize_skill(skill_dir)
    assert result.original_lines == result.optimized_lines
    assert len(result.extracted_references) == 0
    assert result.passed_audit is True


def test_optimize_extracts_large_sections(tmp_path: Path) -> None:
    skill_dir = tmp_path / "bloated-skill"
    skill_dir.mkdir()

    # Generate a bloated SKILL.md with 600 lines
    lines = ["# Bloated Enterprise Skill", "", "## Core Workflow", "Always follow this core rule."]
    lines.append("")
    lines.append("## Detailed Database Guidelines")
    for i in range(250):
        lines.append(f"Database guideline rule #{i + 1}: Ensure transaction safety and indexing.")
    lines.append("")
    lines.append("## Extensive API Schema Manual")
    for i in range(250):
        lines.append(f"API Schema field definition #{i + 1}: Required type string.")

    body = "\n".join(lines) + "\n"
    skill = Skill(
        name="bloated-skill",
        description="A skill that originally exceeded progressive disclosure context budgets",
        body=body,
    )
    pkg = SkillPackage(skill=skill)
    pkg.save(skill_dir)

    assert pkg.skill.body_lines > 500

    out_dir = tmp_path / "optimized-dest"
    result = optimize_skill(skill_dir, output_dir=out_dir, max_lines=200)

    assert result.optimized_lines <= 200
    assert len(result.extracted_references) >= 2
    assert (out_dir / "SKILL.md").exists()
    assert (out_dir / "references" / "detailed-database-guidelines.md").exists()
    assert (out_dir / "references" / "extensive-api-schema-manual.md").exists()

    # Verify reload and audit
    optimized_pkg = SkillPackage.load(out_dir)
    assert "detailed-database-guidelines.md" in optimized_pkg.references
    assert "extensive-api-schema-manual.md" in optimized_pkg.references
    assert result.passed_audit is True


def test_optimize_cli_command(tmp_path: Path) -> None:
    skill_dir = tmp_path / "cli-bloated"
    skill_dir.mkdir()

    lines = ["# CLI Bloated Skill", "", "## Intro", "Quick intro."]
    lines.append("## Long Reference Section")
    for i in range(100):
        lines.append(f"Step {i}: detailed documentation step.")

    body = "\n".join(lines) + "\n"
    skill = Skill(name="cli-bloated", description="Bloated CLI skill", body=body)
    pkg = SkillPackage(skill=skill)
    pkg.save(skill_dir)

    res = runner.invoke(app, ["optimize", str(skill_dir), "--max-lines", "50"])
    assert res.exit_code == 0
    assert "Optimized 'cli-bloated'" in res.output
    assert "references/long-reference-section.md" in res.output

    # Test JSON mode
    res_json = runner.invoke(app, ["optimize", str(skill_dir), "--json"])
    assert res_json.exit_code == 0
    data = json.loads(res_json.stdout)
    assert data["skill"] == "cli-bloated"
    assert data["passed_audit"] is True

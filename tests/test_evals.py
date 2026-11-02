import json
from pathlib import Path

from typer.testing import CliRunner

from skillforge.cli import app
from skillforge.evals import init_evals, run_evals
from skillforge.skill import Skill, SkillPackage

runner = CliRunner()


def test_evals_init_and_run(tmp_path: Path) -> None:
    skill_dir = tmp_path / "sql-reviewer"
    skill_dir.mkdir()
    skill = Skill(
        "sql-reviewer",
        "Review SQL queries for syntax errors and injection vulnerabilities. Use when editing database queries.",
        "# SQL Reviewer\nVerify all queries use parameterized inputs.\n",
    )
    pkg = SkillPackage(skill=skill)
    pkg.save(skill_dir)

    # 1. Initialize starter evals
    evals_path = init_evals(skill_dir)
    assert evals_path.exists()
    assert (skill_dir / "evals" / "evals.json").exists()

    # 2. Run evals
    report = run_evals(skill_dir)
    assert report.total_cases == 4
    assert report.passed_cases == 4
    assert report.failed_cases == 0
    assert report.passed is True


def test_evals_detects_failure_and_forbidden_kw(tmp_path: Path) -> None:
    skill_dir = tmp_path / "demo-skill"
    skill_dir.mkdir()
    skill = Skill(
        "demo-skill",
        "Use when doing demo actions",
        "# Demo body with secret_token\n",
    )
    pkg = SkillPackage(skill=skill)
    pkg.save(skill_dir)

    evals_dir = skill_dir / "evals"
    evals_dir.mkdir()
    evals_file = evals_dir / "evals.json"
    evals_file.write_text(
        json.dumps([
            {
                "id": "should_fail_forbidden_kw",
                "prompt": "Run a demo task",
                "should_trigger": True,
                "forbidden_keywords": ["secret_token"],
            },
            {
                "id": "should_fail_false_trigger",
                "prompt": "Completely unrelated prompt with demo word",
                "should_trigger": False,
            },
        ]),
        encoding="utf-8",
    )

    report = run_evals(skill_dir)
    assert report.failed_cases == 2
    assert report.passed is False


def test_cli_test_command(tmp_path: Path) -> None:
    skill_dir = tmp_path / "cli-skill"
    skill_dir.mkdir()
    skill = Skill("cli-skill", "Use when executing cli operations", "# CLI Skill\n")
    pkg = SkillPackage(skill=skill)
    pkg.save(skill_dir)

    # CLI --init
    res_init = runner.invoke(app, ["test", str(skill_dir), "--init"])
    assert res_init.exit_code == 0
    assert "Initialized eval suite" in res_init.output

    # CLI test run
    res_run = runner.invoke(app, ["test", str(skill_dir)])
    assert res_run.exit_code == 0
    assert "PASSED" in res_run.output

    # CLI --json
    res_json = runner.invoke(app, ["test", str(skill_dir), "--json"])
    assert res_json.exit_code == 0
    data = json.loads(res_json.stdout)
    assert data["passed"] is True
    assert data["total_cases"] == 4

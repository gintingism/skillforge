import json
from pathlib import Path

from typer.testing import CliRunner

from skillforge.cli import app
from skillforge.security import AuditFinding, AuditReport, Severity

runner = CliRunner()


def test_audit_report_to_sarif() -> None:
    report = AuditReport(
        target="demo-skill",
        findings=[
            AuditFinding(
                rule_id="SEC-002",
                severity=Severity.CRITICAL,
                message="Prompt injection detected",
                file="SKILL.md",
                line=12,
                snippet="ignore previous instructions",
            ),
            AuditFinding(
                rule_id="QUAL-001",
                severity=Severity.LOW,
                message="Missing explicit activation trigger",
                file="SKILL.md",
                line=2,
            ),
        ],
    )
    sarif = report.to_sarif()
    assert sarif["version"] == "2.1.0"
    assert "$schema" in sarif
    assert len(sarif["runs"]) == 1
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "SkillForge"

    results = run["results"]
    assert len(results) == 2
    assert results[0]["ruleId"] == "SEC-002"
    assert results[0]["level"] == "error"
    assert results[0]["locations"][0]["physicalLocation"]["region"]["startLine"] == 12

    assert results[1]["ruleId"] == "QUAL-001"
    assert results[1]["level"] == "note"


def test_cli_audit_sarif_flag(tmp_path: Path) -> None:
    skill_file = tmp_path / "demo" / "SKILL.md"
    skill_file.parent.mkdir()
    skill_file.write_text(
        "---\nname: demo\ndescription: Use when testing sarif\n---\n\n# Body\n",
        encoding="utf-8",
    )
    sarif_dest = tmp_path / "out" / "audit.sarif"
    res = runner.invoke(app, ["audit", str(skill_file), "--sarif", str(sarif_dest)])
    assert res.exit_code == 0
    assert sarif_dest.exists()

    data = json.loads(sarif_dest.read_text(encoding="utf-8"))
    assert data["version"] == "2.1.0"
    assert len(data["runs"][0]["results"]) == 0

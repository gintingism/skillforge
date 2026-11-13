"""Tests for CycloneDX/SPDX SBOM, SLSA v1.0 Provenance, Dependency Graph, and Context Rule Sync."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from skillforge.cli import app
from skillforge.dependency_graph import analyze_dependency_graph
from skillforge.provenance import generate_provenance, verify_provenance, write_provenance
from skillforge.rule_sync import detect_directive_conflicts, sync_context_rules
from skillforge.sbom import generate_sbom
from skillforge.skill import Skill, SkillPackage

runner = CliRunner()


def _make_skill_dir(root: Path, name: str, deps: list[str] | None = None, tools: str | None = None) -> Path:
    skill_dir = root / name
    skill_dir.mkdir(parents=True, exist_ok=True)
    meta: dict[str, object] = {"version": "1.2.0"}
    if deps:
        meta["dependencies"] = deps
    skill = Skill(
        name=name,
        description=f"Test skill {name} for deterministic supply chain verification.",
        body="# Overview\n\nRun standard verification steps.\n",
        license="MIT",
        allowed_tools=tools,
        metadata=meta,
    )
    pkg = SkillPackage(skill=skill, source_dir=skill_dir)
    pkg.save(skill_dir)
    return skill_dir


def test_sbom_cyclonedx_and_spdx_generation(tmp_path: Path) -> None:
    skills_root = tmp_path / "skills"
    _make_skill_dir(skills_root, "alpha-linter", tools="Read Grep")
    _make_skill_dir(skills_root, "beta-deployer", deps=["alpha-linter"], tools="Read Bash")

    mcp_cfg = {
        "mcpServers": {
            "postgres-mcp": {
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-postgres"],
            }
        }
    }
    (tmp_path / "mcp.json").write_text(json.dumps(mcp_cfg), encoding="utf-8")

    packages = {
        "alpha-linter": SkillPackage.load(skills_root / "alpha-linter"),
        "beta-deployer": SkillPackage.load(skills_root / "beta-deployer"),
    }

    cdx_report = generate_sbom(packages, project_root=tmp_path, sbom_format="cyclonedx")
    assert cdx_report.format_name == "CycloneDX"
    assert cdx_report.spec_version == "1.6"
    assert len(cdx_report.components) == 3  # 2 skills + 1 MCP server
    doc = cdx_report.document
    assert doc["bomFormat"] == "CycloneDX"
    assert len(doc["components"]) == 3
    assert any(c["name"] == "postgres-mcp" for c in doc["components"])

    spdx_report = generate_sbom(packages, project_root=tmp_path, sbom_format="spdx")
    assert spdx_report.format_name == "SPDX"
    assert spdx_report.document["spdxVersion"] == "SPDX-2.3"
    assert len(spdx_report.document["packages"]) == 2


def test_slsa_provenance_sign_verify_and_tamper_detection(tmp_path: Path) -> None:
    skill_dir = _make_skill_dir(tmp_path, "secure-release", deps=["base-check"])
    (skill_dir / "scripts").mkdir(exist_ok=True)
    (skill_dir / "scripts" / "helper.py").write_text("print('ok')\n", encoding="utf-8")

    secret_key = "0123456789abcdef0123456789abcdef"
    envelope = generate_provenance(skill_dir, signing_key=secret_key, signer_id="ci-bot")
    prov_path = write_provenance(skill_dir, envelope)
    assert prov_path.is_file()

    # Valid verification with matching key
    res_ok = verify_provenance(skill_dir, signing_key=secret_key)
    assert res_ok.valid is True
    assert res_ok.signature_verified is True
    assert res_ok.subject_count == 2

    # Wrong key fails signature check
    res_bad_key = verify_provenance(skill_dir, signing_key="fedcba9876543210fedcba9876543210")
    assert res_bad_key.valid is False
    assert any("signature mismatch" in i.lower() for i in res_bad_key.issues)

    # Tamper with bundled script
    (skill_dir / "scripts" / "helper.py").write_text("print('tampered')\n", encoding="utf-8")
    res_tampered = verify_provenance(skill_dir, signing_key=secret_key)
    assert res_tampered.valid is False
    assert any("digest mismatch" in i.lower() for i in res_tampered.issues)


def test_dependency_graph_topological_sort_and_escalation(tmp_path: Path) -> None:
    _make_skill_dir(tmp_path, "step-one", tools="Read")
    _make_skill_dir(tmp_path, "step-two", deps=["step-one"], tools="Read Bash")
    _make_skill_dir(tmp_path, "step-three", deps=["step-two"], tools="Read")

    packages = {
        name: SkillPackage.load(tmp_path / name)
        for name in ("step-one", "step-two", "step-three")
    }
    report = analyze_dependency_graph(packages)
    assert report.passed is True
    assert report.topological_order.index("step-one") < report.topological_order.index("step-two")
    assert report.topological_order.index("step-two") < report.topological_order.index("step-three")

    # DEP-003 privilege escalation warning: step-three (Read only) depends on step-two (Read Bash)
    assert any(i.rule_id == "DEP-003" and i.skill_name == "step-three" for i in report.issues)
    mermaid_str = report.to_mermaid()
    assert "flowchart TD" in mermaid_str
    assert "step_three --> step_two" in mermaid_str


def test_dependency_graph_cycle_and_missing_detection(tmp_path: Path) -> None:
    _make_skill_dir(tmp_path, "cycle-a", deps=["cycle-b"])
    _make_skill_dir(tmp_path, "cycle-b", deps=["cycle-a", "nonexistent-skill"])

    packages = {
        "cycle-a": SkillPackage.load(tmp_path / "cycle-a"),
        "cycle-b": SkillPackage.load(tmp_path / "cycle-b"),
    }
    report = analyze_dependency_graph(packages)
    assert report.passed is False
    assert report.topological_order == []
    rule_ids = {i.rule_id for i in report.issues}
    assert "DEP-001" in rule_ids
    assert "DEP-002" in rule_ids


def test_rule_sync_and_conflict_detection(tmp_path: Path) -> None:
    agents_md = tmp_path / "AGENTS.md"
    agents_md.write_text(
        "# Project Rules\n\n- Always use pytest for running unit tests.\n- Never commit secrets to git.\n",
        encoding="utf-8",
    )

    # Sync to cursor, claude, and cursorrules
    sync_rep = sync_context_rules(tmp_path, targets=["cursor", "claude", "cursorrules"], check_only=False)
    assert sync_rep.passed is True
    assert (tmp_path / ".cursor" / "rules" / "00-core.mdc").is_file()
    assert (tmp_path / "CLAUDE.md").is_file()
    assert (tmp_path / ".cursorrules").is_file()

    # Check mode passes immediately after sync
    check_ok = sync_context_rules(tmp_path, targets=["cursor", "claude", "cursorrules"], check_only=True)
    assert check_ok.passed is True

    # Introduce conflicting instruction in CLAUDE.md
    (tmp_path / "CLAUDE.md").write_text(
        "# Project Rules\n\n- Never use pytest for running unit tests.\n",
        encoding="utf-8",
    )
    check_fail = sync_context_rules(tmp_path, targets=["cursor", "claude"], check_only=True)
    assert check_fail.passed is False
    issue_rules = {i.rule_id for i in check_fail.issues}
    assert "SYNC-001" in issue_rules
    assert "SYNC-002" in issue_rules

    conflicts = detect_directive_conflicts(
        "Always use pnpm for packages.",
        "Never use pnpm in this repository.",
    )
    assert len(conflicts) == 1


def test_cli_commands_end_to_end(tmp_path: Path) -> None:
    skills_dir = tmp_path / "skills"
    s1 = _make_skill_dir(skills_dir, "core-auth", tools="Read")
    _make_skill_dir(skills_dir, "api-gateway", deps=["core-auth"], tools="Read")

    # 1. CLI sbom
    bom_out = tmp_path / "bom.json"
    res_sbom = runner.invoke(app, ["sbom", str(tmp_path), "--output", str(bom_out), "--json"])
    assert res_sbom.exit_code == 0
    assert bom_out.is_file()
    bom_data = json.loads(bom_out.read_text(encoding="utf-8"))
    assert bom_data["bomFormat"] == "CycloneDX"

    # 2. CLI provenance & verify-provenance
    key = "a" * 32
    res_prov = runner.invoke(app, ["provenance", str(s1), "--key", key])
    assert res_prov.exit_code == 0
    res_vprov = runner.invoke(app, ["verify-provenance", str(s1), "--key", key, "--json"])
    assert res_vprov.exit_code == 0
    assert json.loads(res_vprov.stdout)["valid"] is True

    # 3. CLI graph
    res_graph = runner.invoke(app, ["graph", str(tmp_path), "--mermaid"])
    assert res_graph.exit_code == 0
    assert "flowchart TD" in res_graph.stdout

    # 4. CLI sync-rules
    (tmp_path / "AGENTS.md").write_text("# Core Rules\n\nAlways run mypy before commit.\n", encoding="utf-8")
    res_sync = runner.invoke(app, ["sync-rules", str(tmp_path), "--targets", "cursor,claude"])
    assert res_sync.exit_code == 0
    res_check = runner.invoke(app, ["sync-rules", str(tmp_path), "--targets", "cursor,claude", "--check"])
    assert res_check.exit_code == 0

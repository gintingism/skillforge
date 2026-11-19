"""Tests for v0.8.0 improvements: adapters, Ed25519 signing, multi-runtime sandbox, MCP tools, and firewall wrapper."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from skillforge.adapters import (
    CodexCliAdapter,
    GeminiCliAdapter,
    OpenCodeAdapter,
    RooCodeAdapter,
    detect_adapters,
)
from skillforge.errors import SkillForgeError
from skillforge.mcp_firewall import wrap_mcp_config
from skillforge.mcp_server import create_mcp_server
from skillforge.registry import BuiltinRegistry
from skillforge.sandbox_runner import run_in_sandbox
from skillforge.signing import SkillSigner
from skillforge.skill import Skill


def _sample_skill() -> Skill:
    return Skill(
        name="sample-skill",
        description="Sample skill for adapter testing.",
        body="# Sample\n\nUse this skill carefully.",
    )


def test_new_ecosystem_adapters_lifecycle(tmp_path: Path) -> None:
    skill = _sample_skill()
    cases = [
        (OpenCodeAdapter(), ".opencode"),
        (RooCodeAdapter(), ".roo"),
        (CodexCliAdapter(), ".codex"),
        (GeminiCliAdapter(), ".gemini"),
    ]
    for adapter, marker in cases:
        proj = tmp_path / marker.strip(".")
        proj.mkdir()
        if isinstance(adapter, GeminiCliAdapter):
            (proj / "GEMINI.md").write_text("# Gemini\n", encoding="utf-8")
        else:
            (proj / marker).mkdir()
        assert adapter.detect(proj) is True
        installed = adapter.install(skill, proj)
        assert installed.is_file()
        assert adapter.list_skills(proj) == ["sample-skill"]
        assert adapter.remove("sample-skill", proj) is True
        assert adapter.list_skills(proj) == []
        detected = detect_adapters(proj)
        assert any(isinstance(a, type(adapter)) for a in detected)


def test_ed25519_sign_and_verify_roundtrip(tmp_path: Path) -> None:
    skill_dir = tmp_path / "my-skill"
    skill_dir.mkdir()
    (skill_dir / "SKILL.md").write_text("---\nname: my-skill\ndescription: Test.\n---\nBody\n", encoding="utf-8")

    priv_pem, pub_pem = SkillSigner.generate_ed25519_keypair()
    sig_data = SkillSigner.sign_skill(skill_dir, priv_pem, signer_id="ci-bot", algorithm="ed25519")
    assert sig_data["algorithm"] == "ed25519"
    SkillSigner.write_signature(skill_dir, sig_data)

    ok = SkillSigner.verify_skill(skill_dir, key=pub_pem)
    assert ok.valid is True
    assert ok.algorithm == "ed25519"
    assert ok.signer_id == "ci-bot"

    _, other_pub = SkillSigner.generate_ed25519_keypair()
    bad_key = SkillSigner.verify_skill(skill_dir, key=other_pub)
    assert bad_key.valid is False
    assert any("Ed25519 signature mismatch" in issue for issue in bad_key.issues)

    (skill_dir / "SKILL.md").write_text("tampered", encoding="utf-8")
    tampered = SkillSigner.verify_skill(skill_dir, key=pub_pem)
    assert tampered.valid is False
    assert any("Content modified" in issue for issue in tampered.issues)


def test_sandbox_runner_shell_and_extension_validation(tmp_path: Path) -> None:
    sh_script = tmp_path / "ok.sh"
    sh_script.write_text("#!/usr/bin/env bash\necho 'sandbox-sh-ok'\n", encoding="utf-8")
    res = run_in_sandbox(sh_script, use_os_jail=False)
    assert res.passed is True
    assert "sandbox-sh-ok" in res.stdout
    assert res.backend == "subprocess-env-jail"

    bad_script = tmp_path / "bad.rb"
    bad_script.write_text("puts 'hi'\n", encoding="utf-8")
    with pytest.raises(SkillForgeError, match="Unsupported sandbox script extension"):
        run_in_sandbox(bad_script, use_os_jail=False)


def test_wrap_mcp_config_idempotent(tmp_path: Path) -> None:
    cfg = tmp_path / "mcp.json"
    cfg.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "fs": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem"]},
                    "remote": {"url": "https://example.com/mcp"},
                }
            }
        ),
        encoding="utf-8",
    )

    first = wrap_mcp_config(cfg)
    assert first["wrapped_servers"] == 1
    parsed = json.loads(cfg.read_text(encoding="utf-8"))
    assert parsed["mcpServers"]["fs"]["command"] == "skillforge"
    assert parsed["mcpServers"]["fs"]["args"][:2] == ["firewall-mcp", "--"]
    assert parsed["mcpServers"]["remote"] == {"url": "https://example.com/mcp"}

    second = wrap_mcp_config(cfg)
    assert second["wrapped_servers"] == 0


def test_mcp_server_exposes_audit_mcp_and_check_policy(tmp_path: Path) -> None:
    server = create_mcp_server(BuiltinRegistry())
    tool_names = {t.name for t in server._tool_manager.list_tools()}  # noqa: SLF001
    assert {"audit_mcp_config", "check_policy"}.issubset(tool_names)

    mcp_cfg = tmp_path / "mcp.json"
    mcp_cfg.write_text(json.dumps({"mcpServers": {"ok": {"command": "uvx", "args": ["mcp-server==1.0.0"]}}}), encoding="utf-8")
    audit_raw = server._tool_manager._tools["audit_mcp_config"].fn(str(mcp_cfg))  # noqa: SLF001
    audit_data = json.loads(audit_raw)
    assert audit_data["passed"] is True

    policy_file = tmp_path / ".skillforge-policy.yaml"
    policy_file.write_text("version: '1.0'\nmin_score: 80\n", encoding="utf-8")
    skill_md = "---\nname: clean-skill\ndescription: Clean skill.\n---\n# Clean\nDo safe work.\n"
    policy_raw = server._tool_manager._tools["check_policy"].fn(skill_md, str(policy_file))  # noqa: SLF001
    policy_data = json.loads(policy_raw)
    assert policy_data["policy_passed"] is True


def test_ed25519_lockfile_sign_and_verify(tmp_path: Path) -> None:
    lock_file = tmp_path / "skillforge.lock"
    lock_file.write_text('{"version": "1", "skills": {}}\n', encoding="utf-8")

    priv_pem, pub_pem = SkillSigner.generate_ed25519_keypair()
    sig_path = SkillSigner.sign_lockfile(lock_file, priv_pem, signer_id="release-bot", algorithm="ed25519")
    assert sig_path.is_file()

    ok = SkillSigner.verify_lockfile(lock_file, key=pub_pem)
    assert ok.valid is True
    assert ok.algorithm == "ed25519"

    _, other_pub = SkillSigner.generate_ed25519_keypair()
    bad = SkillSigner.verify_lockfile(lock_file, key=other_pub)
    assert bad.valid is False
    assert any("Ed25519 signature mismatch" in issue for issue in bad.issues)


def test_ed25519_slsa_provenance_roundtrip(tmp_path: Path) -> None:
    from skillforge.provenance import generate_provenance, verify_provenance, write_provenance

    skill_dir = tmp_path / "prov-skill"
    skill_dir.mkdir()
    (skill_dir / "SKILL.md").write_text(
        "---\nname: prov-skill\ndescription: Signed SLSA skill.\n---\n# Body\nSafe instructions.\n",
        encoding="utf-8",
    )

    priv_pem, pub_pem = SkillSigner.generate_ed25519_keypair()
    envelope = generate_provenance(skill_dir, signing_key=priv_pem, signer_id="ci-ed25519", algorithm="ed25519")
    assert envelope["signatures"][0]["algorithm"] == "ed25519"
    write_provenance(skill_dir, envelope)

    verified = verify_provenance(skill_dir, signing_key=pub_pem)
    assert verified.valid is True
    assert verified.signature_verified is True

    _, other_pub = SkillSigner.generate_ed25519_keypair()
    failed = verify_provenance(skill_dir, signing_key=other_pub)
    assert failed.valid is False
    assert failed.signature_verified is False
    assert any("Ed25519 signature mismatch" in issue for issue in failed.issues)


def test_rule_sync_supports_gemini_and_copilot_targets(tmp_path: Path) -> None:
    from skillforge.rule_sync import sync_context_rules

    (tmp_path / "AGENTS.md").write_text("# Rules\n\nAlways run pytest.\n", encoding="utf-8")
    report = sync_context_rules(tmp_path, targets=["gemini", "copilot"])
    assert report.passed is True
    assert (tmp_path / "GEMINI.md").is_file()
    assert (tmp_path / ".github" / "copilot-instructions.md").is_file()

    check = sync_context_rules(tmp_path, targets=["gemini", "copilot"], check_only=True)
    assert check.passed is True


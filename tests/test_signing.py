"""Tests for cryptographic signing and verification (SkillSigner)."""

from pathlib import Path

import pytest
from typer.testing import CliRunner

from skillforge.cli import app
from skillforge.signing import SkillSigner


@pytest.fixture
def temp_skill(tmp_path: Path) -> Path:
    skill_dir = tmp_path / "sample-skill"
    skill_dir.mkdir()
    (skill_dir / "SKILL.md").write_text(
        "---\nname: sample-skill\ndescription: A safe test skill.\n---\nSafe execution instructions.\n",
        encoding="utf-8",
    )
    ref_dir = skill_dir / "references"
    ref_dir.mkdir()
    (ref_dir / "guide.md").write_text("# Reference Guide\nClean content.\n", encoding="utf-8")
    return skill_dir


def test_keygen() -> None:
    key = SkillSigner.generate_key()
    assert isinstance(key, str)
    assert len(key) == 64
    int(key, 16)  # Must be valid hex


def test_sign_and_verify_skill(temp_skill: Path) -> None:
    key = SkillSigner.generate_key()
    payload = SkillSigner.sign_skill(temp_skill, key, signer_id="sec-team")
    assert payload["signer_id"] == "sec-team"
    assert len(payload["manifest"]) == 2

    sig_file = SkillSigner.write_signature(temp_skill, payload)
    assert sig_file.is_file()

    # Verification with key
    res = SkillSigner.verify_skill(temp_skill, key=key)
    assert res.valid is True
    assert res.file_count == 2
    assert res.signer_id == "sec-team"
    assert len(res.issues) == 0


def test_verify_fails_on_tampered_content(temp_skill: Path) -> None:
    key = SkillSigner.generate_key()
    payload = SkillSigner.sign_skill(temp_skill, key)
    SkillSigner.write_signature(temp_skill, payload)

    # Tamper with file
    (temp_skill / "SKILL.md").write_text("Tampered content!", encoding="utf-8")

    res = SkillSigner.verify_skill(temp_skill, key=key)
    assert res.valid is False
    assert any("Content modified: SKILL.md" in issue for issue in res.issues)


def test_verify_fails_on_untracked_file_added(temp_skill: Path) -> None:
    key = SkillSigner.generate_key()
    payload = SkillSigner.sign_skill(temp_skill, key)
    SkillSigner.write_signature(temp_skill, payload)

    # Inject unauthorized script
    (temp_skill / "backdoor.sh").write_text("echo evil", encoding="utf-8")

    res = SkillSigner.verify_skill(temp_skill, key=key)
    assert res.valid is False
    assert any("Untracked/unverified file added: backdoor.sh" in issue for issue in res.issues)


def test_verify_fails_on_deleted_file(temp_skill: Path) -> None:
    key = SkillSigner.generate_key()
    payload = SkillSigner.sign_skill(temp_skill, key)
    SkillSigner.write_signature(temp_skill, payload)

    # Delete reference
    (temp_skill / "references" / "guide.md").unlink()

    res = SkillSigner.verify_skill(temp_skill, key=key)
    assert res.valid is False
    assert any("Missing file: references/guide.md" in issue for issue in res.issues)


def test_sign_and_verify_lockfile(tmp_path: Path) -> None:
    lock_file = tmp_path / "skillforge.lock"
    lock_file.write_text('{"my-skill": {"sha256": "abc12345"}}', encoding="utf-8")

    key = SkillSigner.generate_key()
    sig_path = SkillSigner.sign_lockfile(lock_file, key, signer_id="ci-bot")
    assert sig_path.is_file()

    res = SkillSigner.verify_lockfile(lock_file, key=key)
    assert res.valid is True
    assert res.signer_id == "ci-bot"

    # Modify lockfile
    lock_file.write_text('{"my-skill": {"sha256": "hacked"}}', encoding="utf-8")
    tampered_res = SkillSigner.verify_lockfile(lock_file, key=key)
    assert tampered_res.valid is False


def test_cli_signing_and_verification_flow(temp_skill: Path) -> None:
    runner = CliRunner()

    # 1. keygen
    key_res = runner.invoke(app, ["keygen"])
    assert key_res.exit_code == 0
    key = key_res.output.strip().splitlines()[-1]

    # 2. sign
    sign_res = runner.invoke(app, ["sign", str(temp_skill), "--key", key, "--signer", "auditor-1"])
    assert sign_res.exit_code == 0
    assert "Signed skill package" in sign_res.output

    # 3. verify
    verify_res = runner.invoke(app, ["verify-signature", str(temp_skill), "--key", key])
    assert verify_res.exit_code == 0
    assert "Verification PASSED" in verify_res.output

    # 4. tamper and verify failure
    (temp_skill / "tamper.txt").write_text("evil", encoding="utf-8")
    tamper_res = runner.invoke(app, ["verify-signature", str(temp_skill), "--key", key])
    assert tamper_res.exit_code != 0
    assert "TAMPER DETECTED" in tamper_res.output

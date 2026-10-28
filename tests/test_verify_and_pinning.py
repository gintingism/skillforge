import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from skillforge.cli import app
from skillforge.errors import RegistryError
from skillforge.registry import GitRemoteRegistry
from skillforge.skill import Skill, SkillPackage

runner = CliRunner()


def test_parse_spec_with_ref() -> None:
    # 1. owner/repo:skill
    url, skill, ref = GitRemoteRegistry.parse_spec_with_ref("owner/repo:my-skill")
    assert url == "https://github.com/owner/repo.git"
    assert skill == "my-skill"
    assert ref is None

    # 2. owner/repo:skill@v1.2.0
    url, skill, ref = GitRemoteRegistry.parse_spec_with_ref("owner/repo:my-skill@v1.2.0")
    assert url == "https://github.com/owner/repo.git"
    assert skill == "my-skill"
    assert ref == "v1.2.0"

    # 3. owner/repo@v1.2.0:my-skill
    url, skill, ref = GitRemoteRegistry.parse_spec_with_ref("owner/repo@v1.2.0:my-skill")
    assert url == "https://github.com/owner/repo.git"
    assert skill == "my-skill"
    assert ref == "v1.2.0"

    # 4. full https url with ref
    url, skill, ref = GitRemoteRegistry.parse_spec_with_ref("https://github.com/owner/repo.git@main:my-skill")
    assert url == "https://github.com/owner/repo.git"
    assert skill == "my-skill"
    assert ref == "main"

    # 5. Git option or unsafe ref rejected
    with pytest.raises(RegistryError):
        GitRemoteRegistry.parse_spec_with_ref("owner/repo:my-skill@--upload-pack=foo")

    with pytest.raises(RegistryError):
        GitRemoteRegistry.parse_spec_with_ref("owner/repo:my-skill@ref;rm -rf")


def test_verify_command_no_lockfile(tmp_path: Path) -> None:
    res = runner.invoke(app, ["verify", "--project", str(tmp_path)])
    assert res.exit_code == 1
    assert "Lockfile not found" in res.output


def test_verify_command_passed_and_json(tmp_path: Path) -> None:
    project = tmp_path / "proj"
    skill_dir = project / ".claude" / "skills" / "demo-skill"
    skill_dir.mkdir(parents=True)

    skill = Skill("demo-skill", "Demo description when testing verify", "# Demo body\n")
    pkg = SkillPackage(skill=skill)
    pkg.save(skill_dir)

    # Create matching skillforge.lock
    lock_file = project / "skillforge.lock"
    lock_file.write_text(
        json.dumps({
            "demo-skill": {
                "spec": "owner/repo:demo-skill",
                "version": "1.0.0",
                "sha256": pkg.compute_sha256(),
                "commit": "abcdef1234567890abcdef1234567890abcdef12",
            }
        }),
        encoding="utf-8",
    )

    # Standard human-readable output
    res = runner.invoke(app, ["verify", "--project", str(project)])
    assert res.exit_code == 0, res.output
    assert "OK       demo-skill" in res.output
    assert "Verification PASSED" in res.output

    # JSON output
    res_json = runner.invoke(app, ["verify", "--project", str(project), "--json"])
    assert res_json.exit_code == 0, res_json.output
    data = json.loads(res_json.stdout)
    assert data["status"] == "PASSED"
    assert len(data["results"]) == 1
    assert data["results"][0]["status"] == "VERIFIED"


def test_verify_command_detects_drift_and_missing(tmp_path: Path) -> None:
    project = tmp_path / "proj"
    skill_dir = project / ".cursor" / "skills" / "tampered-skill"
    skill_dir.mkdir(parents=True)

    skill = Skill("tampered-skill", "Original description when created", "# Tampered content\n")
    pkg = SkillPackage(skill=skill)
    pkg.save(skill_dir)

    # Lockfile specifies a different sha256 and also includes a missing skill
    lock_file = project / "skillforge.lock"
    lock_file.write_text(
        json.dumps({
            "tampered-skill": {
                "spec": "owner/repo:tampered-skill",
                "sha256": "0000000000000000000000000000000000000000000000000000000000000000",
            },
            "ghost-skill": {
                "spec": "owner/repo:ghost-skill",
                "sha256": "1111111111111111111111111111111111111111111111111111111111111111",
            },
        }),
        encoding="utf-8",
    )

    res = runner.invoke(app, ["verify", "--project", str(project)])
    assert res.exit_code == 1
    assert "DRIFT" in res.output
    assert "MISSING" in res.output
    assert "Verification FAILED" in res.output

    res_json = runner.invoke(app, ["verify", "--project", str(project), "--json"])
    assert res_json.exit_code == 0  # CLI exits 0 with JSON output reporting status FAILED
    data = json.loads(res_json.stdout)
    assert data["status"] == "FAILED"
    statuses = {r["skill"]: r["status"] for r in data["results"]}
    assert statuses["tampered-skill"] == "DRIFT"
    assert statuses["ghost-skill"] == "MISSING"

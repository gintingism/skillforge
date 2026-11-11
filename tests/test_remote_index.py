"""Tests for remote skill indexing and search (RemoteIndex)."""

from pathlib import Path

from typer.testing import CliRunner

from skillforge.cli import app
from skillforge.remote_index import RemoteIndex, RemoteSkillRecord


def test_default_index_contains_curated_skills(tmp_path: Path) -> None:
    cache_file = tmp_path / "index.json"
    idx = RemoteIndex(cache_file=cache_file)
    assert len(idx._skills) >= 5

    res = idx.search("trifecta")
    assert len(res) == 1
    assert res[0].name == "lethal-trifecta-guard"
    assert res[0].verified is True


def test_search_by_query_and_tag(tmp_path: Path) -> None:
    cache_file = tmp_path / "index.json"
    idx = RemoteIndex(cache_file=cache_file)

    res_git = idx.search("", tag="git")
    assert any(s.name == "git-worktree-isolation" for s in res_git)

    res_sec = idx.search("memory", tag="security")
    assert len(res_sec) >= 1
    assert res_sec[0].name == "memory-hygiene-sentinel"


def test_index_directory(tmp_path: Path) -> None:
    repo_dir = tmp_path / "mock-repo"
    repo_dir.mkdir()
    skill_dir = repo_dir / "skills" / "custom-helper"
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text(
        "---\nname: custom-helper\ndescription: A safe utility skill.\n---\nHelpful actions.\n",
        encoding="utf-8",
    )

    idx_file = tmp_path / "custom_index.json"
    idx = RemoteIndex(cache_file=idx_file)
    found = idx.index_directory(repo_dir, "https://github.com/myorg/myrepo")
    assert len(found) == 1
    assert found[0].name == "custom-helper"
    assert found[0].security_score >= 80
    assert idx_file.is_file()


def test_cli_search_remote() -> None:
    runner = CliRunner()
    res = runner.invoke(app, ["search-remote", "sentinel"])
    assert res.exit_code == 0
    assert "Found" in res.output
    assert "sentinel" in res.output.lower()


def test_cli_index_command(tmp_path: Path) -> None:
    skill_dir = tmp_path / "test-skill"
    skill_dir.mkdir()
    (skill_dir / "SKILL.md").write_text(
        "---\nname: test-skill\ndescription: Test index skill.\n---\nDo work.\n",
        encoding="utf-8",
    )

    runner = CliRunner()
    res = runner.invoke(app, ["index", str(tmp_path), "--url", "https://github.com/acme/skills"])
    assert res.exit_code == 0
    assert "Indexed 1 skill(s)" in res.output

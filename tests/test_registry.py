from pathlib import Path
import subprocess

import pytest

from skillforge.errors import RegistryError
from skillforge.registry import GitRemoteRegistry, LocalRegistry
from skillforge.skill import Skill, SkillPackage


def test_local_registry_search_and_install(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "SKILL.md").write_text(
        "---\nname: demo\ndescription: A demo skill\n---\n\nUse it.\n",
        encoding="utf-8",
    )
    registry = LocalRegistry(tmp_path / "registry")
    registry.publish(Skill.load(source / "SKILL.md"))
    assert [s.name for s in registry.search("demo")] == ["demo"]
    destination = tmp_path / "installed"
    installed = registry.install("demo", destination)
    assert installed == destination / "SKILL.md"
    assert installed.exists()


def test_local_registry_package_publish_and_install(tmp_path: Path) -> None:
    skill = Skill("pkg-demo", "A packaged skill", "# Demo\n")
    package = SkillPackage(
        skill=skill,
        scripts={"check.py": "print('ok')"},
        references={"manual.md": "# Manual"},
    )
    registry = LocalRegistry(tmp_path / "registry")
    registry.publish_package(package)

    pkg = registry.get_package("pkg-demo")
    assert pkg.skill.name == "pkg-demo"
    assert "check.py" in pkg.scripts

    dest = tmp_path / "installed_pkg"
    registry.install("pkg-demo", dest)
    assert (dest / "SKILL.md").exists()
    assert (dest / "scripts" / "check.py").exists()
    assert (dest / "references" / "manual.md").exists()


def test_local_registry_empty_and_missing_skill(tmp_path: Path) -> None:
    registry = LocalRegistry(tmp_path / "empty")
    assert registry.search("anything") == []
    with pytest.raises(RegistryError, match="not found"):
        registry.install("missing", tmp_path / "installed")


def test_local_registry_reports_invalid_skill(tmp_path: Path) -> None:
    invalid = tmp_path / "registry" / "broken"
    invalid.mkdir(parents=True)
    (invalid / "SKILL.md").write_text("not frontmatter", encoding="utf-8")
    with pytest.raises(RegistryError, match="Invalid registry skill"):
        LocalRegistry(tmp_path / "registry").search("")


def test_git_remote_registry_spec_parsing() -> None:
    url, skill = GitRemoteRegistry.parse_spec("anthropics/skills:pdf")
    assert url == "https://github.com/anthropics/skills.git"
    assert skill == "pdf"

    url, skill = GitRemoteRegistry.parse_spec("gintingism/my-repo")
    assert url == "https://github.com/gintingism/my-repo.git"
    assert skill is None

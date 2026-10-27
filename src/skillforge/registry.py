"""Registry interfaces, local filesystem registry, and remote git/github registry."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse

from .errors import RegistryError
from .skill import Skill, SkillPackage


class Registry(ABC):
    """Abstract source of discoverable and installable skills."""

    @abstractmethod
    def search(self, query: str) -> list[Skill]:
        """Return skills whose name or description matches a query."""

    @abstractmethod
    def get(self, name: str) -> Skill:
        """Return a named skill."""

    def get_package(self, name: str) -> SkillPackage:
        """Return a named skill packaged with optional scripts and references."""
        return SkillPackage(skill=self.get(name))

    def install(self, name: str, destination: Path) -> Path:
        """Install a named skill package into destination directory."""
        package = self.get_package(name)
        destination.mkdir(parents=True, exist_ok=True)
        return package.save(destination)


class LocalRegistry(Registry):
    """Filesystem registry storing skills in ``<name>/`` directories."""

    def __init__(self, root: Path) -> None:
        self.root = root

    def publish(self, skill: Skill) -> Path:
        """Publish a single skill into the local registry."""
        target = self.root / skill.name / "SKILL.md"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(skill.render(), encoding="utf-8")
        return target

    def publish_package(self, package: SkillPackage) -> Path:
        """Publish a complete skill package into the local registry."""
        target_dir = self.root / package.skill.name
        package.save(target_dir)
        return target_dir / "SKILL.md"

    def get(self, name: str) -> Skill:
        """Load a named skill from the local registry."""
        return self.get_package(name).skill

    def get_package(self, name: str) -> SkillPackage:
        """Load a complete skill package from the local registry."""
        try:
            Skill.validate_name(name)
        except Exception as exc:
            raise RegistryError(str(exc)) from exc
        skill_dir = self.root / name
        source = skill_dir / "SKILL.md"
        if not source.is_file():
            raise RegistryError(f"Skill not found: {name}")
        try:
            return SkillPackage.load(skill_dir)
        except Exception as exc:
            raise RegistryError(f"Invalid registry skill {source}: {exc}") from exc

    def search(self, query: str) -> list[Skill]:
        """Search names and descriptions case-insensitively."""
        if not self.root.exists():
            return []
        needle = query.casefold()
        skills: list[Skill] = []
        for path in sorted(self.root.glob("*/SKILL.md")):
            try:
                skill = Skill.load(path)
            except Exception as exc:
                raise RegistryError(f"Invalid registry skill {path}: {exc}") from exc
            if needle in skill.name.casefold() or needle in skill.description.casefold():
                skills.append(skill)
        return skills

    def install(self, name: str, destination: Path) -> Path:
        """Install a complete skill package into destination."""
        package = self.get_package(name)
        destination.mkdir(parents=True, exist_ok=True)
        target = destination / "SKILL.md"
        target.write_text(package.skill.render(), encoding="utf-8")
        if package.scripts or package.references or package.assets:
            package.save(destination)
        return target


class BuiltinRegistry(Registry):
    """Explicit registry for skills shipped inside the SkillForge package."""

    def __init__(self) -> None:
        self.root = Path(__file__).parent / "builtin_skills"

    def get(self, name: str) -> Skill:
        """Load a named built-in skill."""
        return self.get_package(name).skill

    def get_package(self, name: str) -> SkillPackage:
        """Load a named built-in skill package."""
        try:
            Skill.validate_name(name)
        except Exception as exc:
            raise RegistryError(str(exc)) from exc
        skill_dir = self.root.joinpath(name)
        path = skill_dir / "SKILL.md"
        if not path.is_file():
            raise RegistryError(f"Built-in skill not found: {name}")
        try:
            return SkillPackage.load(skill_dir)
        except Exception as exc:
            raise RegistryError(f"Invalid built-in skill {path}: {exc}") from exc

    def search(self, query: str) -> list[Skill]:
        """Search shipped skills by name or description."""
        if not self.root.is_dir():
            return []
        needle = query.casefold()
        result: list[Skill] = []
        for path in sorted(self.root.glob("*/SKILL.md")):
            skill = self.get(path.parent.name)
            if needle in skill.name.casefold() or needle in skill.description.casefold():
                result.append(skill)
        return result

    def install(self, name: str, destination: Path) -> Path:
        """Copy a built-in skill into a staging directory."""
        package = self.get_package(name)
        destination.mkdir(parents=True, exist_ok=True)
        target = destination / "SKILL.md"
        target.write_text(package.skill.render(), encoding="utf-8")
        if package.scripts or package.references or package.assets:
            package.save(destination)
        return target


class CompositeRegistry(Registry):
    """Explicitly ordered registry sources; first source wins on duplicate names."""

    def __init__(self, registries: Iterable[Registry]) -> None:
        self.registries = tuple(registries)

    def get(self, name: str) -> Skill:
        """Get a skill from first source containing it."""
        errors: list[str] = []
        for registry in self.registries:
            try:
                return registry.get(name)
            except RegistryError as exc:
                errors.append(str(exc))
        raise RegistryError(f"Skill not found: {name}. Sources: {'; '.join(errors)}")

    def get_package(self, name: str) -> SkillPackage:
        """Get a skill package from first source containing it."""
        errors: list[str] = []
        for registry in self.registries:
            try:
                return registry.get_package(name)
            except RegistryError as exc:
                errors.append(str(exc))
        raise RegistryError(f"Skill not found: {name}. Sources: {'; '.join(errors)}")

    def search(self, query: str) -> list[Skill]:
        """Search all sources and de-duplicate by name."""
        found: dict[str, Skill] = {}
        for registry in self.registries:
            for skill in registry.search(query):
                found.setdefault(skill.name, skill)
        return sorted(found.values(), key=lambda skill: skill.name)

    def install(self, name: str, destination: Path) -> Path:
        """Install a skill resolved from ordered sources."""
        package = self.get_package(name)
        destination.mkdir(parents=True, exist_ok=True)
        target = destination / "SKILL.md"
        target.write_text(package.skill.render(), encoding="utf-8")
        if package.scripts or package.references or package.assets:
            package.save(destination)
        return target


class GitRemoteRegistry(Registry):
    """Remote registry fetching skills directly from GitHub or Git repositories."""

    def __init__(self, cache_dir: Path | None = None) -> None:
        self.cache_dir = cache_dir or (Path.home() / ".skillforge" / "cache")
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    @classmethod
    def parse_spec(cls, spec: str) -> tuple[str, str | None]:
        """Parse 'owner/repo:skill_name' or Git URL into (repo_url, skill_name)."""
        clean = spec.strip()
        if ":" in clean and not clean.startswith(("http://", "https://", "git@")):
            repo_part, skill_part = clean.split(":", 1)
            repo_url = f"https://github.com/{repo_part}.git"
            return repo_url, skill_part
        if ":" in clean and clean.count(":") > 1:
            # Handles https://github.com/owner/repo.git:skill_name
            repo_part, skill_part = clean.rsplit(":", 1)
            return repo_part, skill_part
        if "/" in clean and not clean.startswith(("http://", "https://", "git@")):
            # Handles owner/repo (whole repo as skill or collection)
            return f"https://github.com/{clean}.git", None
        return clean, None

    def _clone_or_update(self, repo_url: str) -> Path:
        """Clone or update repository into local cache directory."""
        sanitized = re.sub(r"[^a-zA-Z0-9_-]", "_", repo_url)
        target = self.cache_dir / sanitized

        if (target / ".git").is_dir():
            try:
                subprocess.run(
                    ["git", "pull", "--ff-only"],
                    cwd=target,
                    check=True,
                    capture_output=True,
                    text=True,
                )
            except Exception:
                # If pull fails (e.g. offline), use existing cache
                pass
            return target

        try:
            subprocess.run(
                ["git", "clone", "--depth", "1", repo_url, str(target)],
                check=True,
                capture_output=True,
                text=True,
            )
            return target
        except Exception as exc:
            raise RegistryError(f"Failed to clone remote repository {repo_url}: {exc}") from exc

    def fetch_skill(self, spec: str) -> SkillPackage:
        """Resolve a remote spec like 'owner/repo:skill' into a SkillPackage."""
        repo_url, skill_name = self.parse_spec(spec)
        repo_dir = self._clone_or_update(repo_url)

        # 1. If skill_name is given, look specifically for that folder or file
        if skill_name:
            candidates = [
                repo_dir / skill_name,
                repo_dir / "skills" / skill_name,
                repo_dir / ".claude" / "skills" / skill_name,
                repo_dir / ".cursor" / "skills" / skill_name,
            ]
            for candidate in candidates:
                if candidate.is_dir() and (candidate / "SKILL.md").is_file():
                    return SkillPackage.load(candidate)
            # Scan recursively
            for match in repo_dir.rglob(f"**/{skill_name}/SKILL.md"):
                if match.is_file():
                    return SkillPackage.load(match.parent)
            raise RegistryError(f"Skill '{skill_name}' not found in repository {repo_url}")

        # 2. Check if the repo root is itself a skill
        if (repo_dir / "SKILL.md").is_file():
            return SkillPackage.load(repo_dir)

        # 3. Check if there are skills in skills/
        skills_dir = repo_dir / "skills"
        if skills_dir.is_dir():
            for child in skills_dir.iterdir():
                if child.is_dir() and (child / "SKILL.md").is_file():
                    return SkillPackage.load(child)

        raise RegistryError(f"No valid skill found in {repo_url}")

    def get(self, name: str) -> Skill:
        """Fetch remote skill by spec and return its Skill object."""
        return self.fetch_skill(name).skill

    def get_package(self, name: str) -> SkillPackage:
        """Fetch remote skill by spec and return its SkillPackage."""
        return self.fetch_skill(name)

    def search(self, query: str) -> list[Skill]:
        """Search skills across cached remote repositories."""
        skills: list[Skill] = []
        for path in self.cache_dir.rglob("SKILL.md"):
            try:
                skill = Skill.load(path)
                if query.casefold() in skill.name.casefold() or query.casefold() in skill.description.casefold():
                    skills.append(skill)
            except Exception:
                pass
        return skills

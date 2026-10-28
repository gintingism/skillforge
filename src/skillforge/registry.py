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

    _OWNER_REPO = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*$")
    _SKILL_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")

    @classmethod
    def parse_spec(cls, spec: str) -> tuple[str, str | None]:
        """Parse 'owner/repo:skill_name' or Git URL into (repo_url, skill_name)."""
        repo_url, skill_name, _ = cls.parse_spec_with_ref(spec)
        return repo_url, skill_name

    @classmethod
    def parse_spec_with_ref(cls, spec: str) -> tuple[str, str | None, str | None]:
        """Parse 'owner/repo:skill_name@ref' or Git URL into (repo_url, skill_name, ref)."""
        clean = spec.strip()
        ref: str | None = None
        has_scheme = clean.startswith(("http://", "https://", "git@", "ssh://"))

        # Extract @ref if present and not a git@ user separator
        if "@" in clean and not (has_scheme and clean.startswith("git@") and clean.count("@") == 1):
            base, ref_part = clean.rsplit("@", 1)
            if ":" in ref_part:
                # e.g. owner/repo@v1.0.0:skill
                ref_extracted, skill_part = ref_part.split(":", 1)
                clean = f"{base}:{skill_part}"
                ref = ref_extracted
            else:
                # e.g. owner/repo:skill@v1.0.0 or owner/repo@v1.0.0
                clean = base
                ref = ref_part
            if ref:
                cls._check_git_ref(ref)

        if ":" in clean and not has_scheme:
            repo_part, skill_part = clean.split(":", 1)
            cls._check_shorthand(repo_part, skill_part)
            return f"https://github.com/{repo_part}.git", skill_part, ref
        if has_scheme and clean.count(":") > 1 and not clean.startswith("git@"):
            # Handles https://github.com/owner/repo.git:skill_name
            repo_part, skill_part = clean.rsplit(":", 1)
            if skill_part.isdigit() or "/" in skill_part:
                return clean, None, ref
            if not cls._SKILL_NAME.fullmatch(skill_part):
                raise RegistryError(f"Invalid skill name in spec: {skill_part!r}")
            return repo_part, skill_part, ref
        if "/" in clean and not has_scheme:
            # Handles owner/repo (whole repo as skill or collection)
            cls._check_shorthand(clean, None)
            return f"https://github.com/{clean}.git", None, ref
        return clean, None, ref

    @classmethod
    def _check_shorthand(cls, repo_part: str, skill_part: str | None) -> None:
        if not cls._OWNER_REPO.fullmatch(repo_part):
            raise RegistryError(
                f"Invalid repository spec {repo_part!r}: expected owner/repo, optionally followed by :skill"
            )
        if skill_part is not None and not cls._SKILL_NAME.fullmatch(skill_part):
            raise RegistryError(f"Invalid skill name in spec: {skill_part!r}")

    @staticmethod
    def _check_git_ref(ref: str) -> None:
        """Validate git ref or commit SHA to block option injection and malformed refs."""
        if not ref or ref.startswith("-"):
            raise RegistryError(f"Invalid or unsafe git ref: {ref!r}")
        if not re.fullmatch(r"^[A-Za-z0-9_./@~^+-]{1,128}$", ref):
            raise RegistryError(f"Invalid git ref characters: {ref!r}")

    def _clone_or_update(self, repo_url: str, ref: str | None = None) -> tuple[Path, str]:
        """Clone or update repository into local cache directory and return (path, commit_sha)."""
        self._check_repo_url(repo_url)
        sanitized = re.sub(r"[^a-zA-Z0-9_-]", "_", repo_url)
        target = self.cache_dir / sanitized

        if (target / ".git").is_dir():
            try:
                subprocess.run(
                    ["git", "fetch", "--all", "--tags", "--prune"],
                    cwd=target,
                    check=True,
                    capture_output=True,
                    text=True,
                )
            except Exception:
                pass
        else:
            try:
                subprocess.run(
                    ["git", "clone", "--", repo_url, str(target)],
                    check=True,
                    capture_output=True,
                    text=True,
                )
            except Exception as exc:
                raise RegistryError(f"Failed to clone remote repository {repo_url}: {exc}") from exc

        if ref:
            self._check_git_ref(ref)
            try:
                subprocess.run(
                    ["git", "checkout", "--detach", ref],
                    cwd=target,
                    check=True,
                    capture_output=True,
                    text=True,
                )
            except Exception as exc:
                raise RegistryError(f"Failed to checkout ref {ref!r} in {repo_url}: {exc}") from exc

        commit_sha = ""
        try:
            head_res = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=target,
                check=True,
                capture_output=True,
                text=True,
            )
            commit_sha = head_res.stdout.strip()
        except Exception:
            pass

        return target, commit_sha

    @staticmethod
    def _check_repo_url(repo_url: str) -> None:
        """Allow only https/ssh remotes so a spec cannot smuggle git options or exotic transports."""
        if repo_url.startswith("-"):
            raise RegistryError(f"Refusing repository spec that looks like a git option: {repo_url!r}")
        if repo_url.startswith("git@"):
            return
        parsed = urlparse(repo_url)
        if parsed.scheme not in {"https", "ssh"} or not parsed.netloc:
            raise RegistryError(
                f"Unsupported repository URL {repo_url!r}: use owner/repo, an https:// URL, or git@host:path"
            )

    def fetch_skill(self, spec: str, commit: str | None = None) -> SkillPackage:
        """Resolve a remote spec like 'owner/repo:skill' into a SkillPackage."""
        repo_url, skill_name, spec_ref = self.parse_spec_with_ref(spec)
        target_ref = commit or spec_ref
        repo_dir, head_commit = self._clone_or_update(repo_url, ref=target_ref)

        package: SkillPackage | None = None
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
                    package = SkillPackage.load(candidate)
                    break
            if package is None:
                # Scan recursively
                for match in repo_dir.rglob(f"**/{skill_name}/SKILL.md"):
                    if match.is_file():
                        package = SkillPackage.load(match.parent)
                        break
            if package is None:
                raise RegistryError(f"Skill '{skill_name}' not found in repository {repo_url}")

        # 2. Check if the repo root is itself a skill
        elif (repo_dir / "SKILL.md").is_file():
            package = SkillPackage.load(repo_dir)

        # 3. Check if there are skills in skills/
        elif (repo_dir / "skills").is_dir():
            for child in (repo_dir / "skills").iterdir():
                if child.is_dir() and (child / "SKILL.md").is_file():
                    package = SkillPackage.load(child)
                    break

        if package is None:
            raise RegistryError(f"No valid skill found in {repo_url}")

        package.commit_sha = head_commit or None
        return package

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

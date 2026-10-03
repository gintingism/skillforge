"""Registry interfaces and a filesystem-backed local implementation."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Iterable

from .errors import RegistryError
from .skill import Skill


class Registry(ABC):
    """Abstract source of discoverable and installable skills."""

    @abstractmethod
    def search(self, query: str) -> list[Skill]:
        """Return skills whose name or description matches a query."""

    @abstractmethod
    def install(self, name: str, destination: Path) -> Path:
        """Install a named skill into a destination directory."""

    @abstractmethod
    def get(self, name: str) -> Skill:
        """Return a named skill."""


class LocalRegistry(Registry):
    """Filesystem registry storing one ``<name>/SKILL.md`` per skill."""

    def __init__(self, root: Path) -> None:
        self.root = root

    def publish(self, skill: Skill) -> Path:
        """Publish a skill into the local registry."""
        target = self.root / skill.name / "SKILL.md"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(skill.render(), encoding="utf-8")
        return target

    def get(self, name: str) -> Skill:
        """Load a named skill from the local registry."""
        try:
            Skill.validate_name(name)
        except Exception as exc:
            raise RegistryError(str(exc)) from exc
        source = self.root / name / "SKILL.md"
        if not source.is_file():
            raise RegistryError(f"Skill not found: {name}")
        try:
            return Skill.load(source)
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
        """Copy a named skill to ``destination/SKILL.md``."""
        skill = self.get(name)
        destination.mkdir(parents=True, exist_ok=True)
        target = destination / "SKILL.md"
        target.write_text(skill.render(), encoding="utf-8")
        return target


class BuiltinRegistry(Registry):
    """Explicit registry for skills shipped inside the SkillForge package."""

    def __init__(self) -> None:
        self.root = Path(__file__).parent / "builtin_skills"

    def get(self, name: str) -> Skill:
        """Load a named built-in skill."""
        try:
            Skill.validate_name(name)
        except Exception as exc:
            raise RegistryError(str(exc)) from exc
        path = self.root.joinpath(name, "SKILL.md")
        if not path.is_file():
            raise RegistryError(f"Built-in skill not found: {name}")
        try:
            return Skill.load(Path(path))
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
        skill = self.get(name)
        destination.mkdir(parents=True, exist_ok=True)
        target = destination / "SKILL.md"
        target.write_text(skill.render(), encoding="utf-8")
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

    def search(self, query: str) -> list[Skill]:
        """Search all sources and de-duplicate by name."""
        found: dict[str, Skill] = {}
        for registry in self.registries:
            for skill in registry.search(query):
                found.setdefault(skill.name, skill)
        return sorted(found.values(), key=lambda skill: skill.name)

    def install(self, name: str, destination: Path) -> Path:
        """Install a skill resolved from ordered sources."""
        skill = self.get(name)
        destination.mkdir(parents=True, exist_ok=True)
        target = destination / "SKILL.md"
        target.write_text(skill.render(), encoding="utf-8")
        return target

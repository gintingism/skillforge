"""Registry interfaces and a filesystem-backed local implementation."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

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

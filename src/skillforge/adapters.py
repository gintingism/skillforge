"""Assistant-specific installation adapters."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from .errors import AdapterError
from .skill import Skill


class Adapter(ABC):
    """Install a universal skill into an assistant-specific project layout."""

    @abstractmethod
    def detect(self, project: Path) -> bool:
        """Return whether this assistant is present in a project."""

    @abstractmethod
    def install(self, skill: Skill, project: Path) -> Path:
        """Install a skill and return its destination path."""


class CopilotAdapter(Adapter):
    """Adapter for GitHub Copilot repository instructions."""

    def detect(self, project: Path) -> bool:
        return (project / ".github").is_dir() or (project / ".github" / "copilot-instructions.md").exists()

    def install(self, skill: Skill, project: Path) -> Path:
        target = project / ".github" / "copilot-instructions.md"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(skill.render(), encoding="utf-8")
        return target


class ClaudeAdapter(Adapter):
    """Adapter for Claude project skills."""

    def detect(self, project: Path) -> bool:
        return (project / ".claude").is_dir()

    def install(self, skill: Skill, project: Path) -> Path:
        target = project / ".claude" / "skills" / skill.name / "SKILL.md"
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(skill.render(), encoding="utf-8")
        except OSError as exc:
            raise AdapterError(f"Unable to install Claude skill: {exc}") from exc
        return target


def detect_adapters(project: Path) -> list[Adapter]:
    """Return adapters detected in a project, in stable order."""
    return [adapter for adapter in (CopilotAdapter(), ClaudeAdapter()) if adapter.detect(project)]

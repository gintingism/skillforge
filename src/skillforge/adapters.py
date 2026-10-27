"""Assistant-specific installation and management adapters."""

from __future__ import annotations

import os
import re
import shutil
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Union

from .errors import AdapterError
from .skill import Skill, SkillPackage

SkillTarget = Union[Skill, SkillPackage]


class Adapter(ABC):
    """Install and manage skills across assistant-specific project layouts."""

    @abstractmethod
    def detect(self, project: Path) -> bool:
        """Return whether this assistant is present in a project."""

    @abstractmethod
    def install(self, skill: SkillTarget, project: Path) -> Path:
        """Install a skill and return its destination path."""

    @abstractmethod
    def remove(self, name: str, project: Path) -> bool:
        """Remove a skill from the project layout. Return True if removed."""

    @abstractmethod
    def list_skills(self, project: Path) -> list[str]:
        """List all skill names installed in this assistant layout."""

    @staticmethod
    def _extract_skill(skill_target: SkillTarget) -> tuple[Skill, SkillPackage | None]:
        if isinstance(skill_target, SkillPackage):
            return skill_target.skill, skill_target
        return skill_target, None

    @staticmethod
    def _safe_rmtree(path: Path) -> None:
        if path.is_dir():
            shutil.rmtree(path)
        elif path.is_file():
            path.unlink()


class CopilotAdapter(Adapter):
    """Adapter for GitHub Copilot repository instructions."""

    def detect(self, project: Path) -> bool:
        return (project / ".github").is_dir() or (project / ".github" / "copilot-instructions.md").exists()

    def install(self, skill: SkillTarget, project: Path) -> Path:
        skill_obj, _ = self._extract_skill(skill)
        target = project / ".github" / "copilot-instructions.md"
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(skill_obj.render(), encoding="utf-8")
        except OSError as exc:
            raise AdapterError(f"Unable to install Copilot instructions: {exc}") from exc
        return target

    def remove(self, name: str, project: Path) -> bool:
        target = project / ".github" / "copilot-instructions.md"
        if target.is_file():
            target.unlink()
            return True
        return False

    def list_skills(self, project: Path) -> list[str]:
        target = project / ".github" / "copilot-instructions.md"
        if target.is_file():
            try:
                skill = Skill.load(target)
                return [skill.name]
            except Exception:
                return ["copilot-instructions"]
        return []


class ClaudeAdapter(Adapter):
    """Adapter for Claude project skills."""

    def detect(self, project: Path) -> bool:
        return (project / ".claude").is_dir()

    def install(self, skill: SkillTarget, project: Path) -> Path:
        skill_obj, package = self._extract_skill(skill)
        skill_dir = project / ".claude" / "skills" / skill_obj.name
        target = skill_dir / "SKILL.md"
        try:
            if package:
                package.save(skill_dir)
            else:
                skill_dir.mkdir(parents=True, exist_ok=True)
                target.write_text(skill_obj.render(), encoding="utf-8")
        except OSError as exc:
            raise AdapterError(f"Unable to install Claude skill: {exc}") from exc
        return target

    def remove(self, name: str, project: Path) -> bool:
        skill_dir = project / ".claude" / "skills" / name
        if skill_dir.exists():
            self._safe_rmtree(skill_dir)
            return True
        return False

    def list_skills(self, project: Path) -> list[str]:
        skills_dir = project / ".claude" / "skills"
        if not skills_dir.is_dir():
            return []
        return sorted([p.parent.name for p in skills_dir.glob("*/SKILL.md")])


class ClaudeCodeAdapter(ClaudeAdapter):
    """Adapter for Claude Code project skills."""


class CursorAdapter(Adapter):
    """Adapter for Cursor project skills."""

    def detect(self, project: Path) -> bool:
        return (project / ".cursor").is_dir()

    def install(self, skill: SkillTarget, project: Path) -> Path:
        skill_obj, package = self._extract_skill(skill)
        skill_dir = project / ".cursor" / "skills" / skill_obj.name
        target = skill_dir / "SKILL.md"
        try:
            if package:
                package.save(skill_dir)
            else:
                skill_dir.mkdir(parents=True, exist_ok=True)
                target.write_text(skill_obj.render(), encoding="utf-8")
        except OSError as exc:
            raise AdapterError(f"Unable to install Cursor skill: {exc}") from exc
        return target

    def remove(self, name: str, project: Path) -> bool:
        skill_dir = project / ".cursor" / "skills" / name
        if skill_dir.exists():
            self._safe_rmtree(skill_dir)
            return True
        return False

    def list_skills(self, project: Path) -> list[str]:
        skills_dir = project / ".cursor" / "skills"
        if not skills_dir.is_dir():
            return []
        return sorted([p.parent.name for p in skills_dir.glob("*/SKILL.md")])


class AntigravityAdapter(Adapter):
    """Adapter for Google Antigravity / Gemini CLI skills."""

    def detect(self, project: Path) -> bool:
        return (project / ".gemini").is_dir()

    def install(self, skill: SkillTarget, project: Path) -> Path:
        skill_obj, package = self._extract_skill(skill)
        skill_dir = project / ".gemini" / "config" / "skills" / skill_obj.name
        target = skill_dir / "SKILL.md"
        try:
            if package:
                package.save(skill_dir)
            else:
                skill_dir.mkdir(parents=True, exist_ok=True)
                target.write_text(skill_obj.render(), encoding="utf-8")
        except OSError as exc:
            raise AdapterError(f"Unable to install Antigravity/Gemini skill: {exc}") from exc
        return target

    def remove(self, name: str, project: Path) -> bool:
        skill_dir = project / ".gemini" / "config" / "skills" / name
        if skill_dir.exists():
            self._safe_rmtree(skill_dir)
            return True
        return False

    def list_skills(self, project: Path) -> list[str]:
        skills_dir = project / ".gemini" / "config" / "skills"
        if not skills_dir.is_dir():
            return []
        return sorted([p.parent.name for p in skills_dir.glob("*/SKILL.md")])


class WindsurfAdapter(Adapter):
    """Adapter for Windsurf editor skills."""

    def detect(self, project: Path) -> bool:
        return (project / ".windsurf").is_dir() or (project / ".windsurfrules").is_file()

    def install(self, skill: SkillTarget, project: Path) -> Path:
        skill_obj, package = self._extract_skill(skill)
        skill_dir = project / ".windsurf" / "skills" / skill_obj.name
        target = skill_dir / "SKILL.md"
        try:
            if package:
                package.save(skill_dir)
            else:
                skill_dir.mkdir(parents=True, exist_ok=True)
                target.write_text(skill_obj.render(), encoding="utf-8")
        except OSError as exc:
            raise AdapterError(f"Unable to install Windsurf skill: {exc}") from exc
        return target

    def remove(self, name: str, project: Path) -> bool:
        skill_dir = project / ".windsurf" / "skills" / name
        if skill_dir.exists():
            self._safe_rmtree(skill_dir)
            return True
        return False

    def list_skills(self, project: Path) -> list[str]:
        skills_dir = project / ".windsurf" / "skills"
        if not skills_dir.is_dir():
            return []
        return sorted([p.parent.name for p in skills_dir.glob("*/SKILL.md")])


class ClineAdapter(Adapter):
    """Adapter for Cline / Roo-Code skills."""

    def detect(self, project: Path) -> bool:
        return (project / ".cline").is_dir() or (project / ".roomodes").is_file()

    def install(self, skill: SkillTarget, project: Path) -> Path:
        skill_obj, package = self._extract_skill(skill)
        skill_dir = project / ".cline" / "skills" / skill_obj.name
        target = skill_dir / "SKILL.md"
        try:
            if package:
                package.save(skill_dir)
            else:
                skill_dir.mkdir(parents=True, exist_ok=True)
                target.write_text(skill_obj.render(), encoding="utf-8")
        except OSError as exc:
            raise AdapterError(f"Unable to install Cline skill: {exc}") from exc
        return target

    def remove(self, name: str, project: Path) -> bool:
        skill_dir = project / ".cline" / "skills" / name
        if skill_dir.exists():
            self._safe_rmtree(skill_dir)
            return True
        return False

    def list_skills(self, project: Path) -> list[str]:
        skills_dir = project / ".cline" / "skills"
        if not skills_dir.is_dir():
            return []
        return sorted([p.parent.name for p in skills_dir.glob("*/SKILL.md")])


class AgentsMarkdownAdapter(Adapter):
    """Adapter for universal AGENTS.md instruction catalogs."""

    def detect(self, project: Path) -> bool:
        return (project / "AGENTS.md").is_file() or (project / ".agents").is_dir()

    def install(self, skill: SkillTarget, project: Path) -> Path:
        skill_obj, _ = self._extract_skill(skill)
        target = project / "AGENTS.md"
        try:
            existing = target.read_text(encoding="utf-8") if target.is_file() else ""
            block = (
                f"\n<!-- skillforge:{skill_obj.name}:start -->\n"
                f"### Skill: {skill_obj.name}\n"
                f"{skill_obj.description}\n\n"
                f"{skill_obj.body.strip()}\n"
                f"<!-- skillforge:{skill_obj.name}:end -->\n"
            )
            marker_start = f"<!-- skillforge:{skill_obj.name}:start -->"
            marker_end = f"<!-- skillforge:{skill_obj.name}:end -->"
            if marker_start in existing and marker_end in existing:
                before = existing.split(marker_start)[0]
                after = existing.split(marker_end)[1]
                updated = before + block.strip() + after
            else:
                updated = (existing.rstrip() + "\n\n" + block.strip() + "\n").lstrip()
            target.write_text(updated, encoding="utf-8")
        except OSError as exc:
            raise AdapterError(f"Unable to update AGENTS.md: {exc}") from exc
        return target

    def remove(self, name: str, project: Path) -> bool:
        target = project / "AGENTS.md"
        if not target.is_file():
            return False
        content = target.read_text(encoding="utf-8")
        marker_start = f"<!-- skillforge:{name}:start -->"
        marker_end = f"<!-- skillforge:{name}:end -->"
        if marker_start in content and marker_end in content:
            before = content.split(marker_start)[0]
            after = content.split(marker_end)[1]
            target.write_text((before.rstrip() + "\n" + after.lstrip()).strip() + "\n", encoding="utf-8")
            return True
        return False

    def list_skills(self, project: Path) -> list[str]:
        target = project / "AGENTS.md"
        if not target.is_file():
            return []
        content = target.read_text(encoding="utf-8")
        return re.findall(r"<!-- skillforge:(.*?):start -->", content)


def detect_adapters(project: Path, global_scope: bool = False) -> list[Adapter]:
    """Return adapters detected in a project (or global config), in stable order."""
    if global_scope:
        return [
            ClaudeCodeAdapter(),
            AntigravityAdapter(),
            CursorAdapter(),
        ]

    adapters = (
        CopilotAdapter(),
        ClaudeCodeAdapter(),
        CursorAdapter(),
        AntigravityAdapter(),
        WindsurfAdapter(),
        ClineAdapter(),
        AgentsMarkdownAdapter(),
    )
    return [adapter for adapter in adapters if adapter.detect(project)]

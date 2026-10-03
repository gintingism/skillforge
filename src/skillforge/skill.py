"""The universal SKILL.md document model."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from .errors import SkillParseError, SkillValidationError

_SAFE_NAME = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")


@dataclass(frozen=True, slots=True)
class Skill:
    """A portable skill with validated YAML metadata and Markdown content."""

    name: str
    description: str
    body: str

    def __post_init__(self) -> None:
        self.validate_name(self.name)
        if not isinstance(self.description, str) or not self.description.strip():
            raise SkillValidationError("Skill description is required")

    @staticmethod
    def validate_name(name: str) -> None:
        """Validate a skill name before using it as a filesystem path."""
        if not isinstance(name, str) or not name.strip():
            raise SkillValidationError("Skill name is required")
        if not _SAFE_NAME.fullmatch(name):
            raise SkillValidationError(
                "Skill name must be safe for filesystem paths: "
                "lowercase letters, numbers, '-' or '_' only"
            )

    @classmethod
    def load(cls, path: Path) -> "Skill":
        """Load and validate a SKILL.md file from disk."""
        try:
            return parse_skill(path.read_text(encoding="utf-8"))
        except OSError as exc:
            raise SkillParseError(f"Unable to read skill file {path}: {exc}") from exc

    def render(self) -> str:
        """Render the skill as a canonical SKILL.md document."""
        metadata = yaml.safe_dump(
            {"name": self.name, "description": self.description},
            sort_keys=False,
            allow_unicode=False,
        ).strip()
        return f"---\n{metadata}\n---\n\n{self.body}"


def parse_skill(document: str) -> Skill:
    """Parse a SKILL.md document with YAML frontmatter."""
    if not document.startswith("---"):
        raise SkillParseError("SKILL.md must begin with YAML frontmatter")
    parts = document.split("---", 2)
    if len(parts) != 3:
        raise SkillParseError("SKILL.md frontmatter must be closed with '---'")
    try:
        metadata: Any = yaml.safe_load(parts[1])
    except yaml.YAMLError as exc:
        raise SkillParseError(f"Invalid YAML frontmatter: {exc}") from exc
    if not isinstance(metadata, dict):
        raise SkillValidationError("Skill frontmatter must be a mapping")
    return Skill(
        name=metadata.get("name", ""),
        description=metadata.get("description", ""),
        body=parts[2].lstrip("\r\n"),
    )

"""The universal SKILL.md document and package model."""

from __future__ import annotations

import os
import re
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

import yaml

from .errors import SkillParseError, SkillValidationError

_SAFE_NAME = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")


@dataclass(frozen=True, slots=True)
class Skill:
    """A portable skill with validated YAML metadata and Markdown content."""

    name: str
    description: str
    body: str
    license: str | None = None
    compatibility: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    allowed_tools: str | None = None

    def __post_init__(self) -> None:
        self.validate_name(self.name)
        if not isinstance(self.description, str) or not self.description.strip():
            raise SkillValidationError("Skill description is required")
        if len(self.description) > 1024:
            raise SkillValidationError("Skill description exceeds maximum length of 1024 characters")
        if self.compatibility is not None and len(self.compatibility) > 500:
            raise SkillValidationError("Skill compatibility exceeds maximum length of 500 characters")

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
        if "--" in name:
            raise SkillValidationError("Skill name must not contain consecutive hyphens ('--')")

    @classmethod
    def load(cls, path: Path) -> "Skill":
        """Load and validate a SKILL.md file or skill directory from disk."""
        target = path / "SKILL.md" if path.is_dir() else path
        try:
            return parse_skill(target.read_text(encoding="utf-8"))
        except OSError as exc:
            raise SkillParseError(f"Unable to read skill file {target}: {exc}") from exc

    def render(self) -> str:
        """Render the skill as a canonical SKILL.md document with YAML frontmatter."""
        meta_dict: dict[str, Any] = {
            "name": self.name,
            "description": self.description,
        }
        if self.license:
            meta_dict["license"] = self.license
        if self.compatibility:
            meta_dict["compatibility"] = self.compatibility
        if self.allowed_tools:
            meta_dict["allowed-tools"] = self.allowed_tools
        if self.metadata:
            meta_dict["metadata"] = dict(self.metadata)

        frontmatter = yaml.safe_dump(
            meta_dict,
            sort_keys=False,
            allow_unicode=False,
        ).strip()
        body = self.body.lstrip("\r\n")
        return f"---\n{frontmatter}\n---\n\n{body}"


def parse_skill(document: str) -> Skill:
    """Parse a SKILL.md document with YAML frontmatter."""
    if not document.startswith("---"):
        raise SkillParseError("SKILL.md must begin with YAML frontmatter")
    parts = document.split("---", 2)
    if len(parts) != 3:
        raise SkillParseError("SKILL.md frontmatter must be closed with '---'")
    try:
        raw_meta: Any = yaml.safe_load(parts[1])
    except yaml.YAMLError as exc:
        raise SkillParseError(f"Invalid YAML frontmatter: {exc}") from exc
    if not isinstance(raw_meta, dict):
        raise SkillValidationError("Skill frontmatter must be a mapping")

    name = str(raw_meta.get("name", ""))
    description = str(raw_meta.get("description", ""))
    license_val = raw_meta.get("license")
    compatibility_val = raw_meta.get("compatibility")
    allowed_tools = raw_meta.get("allowed-tools") or raw_meta.get("allowed_tools")
    extra_metadata = raw_meta.get("metadata")

    return Skill(
        name=name,
        description=description,
        body=parts[2].lstrip("\r\n"),
        license=str(license_val) if license_val is not None else None,
        compatibility=str(compatibility_val) if compatibility_val is not None else None,
        metadata=dict(extra_metadata) if isinstance(extra_metadata, dict) else {},
        allowed_tools=str(allowed_tools) if allowed_tools is not None else None,
    )


@dataclass
class SkillPackage:
    """A portable skill package directory containing SKILL.md and optional resources."""

    skill: Skill
    scripts: dict[str, str] = field(default_factory=dict)
    references: dict[str, str] = field(default_factory=dict)
    assets: dict[str, bytes] = field(default_factory=dict)
    source_dir: Path | None = None

    @classmethod
    def load(cls, path: Path) -> "SkillPackage":
        """Load a skill package from a directory or a single SKILL.md file."""
        if path.is_file():
            skill = Skill.load(path)
            parent = path.parent
            if parent.is_dir() and (parent / "SKILL.md").exists() and parent.name == skill.name:
                return cls.load(parent)
            return cls(skill=skill, source_dir=parent)

        if not path.is_dir():
            raise SkillParseError(f"Directory not found: {path}")

        skill_file = path / "SKILL.md"
        if not skill_file.is_file():
            raise SkillParseError(f"SKILL.md not found in {path}")

        skill = Skill.load(skill_file)
        scripts: dict[str, str] = {}
        references: dict[str, str] = {}
        assets: dict[str, bytes] = {}

        scripts_dir = path / "scripts"
        if scripts_dir.is_dir():
            for file_path in scripts_dir.rglob("*"):
                if file_path.is_file():
                    rel = file_path.relative_to(scripts_dir).as_posix()
                    try:
                        scripts[rel] = file_path.read_text(encoding="utf-8")
                    except UnicodeDecodeError:
                        pass

        refs_dir = path / "references"
        if refs_dir.is_dir():
            for file_path in refs_dir.rglob("*"):
                if file_path.is_file():
                    rel = file_path.relative_to(refs_dir).as_posix()
                    try:
                        references[rel] = file_path.read_text(encoding="utf-8")
                    except UnicodeDecodeError:
                        pass

        assets_dir = path / "assets"
        if assets_dir.is_dir():
            for file_path in assets_dir.rglob("*"):
                if file_path.is_file():
                    rel = file_path.relative_to(assets_dir).as_posix()
                    assets[rel] = file_path.read_bytes()

        return cls(
            skill=skill,
            scripts=scripts,
            references=references,
            assets=assets,
            source_dir=path,
        )

    def save(self, destination: Path) -> Path:
        """Save the complete skill package to destination directory."""
        destination.mkdir(parents=True, exist_ok=True)
        (destination / "SKILL.md").write_text(self.skill.render(), encoding="utf-8")

        if self.scripts:
            scripts_dir = destination / "scripts"
            scripts_dir.mkdir(parents=True, exist_ok=True)
            for rel_path, content in self.scripts.items():
                target = scripts_dir / rel_path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(content, encoding="utf-8")

        if self.references:
            refs_dir = destination / "references"
            refs_dir.mkdir(parents=True, exist_ok=True)
            for rel_path, content in self.references.items():
                target = refs_dir / rel_path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(content, encoding="utf-8")

        if self.assets:
            assets_dir = destination / "assets"
            assets_dir.mkdir(parents=True, exist_ok=True)
            for rel_path, data in self.assets.items():
                target = assets_dir / rel_path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)

        return destination

    def pack_zip(self, output: Path) -> Path:
        """Pack the skill package into a zip archive with safe relative paths."""
        output.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
            prefix = self.skill.name
            archive.writestr(f"{prefix}/SKILL.md", self.skill.render())
            for rel_path, content in self.scripts.items():
                archive.writestr(f"{prefix}/scripts/{rel_path}", content)
            for rel_path, content in self.references.items():
                archive.writestr(f"{prefix}/references/{rel_path}", content)
            for rel_path, data in self.assets.items():
                archive.writestr(f"{prefix}/assets/{rel_path}", data)
        return output

    @classmethod
    def unpack_zip(cls, archive_path: Path, output_dir: Path) -> "SkillPackage":
        """Unpack a zip archive safely, protecting against zip slip path traversal."""
        if not archive_path.is_file():
            raise SkillParseError(f"Archive not found: {archive_path}")

        output_dir.mkdir(parents=True, exist_ok=True)
        resolved_out = output_dir.resolve()

        with zipfile.ZipFile(archive_path, "r") as archive:
            for member in archive.infolist():
                member_path = resolved_out / member.filename
                if not member_path.resolve().is_relative_to(resolved_out):
                    raise SkillValidationError(f"Archive contains path traversal: {member.filename}")
            archive.extractall(output_dir)

        # Locate unpacked skill directory
        subdirs = [d for d in output_dir.iterdir() if d.is_dir() and (d / "SKILL.md").exists()]
        if subdirs:
            return cls.load(subdirs[0])
        if (output_dir / "SKILL.md").exists():
            return cls.load(output_dir)
        raise SkillParseError(f"No SKILL.md found in unpacked archive {archive_path}")

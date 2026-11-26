"""The universal SKILL.md document and package model."""

from __future__ import annotations

import hashlib
import os
import re
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

import yaml

from .errors import SkillParseError, SkillValidationError

_SAFE_NAME = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
_CLAUDE_DYNAMIC_CMD_RE = re.compile(r"!\`[^`\n]+\`")

AGENTSKILLS_SPEC_FRONTMATTER_KEYS: frozenset[str] = frozenset(
    {"name", "description", "license", "compatibility", "metadata", "allowed-tools"}
)
CLAUDE_EXTENSION_FRONTMATTER_KEYS: frozenset[str] = frozenset(
    {
        "disable-model-invocation",
        "disable_model_invocation",
        "user-invocable",
        "argument-hint",
        "hooks",
        "model",
        "effort",
        "context",
        "agent",
        "paths",
        "shell",
    }
)


def estimate_tokens(text: str) -> int:
    """Estimate LLM token count using the standard ~4 chars/token heuristic."""
    stripped = text.strip()
    if not stripped:
        return 0
    return max(1, (len(stripped) + 3) // 4)


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
    disable_model_invocation: bool = False
    extra_frontmatter: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.validate_name(self.name)
        if not isinstance(self.description, str) or not self.description.strip():
            raise SkillValidationError("Skill description is required")
        if len(self.description) > 1024:
            raise SkillValidationError("Skill description exceeds maximum length of 1024 characters")
        if self.compatibility is not None and len(self.compatibility) > 500:
            raise SkillValidationError("Skill compatibility exceeds maximum length of 500 characters")

    @property
    def pointer_tokens(self) -> int:
        """Startup context window token cost (0 when disable_model_invocation is True)."""
        if self.disable_model_invocation:
            return 0
        return estimate_tokens(f"{self.name}: {self.description}")

    @property
    def body_tokens(self) -> int:
        """On-demand token cost when the skill body is loaded into context."""
        return estimate_tokens(self.body)

    @property
    def body_lines(self) -> int:
        """Line count of the skill markdown body."""
        return len(self.body.splitlines())

    @property
    def dependencies(self) -> tuple[str, ...]:
        """Declared skill dependencies from frontmatter metadata."""
        raw_deps = self.metadata.get("dependencies")
        if isinstance(raw_deps, (list, tuple)):
            return tuple(str(d).strip() for d in raw_deps if str(d).strip())
        if isinstance(raw_deps, str) and raw_deps.strip():
            return tuple(part.strip() for part in raw_deps.split(",") if part.strip())
        return ()

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

    def validate_strict_spec(self, source_dir: Path | None = None) -> list[str]:
        """Validate strict AAIF agentskills.io open specification conformance."""
        issues: list[str] = []
        strict_name_re = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$")
        if not strict_name_re.fullmatch(self.name) or "--" in self.name:
            issues.append(
                f"Skill name '{self.name}' violates strict agentskills.io spec "
                "(1-64 lowercase alphanumeric or single hyphens, no underscores or trailing hyphens)"
            )
        if source_dir is not None and source_dir.name != self.name:
            issues.append(
                f"Skill directory '{source_dir.name}' must match frontmatter name '{self.name}'"
            )
        if len(self.description) > 1024:
            issues.append(
                f"Skill description ({len(self.description)} chars) exceeds agentskills.io 1024-char limit"
            )
        if self.compatibility is not None and len(self.compatibility) > 500:
            issues.append(
                f"Skill compatibility ({len(self.compatibility)} chars) exceeds agentskills.io 500-char limit"
            )
        unexpected_keys = sorted(
            k for k in self.extra_frontmatter.keys() if k not in AGENTSKILLS_SPEC_FRONTMATTER_KEYS
        )
        if self.disable_model_invocation and "disable-model-invocation" not in unexpected_keys and "disable_model_invocation" not in unexpected_keys:
            unexpected_keys.append("disable-model-invocation")
        if unexpected_keys:
            issues.append(
                f"Unexpected top-level frontmatter key(s): {', '.join(unexpected_keys)}. "
                f"AAIF agentskills.io allows only 6 fields ({', '.join(sorted(AGENTSKILLS_SPEC_FRONTMATTER_KEYS))}); "
                "move custom keys under metadata or run 'skillforge normalize'"
            )
        if _CLAUDE_DYNAMIC_CMD_RE.search(self.body):
            issues.append(
                "Body uses Claude Code dynamic command syntax (!`cmd`), which is non-portable outside Claude Code"
            )
        if self.body_tokens > 5000:
            issues.append(
                f"SKILL.md body (~{self.body_tokens} tokens) exceeds agentskills.io 5000-token cap"
            )
        if self.body_lines > 500:
            issues.append(
                f"SKILL.md body ({self.body_lines} lines) exceeds agentskills.io 500-line limit"
            )
        for k, v in self.metadata.items():
            if k == "dependencies":
                continue
            if not isinstance(k, str) or not isinstance(v, str):
                issues.append(
                    f"Metadata entry '{k}' must map a string key to a string value under strict spec"
                )
        return issues

    def normalize_portable(self, *, fix_name: bool = False) -> tuple["Skill", list[str]]:
        """Normalize a Skill to conform strictly to the 6-field AAIF agentskills.io spec."""
        changes: list[str] = []
        new_name = self.name
        if fix_name and ("_" in new_name or new_name.startswith("-") or new_name.endswith("-")):
            cleaned = re.sub(r"[^a-z0-9-]+", "-", new_name.lower().replace("_", "-")).strip("-")
            cleaned = re.sub(r"-{2,}", "-", cleaned)[:64]
            if cleaned and cleaned != new_name:
                changes.append(f"Normalized skill name '{new_name}' -> '{cleaned}'")
                new_name = cleaned

        new_meta: dict[str, Any] = {}
        for k, v in self.metadata.items():
            key_str = str(k)
            if isinstance(v, str):
                new_meta[key_str] = v
            elif isinstance(v, (list, tuple)):
                joined = ", ".join(str(item).strip() for item in v if str(item).strip())
                new_meta[key_str] = joined
                changes.append(f"Converted metadata.{key_str} list to comma-separated string")
            else:
                new_meta[key_str] = str(v)
                changes.append(f"Converted metadata.{key_str} value to string")

        for k, v in sorted(self.extra_frontmatter.items()):
            if k in AGENTSKILLS_SPEC_FRONTMATTER_KEYS:
                continue
            if k in CLAUDE_EXTENSION_FRONTMATTER_KEYS:
                changes.append(f"Removed Claude-only frontmatter key '{k}' for cross-platform portability")
                continue
            if k == "allowed_tools":
                changes.append("Normalized frontmatter key 'allowed_tools' -> 'allowed-tools'")
                continue
            if k not in new_meta:
                if isinstance(v, (list, tuple)):
                    new_meta[k] = ", ".join(str(item).strip() for item in v if str(item).strip())
                else:
                    new_meta[k] = str(v)
                changes.append(f"Moved top-level frontmatter key '{k}' under metadata.{k}")

        if self.disable_model_invocation and "disable-model-invocation" not in self.extra_frontmatter:
            changes.append("Removed Claude-only frontmatter key 'disable-model-invocation' for portability")

        normalized = Skill(
            name=new_name,
            description=self.description,
            body=self.body,
            license=self.license,
            compatibility=self.compatibility,
            metadata=new_meta,
            allowed_tools=self.allowed_tools,
            disable_model_invocation=False,
            extra_frontmatter={},
        )
        return normalized, changes

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
        if self.disable_model_invocation:
            meta_dict["disable-model-invocation"] = True
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
    disable_model = raw_meta.get("disable-model-invocation")
    if disable_model is None:
        disable_model = raw_meta.get("disable_model_invocation", False)
    extra_metadata = raw_meta.get("metadata")
    meta_dict = dict(extra_metadata) if isinstance(extra_metadata, dict) else {}
    top_deps = raw_meta.get("dependencies")
    if top_deps is not None and "dependencies" not in meta_dict:
        meta_dict["dependencies"] = top_deps

    extra_fm = {
        str(k): v
        for k, v in raw_meta.items()
        if str(k) not in AGENTSKILLS_SPEC_FRONTMATTER_KEYS
    }

    return Skill(
        name=name,
        description=description,
        body=parts[2].lstrip("\r\n"),
        license=str(license_val) if license_val is not None else None,
        compatibility=str(compatibility_val) if compatibility_val is not None else None,
        metadata=meta_dict,
        allowed_tools=str(allowed_tools) if allowed_tools is not None else None,
        disable_model_invocation=bool(disable_model),
        extra_frontmatter=extra_fm,
    )


@dataclass
class SkillPackage:
    """A portable skill package directory containing SKILL.md and optional resources."""

    skill: Skill
    scripts: dict[str, str] = field(default_factory=dict)
    references: dict[str, str] = field(default_factory=dict)
    assets: dict[str, bytes] = field(default_factory=dict)
    source_dir: Path | None = None
    commit_sha: str | None = None
    unexpected_binaries: dict[str, bytes] = field(default_factory=dict)

    @property
    def resource_tokens(self) -> int:
        """Total estimated tokens across bundled scripts and references."""
        total = 0
        for content in self.scripts.values():
            total += estimate_tokens(content)
        for content in self.references.values():
            total += estimate_tokens(content)
        return total

    @property
    def total_tokens(self) -> int:
        """Total estimated tokens across SKILL.md body and all bundled text resources."""
        return self.skill.body_tokens + self.resource_tokens

    def compute_sha256(self) -> str:
        """Compute a deterministic SHA-256 hex digest of the entire skill package."""
        hasher = hashlib.sha256()
        hasher.update(b"SKILL.md\0")
        hasher.update(self.skill.render().encode("utf-8"))
        for rel_path, content in sorted(self.scripts.items()):
            hasher.update(f"\0scripts/{rel_path}\0".encode("utf-8"))
            hasher.update(content.encode("utf-8"))
        for rel_path, content in sorted(self.references.items()):
            hasher.update(f"\0references/{rel_path}\0".encode("utf-8"))
            hasher.update(content.encode("utf-8"))
        for rel_path, data in sorted(self.assets.items()):
            hasher.update(f"\0assets/{rel_path}\0".encode("utf-8"))
            hasher.update(data)
        return hasher.hexdigest()

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
        unexpected_binaries: dict[str, bytes] = {}

        scripts_dir = path / "scripts"
        if scripts_dir.is_dir():
            for file_path in scripts_dir.rglob("*"):
                if file_path.is_file():
                    rel = file_path.relative_to(scripts_dir).as_posix()
                    try:
                        scripts[rel] = file_path.read_text(encoding="utf-8")
                    except UnicodeDecodeError:
                        unexpected_binaries[f"scripts/{rel}"] = file_path.read_bytes()

        refs_dir = path / "references"
        if refs_dir.is_dir():
            for file_path in refs_dir.rglob("*"):
                if file_path.is_file():
                    rel = file_path.relative_to(refs_dir).as_posix()
                    try:
                        references[rel] = file_path.read_text(encoding="utf-8")
                    except UnicodeDecodeError:
                        unexpected_binaries[f"references/{rel}"] = file_path.read_bytes()

        assets_dir = path / "assets"
        if assets_dir.is_dir():
            for file_path in assets_dir.rglob("*"):
                if file_path.is_file():
                    rel = file_path.relative_to(assets_dir).as_posix()
                    assets[rel] = file_path.read_bytes()

        bytecode_or_archive_exts = (
            ".pyc", ".pyo", ".wasm", ".class", ".beam", ".so", ".dll", ".dylib", ".exe",
            ".docx", ".xlsx", ".pptx", ".odt", ".zip", ".jar",
        )
        for file_path in path.rglob("*"):
            if not file_path.is_file():
                continue
            rel_top = file_path.relative_to(path).as_posix()
            if rel_top.startswith(("assets/", ".git/")):
                continue
            if rel_top in unexpected_binaries:
                continue
            if rel_top.lower().endswith(bytecode_or_archive_exts):
                unexpected_binaries[rel_top] = file_path.read_bytes()

        return cls(
            skill=skill,
            scripts=scripts,
            references=references,
            assets=assets,
            source_dir=path,
            unexpected_binaries=unexpected_binaries,
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

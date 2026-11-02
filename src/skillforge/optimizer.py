"""Automatic progressive disclosure refactoring and context budget optimizer for skills."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .errors import SkillForgeError
from .security import SkillAuditor
from .skill import Skill, SkillPackage, estimate_tokens

_HEADING_PATTERN = re.compile(r"^##\s+(.+)$")
_CODE_FENCE_PREFIXES = ("```", "~~~")


@dataclass
class OptimizationResult:
    """Detailed summary of skill optimization."""

    skill_name: str
    original_lines: int
    optimized_lines: int
    original_tokens: int
    optimized_tokens: int
    extracted_references: list[str] = field(default_factory=list)
    saved_path: Path | None = None
    passed_audit: bool = True
    audit_findings: list[str] = field(default_factory=list)

    @property
    def lines_saved(self) -> int:
        return max(0, self.original_lines - self.optimized_lines)

    @property
    def tokens_saved(self) -> int:
        return max(0, self.original_tokens - self.optimized_tokens)

    def to_dict(self) -> dict[str, Any]:
        return {
            "skill": self.skill_name,
            "original_lines": self.original_lines,
            "optimized_lines": self.optimized_lines,
            "lines_saved": self.lines_saved,
            "original_tokens": self.original_tokens,
            "optimized_tokens": self.optimized_tokens,
            "tokens_saved": self.tokens_saved,
            "extracted_references": self.extracted_references,
            "saved_path": str(self.saved_path) if self.saved_path else None,
            "passed_audit": self.passed_audit,
            "audit_findings": self.audit_findings,
        }


def _slugify(text: str) -> str:
    """Create a safe filesystem-friendly slug for markdown references."""
    slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return slug or "reference"


def _split_markdown_sections(text: str) -> tuple[str, list[dict[str, Any]]]:
    """Split markdown into preamble and level-2 sections safely respecting code blocks."""
    lines = text.splitlines(keepends=True)
    preamble_lines: list[str] = []
    sections: list[dict[str, Any]] = []

    current_title: str | None = None
    current_header: str = ""
    current_lines: list[str] = []
    in_code_block = False

    for line in lines:
        stripped = line.strip()
        if stripped.startswith(_CODE_FENCE_PREFIXES):
            in_code_block = not in_code_block
            if current_title is None:
                preamble_lines.append(line)
            else:
                current_lines.append(line)
            continue

        if not in_code_block and stripped.startswith("## ") and not stripped.startswith("###"):
            if current_title is not None:
                sections.append(
                    {
                        "title": current_title,
                        "header": current_header,
                        "body": "".join(current_lines),
                        "line_count": len(current_lines),
                    }
                )
            match = _HEADING_PATTERN.match(stripped)
            current_title = match.group(1).strip() if match else "Section"
            current_header = line
            current_lines = []
        else:
            if current_title is None:
                preamble_lines.append(line)
            else:
                current_lines.append(line)

    if current_title is not None:
        sections.append(
            {
                "title": current_title,
                "header": current_header,
                "body": "".join(current_lines),
                "line_count": len(current_lines),
            }
        )

    return "".join(preamble_lines), sections


def optimize_skill(
    package_dir: Path,
    output_dir: Path | None = None,
    max_lines: int = 400,
    max_tokens: int = 4000,
) -> OptimizationResult:
    """
    Refactor an oversized SKILL.md into progressive disclosure references.

    Extracts large secondary guide sections into references/ while leaving
    an explicit progressive disclosure pointer in SKILL.md.
    """
    pkg = SkillPackage.load(package_dir)
    orig_lines = pkg.skill.body_lines
    orig_tokens = pkg.skill.body_tokens

    # Check if already within budget
    if orig_lines <= max_lines and orig_tokens <= max_tokens:
        destination = output_dir or package_dir
        if output_dir:
            pkg.save(destination)
        auditor = SkillAuditor()
        report = auditor.audit_package(pkg)
        return OptimizationResult(
            skill_name=pkg.skill.name,
            original_lines=orig_lines,
            optimized_lines=orig_lines,
            original_tokens=orig_tokens,
            optimized_tokens=orig_tokens,
            extracted_references=[],
            saved_path=destination,
            passed_audit=report.passed,
            audit_findings=[f"{f.rule_id}: {f.message}" for f in report.findings],
        )

    preamble, sections = _split_markdown_sections(pkg.skill.body)
    if not sections:
        # Cannot split without level-2 sections
        destination = output_dir or package_dir
        if output_dir:
            pkg.save(destination)
        auditor = SkillAuditor()
        report = auditor.audit_package(pkg)
        return OptimizationResult(
            skill_name=pkg.skill.name,
            original_lines=orig_lines,
            optimized_lines=orig_lines,
            original_tokens=orig_tokens,
            optimized_tokens=orig_tokens,
            extracted_references=[],
            saved_path=destination,
            passed_audit=report.passed,
            audit_findings=[f"{f.rule_id}: {f.message}" for f in report.findings],
        )

    extracted_names: list[str] = []
    updated_references = dict(pkg.references)
    extracted_map: dict[int, str] = {}

    # Sort sections by body line count descending so we extract the largest bloat first
    indexed_sections = sorted(
        enumerate(sections),
        key=lambda item: len(item[1]["body"].splitlines()),
        reverse=True,
    )

    for idx, sec in indexed_sections:
        sec_lines = len(sec["body"].splitlines())
        if sec_lines < 15:
            # Keep small sections directly in SKILL.md
            continue

        title = sec["title"]
        base_slug = _slugify(title)
        ref_filename = f"{base_slug}.md"
        counter = 2
        while ref_filename in updated_references:
            ref_filename = f"{base_slug}-{counter}.md"
            counter += 1

        ref_content = f"# {title}\n\n{sec['body'].strip()}\n"
        updated_references[ref_filename] = ref_content
        extracted_names.append(f"references/{ref_filename}")
        extracted_map[idx] = ref_filename

        # Check running size
        candidate_body_lines: list[str] = [preamble.rstrip("\r\n")]
        for s_idx, s in enumerate(sections):
            candidate_body_lines.append("")
            candidate_body_lines.append(f"## {s['title']}")
            if s_idx in extracted_map:
                fname = extracted_map[s_idx]
                candidate_body_lines.append(
                    f"Detailed specifications and guides are documented in [references/{fname}](references/{fname}). "
                    "Read this reference file when executing this specific workflow."
                )
            else:
                candidate_body_lines.append(s["body"].rstrip("\r\n"))

        candidate_body = "\n".join(candidate_body_lines).strip() + "\n"
        cur_lines = len(candidate_body.splitlines())
        cur_tokens = estimate_tokens(candidate_body)

        if cur_lines <= max_lines and cur_tokens <= max_tokens:
            break

    # Build final body
    final_lines: list[str] = [preamble.rstrip("\r\n")]
    for s_idx, s in enumerate(sections):
        final_lines.append("")
        final_lines.append(f"## {s['title']}")
        if s_idx in extracted_map:
            fname = extracted_map[s_idx]
            final_lines.append(
                f"Detailed specifications and guides are documented in [references/{fname}](references/{fname}). "
                "Read this reference file when executing this specific workflow."
            )
        else:
            final_lines.append(s["body"].strip())

    optimized_body = "\n".join(final_lines).strip() + "\n"

    new_skill = Skill(
        name=pkg.skill.name,
        description=pkg.skill.description,
        body=optimized_body,
        license=pkg.skill.license,
        compatibility=pkg.skill.compatibility,
        allowed_tools=pkg.skill.allowed_tools,
        disable_model_invocation=pkg.skill.disable_model_invocation,
        metadata=dict(pkg.skill.metadata),
    )

    optimized_package = SkillPackage(
        skill=new_skill,
        scripts=dict(pkg.scripts),
        references=updated_references,
        assets=dict(pkg.assets),
        source_dir=pkg.source_dir,
    )

    destination = output_dir or package_dir
    optimized_package.save(destination)

    auditor = SkillAuditor()
    audit_report = auditor.audit_package(optimized_package)

    return OptimizationResult(
        skill_name=pkg.skill.name,
        original_lines=orig_lines,
        optimized_lines=new_skill.body_lines,
        original_tokens=orig_tokens,
        optimized_tokens=new_skill.body_tokens,
        extracted_references=extracted_names,
        saved_path=destination,
        passed_audit=audit_report.passed,
        audit_findings=[f"{f.rule_id}: {f.message}" for f in audit_report.findings],
    )

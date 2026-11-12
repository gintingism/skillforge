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


_CORE_SECTION_KEYWORDS = frozenset({
    "overview", "when to use", "quickstart", "core workflow", "summary", "rules", "constraints"
})


def _extract_code_blocks(text: str) -> list[str]:
    """Extract normalized fenced code block contents to verify zero code loss."""
    blocks: list[str] = []
    in_block = False
    cur: list[str] = []
    for line in text.splitlines():
        if line.strip().startswith(_CODE_FENCE_PREFIXES):
            if in_block:
                blocks.append("\n".join(cur).strip())
                cur = []
                in_block = False
            else:
                in_block = True
        elif in_block:
            cur.append(line.rstrip())
    return [b for b in blocks if b]


def verify_semantic_preservation(original_body: str, refactored_pkg: SkillPackage) -> tuple[bool, float]:
    """Verify that refactored skill + references preserve all code blocks and domain vocabulary."""
    combined_after = refactored_pkg.skill.body + "\n" + "\n".join(refactored_pkg.references.values())

    orig_blocks = _extract_code_blocks(original_body)
    after_blocks = _extract_code_blocks(combined_after)
    for b in orig_blocks:
        if b not in after_blocks and b not in combined_after:
            return False, 0.0

    orig_words = set(re.findall(r"\b[a-zA-Z_][a-zA-Z0-9_-]{3,}\b", original_body.lower()))
    if not orig_words:
        return True, 1.0
    after_words = set(re.findall(r"\b[a-zA-Z_][a-zA-Z0-9_-]{3,}\b", combined_after.lower()))
    preserved_ratio = len(orig_words & after_words) / len(orig_words)
    return preserved_ratio >= 0.98, round(preserved_ratio, 4)


def refactor_progressive_skill(
    package_dir: Path,
    output_dir: Path | None = None,
    target_tokens: int = 500,
    min_section_lines: int = 8,
) -> dict[str, Any]:
    """Slice a monolithic SKILL.md into progressive disclosure references with semantic verification."""
    pkg = SkillPackage.load(package_dir)
    orig_body = pkg.skill.body
    orig_lines = pkg.skill.body_lines
    orig_tokens = pkg.skill.body_tokens

    preamble, sections = _split_markdown_sections(orig_body)
    extracted_names: list[str] = []
    updated_references = dict(pkg.references)
    extracted_map: dict[int, str] = {}

    # Identify candidate sections to extract (non-core sections first, then largest)
    def _sort_key(item: tuple[int, dict[str, Any]]) -> tuple[int, int]:
        idx, sec = item
        title_lower = str(sec["title"]).lower()
        is_core = any(k in title_lower for k in _CORE_SECTION_KEYWORDS)
        return (0 if is_core else 1, len(str(sec["body"]).splitlines()))

    ranked = sorted(enumerate(sections), key=_sort_key, reverse=True)

    for idx, sec in ranked:
        sec_lines = len(str(sec["body"]).splitlines())
        if sec_lines < min_section_lines:
            continue

        # Check if current body is already within target_tokens
        rem_text = preamble + "\n" + "\n".join(
            s["body"] for i, s in enumerate(sections) if i not in extracted_map
        )
        if estimate_tokens(rem_text) <= target_tokens and extracted_map:
            break

        title = str(sec["title"])
        base_slug = _slugify(title)
        ref_filename = f"{base_slug}.md"
        counter = 2
        while ref_filename in updated_references:
            ref_filename = f"{base_slug}-{counter}.md"
            counter += 1

        updated_references[ref_filename] = f"# {title}\n\n{str(sec['body']).strip()}\n"
        extracted_names.append(f"references/{ref_filename}")
        extracted_map[idx] = ref_filename

    final_lines: list[str] = [preamble.rstrip("\r\n")]
    for s_idx, s in enumerate(sections):
        final_lines.append("")
        final_lines.append(f"## {s['title']}")
        if s_idx in extracted_map:
            fname = extracted_map[s_idx]
            final_lines.append(
                f"See [references/{fname}](references/{fname}) for full specifications and examples."
            )
        else:
            final_lines.append(str(s["body"]).strip())

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
    refactored_pkg = SkillPackage(
        skill=new_skill,
        scripts=dict(pkg.scripts),
        references=updated_references,
        assets=dict(pkg.assets),
        source_dir=pkg.source_dir,
    )

    preserved, ratio = verify_semantic_preservation(orig_body, refactored_pkg)
    if not preserved:
        raise SkillForgeError(f"Semantic preservation check failed (ratio={ratio}). Aborting refactor.")

    destination = output_dir or package_dir
    refactored_pkg.save(destination)
    audit_report = SkillAuditor().audit_package(refactored_pkg)

    return {
        "skill": pkg.skill.name,
        "original_lines": orig_lines,
        "optimized_lines": new_skill.body_lines,
        "original_tokens": orig_tokens,
        "optimized_tokens": new_skill.body_tokens,
        "tokens_saved": max(0, orig_tokens - new_skill.body_tokens),
        "extracted_references": extracted_names,
        "semantic_preservation_ratio": ratio,
        "semantic_preserved": preserved,
        "passed_audit": audit_report.passed,
        "saved_path": str(destination),
    }

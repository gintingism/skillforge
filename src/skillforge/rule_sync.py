"""Universal context rules synchronizer and cross-editor conflict resolver."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from skillforge.errors import SkillForgeError
from skillforge.security import Severity

SYNC_HEADER_PREFIX = "<!-- skillforge-sync-sha256: "
SYNC_HEADER_SUFFIX = " -->"

TARGET_PATHS: dict[str, str] = {
    "cursor": ".cursor/rules/00-core.mdc",
    "claude": "CLAUDE.md",
    "cursorrules": ".cursorrules",
    "windsurf": ".windsurfrules",
    "cline": ".clinerules",
}

_DIRECTIVE_RE = re.compile(
    r"(?i)\b(always|never|must|do\s+not|use|prefer|forbid|prohibit)\s+([a-z0-9_./-]+(?:\s+[a-z0-9_./-]+){0,3})"
)
_POSITIVE_VERBS = {"always", "must", "use", "prefer"}
_NEGATIVE_VERBS = {"never", "do not", "forbid", "prohibit"}


class RuleSyncError(SkillForgeError):
    """Raised when context rule synchronization fails."""


@dataclass(frozen=True, slots=True)
class SyncIssue:
    """An issue found during rule drift or conflict inspection."""

    rule_id: str
    severity: Severity
    target_file: str
    message: str


@dataclass
class RuleSyncReport:
    """Result of synchronizing or checking multi-editor context files against AGENTS.md."""

    source_file: str
    source_sha256: str
    synced_files: list[str] = field(default_factory=list)
    checked_files: list[str] = field(default_factory=list)
    issues: list[SyncIssue] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return len(self.issues) == 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "source_file": self.source_file,
            "source_sha256": self.source_sha256,
            "synced_files": self.synced_files,
            "checked_files": self.checked_files,
            "issues_count": len(self.issues),
            "issues": [
                {
                    "rule_id": i.rule_id,
                    "severity": i.severity.value,
                    "target_file": i.target_file,
                    "message": i.message,
                }
                for i in self.issues
            ],
        }

    def render_text(self) -> str:
        status = "PASSED" if self.passed else "DRIFT / CONFLICT DETECTED"
        lines = [
            f"Context Rule Sync Report: {status}",
            f"  Source of Truth: {self.source_file} (sha256: {self.source_sha256[:12]}...)",
        ]
        if self.synced_files:
            lines.append(f"  Synced Targets:  {', '.join(self.synced_files)}")
        if self.checked_files:
            lines.append(f"  Checked Targets: {', '.join(self.checked_files)}")
        if self.issues:
            lines.append("\nIssues:")
            for issue in self.issues:
                lines.append(f"  [{issue.severity.value}] {issue.rule_id} ({issue.target_file}): {issue.message}")
        return "\n".join(lines)


def _normalize_body(text: str) -> str:
    """Normalize line endings and strip leading/trailing whitespace for comparison."""
    cleaned_lines = [
        line.rstrip()
        for line in text.replace("\r\n", "\n").splitlines()
        if not line.strip().startswith(SYNC_HEADER_PREFIX)
    ]
    return "\n".join(cleaned_lines).strip()


def _compute_source_sha256(source_body: str) -> str:
    norm = _normalize_body(source_body)
    return hashlib.sha256(norm.encode("utf-8")).hexdigest()


def _render_target_content(target_key: str, source_body: str, source_sha: str) -> str:
    norm_body = _normalize_body(source_body)
    stamp = f"{SYNC_HEADER_PREFIX}{source_sha}{SYNC_HEADER_SUFFIX}"
    if target_key == "cursor":
        frontmatter = (
            "---\n"
            "description: Core repository instructions synchronized from AGENTS.md\n"
            'globs: "*"\n'
            "alwaysApply: true\n"
            "---"
        )
        return f"{frontmatter}\n\n{stamp}\n\n{norm_body}\n"
    return f"{stamp}\n\n{norm_body}\n"


def _strip_mdc_frontmatter(text: str) -> str:
    """Strip YAML frontmatter from a Cursor .mdc rule file if present."""
    if text.startswith("---"):
        parts = text.split("---", 2)
        if len(parts) == 3:
            return parts[2]
    return text


def _extract_directives(text: str) -> tuple[set[str], set[str]]:
    """Extract normalized positive and negative subject phrases from instruction prose."""
    pos: set[str] = set()
    neg: set[str] = set()
    for line in text.splitlines():
        # Handle 'never use X' / 'do not use X' before generic 'use X'
        lower_line = re.sub(r"\s+", " ", line.strip().lower())
        neg_use_match = re.findall(
            r"\b(?:never|do not|must not|forbid|prohibit)\s+(?:use\s+|run\s+|commit\s+)?([a-z0-9_./-]+)",
            lower_line,
        )
        for item in neg_use_match:
            if len(item) > 2:
                neg.add(item)

        pos_use_match = re.findall(
            r"(?<!never )(?<!not )\b(?:always|must)\s+(?:use\s+|run\s+)?([a-z0-9_./-]+)",
            lower_line,
        )
        for item in pos_use_match:
            if len(item) > 2 and item not in ("use", "run", "never", "not"):
                pos.add(item)
    return pos, neg


def detect_directive_conflicts(source_text: str, other_text: str) -> list[str]:
    """Detect opposing directives (e.g. 'always use pnpm' vs 'never use pnpm') between two rule files."""
    src_pos, src_neg = _extract_directives(source_text)
    oth_pos, oth_neg = _extract_directives(other_text)

    conflicts: list[str] = []
    for subj in sorted(src_pos & oth_neg):
        conflicts.append(f"Source mandates '{subj}' while target forbids '{subj}'")
    for subj in sorted(src_neg & oth_pos):
        conflicts.append(f"Source forbids '{subj}' while target mandates '{subj}'")
    return conflicts


def sync_context_rules(
    project_root: Path,
    source_file: str = "AGENTS.md",
    targets: list[str] | None = None,
    check_only: bool = False,
) -> RuleSyncReport:
    """Synchronize or verify multi-editor rule files from AGENTS.md."""
    src_path = project_root / source_file
    if not src_path.is_file():
        raise RuleSyncError(f"Source context file not found: {src_path}")

    source_text = src_path.read_text(encoding="utf-8")
    source_sha = _compute_source_sha256(source_text)
    norm_source = _normalize_body(source_text)

    selected_targets = targets or ["cursor", "claude", "cursorrules"]
    for t in selected_targets:
        if t not in TARGET_PATHS:
            raise RuleSyncError(
                f"Unknown sync target '{t}'. Valid targets: {', '.join(sorted(TARGET_PATHS))}"
            )

    synced: list[str] = []
    checked: list[str] = []
    issues: list[SyncIssue] = []

    if not check_only:
        for t in selected_targets:
            rel_dest = TARGET_PATHS[t]
            dest_path = project_root / rel_dest
            dest_path.parent.mkdir(parents=True, exist_ok=True)
            rendered = _render_target_content(t, source_text, source_sha)
            dest_path.write_text(rendered, encoding="utf-8")
            synced.append(rel_dest)
        return RuleSyncReport(
            source_file=source_file,
            source_sha256=source_sha,
            synced_files=synced,
            checked_files=[],
            issues=[],
        )

    # Check mode: inspect specified targets that exist (or flag missing if explicitly requested)
    for t in selected_targets:
        rel_dest = TARGET_PATHS[t]
        dest_path = project_root / rel_dest
        checked.append(rel_dest)

        if not dest_path.is_file():
            issues.append(
                SyncIssue(
                    rule_id="SYNC-001",
                    severity=Severity.HIGH,
                    target_file=rel_dest,
                    message=f"Target context file '{rel_dest}' is missing; run 'skillforge sync-rules' to generate it.",
                )
            )
            continue

        target_raw = dest_path.read_text(encoding="utf-8")
        target_body = _strip_mdc_frontmatter(target_raw) if t == "cursor" else target_raw
        norm_target = _normalize_body(target_body)

        # Check for directive contradictions first
        conflicts = detect_directive_conflicts(source_text, target_body)
        for c_msg in conflicts:
            issues.append(
                SyncIssue(
                    rule_id="SYNC-002",
                    severity=Severity.CRITICAL,
                    target_file=rel_dest,
                    message=f"Conflicting instruction directive detected: {c_msg}.",
                )
            )

        if norm_target != norm_source:
            issues.append(
                SyncIssue(
                    rule_id="SYNC-001",
                    severity=Severity.HIGH,
                    target_file=rel_dest,
                    message=f"Rule drift detected between '{source_file}' and '{rel_dest}'.",
                )
            )

    return RuleSyncReport(
        source_file=source_file,
        source_sha256=source_sha,
        synced_files=[],
        checked_files=checked,
        issues=issues,
    )

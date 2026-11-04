"""Context file linter for AGENTS.md, CLAUDE.md, and assistant instruction files."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .security import Severity
from .skill import estimate_tokens

_BUZZWORDS_PATTERN = re.compile(
    r"(?i)\b(world-class|seamless|cutting-edge|game-changer|next-generation|empower|delve into|revolutioniz[a-z]*)\b"
)
_BOUNDARY_PATTERN = re.compile(
    r"(?i)\b(always|never|ask\s+first|do\s+not|must\s+not|prohibited|guardrail|strictly)\b"
)
_PINNED_DEP_PATTERN = re.compile(
    r"(?i)\b[a-z0-9_.-]+\s*(?:==|>=|<=|~=|\^)\s*\d+\.\d+"
)
_MAX_CONTEXT_LINES = 150


@dataclass(frozen=True, slots=True)
class ContextFinding:
    """A finding from context file linting."""

    rule_id: str
    severity: Severity
    file: str
    message: str
    line: int | None = None
    snippet: str | None = None


@dataclass
class ContextReport:
    """Consolidated context linting report for a project."""

    project_path: str
    files_scanned: list[str] = field(default_factory=list)
    findings: list[ContextFinding] = field(default_factory=list)
    total_lines: int = 0
    total_tokens: int = 0

    @property
    def passed(self) -> bool:
        """Passes if there are no WARNING findings."""
        return not any(f.severity == Severity.HIGH for f in self.findings)

    def to_dict(self) -> dict[str, Any]:
        """Convert report to dictionary."""
        return {
            "project_path": self.project_path,
            "passed": self.passed,
            "files_scanned": self.files_scanned,
            "total_lines": self.total_lines,
            "total_tokens": self.total_tokens,
            "findings_count": len(self.findings),
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "severity": f.severity.value,
                    "file": f.file,
                    "message": f.message,
                    "line": f.line,
                    "snippet": f.snippet,
                }
                for f in self.findings
            ],
        }

    def render_text(self) -> str:
        """Render terminal summary."""
        status = "PASSED" if self.passed else "WARNINGS DETECTED"
        lines = [
            f"Context Linter: {self.project_path}",
            f"Status: {status}",
            f"Files Scanned: {len(self.files_scanned)} ({', '.join(self.files_scanned) if self.files_scanned else 'None'})",
            f"Context Overhead: ~{self.total_tokens} tokens across {self.total_lines} lines",
            f"Total Findings: {len(self.findings)}",
        ]
        if self.findings:
            lines.append("\nFindings:")
            for f in self.findings:
                loc = f"{f.file}:{f.line}" if f.line else f.file
                lines.append(f"  [{f.severity.value}] {f.rule_id} ({loc}): {f.message}")
                if f.snippet:
                    lines.append(f"      Snippet: {f.snippet.strip()}")
        return "\n".join(lines)


def lint_context_file(file_path: Path, project_root: Path) -> list[ContextFinding]:
    """Lint an individual context instruction file."""
    findings: list[ContextFinding] = []
    rel_name = file_path.relative_to(project_root).as_posix()
    try:
        content = file_path.read_text(encoding="utf-8")
    except OSError as exc:
        findings.append(
            ContextFinding(
                rule_id="CTX-000",
                severity=Severity.HIGH,
                file=rel_name,
                message=f"Unable to read context file: {exc}",
            )
        )
        return findings

    lines = content.splitlines()
    line_count = len(lines)

    # CTX-001: Context file line count bloat
    if line_count > _MAX_CONTEXT_LINES:
        findings.append(
            ContextFinding(
                rule_id="CTX-001",
                severity=Severity.HIGH,
                file=rel_name,
                message=(
                    f"Context file has {line_count} lines (exceeds {_MAX_CONTEXT_LINES}-line ceiling); "
                    "oversized context degrades model attention and inflates per-turn token cost. "
                    "Prune self-evident instructions or extract deep manuals to references/"
                ),
                snippet=f"Total lines: {line_count}",
            )
        )

    # Check for redundant manifests in repository
    has_manifest = any(
        (project_root / m).is_file()
        for m in ("package.json", "pyproject.toml", "Cargo.toml", "go.mod", "requirements.txt")
    )

    has_boundary = False

    for idx, line in enumerate(lines, start=1):
        # CTX-002: Redundant dependency listing
        if has_manifest:
            match_dep = _PINNED_DEP_PATTERN.search(line)
            if match_dep:
                findings.append(
                    ContextFinding(
                        rule_id="CTX-002",
                        severity=Severity.MEDIUM,
                        file=rel_name,
                        line=idx,
                        message=(
                            f"Redundant version pinning or dependency listing in context: '{match_dep.group(0)}' "
                            "(agents discover dependencies natively from package manifests)"
                        ),
                        snippet=line.strip()[:80],
                    )
                )

        # CTX-003: Non-actionable buzzwords
        match_buzz = _BUZZWORDS_PATTERN.search(line)
        if match_buzz:
            findings.append(
                ContextFinding(
                    rule_id="CTX-003",
                    severity=Severity.LOW,
                    file=rel_name,
                    line=idx,
                    message=(
                        f"Non-actionable buzzword in machine instructions: '{match_buzz.group(0)}' "
                        "(replace decorative adjectives with concrete constraints)"
                    ),
                    snippet=line.strip()[:80],
                )
            )

        if _BOUNDARY_PATTERN.search(line):
            has_boundary = True

    # CTX-004: Missing boundary guardrails
    if line_count > 5 and not has_boundary:
        findings.append(
            ContextFinding(
                rule_id="CTX-004",
                severity=Severity.LOW,
                file=rel_name,
                message=(
                    "Context file lacks explicit operational boundaries; "
                    "specify clear guardrails (e.g. 'Always run tests before completing', 'Never commit secrets')"
                ),
            )
        )

    return findings


def discover_context_files(project_root: Path) -> list[Path]:
    """Discover standard agent context files in a project."""
    candidates = (
        project_root / "AGENTS.md",
        project_root / "CLAUDE.md",
        project_root / ".cursorrules",
        project_root / ".windsurfrules",
        project_root / ".gemini" / "GEMINI.md",
    )
    found = [p for p in candidates if p.is_file()]

    # Cursor .cursor/rules/*.mdc
    rules_dir = project_root / ".cursor" / "rules"
    if rules_dir.is_dir():
        for r in sorted(rules_dir.glob("*.mdc")):
            if r.is_file():
                found.append(r)

    return found


def lint_project_context(project_root: Path) -> ContextReport:
    """Run context linting on all discovered context files in a project."""
    files = discover_context_files(project_root)
    all_findings: list[ContextFinding] = []
    total_lines = 0
    total_tokens = 0
    scanned_names: list[str] = []

    for file_path in files:
        rel_name = file_path.relative_to(project_root).as_posix()
        scanned_names.append(rel_name)
        try:
            text = file_path.read_text(encoding="utf-8")
            total_lines += len(text.splitlines())
            total_tokens += estimate_tokens(text)
        except OSError:
            pass
        all_findings.extend(lint_context_file(file_path, project_root))

    return ContextReport(
        project_path=project_root.resolve().name or str(project_root),
        files_scanned=scanned_names,
        findings=all_findings,
        total_lines=total_lines,
        total_tokens=total_tokens,
    )

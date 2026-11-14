"""Machine-wide and project-wide discovery sweep across skills and MCP configurations."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .security import AuditReport, SkillAuditor, audit_mcp_config
from .skill import SkillPackage

_MCP_FILENAMES = (
    "mcp.json",
    ".cursor/mcp.json",
    ".vscode/mcp.json",
    "claude_desktop_config.json",
)

_PROJECT_SKILL_SUBDIRS = (
    ".claude/skills",
    ".cursor/skills",
    ".gemini/skills",
    ".gemini/config/skills",
    ".windsurf/skills",
    ".cline/skills",
    ".agents/skills",
    "skills",
    ".skillforge",
)

_HOME_SCAN_SUBDIRS = (
    ".claude",
    ".claude/skills",
    ".cursor",
    ".cursor/skills",
    ".gemini",
    ".gemini/config/skills",
    ".windsurf",
    ".windsurf/skills",
    ".agents/skills",
    ".vscode",
)


@dataclass
class SweepReport:
    """Consolidated report across all discovered skills and MCP configs."""

    skills_scanned: int
    mcp_configs_scanned: int
    skill_reports: list[AuditReport] = field(default_factory=list)
    mcp_reports: list[AuditReport] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        """Pass only if every skill and MCP config audit passes."""
        return all(r.passed for r in self.skill_reports) and all(r.passed for r in self.mcp_reports)

    def to_dict(self) -> dict[str, Any]:
        """Serialize sweep results into JSON-compatible structure."""
        total_findings = sum(len(r.findings) for r in self.skill_reports) + sum(
            len(r.findings) for r in self.mcp_reports
        )
        return {
            "passed": self.passed,
            "skills_scanned": self.skills_scanned,
            "mcp_configs_scanned": self.mcp_configs_scanned,
            "total_findings": total_findings,
            "skill_reports": [r.to_dict() for r in self.skill_reports],
            "mcp_reports": [r.to_dict() for r in self.mcp_reports],
        }

    def to_sarif(self) -> dict[str, Any]:
        """Combine all skill and MCP config findings into a single SARIF v2.1.0 report."""
        combined = AuditReport(
            target="skillforge-sweep",
            findings=[f for rep in (*self.skill_reports, *self.mcp_reports) for f in rep.findings],
        )
        return combined.to_sarif()

    def render_text(self) -> str:
        """Render concise sweep report for terminal display."""
        status = "PASSED" if self.passed else "FAILED"
        lines = [
            f"SkillForge Machine Sweep: {status}",
            f"  Skills Scanned:      {self.skills_scanned}",
            f"  MCP Configs Scanned: {self.mcp_configs_scanned}",
        ]
        for rep in self.skill_reports:
            flag = "OK" if rep.passed else "FAIL"
            lines.append(
                f"  [{flag}] Skill '{rep.target}' (Score: {rep.score}/100, Findings: {len(rep.findings)})"
            )
            for finding in rep.findings:
                lines.append(f"      [{finding.severity.value}] {finding.rule_id}: {finding.message}")
        for rep in self.mcp_reports:
            flag = "OK" if rep.passed else "FAIL"
            lines.append(
                f"  [{flag}] MCP Config '{rep.target}' (Score: {rep.score}/100, Findings: {len(rep.findings)})"
            )
            for finding in rep.findings:
                lines.append(f"      [{finding.severity.value}] {finding.rule_id} ({finding.file}): {finding.message}")
        return "\n".join(lines)


def _discover_skill_dirs(search_roots: list[Path]) -> list[Path]:
    seen: set[Path] = set()
    discovered: list[Path] = []
    for root in search_roots:
        if not root.is_dir():
            continue
        direct_skill = root / "SKILL.md"
        if direct_skill.is_file():
            resolved = root.resolve()
            if resolved not in seen:
                seen.add(resolved)
                discovered.append(resolved)
        for skill_md in sorted(root.rglob("SKILL.md")):
            # Ignore virtualenvs or git internals inside scanned roots
            parts = skill_md.parts
            if any(skip in parts for skip in (".git", "node_modules", ".venv", "venv", "__pycache__")):
                continue
            resolved = skill_md.parent.resolve()
            if resolved not in seen:
                seen.add(resolved)
                discovered.append(resolved)
    return discovered


def _discover_mcp_files(roots: list[Path]) -> list[Path]:
    seen: set[Path] = set()
    discovered: list[Path] = []
    for root in roots:
        if root.is_file() and root.name.endswith(".json"):
            resolved = root.resolve()
            if resolved not in seen:
                seen.add(resolved)
                discovered.append(resolved)
            continue
        if not root.is_dir():
            continue
        for rel in _MCP_FILENAMES:
            candidate = root / rel
            if candidate.is_file():
                resolved = candidate.resolve()
                if resolved not in seen:
                    seen.add(resolved)
                    discovered.append(resolved)
    return discovered


def run_machine_sweep(
    project_root: Path,
    include_home: bool = False,
    extra_roots: list[Path] | None = None,
) -> SweepReport:
    """Sweep project (and optionally home IDE directories) for all skills and MCP configs."""
    skill_roots: list[Path] = [project_root]
    mcp_roots: list[Path] = [project_root]

    for rel in _PROJECT_SKILL_SUBDIRS:
        candidate = project_root / rel
        if candidate.is_dir():
            skill_roots.append(candidate)

    if extra_roots:
        for r in extra_roots:
            skill_roots.append(r)
            mcp_roots.append(r)

    if include_home:
        home_dir = Path.home()
        for rel in _HOME_SCAN_SUBDIRS:
            candidate = home_dir / rel
            if candidate.is_dir():
                skill_roots.append(candidate)
                mcp_roots.append(candidate)

    auditor = SkillAuditor()
    skill_dirs = _discover_skill_dirs(skill_roots)
    skill_reports: list[AuditReport] = []
    for sdir in skill_dirs:
        try:
            pkg = SkillPackage.load(sdir)
            skill_reports.append(auditor.audit_package(pkg))
        except Exception:
            continue

    mcp_files = _discover_mcp_files(mcp_roots)
    mcp_reports: list[AuditReport] = []
    for mfile in mcp_files:
        try:
            mcp_reports.append(audit_mcp_config(mfile))
        except Exception:
            continue

    return SweepReport(
        skills_scanned=len(skill_reports),
        mcp_configs_scanned=len(mcp_reports),
        skill_reports=skill_reports,
        mcp_reports=mcp_reports,
    )

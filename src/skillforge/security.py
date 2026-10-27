"""Security auditor and anti-prompt-injection scanner for portable skills."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from .errors import SecurityAuditError
from .skill import SkillPackage, parse_skill


class Severity(str, Enum):
    """Severity levels for audit findings."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass(frozen=True, slots=True)
class AuditFinding:
    """A specific security or quality finding."""

    rule_id: str
    severity: Severity
    message: str
    file: str
    line: int | None = None
    snippet: str | None = None


@dataclass
class AuditReport:
    """Complete audit report of a skill document or package."""

    target: str
    findings: list[AuditFinding] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        """Audit passes if there are no CRITICAL or HIGH findings."""
        return not any(
            f.severity in (Severity.CRITICAL, Severity.HIGH) for f in self.findings
        )

    @property
    def score(self) -> int:
        """Compute 0-100 score based on finding severities."""
        score = 100
        for f in self.findings:
            if f.severity == Severity.CRITICAL:
                score -= 40
            elif f.severity == Severity.HIGH:
                score -= 20
            elif f.severity == Severity.MEDIUM:
                score -= 10
            elif f.severity == Severity.LOW:
                score -= 5
        return max(0, score)

    def to_dict(self) -> dict[str, Any]:
        """Serialize report to a dictionary."""
        return {
            "target": self.target,
            "passed": self.passed,
            "score": self.score,
            "findings_count": len(self.findings),
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "severity": f.severity.value,
                    "message": f.message,
                    "file": f.file,
                    "line": f.line,
                    "snippet": f.snippet,
                }
                for f in self.findings
            ],
        }

    def render_text(self) -> str:
        """Render a clean terminal-friendly text summary."""
        status = "PASSED" if self.passed else "FAILED"
        lines = [
            f"Audit Report: {self.target}",
            f"Status: {status} (Score: {self.score}/100)",
            f"Total Findings: {len(self.findings)}",
        ]
        if self.findings:
            lines.append("\nFindings:")
            for f in self.findings:
                location = f"{f.file}:{f.line}" if f.line else f.file
                lines.append(f"  [{f.severity.value}] {f.rule_id} ({location}): {f.message}")
                if f.snippet:
                    lines.append(f"      Snippet: {f.snippet.strip()}")
        return "\n".join(lines)


# Regex patterns for security checks
_INVISIBLE_UNICODE_CHARS = re.compile(
    r"[\u200B-\u200D\uFEFF\u202A-\u202E\u2066-\u2069\U000E0000-\U000E007F]"
)

_INJECTION_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "SEC-002",
        re.compile(
            r"(?i)\bignore\s+(all\s+|previous\s+|prior\s+)*(instructions|directives|prompts|rules)\b"
        ),
    ),
    (
        "SEC-002",
        re.compile(
            r"(?i)\bdisregard\s+(all\s+|previous\s+|prior\s+)*(instructions|directives|rules)\b"
        ),
    ),
    (
        "SEC-002",
        re.compile(
            r"(?i)\b(system\s+override|override\s+system\s+prompt|developer\s+mode\s+activated)\b"
        ),
    ),
    (
        "SEC-002",
        re.compile(
            r"(?i)\byou\s+are\s+now\s+(in\s+jailbreak|DAN|unrestricted|freed\s+from\s+rules)\b"
        ),
    ),
]

_EXFILTRATION_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "SEC-003",
        re.compile(r"(?i)\b(curl|wget)\b.*(\|\s*(bash|sh|zsh|powershell|pwsh)\b)"),
    ),
    (
        "SEC-003",
        re.compile(r"(?i)\bbase64\s+(-d|--decode)\s*\|\s*(bash|sh|zsh|powershell)\b"),
    ),
    (
        "SEC-003",
        re.compile(r"(?i)\b(curl|wget)\b.*(--post-data|-d\s+@|-F\s+@).*"),
    ),
    (
        "SEC-003",
        re.compile(r"(?i)\brm\s+-rf\s+(/|~|\$HOME)\b"),
    ),
]

_CREDENTIAL_ACCESS_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "SEC-004",
        re.compile(r"(?i)(\.ssh/id_rsa|\.ssh/id_ed25519|\.aws/credentials|\.config/gcloud)"),
    ),
]

_TRIGGER_KEYWORDS = ("when", "use when", "for", "if", "trigger", "tasks")


class SkillAuditor:
    """Security and compliance auditor for SKILL.md and skill packages."""

    def audit_package(self, package: SkillPackage) -> AuditReport:
        """Audit an entire skill package."""
        target_name = package.skill.name or (package.source_dir.name if package.source_dir else "unknown")
        findings: list[AuditFinding] = []

        # Audit SKILL.md
        skill_text = package.skill.render()
        findings.extend(self._scan_text(skill_text, "SKILL.md"))

        # Folder name match
        if package.source_dir and package.source_dir.name != package.skill.name:
            findings.append(
                AuditFinding(
                    rule_id="QUAL-002",
                    severity=Severity.MEDIUM,
                    message=(
                        f"Directory name '{package.source_dir.name}' does not match "
                        f"skill name '{package.skill.name}'"
                    ),
                    file="SKILL.md",
                )
            )

        # Trigger quality check
        desc_lower = package.skill.description.lower()
        if not any(keyword in desc_lower for keyword in _TRIGGER_KEYWORDS):
            findings.append(
                AuditFinding(
                    rule_id="QUAL-001",
                    severity=Severity.LOW,
                    message=(
                        "Skill description should include progressive disclosure trigger conditions "
                        "(e.g., 'Use when asked to...', 'When handling...')"
                    ),
                    file="SKILL.md",
                    snippet=package.skill.description[:120],
                )
            )

        # Audit scripts
        for rel_path, content in package.scripts.items():
            findings.extend(self._scan_text(content, f"scripts/{rel_path}"))
            findings.extend(self._scan_shell_content(content, f"scripts/{rel_path}"))

        # Audit references
        for rel_path, content in package.references.items():
            findings.extend(self._scan_text(content, f"references/{rel_path}"))

        return AuditReport(target=target_name, findings=findings)

    def audit_file_or_dir(self, path: Path) -> AuditReport:
        """Audit a file or directory from disk."""
        package = SkillPackage.load(path)
        return self.audit_package(package)

    def audit_content(self, content: str, target_name: str = "document") -> AuditReport:
        """Audit raw SKILL.md content without disk operations."""
        skill = parse_skill(content)
        package = SkillPackage(skill=skill)
        return self.audit_package(package)

    def _scan_text(self, text: str, filename: str) -> list[AuditFinding]:
        """Scan general text for hidden unicode and prompt injections."""
        findings: list[AuditFinding] = []
        lines = text.splitlines()

        for idx, line in enumerate(lines, start=1):
            # Check invisible unicode
            match_unicode = _INVISIBLE_UNICODE_CHARS.search(line)
            if match_unicode:
                findings.append(
                    AuditFinding(
                        rule_id="SEC-001",
                        severity=Severity.CRITICAL,
                        message="Hidden or zero-width unicode character detected (possible payload obfuscation)",
                        file=filename,
                        line=idx,
                        snippet=repr(line),
                    )
                )

            # Check prompt injection patterns
            for rule_id, pattern in _INJECTION_PATTERNS:
                match_inj = pattern.search(line)
                if match_inj:
                    findings.append(
                        AuditFinding(
                            rule_id=rule_id,
                            severity=Severity.CRITICAL,
                            message=f"Prompt injection pattern detected: '{match_inj.group(0)}'",
                            file=filename,
                            line=idx,
                            snippet=line.strip(),
                        )
                    )

            # Check credential patterns in text
            for rule_id, pattern in _CREDENTIAL_ACCESS_PATTERNS:
                match_cred = pattern.search(line)
                if match_cred:
                    findings.append(
                        AuditFinding(
                            rule_id=rule_id,
                            severity=Severity.MEDIUM,
                            message=f"Direct access to sensitive credential path: '{match_cred.group(0)}'",
                            file=filename,
                            line=idx,
                            snippet=line.strip(),
                        )
                    )

        return findings

    def _scan_shell_content(self, text: str, filename: str) -> list[AuditFinding]:
        """Scan executable shell or python scripts for dangerous patterns."""
        findings: list[AuditFinding] = []
        lines = text.splitlines()
        for idx, line in enumerate(lines, start=1):
            for rule_id, pattern in _EXFILTRATION_PATTERNS:
                match = pattern.search(line)
                if match:
                    findings.append(
                        AuditFinding(
                            rule_id=rule_id,
                            severity=Severity.HIGH,
                            message=f"Suspicious shell execution or potential exfiltration pattern: '{match.group(0)}'",
                            file=filename,
                            line=idx,
                            snippet=line.strip(),
                        )
                    )
        return findings


def audit_path(path: Path) -> AuditReport:
    """Convenience helper to audit a skill file or directory."""
    return SkillAuditor().audit_file_or_dir(path)

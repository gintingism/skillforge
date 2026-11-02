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
    pointer_tokens: int = 0
    body_tokens: int = 0
    body_lines: int = 0

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
            "pointer_tokens": self.pointer_tokens,
            "body_tokens": self.body_tokens,
            "body_lines": self.body_lines,
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
            f"Context Load: {self.pointer_tokens} pointer tokens | {self.body_tokens} body tokens ({self.body_lines} lines)",
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

    def to_sarif(self) -> dict[str, Any]:
        """Convert findings to OASIS SARIF v2.1.0 format for GitHub Code Scanning."""
        rule_meta: dict[str, tuple[str, str]] = {
            "SEC-001": ("Invisible Unicode Detection", "Detects zero-width and invisible unicode characters hiding instructions."),
            "SEC-002": ("Prompt Injection Directive", "Detects instructions attempting to override system prompts or jailbreak the agent."),
            "SEC-003": ("Dangerous Command Execution", "Detects destructive shell pipelines, reverse shells, or remote script piped to bash."),
            "SEC-004": ("Credential Path Access", "Detects unauthorized attempts to access ~/.ssh, ~/.aws, or environment secrets."),
            "SEC-005": ("Trojan Source Bidi Characters", "Detects bidirectional unicode control characters that alter execution order."),
            "SEC-006": ("Markdown Link Spoofing", "Detects deceptive markdown links with mismatched labels and destinations."),
            "QUAL-001": ("Trigger Quality", "Checks whether skill descriptions include explicit activation conditions."),
            "QUAL-002": ("Directory Alignment", "Checks whether directory name matches frontmatter name."),
            "QUAL-003": ("Context Budget Limit", "Flags bloated skills exceeding recommended token and line limits."),
            "QUAL-004": ("Broken Resource Pointer", "Checks whether cited scripts or references exist in the package."),
            "QUAL-006": ("Applicability Hijacking", "Flags overbroad trigger descriptions claiming all tasks."),
        }
        sarif_rules: list[dict[str, Any]] = []
        for rid, (rname, rdesc) in sorted(rule_meta.items()):
            sarif_rules.append({
                "id": rid,
                "name": rname,
                "shortDescription": {"text": rdesc},
                "defaultConfiguration": {
                    "level": "error" if rid.startswith("SEC") else "warning"
                },
            })

        results: list[dict[str, Any]] = []
        for f in self.findings:
            level = "error" if f.severity in (Severity.CRITICAL, Severity.HIGH) else (
                "warning" if f.severity == Severity.MEDIUM else "note"
            )
            loc: dict[str, Any] = {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": f.file
                    }
                }
            }
            if f.line is not None:
                region: dict[str, Any] = {"startLine": f.line}
                if f.snippet:
                    region["snippet"] = {"text": f.snippet.strip()}
                loc["physicalLocation"]["region"] = region

            results.append({
                "ruleId": f.rule_id,
                "level": level,
                "message": {"text": f.message},
                "locations": [loc],
            })

        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "SkillForge",
                            "version": "0.4.1",
                            "informationUri": "https://github.com/gintingism/skillforge",
                            "rules": sarif_rules,
                        }
                    },
                    "results": results,
                }
            ],
        }


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

_EXFILTRATION_ENDPOINT_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "SEC-005",
        re.compile(r"(?i)\b(https?://)?([a-z0-9_-]+\.)?(webhook\.site|pipedream\.net|requestbin\.net|burpcollaborator\.net)\b"),
    ),
    (
        "SEC-005",
        re.compile(r"(?i)\b(curl|wget)\b.*(--data|-d|--post-data|-F)\b.*(\$|\b(process\.env|os\.environ)\b).*(api[_-]?key|token|secret|password|auth)"),
    ),
]

_HARDCODED_SECRET_PATTERNS: list[tuple[str, re.Pattern[str], Severity]] = [
    ("SEC-006", re.compile(r"\bghp_[A-Za-z0-9]{36}\b"), Severity.CRITICAL),
    ("SEC-006", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{82}\b"), Severity.CRITICAL),
    ("SEC-006", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{32,}\b"), Severity.CRITICAL),
    ("SEC-006", re.compile(r"\bAIzaSy[A-Za-z0-9_-]{33}\b"), Severity.CRITICAL),
    ("SEC-006", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), Severity.HIGH),
]

_OVERBROAD_TRIGGER_PATTERN = re.compile(
    r"(?i)\b(always\s+use\s+(this\s+skill|for\s+all)|trigger\s+on\s+all|for\s+any\s+(task|request|prompt|question)|execute\s+this\s+first\s+before\s+anything)\b"
)

_DEFENSIVE_CONTEXT_PATTERN = re.compile(
    r"(?i)\b(flag\s+it|steer\s+you|warn|reject|detect|defend|counter|malicious|attack|payload|untrusted|sanitiz)\b"
)

_TRIGGER_PATTERN = re.compile(r"(?i)\b(when|for|if|triggers?|triggered|tasks?)\b")
_MAX_BODY_LINES = 500
_MAX_BODY_TOKENS = 5000
_DISCLOSED_PATH_PATTERN = re.compile(
    r"(?:`|\()(?:\./)?(scripts|references)/([a-zA-Z0-9_.-]+(?:/[a-zA-Z0-9_.-]+)*\.[a-zA-Z0-9]+)(?:`|\))"
)


class SkillAuditor:
    """Security and compliance auditor for SKILL.md and skill packages."""

    def audit_package(self, package: SkillPackage, *, check_resources: bool = True) -> AuditReport:
        """Audit an entire skill package."""
        target_name = package.skill.name or (package.source_dir.name if package.source_dir else "unknown")
        findings: list[AuditFinding] = []

        skill_text = package.skill.render()
        findings.extend(self._scan_text(skill_text, "SKILL.md"))

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

        match_hijack = _OVERBROAD_TRIGGER_PATTERN.search(package.skill.description)
        if match_hijack:
            findings.append(
                AuditFinding(
                    rule_id="QUAL-006",
                    severity=Severity.MEDIUM,
                    message=(
                        f"Overbroad trigger or applicability hijacking pattern: '{match_hijack.group(0)}' "
                        "(skills should specify scoped trigger conditions rather than claiming all tasks)"
                    ),
                    file="SKILL.md",
                    snippet=package.skill.description[:120],
                )
            )

        if not package.skill.disable_model_invocation and not _TRIGGER_PATTERN.search(
            package.skill.description
        ):
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

        if package.skill.body_lines > _MAX_BODY_LINES or package.skill.body_tokens > _MAX_BODY_TOKENS:
            findings.append(
                AuditFinding(
                    rule_id="QUAL-003",
                    severity=Severity.LOW,
                    message=(
                        f"SKILL.md body ({package.skill.body_lines} lines, ~{package.skill.body_tokens} tokens) "
                        f"exceeds progressive disclosure budget ({_MAX_BODY_LINES} lines / {_MAX_BODY_TOKENS} tokens); "
                        "extract detailed reference material into references/"
                    ),
                    file="SKILL.md",
                )
            )

        if check_resources:
            findings.extend(self._check_disclosed_paths(package))

        for rel_path, content in package.scripts.items():
            findings.extend(self._scan_text(content, f"scripts/{rel_path}"))
            findings.extend(self._scan_shell_content(content, f"scripts/{rel_path}"))

        for rel_path, content in package.references.items():
            findings.extend(self._scan_text(content, f"references/{rel_path}"))

        return AuditReport(
            target=target_name,
            findings=findings,
            pointer_tokens=package.skill.pointer_tokens,
            body_tokens=package.skill.body_tokens,
            body_lines=package.skill.body_lines,
        )

    def _check_disclosed_paths(self, package: SkillPackage) -> list[AuditFinding]:
        """Verify that files referenced via progressive disclosure exist in the package."""
        findings: list[AuditFinding] = []
        seen: set[tuple[str, str]] = set()
        in_fence = False
        for idx, line in enumerate(package.skill.body.splitlines(), start=1):
            if line.lstrip().startswith(("```", "~~~")):
                in_fence = not in_fence
                continue
            if in_fence:
                continue
            for match in _DISCLOSED_PATH_PATTERN.finditer(line):
                folder, rel_path = match.group(1), match.group(2)
                if (folder, rel_path) in seen:
                    continue
                seen.add((folder, rel_path))
                exists = (
                    rel_path in package.scripts
                    if folder == "scripts"
                    else rel_path in package.references
                )
                if not exists:
                    findings.append(
                        AuditFinding(
                            rule_id="QUAL-004",
                            severity=Severity.HIGH,
                            message=(
                                f"Broken progressive disclosure pointer: '{folder}/{rel_path}' "
                                "is referenced in SKILL.md but missing from package"
                            ),
                            file="SKILL.md",
                            line=idx,
                            snippet=line.strip(),
                        )
                    )
        return findings

    def audit_file_or_dir(self, path: Path) -> AuditReport:
        """Audit a file or directory from disk."""
        package = SkillPackage.load(path)
        return self.audit_package(package)

    def audit_content(self, content: str, target_name: str = "document") -> AuditReport:
        """Audit raw SKILL.md content without disk operations."""
        skill = parse_skill(content)
        package = SkillPackage(skill=skill)
        return self.audit_package(package, check_resources=False)

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
                    # A quoted phrase next to words like "flag" or "reject" is usually a guide
                    # teaching the agent to resist injection. Report it, but do not fail the audit:
                    # an attacker can fake this framing, so it must stay visible to a human reviewer.
                    quoted_defense = bool(
                        _DEFENSIVE_CONTEXT_PATTERN.search(line) and re.search(r"[\"'`]", line)
                    )
                    findings.append(
                        AuditFinding(
                            rule_id=rule_id,
                            severity=Severity.MEDIUM if quoted_defense else Severity.CRITICAL,
                            message=(
                                f"Quoted prompt injection phrase in defensive-looking text: '{match_inj.group(0)}' "
                                "(verify this line warns against the phrase rather than obeying it)"
                                if quoted_defense
                                else f"Prompt injection pattern detected: '{match_inj.group(0)}'"
                            ),
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

            # Check exfiltration endpoints in text
            for rule_id, pattern in _EXFILTRATION_ENDPOINT_PATTERNS:
                match_exfil = pattern.search(line)
                if match_exfil:
                    findings.append(
                        AuditFinding(
                            rule_id=rule_id,
                            severity=Severity.HIGH,
                            message=f"Suspicious external data exfiltration pattern: '{match_exfil.group(0)}'",
                            file=filename,
                            line=idx,
                            snippet=line.strip(),
                        )
                    )

            # Check hardcoded secrets / high-entropy API tokens
            for rule_id, pattern, severity in _HARDCODED_SECRET_PATTERNS:
                match_sec = pattern.search(line)
                if match_sec:
                    findings.append(
                        AuditFinding(
                            rule_id=rule_id,
                            severity=severity,
                            message=f"Hardcoded API secret or credential token pattern detected: '{match_sec.group(0)[:8]}...'",
                            file=filename,
                            line=idx,
                            snippet=line.strip()[:60],
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
            for rule_id, pattern in _EXFILTRATION_ENDPOINT_PATTERNS:
                match_exfil = pattern.search(line)
                if match_exfil:
                    findings.append(
                        AuditFinding(
                            rule_id=rule_id,
                            severity=Severity.HIGH,
                            message=f"Outbound exfiltration endpoint or credential transmission: '{match_exfil.group(0)}'",
                            file=filename,
                            line=idx,
                            snippet=line.strip(),
                        )
                    )
        return findings


def audit_path(path: Path) -> AuditReport:
    """Convenience helper to audit a skill file or directory."""
    return SkillAuditor().audit_file_or_dir(path)

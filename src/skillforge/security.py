"""Security auditor and anti-prompt-injection scanner for portable skills."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from . import __version__
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
            "SEC-001": ("Invisible & Bidi Unicode Detection", "Detects zero-width, invisible, and bidirectional unicode characters hiding instructions."),
            "SEC-002": ("Prompt Injection Directive", "Detects instructions attempting to override system prompts or jailbreak the agent."),
            "SEC-003": ("Dangerous Command Execution", "Detects destructive shell pipelines, reverse shells, or remote script piped to bash."),
            "SEC-004": ("Credential Path Access", "Detects unauthorized attempts to access sensitive local credential paths."),
            "SEC-005": ("Suspicious Exfiltration Endpoint", "Detects outbound data transmission to webhook or request-capture endpoints."),
            "SEC-006": ("Hardcoded Credential Token", "Detects hardcoded API secrets or provider access tokens."),
            "SEC-007": ("Markdown Link Spoofing", "Detects deceptive markdown links where visible URL host differs from destination host."),
            "SEC-008": ("Python AST Dangerous Call or Taint Flow", "Detects dangerous Python AST calls (eval, exec, shell=True, unsafe deserialization) or env-to-network taint."),
            "SEC-009": ("Unrestricted Tool Scope", "Flags wildcard tool permissions (such as '*' or 'Bash(*)') in YAML frontmatter."),
            "SEC-010": ("Markdown-as-Installer Deceptive Instruction", "Detects instructions prompting the user or agent to execute unverified install scripts or remote terminal pipelines."),
            "SEC-011": ("Executable Payload in Assets", "Detects native executables or script file types stored under assets/ instead of scripts/."),
            "SEC-012": ("Allowed-Tools Scope Violation", "Detects shell commands or execution scripts in skill body when allowed-tools excludes shell execution or restricts tools."),
            "QUAL-008": ("Metadata Value Types", "Checks that metadata maps string keys to string values as the agentskills.io spec requires."),
            "QUAL-001": ("Trigger Quality", "Checks whether skill descriptions include explicit activation conditions."),
            "QUAL-002": ("Directory Alignment", "Checks whether directory name matches frontmatter name."),
            "QUAL-003": ("Context Budget Limit", "Flags bloated skills exceeding recommended token and line limits."),
            "QUAL-004": ("Broken Resource Pointer", "Checks whether cited scripts or references exist in the package."),
            "QUAL-006": ("Applicability Hijacking", "Flags overbroad trigger descriptions claiming all tasks."),
            "QUAL-007": ("Standard Spec Name Formatting", "Checks whether skill name conforms to agentskills.io standard (lowercase alphanumeric and hyphens only, no leading or trailing hyphens)."),
            "QUAL-009": ("Nested Reference Chain", "Flags reference files that link to secondary reference files instead of keeping disclosure one-level-deep from SKILL.md."),
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
                            "version": __version__,
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
    r"(?:`|\()(?:\./)?(scripts|references|assets)/([a-zA-Z0-9_.-]+(?:/[a-zA-Z0-9_.-]+)*\.[a-zA-Z0-9]+)(?:`|\))"
)
_MARKDOWN_LINK_PATTERN = re.compile(r"\[([^\]]+)\]\(([^)]+)\)")
_UNRESTRICTED_TOOL_PATTERN = re.compile(
    r"(?i)(?:^|[\s,])(\*|(?:bash|sh|shell|cmd|powershell)\(\*\))(?:$|[\s,])"
)
_EXECUTION_TOOL_NAMES = frozenset({
    "bash",
    "sh",
    "shell",
    "terminal",
    "powershell",
    "pwsh",
    "cmd",
    "run_command",
    "execute_command",
    "exec",
    "subprocess",
})
_SHELL_FENCE_PATTERN = re.compile(
    r"```(?:bash|sh|shell|zsh|powershell|pwsh|cmd)\b", re.IGNORECASE
)
_MARKDOWN_INSTALLER_PATTERNS: list[re.Pattern[str]] = [
    re.compile(
        r"(?i)(?:\b(?:run|execute)\s+(?:this\s+)?(?:installer|install\s+script|payload)|\b(?:copy\s+and\s+paste|paste)\s+(?:this\s+)?(?:command\s+)?(?:in|into)\s+(?:your\s+)?(?:terminal|shell|console|bash|powershell))\b.*?(?:curl|wget|powershell|iex|bash\s+-c|sh\s+-c|python\s+-c)"
    ),
    re.compile(
        r"(?i)\b(?:curl|wget)\b[^\n`]+(?:\|\s*(?:bash|sh|zsh|powershell|pwsh)|>\s*/tmp/[^\n`]+\s*&&\s*(?:bash|sh))"
    ),
    re.compile(
        r"(?i)\b(?:irm|iwr|invoke-restmethod|invoke-webrequest)\b[^\n`]*\|\s*(?:iex|invoke-expression)\b"
    ),
]
_EXECUTABLE_MAGIC = (b"\x7fELF", b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe")
_EXECUTABLE_ASSET_SUFFIXES = (".exe", ".dll", ".so", ".dylib", ".jar", ".sh", ".bat", ".cmd", ".ps1", ".scr", ".msi")
_SPEC_NAME_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$")

_NETWORK_MODULES = frozenset({
    "urllib",
    "urllib.request",
    "requests",
    "httpx",
    "socket",
    "http",
    "http.client",
    "aiohttp",
})
_DANGEROUS_BUILTINS = frozenset({"eval", "exec", "compile", "__import__"})
_DANGEROUS_ATTR_CALLS: dict[tuple[str, str], str] = {
    ("os", "system"): "os.system()",
    ("os", "popen"): "os.popen()",
    ("pty", "spawn"): "pty.spawn()",
    ("pickle", "loads"): "pickle.loads()",
    ("pickle", "load"): "pickle.load()",
    ("marshal", "loads"): "marshal.loads()",
    ("marshal", "load"): "marshal.load()",
}
_SUBPROCESS_CALLS = frozenset({"run", "Popen", "call", "check_output", "check_call"})


class _PythonASTScanner(ast.NodeVisitor):
    """AST visitor detecting dangerous calls and env-to-network taint in Python scripts."""

    def __init__(self, filename: str, lines: list[str]) -> None:
        self.filename = filename
        self.lines = lines
        self.findings: list[AuditFinding] = []
        self.env_access_line: int | None = None
        self.network_import_line: int | None = None

    def _snippet(self, lineno: int | None) -> str | None:
        if lineno is not None and 1 <= lineno <= len(self.lines):
            return self.lines[lineno - 1].strip()
        return None

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            if alias.name in _NETWORK_MODULES or alias.name.split(".")[0] in _NETWORK_MODULES:
                if self.network_import_line is None:
                    self.network_import_line = node.lineno
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module and (
            node.module in _NETWORK_MODULES or node.module.split(".")[0] in _NETWORK_MODULES
        ):
            if self.network_import_line is None:
                self.network_import_line = node.lineno
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if isinstance(node.value, ast.Name) and node.value.id == "os" and node.attr == "environ":
            if self.env_access_line is None:
                self.env_access_line = node.lineno
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
            if func_name in _DANGEROUS_BUILTINS:
                self.findings.append(
                    AuditFinding(
                        rule_id="SEC-008",
                        severity=Severity.HIGH,
                        message=f"Python AST dangerous dynamic execution call: '{func_name}()'",
                        file=self.filename,
                        line=node.lineno,
                        snippet=self._snippet(node.lineno),
                    )
                )
        elif isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            mod_name = node.func.value.id
            attr_name = node.func.attr
            if (mod_name, attr_name) == ("os", "getenv"):
                if self.env_access_line is None:
                    self.env_access_line = node.lineno
            elif (mod_name, attr_name) in _DANGEROUS_ATTR_CALLS:
                label = _DANGEROUS_ATTR_CALLS[(mod_name, attr_name)]
                self.findings.append(
                    AuditFinding(
                        rule_id="SEC-008",
                        severity=Severity.HIGH,
                        message=f"Python AST unsafe execution or deserialization call: '{label}'",
                        file=self.filename,
                        line=node.lineno,
                        snippet=self._snippet(node.lineno),
                    )
                )
            elif mod_name == "subprocess" and attr_name in _SUBPROCESS_CALLS:
                for kw in node.keywords:
                    if (
                        kw.arg == "shell"
                        and isinstance(kw.value, ast.Constant)
                        and kw.value.value is True
                    ):
                        self.findings.append(
                            AuditFinding(
                                rule_id="SEC-008",
                                severity=Severity.HIGH,
                                message=f"Python AST subprocess.{attr_name}() invoked with shell=True",
                                file=self.filename,
                                line=node.lineno,
                                snippet=self._snippet(node.lineno),
                            )
                        )
        self.generic_visit(node)

    def finalize(self) -> list[AuditFinding]:
        if self.env_access_line is not None and self.network_import_line is not None:
            line = max(self.env_access_line, self.network_import_line)
            self.findings.append(
                AuditFinding(
                    rule_id="SEC-008",
                    severity=Severity.CRITICAL,
                    message=(
                        "Python AST taint flow: script reads environment variables "
                        f"(line {self.env_access_line}) and imports network client modules "
                        f"(line {self.network_import_line})"
                    ),
                    file=self.filename,
                    line=line,
                    snippet=self._snippet(line),
                )
            )
        return self.findings


class SkillAuditor:
    """Security and compliance auditor for SKILL.md and skill packages."""

    def _scan_asset(self, rel_path: str, data: bytes) -> list[AuditFinding]:
        """Flag executable payloads in assets/ and scan text assets like any other prose."""
        file_label = f"assets/{rel_path}"
        findings: list[AuditFinding] = []
        is_pe = data.startswith(b"MZ") and b"PE\x00\x00" in data[:1024]
        if is_pe or data.startswith(_EXECUTABLE_MAGIC):
            findings.append(
                AuditFinding(
                    rule_id="SEC-011",
                    severity=Severity.HIGH,
                    message="assets/ contains a native executable (PE, ELF, or Mach-O header); assets should be static data",
                    file=file_label,
                )
            )
        elif rel_path.lower().endswith(_EXECUTABLE_ASSET_SUFFIXES):
            findings.append(
                AuditFinding(
                    rule_id="SEC-011",
                    severity=Severity.MEDIUM,
                    message="assets/ contains an executable or script file type; place runnable code in scripts/ so it is audited as code",
                    file=file_label,
                )
            )
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            return findings
        findings.extend(self._scan_text(text, file_label))
        return findings

    def audit_package(self, package: SkillPackage, *, check_resources: bool = True) -> AuditReport:
        """Audit an entire skill package."""
        target_name = package.skill.name or (package.source_dir.name if package.source_dir else "unknown")
        findings: list[AuditFinding] = []

        skill_text = package.skill.render()
        findings.extend(self._scan_text(skill_text, "SKILL.md"))

        if package.skill.allowed_tools and _UNRESTRICTED_TOOL_PATTERN.search(package.skill.allowed_tools):
            findings.append(
                AuditFinding(
                    rule_id="SEC-009",
                    severity=Severity.MEDIUM,
                    message=(
                        f"Unrestricted tool permission scope in frontmatter allowed-tools: "
                        f"'{package.skill.allowed_tools}'"
                    ),
                    file="SKILL.md",
                    snippet=f"allowed-tools: {package.skill.allowed_tools}",
                )
            )

        if package.skill.allowed_tools:
            allowed_tokens = {
                t.strip().lower()
                for t in re.findall(r"[a-zA-Z0-9_.*-]+(?:\([^)]*\))?", package.skill.allowed_tools)
                if t.strip()
            }
            has_exec_tool = any(
                re.sub(r"\(.*\)", "", t).strip() in _EXECUTION_TOOL_NAMES or t == "*"
                for t in allowed_tokens
            )
            if not has_exec_tool:
                if _SHELL_FENCE_PATTERN.search(package.skill.body):
                    findings.append(
                        AuditFinding(
                            rule_id="SEC-012",
                            severity=Severity.HIGH,
                            message=(
                                f"Skill body contains shell execution blocks, but frontmatter allowed-tools "
                                f"excludes command execution: '{package.skill.allowed_tools}'"
                            ),
                            file="SKILL.md",
                            snippet=f"allowed-tools: {package.skill.allowed_tools}",
                        )
                    )
                elif package.scripts:
                    findings.append(
                        AuditFinding(
                            rule_id="SEC-012",
                            severity=Severity.HIGH,
                            message=(
                                f"Skill package contains executable scripts in scripts/, but frontmatter allowed-tools "
                                f"excludes command execution: '{package.skill.allowed_tools}'"
                            ),
                            file="SKILL.md",
                            snippet=f"allowed-tools: {package.skill.allowed_tools}",
                        )
                    )

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

        if not _SPEC_NAME_PATTERN.fullmatch(package.skill.name) or "--" in package.skill.name:
            findings.append(
                AuditFinding(
                    rule_id="QUAL-007",
                    severity=Severity.LOW,
                    message=(
                        f"Skill name '{package.skill.name}' does not strictly conform to agentskills.io spec: "
                        "use lowercase alphanumeric characters and single hyphens only, with no leading/trailing hyphens or underscores"
                    ),
                    file="SKILL.md",
                    snippet=f"name: {package.skill.name}",
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
            script_file = f"scripts/{rel_path}"
            findings.extend(self._scan_text(content, script_file))
            findings.extend(self._scan_shell_content(content, script_file))
            if rel_path.endswith(".py") or content.startswith("#!") and "python" in content.splitlines()[0]:
                findings.extend(self._scan_python_ast(content, script_file))

        for rel_path, content in package.references.items():
            findings.extend(self._scan_text(content, f"references/{rel_path}"))

        for rel_path, data in package.assets.items():
            findings.extend(self._scan_asset(rel_path, data))

        bad_metadata = [
            f"{key!r}: {value!r}"
            for key, value in package.skill.metadata.items()
            if not isinstance(key, str) or not isinstance(value, str)
        ]
        if bad_metadata:
            findings.append(
                AuditFinding(
                    rule_id="QUAL-008",
                    severity=Severity.LOW,
                    message=(
                        "metadata must map string keys to string values per the agentskills.io spec; "
                        "quote numbers and booleans (for example version: \"1.0\")"
                    ),
                    file="SKILL.md",
                    snippet=bad_metadata[0],
                )
            )

        return AuditReport(
            target=target_name,
            findings=findings,
            pointer_tokens=package.skill.pointer_tokens,
            body_tokens=package.skill.body_tokens,
            body_lines=package.skill.body_lines,
        )

    def _scan_python_ast(self, content: str, filename: str) -> list[AuditFinding]:
        """Parse and inspect Python scripts using AST and taint analysis."""
        try:
            tree = ast.parse(content, filename=filename)
        except SyntaxError:
            return []
        scanner = _PythonASTScanner(filename, content.splitlines())
        scanner.visit(tree)
        return scanner.finalize()

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
                if folder == "scripts":
                    exists = rel_path in package.scripts
                elif folder == "references":
                    exists = rel_path in package.references
                else:
                    exists = rel_path in package.assets
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

        for ref_name, ref_content in sorted(package.references.items()):
            ref_file = f"references/{ref_name}"
            in_ref_fence = False
            for r_idx, r_line in enumerate(ref_content.splitlines(), start=1):
                if r_line.lstrip().startswith(("```", "~~~")):
                    in_ref_fence = not in_ref_fence
                    continue
                if in_ref_fence:
                    continue
                for match in _DISCLOSED_PATH_PATTERN.finditer(r_line):
                    folder, rel_path = match.group(1), match.group(2)
                    if folder == "references" and rel_path != ref_name:
                        findings.append(
                            AuditFinding(
                                rule_id="QUAL-009",
                                severity=Severity.LOW,
                                message=(
                                    f"Nested reference chain '{folder}/{rel_path}' inside '{ref_file}': "
                                    "link reference files directly from SKILL.md (one-level-deep)"
                                ),
                                file=ref_file,
                                line=r_idx,
                                snippet=r_line.strip(),
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

            # Check markdown link spoofing (SEC-007)
            for match_link in _MARKDOWN_LINK_PATTERN.finditer(line):
                label_raw = match_link.group(1).strip().strip("`")
                target_raw = match_link.group(2).strip().split()[0]
                if label_raw.startswith(("http://", "https://")) and target_raw.startswith(
                    ("http://", "https://")
                ):
                    label_host = (urlparse(label_raw).hostname or "").lower().removeprefix("www.")
                    target_host = (urlparse(target_raw).hostname or "").lower().removeprefix("www.")
                    if label_host and target_host and label_host != target_host:
                        findings.append(
                            AuditFinding(
                                rule_id="SEC-007",
                                severity=Severity.HIGH,
                                message=(
                                    f"Markdown link spoofing detected: visible URL host '{label_host}' "
                                    f"points to different destination host '{target_host}'"
                                ),
                                file=filename,
                                line=idx,
                                snippet=line.strip(),
                            )
                        )

            # Check Markdown-as-Installer / ClickFix patterns (SEC-010)
            for inst_pattern in _MARKDOWN_INSTALLER_PATTERNS:
                match_inst = inst_pattern.search(line)
                if match_inst:
                    quoted_defense = bool(
                        _DEFENSIVE_CONTEXT_PATTERN.search(line) and re.search(r"[\"'`]", line)
                    )
                    findings.append(
                        AuditFinding(
                            rule_id="SEC-010",
                            severity=Severity.MEDIUM if quoted_defense else Severity.HIGH,
                            message=(
                                f"Markdown-as-Installer deceptive command instruction detected: '{match_inst.group(0)[:70]}'"
                            ),
                            file=filename,
                            line=idx,
                            snippet=line.strip()[:100],
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


def _discover_collection_packages(root: Path) -> list[SkillPackage]:
    """Discover skill packages within a collection directory or project root."""
    packages: dict[str, SkillPackage] = {}
    search_roots = (
        root,
        root / "skills",
        root / ".claude" / "skills",
        root / ".cursor" / "skills",
        root / ".gemini" / "skills",
        root / ".gemini" / "config" / "skills",
        root / ".windsurf" / "skills",
        root / ".cline" / "skills",
        root / ".agents" / "skills",
        root / ".skillforge",
        root / "src" / "skillforge" / "builtin_skills",
    )
    for candidate in search_roots:
        if candidate.is_dir():
            for skill_md in sorted(candidate.glob("*/SKILL.md")):
                try:
                    pkg = SkillPackage.load(skill_md.parent)
                    packages.setdefault(pkg.skill.name, pkg)
                except Exception:
                    pass
    return [packages[name] for name in sorted(packages)]


def audit_path(path: Path) -> AuditReport:
    """Convenience helper to audit a skill file, skill package, or multi-skill directory."""
    auditor = SkillAuditor()
    if path.is_file() or (path / "SKILL.md").is_file():
        return auditor.audit_file_or_dir(path)

    if path.is_dir():
        packages = _discover_collection_packages(path)
        if packages:
            if len(packages) == 1:
                return auditor.audit_package(packages[0])
            combined_findings: list[AuditFinding] = []
            total_pointer = 0
            total_body = 0
            total_lines = 0
            for pkg in packages:
                rep = auditor.audit_package(pkg)
                total_pointer += rep.pointer_tokens
                total_body += rep.body_tokens
                total_lines += rep.body_lines
                for f in rep.findings:
                    combined_findings.append(
                        AuditFinding(
                            rule_id=f.rule_id,
                            severity=f.severity,
                            message=f.message,
                            file=f"{pkg.skill.name}/{f.file}",
                            line=f.line,
                            snippet=f.snippet,
                        )
                    )
            label = path.resolve().name or str(path)
            return AuditReport(
                target=f"{label} ({len(packages)} skills)",
                findings=combined_findings,
                pointer_tokens=total_pointer,
                body_tokens=total_body,
                body_lines=total_lines,
            )

    return auditor.audit_file_or_dir(path)

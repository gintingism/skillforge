"""Security auditor and anti-prompt-injection scanner for portable skills."""

from __future__ import annotations

import ast
import json
import os
import re
import subprocess
import sys
import tempfile
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
            "SEC-013": ("Persistent Memory & Git Hook Poisoning", "Detects shell redirection or append operations targeting persistent agent memory files or git hooks."),
            "SEC-014": ("Lethal Trifecta Compound Risk", "Detects skills combining private credential access, untrusted external ingestion, and outbound network egress."),
            "SEC-015": ("Obfuscated Payloads & Encoded Command Execution", "Detects base64 pipelines, hex-escapes, or obfuscated decoder execution wrappers (Cisco obfuscation)."),
            "SEC-016": ("Destructive Resource Abuse & Fork Bombs", "Detects fork bombs, disk exhaustion, or destructive block device formatting (Cisco resource_abuse)."),
            "SEC-017": ("Unpinned Runtime Dependency Injection", "Detects unpinned package installations from public registries without cryptographic hash or version locks (Cisco supply_chain)."),
            "MCP-001": ("Plaintext Secret in MCP Environment", "Detects embedded API keys or high-entropy credentials inside MCP server env configuration."),
            "MCP-002": ("Shell Wrapper in MCP Command", "Detects arbitrary shell execution wrappers (bash, sh, powershell) in MCP server command fields."),
            "MCP-003": ("Unpinned Package in MCP Invocation", "Detects unpinned npx or uvx server launches without exact version tags in MCP args."),
            "MCP-004": ("Overbroad Filesystem Root Scope", "Detects whole-filesystem or user-root directory access grants in MCP server arguments."),
            "MCP-005": ("MCP Tool Poisoning Directive", "Detects hidden prompt injection, secret harvesting, or stealth instructions embedded inside MCP tool descriptions or schemas."),
            "MCP-006": ("MCP Cross-Server Tool Shadowing", "Detects duplicate tool names declared across multiple MCP servers or shadowing built-in agent tools."),
            "MCP-007": ("MCP Cross-Server Toxic Flow", "Detects toxic multi-server combinations uniting untrusted external ingestion, sensitive local data access, and external network egress."),
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
_MEMORY_POISONING_PATTERNS: list[re.Pattern[str]] = [
    re.compile(
        r"(?i)(?:>>|>|\|\s*tee(?:\s+-a)?)\s*[\"']?(?:~\/|\$HOME\/|\.\.?\/)*(?:CLAUDE\.md|AGENTS\.md|MEMORY\.md|\.cursorrules|\.windsurfrules|\.clinerules|\.github\/copilot-instructions\.md|\.bashrc|\.zshrc|\.profile|\.git\/hooks\/[a-z0-9_-]+)\b"
    ),
]
_TRIFECTA_PRIVATE_DATA = re.compile(
    r"(?i)(?:\.ssh/id_|\.aws/credentials|\.config/gcloud|\bos\.environ\b|\bos\.getenv\s*\(|\bprocess\.env\b|\$(?:AWS_SECRET|OPENAI_API_KEY|ANTHROPIC_API_KEY|GITHUB_TOKEN|SECRET_KEY|DATABASE_URL)\b|\bcat\s+[^\n`]*\.env\b)"
)
_TRIFECTA_UNTRUSTED_INGEST = re.compile(
    r"(?i)(?:\b(?:curl|wget)\b[^\n`]*https?://|\b(?:requests|httpx)\.(?:get|request)\s*\(|\burllib\.request\.urlopen\s*\()"
)
_TRIFECTA_EXTERNAL_EGRESS = re.compile(
    r"(?i)(?:\b(?:curl|wget)\b[^\n`]*(?:-X\s*POST|--data|-d\s+|--post-data|-F\s+)|\b(?:requests|httpx)\.(?:post|put)\s*\(|\burllib\.request\.Request\s*\([^\n`]*data=|\b(?:webhook\.site|pipedream\.net|requestbin\.net|burpcollaborator\.net)\b)"
)
_OBFUSCATION_PATTERNS: list[tuple[str, re.Pattern[str], Severity]] = [
    (
        "SEC-015",
        re.compile(
            r"(?i)\b(?:echo\s+[A-Za-z0-9+/=]{20,}\s*\|\s*base64\s+(-d|--decode)\s*\|\s*(?:bash|sh|zsh|powershell|pwsh)|base64\s+(-d|--decode)\s*\|\s*(?:bash|sh|zsh|powershell|pwsh|eval))"
        ),
        Severity.CRITICAL,
    ),
    (
        "SEC-015",
        re.compile(
            r"(?i)\bpython(?:3)?\s+-c\s+[\"'].*?(?:b64decode|decode\(['\"]base64['\"]\)).*?exec\s*\("
        ),
        Severity.CRITICAL,
    ),
    (
        "SEC-015",
        re.compile(
            r"(?i)\bpowershell\b.*?(?:-enc|-encodedcommand)\s+[A-Za-z0-9+/=]{20,}"
        ),
        Severity.HIGH,
    ),
    (
        "SEC-015",
        re.compile(r"(?i)(?:\\x[0-9a-fA-F]{2}){8,}"),
        Severity.HIGH,
    ),
    (
        "SEC-015",
        re.compile(r"(?i)\b(?:xxd\s+-r\b.*\|\s*(?:bash|sh|zsh|eval))"),
        Severity.HIGH,
    ),
]

_RESOURCE_ABUSE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "SEC-016",
        re.compile(r"(?::\(\)\s*\{\s*:\|:&\s*\};:|:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\};:|\$0\s*\|\s*\$0\s*&)"),
    ),
    (
        "SEC-016",
        re.compile(r"(?i)\b(?:dd\s+if=/dev/(?:urandom|zero)\s+of=(?:/dev/|[^\s]+)|cat\s+/dev/zero\s*>\s*[^\s]+)"),
    ),
    (
        "SEC-016",
        re.compile(r"(?i)\b(?:mkfs(?:\.[a-z0-9]+)?\s+/dev/|fdisk\s+/dev/sd)"),
    ),
    (
        "SEC-016",
        re.compile(r"(?i)>\s*/dev/sd[a-z][0-9]*\b"),
    ),
]

_UNPINNED_INSTALL_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "SEC-017",
        re.compile(
            r"(?i)\b(?:pip|pip3|uv\s+pip)\s+install\s+(?!-[rRe]\b|--requirement\b|--editable\b)(?:--user\s+|--upgrade\s+|-U\s+|--quiet\s+|-q\s+)*([a-zA-Z0-9_-]{2,})\s*(?:$|[;&|])"
        ),
    ),
    (
        "SEC-017",
        re.compile(
            r"(?i)\bnpm\s+(?:i|install|add)\s+(?:-g\s+|--global\s+)?([a-zA-Z0-9_-]{2,})\s*(?:$|[;&|])"
        ),
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

    def audit_package(
        self,
        package: SkillPackage,
        *,
        check_resources: bool = True,
        sandbox: bool = False,
    ) -> AuditReport:
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
            is_python = rel_path.endswith(".py") or (
                content.startswith("#!") and "python" in content.splitlines()[0]
            )
            if is_python:
                findings.extend(self._scan_python_ast(content, script_file))
                if sandbox:
                    findings.extend(self._run_script_sandbox(script_file, content))

        for rel_path, content in package.references.items():
            findings.extend(self._scan_text(content, f"references/{rel_path}"))

        for rel_path, data in package.assets.items():
            findings.extend(self._scan_asset(rel_path, data))

        findings.extend(self._check_lethal_trifecta(package))

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

    def _check_lethal_trifecta(self, package: SkillPackage) -> list[AuditFinding]:
        """Detect OWASP AST10 Lethal Trifecta compound risk across package instructions and scripts."""
        has_private = False
        has_ingest = False
        has_egress = False
        egress_snippet: str | None = None

        sources: list[str] = [package.skill.body]
        sources.extend(package.scripts.values())

        for text in sources:
            for line in text.splitlines():
                if _DEFENSIVE_CONTEXT_PATTERN.search(line):
                    continue
                if not has_private and _TRIFECTA_PRIVATE_DATA.search(line):
                    has_private = True
                if not has_ingest and _TRIFECTA_UNTRUSTED_INGEST.search(line):
                    has_ingest = True
                if not has_egress and _TRIFECTA_EXTERNAL_EGRESS.search(line):
                    has_egress = True
                    egress_snippet = line.strip()[:100]

        if has_private and has_ingest and has_egress:
            return [
                AuditFinding(
                    rule_id="SEC-014",
                    severity=Severity.CRITICAL,
                    message=(
                        "Lethal Trifecta compound risk (OWASP AST10): package combines sensitive "
                        "credential/env access, untrusted remote content ingestion, and external network egress"
                    ),
                    file="SKILL.md",
                    snippet=egress_snippet,
                )
            ]
        return []

    def _run_script_sandbox(self, script_file: str, content: str) -> list[AuditFinding]:
        """Execute a bundled Python script inside an offline, network-blocked sandbox subprocess."""
        findings: list[AuditFinding] = []
        harness_code = (
            "import builtins, os, runpy, socket, subprocess, sys, urllib.request\n"
            "def _blocked_net(*a, **kw):\n"
            "    raise RuntimeError('SANDBOX_VIOLATION: outbound network socket blocked')\n"
            "def _blocked_proc(*a, **kw):\n"
            "    raise RuntimeError('SANDBOX_VIOLATION: subprocess execution blocked')\n"
            "socket.socket = _blocked_net\n"
            "socket.create_connection = _blocked_net\n"
            "urllib.request.urlopen = _blocked_net\n"
            "os.system = _blocked_proc\n"
            "os.popen = _blocked_proc\n"
            "subprocess.Popen = _blocked_proc\n"
            "subprocess.run = _blocked_proc\n"
            "subprocess.call = _blocked_proc\n"
            "subprocess.check_output = _blocked_proc\n"
            "target = sys.argv[1]\n"
            "sys.argv = [target]\n"
            "try:\n"
            "    runpy.run_path(target, run_name='__main__')\n"
            "except SystemExit:\n"
            "    pass\n"
        )
        with tempfile.TemporaryDirectory(prefix="skillforge_sbx_") as tmpdir:
            tmp_path = Path(tmpdir)
            target_path = tmp_path / "target_script.py"
            runner_path = tmp_path / "sandbox_runner.py"
            target_path.write_text(content, encoding="utf-8")
            runner_path.write_text(harness_code, encoding="utf-8")

            sanitized_env = {
                "PATH": os.environ.get("PATH", ""),
                "SYSTEMROOT": os.environ.get("SYSTEMROOT", ""),
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONUTF8": "1",
                "OPENAI_API_KEY": "sk-sandbox-canary-token",
            }
            try:
                proc = subprocess.run(
                    [sys.executable, "-I", str(runner_path), str(target_path)],
                    cwd=tmpdir,
                    env=sanitized_env,
                    capture_output=True,
                    text=True,
                    timeout=3.0,
                    check=False,
                )
            except subprocess.TimeoutExpired:
                findings.append(
                    AuditFinding(
                        rule_id="SEC-008",
                        severity=Severity.HIGH,
                        message="Sandbox execution timed out after 3.0s (possible infinite loop or stalling payload)",
                        file=script_file,
                    )
                )
                return findings
            except OSError:
                return findings

            combined_out = f"{proc.stdout}\n{proc.stderr}"
            if "SANDBOX_VIOLATION:" in combined_out:
                reason = "unauthorized network or process call during sandbox execution"
                for line in combined_out.splitlines():
                    if "SANDBOX_VIOLATION:" in line:
                        reason = line.split("SANDBOX_VIOLATION:", 1)[1].strip()
                        break
                findings.append(
                    AuditFinding(
                        rule_id="SEC-008",
                        severity=Severity.CRITICAL,
                        message=f"Runtime sandbox violation: {reason}",
                        file=script_file,
                    )
                )
            elif "sk-sandbox-canary-token" in combined_out:
                findings.append(
                    AuditFinding(
                        rule_id="SEC-008",
                        severity=Severity.CRITICAL,
                        message="Runtime sandbox violation: script leaked canary environment secret to output stream",
                        file=script_file,
                    )
                )
        return findings

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

    def audit_file_or_dir(self, path: Path, *, sandbox: bool = False) -> AuditReport:
        """Audit a file or directory from disk."""
        package = SkillPackage.load(path)
        return self.audit_package(package, sandbox=sandbox)

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

            # Check persistent memory & git hook poisoning patterns (SEC-013)
            for mem_pattern in _MEMORY_POISONING_PATTERNS:
                match_mem = mem_pattern.search(line)
                if match_mem:
                    quoted_defense = bool(
                        _DEFENSIVE_CONTEXT_PATTERN.search(line) and re.search(r"[\"'`]", line)
                    )
                    findings.append(
                        AuditFinding(
                            rule_id="SEC-013",
                            severity=Severity.MEDIUM if quoted_defense else Severity.HIGH,
                            message=(
                                f"Persistent agent memory or git hook modification detected: '{match_mem.group(0).strip()}'"
                            ),
                            file=filename,
                            line=idx,
                            snippet=line.strip()[:100],
                        )
                    )

            # Check obfuscated payloads & encoded command execution (SEC-015)
            for rule_id, pattern, severity in _OBFUSCATION_PATTERNS:
                match_obf = pattern.search(line)
                if match_obf:
                    quoted_defense = bool(
                        _DEFENSIVE_CONTEXT_PATTERN.search(line) and re.search(r"[\"'`]", line)
                    )
                    findings.append(
                        AuditFinding(
                            rule_id=rule_id,
                            severity=Severity.MEDIUM if quoted_defense else severity,
                            message=f"Obfuscated payload or encoded execution wrapper detected: '{match_obf.group(0)[:60]}'",
                            file=filename,
                            line=idx,
                            snippet=line.strip()[:100],
                        )
                    )

            # Check destructive resource abuse & fork bombs (SEC-016)
            for rule_id, pattern in _RESOURCE_ABUSE_PATTERNS:
                match_res = pattern.search(line)
                if match_res:
                    quoted_defense = bool(
                        _DEFENSIVE_CONTEXT_PATTERN.search(line) and re.search(r"[\"'`]", line)
                    )
                    findings.append(
                        AuditFinding(
                            rule_id=rule_id,
                            severity=Severity.MEDIUM if quoted_defense else Severity.CRITICAL,
                            message=f"Destructive resource abuse or fork bomb pattern detected: '{match_res.group(0)[:60]}'",
                            file=filename,
                            line=idx,
                            snippet=line.strip()[:100],
                        )
                    )

            # Check unpinned runtime package installations (SEC-017)
            for rule_id, pattern in _UNPINNED_INSTALL_PATTERNS:
                match_inst = pattern.search(line)
                if match_inst:
                    quoted_defense = bool(
                        _DEFENSIVE_CONTEXT_PATTERN.search(line) and re.search(r"[\"'`]", line)
                    )
                    findings.append(
                        AuditFinding(
                            rule_id=rule_id,
                            severity=Severity.MEDIUM if quoted_defense else Severity.HIGH,
                            message=f"Unpinned runtime package installation from public registry: '{match_inst.group(0).strip()}'",
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
            for rule_id, pattern, severity in _OBFUSCATION_PATTERNS:
                match_obf = pattern.search(line)
                if match_obf:
                    findings.append(
                        AuditFinding(
                            rule_id=rule_id,
                            severity=severity,
                            message=f"Obfuscated script execution or encoded payload: '{match_obf.group(0)[:60]}'",
                            file=filename,
                            line=idx,
                            snippet=line.strip(),
                        )
                    )
            for rule_id, pattern in _RESOURCE_ABUSE_PATTERNS:
                match_res = pattern.search(line)
                if match_res:
                    findings.append(
                        AuditFinding(
                            rule_id=rule_id,
                            severity=Severity.CRITICAL,
                            message=f"Destructive resource abuse or disk/fork bomb pattern in script: '{match_res.group(0)[:60]}'",
                            file=filename,
                            line=idx,
                            snippet=line.strip(),
                        )
                    )
            for rule_id, pattern in _UNPINNED_INSTALL_PATTERNS:
                match_inst = pattern.search(line)
                if match_inst:
                    findings.append(
                        AuditFinding(
                            rule_id=rule_id,
                            severity=Severity.HIGH,
                            message=f"Unpinned package installation in script: '{match_inst.group(0).strip()}'",
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


def audit_path(path: Path, *, sandbox: bool = False) -> AuditReport:
    """Convenience helper to audit a skill file, skill package, or multi-skill directory."""
    auditor = SkillAuditor()
    if path.is_file() or (path / "SKILL.md").is_file():
        return auditor.audit_file_or_dir(path, sandbox=sandbox)

    if path.is_dir():
        packages = _discover_collection_packages(path)
        if packages:
            if len(packages) == 1:
                return auditor.audit_package(packages[0], sandbox=sandbox)
            combined_findings: list[AuditFinding] = []
            total_pointer = 0
            total_body = 0
            total_lines = 0
            for pkg in packages:
                rep = auditor.audit_package(pkg, sandbox=sandbox)
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

    return auditor.audit_file_or_dir(path, sandbox=sandbox)


def audit_mcp_config(path: Path) -> AuditReport:
    """Audit an MCP configuration file (mcp.json or claude_desktop_config.json) for security risks."""
    import json

    target_name = path.name or str(path)
    if not path.is_file():
        raise SecurityAuditError(f"MCP configuration file not found: {path}")

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise SecurityAuditError(f"Failed to parse MCP configuration JSON: {exc}") from exc

    servers: dict[str, Any] = {}
    if isinstance(data, dict):
        if "mcpServers" in data and isinstance(data["mcpServers"], dict):
            servers = data["mcpServers"]
        else:
            servers = {
                k: v for k, v in data.items() if isinstance(v, dict) and "command" in v
            }

    findings: list[AuditFinding] = []
    dangerous_shells = frozenset({"bash", "sh", "cmd", "cmd.exe", "powershell", "pwsh"})
    root_paths = frozenset({"/", "\\", "c:\\", "c:/", "~", "$home"})
    protected_builtin_tools = frozenset({"bash", "read_file", "write_file", "edit_file", "execute_command"})
    poisoning_markers = re.compile(
        r"(?i)(<\s*IMPORTANT\b|do\s+not\s+mention|without\s+telling\s+the\s+user|"
        r"silently\s+(?:read|send|exfiltrate|forward)|~/.cursor/mcp\.json|~/.ssh|~/.aws)"
    )

    tool_registry: dict[str, list[str]] = {}
    server_capabilities: dict[str, set[str]] = {}

    untrusted_keywords = ("github", "fetch", "puppeteer", "playwright", "browser", "slack", "web", "http", "scrape")
    sensitive_keywords = ("filesystem", "postgres", "sqlite", "mysql", "database", "db", "git", "env", "secret", "aws", "ssh")
    egress_keywords = ("fetch", "webhook", "http", "curl", "slack", "email", "smtp", "post", "request")

    for s_name, s_cfg in sorted(servers.items()):
        s_file = f"{target_name}::{s_name}"
        if not isinstance(s_cfg, dict):
            continue

        cmd = str(s_cfg.get("command", "")).strip().lower()
        args: list[str] = (
            [str(a) for a in s_cfg.get("args", [])]
            if isinstance(s_cfg.get("args"), list)
            else []
        )
        env_map = (
            s_cfg.get("env", {}) if isinstance(s_cfg.get("env"), dict) else {}
        )

        # Classify server capabilities for cross-server toxic flow analysis
        combined_text = " ".join([s_name, cmd, *args, str(s_cfg.get("description", ""))]).lower()
        tools_list = s_cfg.get("tools", [])
        if isinstance(tools_list, list):
            for t in tools_list:
                if isinstance(t, dict):
                    combined_text += " " + str(t.get("name", "")) + " " + str(t.get("description", ""))

        caps: set[str] = set()
        if any(k in combined_text for k in untrusted_keywords):
            caps.add("untrusted_ingestion")
        if any(k in combined_text for k in sensitive_keywords):
            caps.add("sensitive_access")
        if any(k in combined_text for k in egress_keywords):
            caps.add("external_egress")
        server_capabilities[s_name] = caps

        # MCP-005: Tool poisoning in server description or embedded tool schemas
        server_desc = str(s_cfg.get("description", ""))
        if server_desc:
            if _INVISIBLE_UNICODE_CHARS.search(server_desc) or poisoning_markers.search(server_desc):
                findings.append(
                    AuditFinding(
                        rule_id="MCP-005",
                        severity=Severity.CRITICAL,
                        message=f"Tool poisoning directive detected in server '{s_name}' description",
                        file=s_file,
                        snippet=server_desc[:80],
                    )
                )

        if isinstance(tools_list, list):
            for tool_item in tools_list:
                if not isinstance(tool_item, dict):
                    continue
                t_name = str(tool_item.get("name", "")).strip()
                t_desc = str(tool_item.get("description", ""))
                t_schema = json.dumps(tool_item.get("inputSchema", {})) if tool_item.get("inputSchema") else ""
                inspect_blob = f"{t_desc} {t_schema}"

                poisoned = False
                if _INVISIBLE_UNICODE_CHARS.search(inspect_blob) or poisoning_markers.search(inspect_blob):
                    poisoned = True
                else:
                    for _, inj_pat in _INJECTION_PATTERNS:
                        if inj_pat.search(inspect_blob):
                            poisoned = True
                            break
                if poisoned:
                    findings.append(
                        AuditFinding(
                            rule_id="MCP-005",
                            severity=Severity.CRITICAL,
                            message=f"Tool poisoning payload detected in tool '{t_name or 'unnamed'}' on server '{s_name}'",
                            file=s_file,
                            snippet=t_desc[:80] if t_desc else t_schema[:80],
                        )
                    )

                if t_name:
                    t_norm = t_name.lower()
                    tool_registry.setdefault(t_norm, []).append(s_name)
                    if t_norm in protected_builtin_tools:
                        findings.append(
                            AuditFinding(
                                rule_id="MCP-006",
                                severity=Severity.HIGH,
                                message=f"Tool shadowing risk: server '{s_name}' overrides built-in tool name '{t_name}'",
                                file=s_file,
                                snippet=f"tool: {t_name}",
                            )
                        )

        # MCP-001: Plaintext secrets in env
        for env_k, env_v in env_map.items():
            if not isinstance(env_v, str):
                continue
            is_secret = False
            for _, pat, sev in _HARDCODED_SECRET_PATTERNS:
                if pat.search(env_v):
                    findings.append(
                        AuditFinding(
                            rule_id="MCP-001",
                            severity=sev,
                            message=f"Hardcoded credential secret pattern in env var '{env_k}': '{env_v[:8]}...'",
                            file=s_file,
                            snippet=f'"{env_k}": "{env_v[:10]}..."',
                        )
                    )
                    is_secret = True
                    break
            if not is_secret and len(env_v) >= 20 and not env_v.startswith(("$", "%", "{")):
                k_upper = env_k.upper()
                if any(x in k_upper for x in ("KEY", "TOKEN", "SECRET", "PASSWORD", "AUTH")):
                    findings.append(
                        AuditFinding(
                            rule_id="MCP-001",
                            severity=Severity.HIGH,
                            message=f"Plaintext credential value in env var '{env_k}' (use runtime variable substitution)",
                            file=s_file,
                            snippet=f'"{env_k}": "{env_v[:8]}..."',
                        )
                    )

        # MCP-002: Shell interpreter as command wrapper
        if Path(cmd).stem in dangerous_shells or cmd in dangerous_shells:
            if any(a.lower() in ("-c", "/c") for a in args):
                findings.append(
                    AuditFinding(
                        rule_id="MCP-002",
                        severity=Severity.HIGH,
                        message=f"MCP server invokes arbitrary shell interpreter as command: '{cmd}'",
                        file=s_file,
                        snippet=f'command: "{cmd}"',
                    )
                )

        # MCP-003: Unpinned package execution in args (npx / uvx)
        if Path(cmd).stem in ("npx", "pnpx", "uvx") or cmd in ("npx", "pnpx", "uvx"):
            for a in args:
                if a.startswith("-"):
                    continue
                if "/" in a and not a.startswith((".", "/")):
                    parts = a.split("@")
                    has_version = len(parts) >= 3 if a.startswith("@") else len(parts) >= 2
                    if not has_version:
                        findings.append(
                            AuditFinding(
                                rule_id="MCP-003",
                                severity=Severity.MEDIUM,
                                message=f"Unpinned package invocation in MCP server args: '{a}' (pin with @version)",
                                file=s_file,
                                snippet=f"args: {args}",
                            )
                        )
                        break
                elif not a.startswith((".", "/")) and "@" not in a and len(a) > 2:
                    findings.append(
                        AuditFinding(
                            rule_id="MCP-003",
                            severity=Severity.MEDIUM,
                            message=f"Unpinned package invocation in MCP server args: '{a}' (pin with @version)",
                            file=s_file,
                            snippet=f"args: {args}",
                        )
                    )
                    break

        # MCP-004: Overbroad filesystem root scope
        for a in args:
            clean_a = a.strip().lower()
            if clean_a in root_paths or clean_a in ("c:\\", "c:/", "/"):
                findings.append(
                    AuditFinding(
                        rule_id="MCP-004",
                        severity=Severity.HIGH,
                        message=f"Overbroad filesystem permission: MCP server granted access to root directory '{a}'",
                        file=s_file,
                        snippet=f"args: {args}",
                    )
                )
                break

    # MCP-006: Duplicate tool names across different MCP servers
    for tool_name, owners in sorted(tool_registry.items()):
        unique_owners = sorted(set(owners))
        if len(unique_owners) > 1:
            findings.append(
                AuditFinding(
                    rule_id="MCP-006",
                    severity=Severity.HIGH,
                    message=(
                        f"Cross-server tool shadowing: tool '{tool_name}' is declared by multiple "
                        f"servers ({', '.join(unique_owners)})"
                    ),
                    file=target_name,
                    snippet=f"tool '{tool_name}': {', '.join(unique_owners)}",
                )
            )

    # MCP-007: Cross-server toxic flow uniting untrusted ingestion + sensitive access + external egress
    if len(server_capabilities) >= 2:
        union_caps: set[str] = set()
        for caps in server_capabilities.values():
            union_caps.update(caps)
        if {"untrusted_ingestion", "sensitive_access", "external_egress"}.issubset(union_caps):
            findings.append(
                AuditFinding(
                    rule_id="MCP-007",
                    severity=Severity.HIGH,
                    message=(
                        "Cross-server toxic flow detected: combined MCP servers unite untrusted external "
                        "ingestion, sensitive local/database access, and external egress channels"
                    ),
                    file=target_name,
                    snippet=f"servers: {', '.join(sorted(server_capabilities))}",
                )
            )

    return AuditReport(target=target_name, findings=findings)

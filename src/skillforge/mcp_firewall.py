"""Runtime Model Context Protocol (MCP) security firewall and JSON-RPC proxy.

Intercepts JSON-RPC 2.0 traffic between an AI agent client and an MCP server to block
prompt injections, command smuggling, credential traversal, SSRF, and secret leakage.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .errors import SkillForgeError

# Rule patterns for MCP parameter and payload inspection
_INVISIBLE_UNICODE = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]")
_PROMPT_INJECTION = re.compile(
    r"(?:ignore\s+(?:all\s+)?(?:previous|prior)\s+instructions|"
    r"system\s+override|disregard\s+safety\s+guidelines|"
    r"you\s+are\s+now\s+in\s+developer\s+mode)",
    re.IGNORECASE,
)
_SHELL_SMUGGLING = re.compile(
    r"(?:;\s*rm\s+-[rf]+|\|\s*(?:ba|z)?sh\b|\$\(\s*(?:curl|wget)\b|"
    r"`\s*(?:curl|wget)\b|\bpowershell(?:\.exe)?\s+-(?:e|enc|encodedcommand)\b|"
    r"\bnc\s+-e\s+/bin/(?:ba)?sh)",
    re.IGNORECASE,
)
_CREDENTIAL_TRAVERSAL = re.compile(
    r"(?:~\/\.ssh\b|~\/\.aws\/credentials\b|\/etc\/(?:passwd|shadow)\b|"
    r"(?:\.\.\/){2,}|\.\.\\\.\.\\|\b\.env\.production\b|\bid_rsa\b)",
    re.IGNORECASE,
)
_SSRF_TARGETS = re.compile(
    r"(?:http:\/\/169\.254\.169\.254\b|http:\/\/metadata\.google\.internal\b|"
    r"http:\/\/127\.0\.0\.1:2375\b|http:\/\/localhost:2375\b)",
    re.IGNORECASE,
)
_SECRET_PATTERNS = re.compile(
    r"(?:ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{50,}|"
    r"sk-ant-[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|AIzaSy[A-Za-z0-9_-]{33})"
)


@dataclass(frozen=True, slots=True)
class FirewallViolation:
    """Single security violation detected in an MCP JSON-RPC payload."""

    rule_id: str
    severity: str
    message: str
    field_path: str


@dataclass
class FirewallDecision:
    """Decision produced after inspecting a JSON-RPC message."""

    action: str  # "ALLOW", "BLOCK", "REDACT"
    direction: str  # "request" or "response"
    method: str
    tool_name: str | None = None
    message_id: Any = None
    violations: list[FirewallViolation] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @property
    def allowed(self) -> bool:
        return self.action in ("ALLOW", "REDACT")

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "action": self.action,
            "direction": self.direction,
            "method": self.method,
            "tool_name": self.tool_name,
            "message_id": self.message_id,
            "violations": [
                {
                    "rule_id": v.rule_id,
                    "severity": v.severity,
                    "message": v.message,
                    "field_path": v.field_path,
                }
                for v in self.violations
            ],
        }


@dataclass
class FirewallAuditSummary:
    """Summary of a batch or stream inspection run."""

    total_messages: int
    allowed_count: int
    blocked_count: int
    redacted_count: int
    decisions: list[FirewallDecision] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return self.blocked_count == 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "total_messages": self.total_messages,
            "allowed_count": self.allowed_count,
            "blocked_count": self.blocked_count,
            "redacted_count": self.redacted_count,
            "decisions": [d.to_dict() for d in self.decisions],
        }


class MCPFirewall:
    """Inline zero-trust inspector for MCP JSON-RPC requests and responses."""

    def __init__(
        self,
        allowed_tools: set[str] | None = None,
        audit_log_path: Path | None = None,
        redact_secrets: bool = True,
    ) -> None:
        self.allowed_tools = allowed_tools
        self.audit_log_path = audit_log_path
        self.redact_secrets = redact_secrets

    def _log_decision(self, decision: FirewallDecision) -> None:
        if self.audit_log_path is None:
            return
        self.audit_log_path.parent.mkdir(parents=True, exist_ok=True)
        with self.audit_log_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(decision.to_dict()) + "\n")

    def _scan_value(self, val: Any, path: str, violations: list[FirewallViolation]) -> None:
        if isinstance(val, str):
            if _INVISIBLE_UNICODE.search(val) or _PROMPT_INJECTION.search(val):
                violations.append(
                    FirewallViolation(
                        rule_id="FW-001",
                        severity="CRITICAL",
                        message="Prompt injection or hidden unicode control sequence detected",
                        field_path=path,
                    )
                )
            if _SHELL_SMUGGLING.search(val):
                violations.append(
                    FirewallViolation(
                        rule_id="FW-002",
                        severity="CRITICAL",
                        message="Shell command injection or pipeline smuggling pattern detected",
                        field_path=path,
                    )
                )
            if _CREDENTIAL_TRAVERSAL.search(val):
                violations.append(
                    FirewallViolation(
                        rule_id="FW-003",
                        severity="HIGH",
                        message="Sensitive credential path or directory traversal attempt detected",
                        field_path=path,
                    )
                )
            if _SSRF_TARGETS.search(val):
                violations.append(
                    FirewallViolation(
                        rule_id="FW-004",
                        severity="HIGH",
                        message="Cloud metadata or local SSRF endpoint detected",
                        field_path=path,
                    )
                )
        elif isinstance(val, dict):
            for k, v in val.items():
                self._scan_value(v, f"{path}.{k}", violations)
        elif isinstance(val, list):
            for idx, item in enumerate(val):
                self._scan_value(item, f"{path}[{idx}]", violations)

    def _redact_value(self, val: Any, path: str, violations: list[FirewallViolation]) -> Any:
        if isinstance(val, str):
            cleaned = val
            if _SECRET_PATTERNS.search(cleaned):
                violations.append(
                    FirewallViolation(
                        rule_id="FW-005",
                        severity="HIGH",
                        message="Plaintext API token or secret redacted from MCP response",
                        field_path=path,
                    )
                )
                if self.redact_secrets:
                    cleaned = _SECRET_PATTERNS.sub("[REDACTED_BY_SKILLFORGE_FIREWALL]", cleaned)
            if _INVISIBLE_UNICODE.search(cleaned) or _PROMPT_INJECTION.search(cleaned):
                violations.append(
                    FirewallViolation(
                        rule_id="FW-001",
                        severity="CRITICAL",
                        message="Indirect prompt injection detected in MCP server response",
                        field_path=path,
                    )
                )
            return cleaned
        if isinstance(val, dict):
            return {k: self._redact_value(v, f"{path}.{k}", violations) for k, v in val.items()}
        if isinstance(val, list):
            return [self._redact_value(item, f"{path}[{idx}]", violations) for idx, item in enumerate(val)]
        return val

    def inspect_request(self, message: dict[str, Any]) -> FirewallDecision:
        """Inspect a client-to-server JSON-RPC request."""
        method = str(message.get("method", "unknown"))
        msg_id = message.get("id")
        params = message.get("params", {})
        tool_name: str | None = None
        violations: list[FirewallViolation] = []

        if method == "tools/call" and isinstance(params, dict):
            tool_name = str(params.get("name", ""))
            if self.allowed_tools is not None and tool_name not in self.allowed_tools:
                violations.append(
                    FirewallViolation(
                        rule_id="FW-006",
                        severity="MEDIUM",
                        message=f"Tool '{tool_name}' is not in the firewall allowlist",
                        field_path="params.name",
                    )
                )

        self._scan_value(params, "params", violations)
        action = "BLOCK" if violations else "ALLOW"
        decision = FirewallDecision(
            action=action,
            direction="request",
            method=method,
            tool_name=tool_name,
            message_id=msg_id,
            violations=violations,
        )
        self._log_decision(decision)
        return decision

    def inspect_response(self, message: dict[str, Any]) -> tuple[FirewallDecision, dict[str, Any]]:
        """Inspect and optionally redact a server-to-client JSON-RPC response."""
        msg_id = message.get("id")
        result = message.get("result")
        violations: list[FirewallViolation] = []

        sanitized_msg = dict(message)
        if result is not None:
            sanitized_msg["result"] = self._redact_value(result, "result", violations)

        has_critical = any(v.rule_id == "FW-001" for v in violations)
        if has_critical:
            action = "BLOCK"
        elif violations:
            action = "REDACT"
        else:
            action = "ALLOW"

        decision = FirewallDecision(
            action=action,
            direction="response",
            method="response",
            message_id=msg_id,
            violations=violations,
        )
        self._log_decision(decision)
        return decision, sanitized_msg

    @staticmethod
    def build_error_response(msg_id: Any, decision: FirewallDecision) -> dict[str, Any]:
        """Build a standard JSON-RPC 2.0 error frame when a request or response is blocked."""
        reasons = "; ".join(f"[{v.rule_id}] {v.message} ({v.field_path})" for v in decision.violations)
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "error": {
                "code": -32001,
                "message": f"Blocked by SkillForge MCP Firewall: {reasons}",
            },
        }

    def audit_stream(self, lines: Iterable[str]) -> FirewallAuditSummary:
        """Inspect a stream of JSONL JSON-RPC messages and return an audit summary."""
        decisions: list[FirewallDecision] = []
        allowed = 0
        blocked = 0
        redacted = 0

        for raw_line in lines:
            stripped = raw_line.strip()
            if not stripped:
                continue
            try:
                payload = json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise SkillForgeError(f"Invalid JSON-RPC line in stream: {exc}") from exc

            if not isinstance(payload, dict):
                continue

            if "method" in payload:
                decision = self.inspect_request(payload)
            else:
                decision, _ = self.inspect_response(payload)

            decisions.append(decision)
            if decision.action == "ALLOW":
                allowed += 1
            elif decision.action == "BLOCK":
                blocked += 1
            elif decision.action == "REDACT":
                redacted += 1

        return FirewallAuditSummary(
            total_messages=len(decisions),
            allowed_count=allowed,
            blocked_count=blocked,
            redacted_count=redacted,
            decisions=decisions,
        )

    def run_stdio_proxy(self, command: list[str]) -> int:
        """Spawn an upstream MCP server and proxy stdio through the firewall."""
        if not command:
            raise SkillForgeError("No upstream MCP server command specified.")

        proc = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=sys.stderr,
            text=True,
            bufsize=1,
        )

        stdout_lock = threading.Lock()

        def _forward_server_stdout() -> None:
            assert proc.stdout is not None
            for line in proc.stdout:
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    msg = json.loads(stripped)
                    if isinstance(msg, dict) and "result" in msg:
                        decision, sanitized = self.inspect_response(msg)
                        if decision.action == "BLOCK":
                            err_frame = self.build_error_response(msg.get("id"), decision)
                            out_str = json.dumps(err_frame)
                        else:
                            out_str = json.dumps(sanitized)
                    else:
                        out_str = stripped
                except Exception:
                    out_str = stripped

                with stdout_lock:
                    sys.stdout.write(out_str + "\n")
                    sys.stdout.flush()

        reader_thread = threading.Thread(target=_forward_server_stdout, daemon=True)
        reader_thread.start()

        try:
            for client_line in sys.stdin:
                stripped = client_line.strip()
                if not stripped:
                    continue
                try:
                    msg = json.loads(stripped)
                except Exception:
                    continue

                if isinstance(msg, dict) and "method" in msg:
                    decision = self.inspect_request(msg)
                    if decision.action == "BLOCK":
                        if msg.get("id") is not None:
                            err_frame = self.build_error_response(msg.get("id"), decision)
                            with stdout_lock:
                                sys.stdout.write(json.dumps(err_frame) + "\n")
                                sys.stdout.flush()
                        continue

                if proc.stdin:
                    proc.stdin.write(stripped + "\n")
                    proc.stdin.flush()
        except KeyboardInterrupt:
            pass
        finally:
            if proc.stdin:
                proc.stdin.close()
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()

        return proc.returncode or 0

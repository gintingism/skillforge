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

        # FW-008: Inspect incoming MCP Event notifications (SEP-3415) for indirect prompt injection
        if method in ("notifications/events", "notifications/tasks", "subscriptions/listen") and isinstance(params, dict):
            ev_violations: list[FirewallViolation] = []
            self._scan_value(params, "params", ev_violations)
            for v in ev_violations:
                violations.append(
                    FirewallViolation(
                        rule_id="FW-008" if v.rule_id == "FW-001" else v.rule_id,
                        severity=v.severity,
                        message=f"MCP Event payload violation ({method}): {v.message}",
                        field_path=v.field_path,
                    )
                )
        else:
            self._scan_value(params, "params", violations)

        # FW-009: Inspect x-mcp-file / uploadUrl arguments for non-TLS, SSRF, or cross-origin credential forwarding
        if isinstance(params, dict):
            self._scan_file_upload_params(params, "params", violations)

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

    def _scan_file_upload_params(self, val: Any, path: str, violations: list[FirewallViolation]) -> None:
        if isinstance(val, dict):
            if val.get("forwardCredentials") is True:
                violations.append(
                    FirewallViolation(
                        rule_id="FW-009",
                        severity="CRITICAL",
                        message="MCP File Upload attempts cross-origin credential forwarding (forwardCredentials=true)",
                        field_path=f"{path}.forwardCredentials",
                    )
                )
            for key in ("uploadUrl", "downloadUrl"):
                raw_url = val.get(key)
                if isinstance(raw_url, str) and raw_url.strip():
                    low = raw_url.strip().lower()
                    if _SSRF_TARGETS.search(low) or low.startswith(("http://10.", "http://192.168.", "http://172.16.")):
                        violations.append(
                            FirewallViolation(
                                rule_id="FW-009",
                                severity="CRITICAL",
                                message=f"MCP File Upload {key} targets private or cloud metadata endpoint (SSRF)",
                                field_path=f"{path}.{key}",
                            )
                        )
                    elif low.startswith("http://") and not low.startswith(("http://localhost", "http://127.0.0.1")):
                        violations.append(
                            FirewallViolation(
                                rule_id="FW-009",
                                severity="HIGH",
                                message=f"MCP File Upload {key} uses unencrypted HTTP on a remote host",
                                field_path=f"{path}.{key}",
                            )
                        )
            for k, v in val.items():
                self._scan_file_upload_params(v, f"{path}.{k}", violations)
        elif isinstance(val, list):
            for idx, item in enumerate(val):
                self._scan_file_upload_params(item, f"{path}[{idx}]", violations)

    def inspect_response(self, message: dict[str, Any]) -> tuple[FirewallDecision, dict[str, Any]]:
        """Inspect and optionally redact a server-to-client JSON-RPC response."""
        msg_id = message.get("id")
        result = message.get("result")
        violations: list[FirewallViolation] = []

        sanitized_msg = dict(message)
        if result is not None:
            # FW-007: Inspect MCP Tasks statusMessage and inputRequests elicitation payloads (SEP-2663/3570)
            if isinstance(result, dict):
                task_objs: list[tuple[str, dict[str, Any]]] = [("result", result)]
                if isinstance(result.get("task"), dict):
                    task_objs.append(("result.task", result["task"]))
                for prefix, tobj in task_objs:
                    status_msg = tobj.get("statusMessage")
                    if isinstance(status_msg, str) and (_INVISIBLE_UNICODE.search(status_msg) or _PROMPT_INJECTION.search(status_msg)):
                        violations.append(
                            FirewallViolation(
                                rule_id="FW-007",
                                severity="CRITICAL",
                                message="Indirect prompt injection detected in MCP Task statusMessage",
                                field_path=f"{prefix}.statusMessage",
                            )
                        )
                    input_reqs = tobj.get("inputRequests")
                    if isinstance(input_reqs, (dict, list)):
                        raw_reqs = json.dumps(input_reqs)
                        if re.search(r"(?i)\b(?:password|api[_-]?key|secret|private[_-]?key|bearer\s+token)\b", raw_reqs):
                            violations.append(
                                FirewallViolation(
                                    rule_id="FW-007",
                                    severity="CRITICAL",
                                    message="MCP Task inputRequests elicitation attempts to harvest user credentials/secrets",
                                    field_path=f"{prefix}.inputRequests",
                                )
                            )
                self._scan_file_upload_params(result, "result", violations)

            sanitized_msg["result"] = self._redact_value(result, "result", violations)

        has_critical = any(v.rule_id in ("FW-001", "FW-007", "FW-008", "FW-009") for v in violations)
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

    def inspect_http_request(
        self,
        headers: dict[str, str],
        body_bytes: bytes,
    ) -> tuple[FirewallDecision, dict[str, Any] | None]:
        """Inspect a stateless MCP 2026-07-28 HTTP JSON-RPC request and routing headers."""
        norm_headers = {k.lower(): v for k, v in headers.items()}
        hdr_method = norm_headers.get("mcp-method", "").strip()
        hdr_name = norm_headers.get("mcp-name", "").strip()

        try:
            payload = json.loads(body_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            decision = FirewallDecision(
                action="BLOCK",
                direction="request",
                method=hdr_method or "unknown",
                tool_name=hdr_name or None,
                violations=[
                    FirewallViolation(
                        rule_id="FW-001",
                        severity="HIGH",
                        message=f"Malformed JSON-RPC HTTP request body: {exc}",
                        field_path="body",
                    )
                ],
            )
            self._log_decision(decision)
            return decision, None

        if not isinstance(payload, dict):
            decision = FirewallDecision(
                action="BLOCK",
                direction="request",
                method=hdr_method or "unknown",
                violations=[
                    FirewallViolation(
                        rule_id="FW-001",
                        severity="HIGH",
                        message="JSON-RPC HTTP body must be an object",
                        field_path="body",
                    )
                ],
            )
            self._log_decision(decision)
            return decision, None

        decision = self.inspect_request(payload)

        # Enforce consistency between MCP 2026-07-28 routing headers and JSON-RPC body
        body_method = str(payload.get("method", ""))
        if hdr_method and body_method and hdr_method != body_method:
            decision.violations.append(
                FirewallViolation(
                    rule_id="FW-006",
                    severity="HIGH",
                    message=f"Mcp-Method header '{hdr_method}' mismatches JSON-RPC method '{body_method}' (header smuggling)",
                    field_path="headers.Mcp-Method",
                )
            )
            decision.action = "BLOCK"

        task_methods = ("tasks/get", "tasks/update", "tasks/cancel")
        if body_method in task_methods:
            params_obj = payload.get("params")
            body_task_id = str(params_obj.get("taskId", "")) if isinstance(params_obj, dict) else ""
            if hdr_name and body_task_id and hdr_name != body_task_id:
                decision.violations.append(
                    FirewallViolation(
                        rule_id="FW-007",
                        severity="HIGH",
                        message=f"Mcp-Name task routing header '{hdr_name}' mismatches params.taskId '{body_task_id}'",
                        field_path="headers.Mcp-Name",
                    )
                )
                decision.action = "BLOCK"
        elif hdr_name and self.allowed_tools is not None and hdr_name not in self.allowed_tools:
            if not any(v.rule_id == "FW-006" and v.field_path == "params.name" for v in decision.violations):
                decision.violations.append(
                    FirewallViolation(
                        rule_id="FW-006",
                        severity="MEDIUM",
                        message=f"Header Mcp-Name '{hdr_name}' is not in firewall allowlist",
                        field_path="headers.Mcp-Name",
                    )
                )
                decision.action = "BLOCK"

        return decision, payload

    def create_http_proxy_server(
        self,
        upstream_url: str,
        *,
        host: str = "127.0.0.1",
        port: int = 8787,
        timeout: float = 15.0,
    ) -> Any:
        """Build a stdlib ThreadingHTTPServer proxying MCP Streamable-HTTP traffic through the firewall."""
        import urllib.error
        import urllib.request
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        firewall = self

        class _MCPProxyHandler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
                return

            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(length) if length > 0 else b""
                req_headers = {k: v for k, v in self.headers.items()}
                decision, parsed = firewall.inspect_http_request(req_headers, body)
                if decision.action == "BLOCK":
                    err_frame = firewall.build_error_response(
                        parsed.get("id") if isinstance(parsed, dict) else None,
                        decision,
                    )
                    out_bytes = json.dumps(err_frame).encode("utf-8")
                    self.send_response(403)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(out_bytes)))
                    self.end_headers()
                    self.wfile.write(out_bytes)
                    return

                fwd_headers = {
                    k: v
                    for k, v in req_headers.items()
                    if k.lower() not in ("host", "content-length", "connection")
                }
                req = urllib.request.Request(upstream_url, data=body, headers=fwd_headers, method="POST")
                try:
                    with urllib.request.urlopen(req, timeout=timeout) as resp:
                        raw_resp = resp.read()
                        status_code = resp.status
                except urllib.error.HTTPError as exc:
                    raw_resp = exc.read()
                    status_code = exc.code
                except (urllib.error.URLError, OSError) as exc:
                    err_bytes = json.dumps(
                        {"jsonrpc": "2.0", "id": None, "error": {"code": -32002, "message": f"Upstream MCP unreachable: {exc}"}}
                    ).encode("utf-8")
                    self.send_response(502)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(err_bytes)))
                    self.end_headers()
                    self.wfile.write(err_bytes)
                    return

                out_bytes = raw_resp
                try:
                    resp_obj = json.loads(raw_resp.decode("utf-8"))
                    if isinstance(resp_obj, dict) and "result" in resp_obj:
                        resp_dec, sanitized = firewall.inspect_response(resp_obj)
                        if resp_dec.action == "BLOCK":
                            out_bytes = json.dumps(firewall.build_error_response(resp_obj.get("id"), resp_dec)).encode("utf-8")
                            status_code = 403
                        else:
                            out_bytes = json.dumps(sanitized).encode("utf-8")
                except (UnicodeDecodeError, json.JSONDecodeError):
                    pass

                self.send_response(status_code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(out_bytes)))
                self.end_headers()
                self.wfile.write(out_bytes)

        return ThreadingHTTPServer((host, port), _MCPProxyHandler)

    def run_http_proxy(self, upstream_url: str, *, host: str = "127.0.0.1", port: int = 8787) -> int:
        """Run the blocking Streamable-HTTP MCP security firewall proxy."""
        server = self.create_http_proxy_server(upstream_url, host=host, port=port)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            server.server_close()
        return 0


def wrap_mcp_config(config_path: Path, output_path: Path | None = None) -> dict[str, Any]:
    """Wrap stdio mcpServers entries in an mcp.json config with skillforge firewall-mcp."""
    if not config_path.is_file():
        raise SkillForgeError(f"MCP config not found: {config_path}")

    try:
        data = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SkillForgeError(f"Invalid MCP config JSON {config_path}: {exc}") from exc

    if not isinstance(data, dict) or not isinstance(data.get("mcpServers"), dict):
        raise SkillForgeError(f"MCP config {config_path} must contain a 'mcpServers' object")

    wrapped_count = 0
    for server_cfg in data["mcpServers"].values():
        if not isinstance(server_cfg, dict):
            continue
        command = server_cfg.get("command")
        if not isinstance(command, str) or not command.strip():
            continue
        args = server_cfg.get("args") or []
        if not isinstance(args, list):
            continue
        if command == "skillforge" and "firewall-mcp" in args:
            continue

        server_cfg["command"] = "skillforge"
        server_cfg["args"] = ["firewall-mcp", "--", command, *[str(a) for a in args]]
        wrapped_count += 1

    target = output_path or config_path
    target.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return {"config": str(target), "wrapped_servers": wrapped_count}

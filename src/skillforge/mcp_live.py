"""Live MCP server introspection, MCP Apps (ui://) auditing, and MCP Server Card inspection.

Supports read-only live discovery of tools/prompts/resources from stdio or stateless HTTP
MCP servers, plus security auditing for MCP Apps iframe resources (MCP-011) and Server Cards.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .errors import SecurityAuditError
from .security import AuditFinding, AuditReport, Severity

_UNSAFE_CSP_RE = re.compile(
    r"(?i)(?:unsafe-inline|unsafe-eval|connect-src\s+[^;]*\*|script-src\s+[^;]*\*|frame-ancestors\s+[^;]*\*)"
)
_WILDCARD_POSTMESSAGE_RE = re.compile(r"(?i)postMessage\s*\([^)]*,\s*['\"]\*['\"]\s*\)")
_INLINE_SCRIPT_EXFIL_RE = re.compile(
    r"(?i)(?:<\s*script\b[^>]*>.*?(?:fetch\s*\(|XMLHttpRequest|document\.cookie|localStorage|eval\s*\()|"
    r"<\s*form\b[^>]*action\s*=\s*['\"]https?://[^>]*>.*?type\s*=\s*['\"]password['\"])",
    re.DOTALL,
)
_POISON_RE = re.compile(
    r"(?i)(?:ignore\s+(?:all\s+)?(?:previous|prior)\s+instructions|<\s*IMPORTANT\b|"
    r"do\s+not\s+mention|without\s+telling\s+the\s+user|~/.ssh|~/.aws|[\u200b-\u200f\u202a-\u202e\ufeff])"
)


@dataclass
class LiveMCPDiscovery:
    """Result of probing a live stdio or HTTP MCP server."""

    server_name: str
    transport: str
    reachable: bool
    tools: list[dict[str, Any]] = field(default_factory=list)
    prompts: list[dict[str, Any]] = field(default_factory=list)
    resources: list[dict[str, Any]] = field(default_factory=list)
    server_info: dict[str, Any] = field(default_factory=dict)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "server_name": self.server_name,
            "transport": self.transport,
            "reachable": self.reachable,
            "tools": self.tools,
            "prompts": self.prompts,
            "resources": self.resources,
            "server_info": self.server_info,
            "error": self.error,
        }


def _read_jsonrpc_response(stdout_lines: list[str], target_id: int) -> dict[str, Any] | None:
    for line in stdout_lines:
        stripped = line.strip()
        if not stripped:
            continue
        try:
            obj = json.loads(stripped)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict) and obj.get("id") == target_id:
            return obj
    return None


def probe_stdio_mcp_server(
    server_name: str,
    command: str,
    args: list[str] | None = None,
    env: dict[str, str] | None = None,
    *,
    timeout: float = 5.0,
) -> LiveMCPDiscovery:
    """Probe a stdio MCP server in read-only mode to fetch live tools/prompts/resources."""
    cmd = [command, *(args or [])]
    proc_env = dict(os.environ)
    if env:
        proc_env.update({str(k): str(v) for k, v in env.items()})

    requests_payload = "\n".join(
        json.dumps(frame)
        for frame in (
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2026-07-28",
                    "capabilities": {},
                    "clientInfo": {"name": "skillforge-auditor", "version": "0.10.0"},
                },
            },
            {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            {"jsonrpc": "2.0", "id": 3, "method": "prompts/list", "params": {}},
            {"jsonrpc": "2.0", "id": 4, "method": "resources/list", "params": {}},
        )
    ) + "\n"

    try:
        proc = subprocess.run(
            cmd,
            input=requests_payload,
            capture_output=True,
            text=True,
            env=proc_env,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return LiveMCPDiscovery(
            server_name=server_name,
            transport="stdio",
            reachable=False,
            error=f"Live stdio probe failed: {exc}",
        )

    lines = proc.stdout.splitlines()
    init_resp = _read_jsonrpc_response(lines, 1)
    tools_resp = _read_jsonrpc_response(lines, 2)
    prompts_resp = _read_jsonrpc_response(lines, 3)
    resources_resp = _read_jsonrpc_response(lines, 4)

    tools = (
        tools_resp.get("result", {}).get("tools", [])
        if isinstance(tools_resp, dict) and isinstance(tools_resp.get("result"), dict)
        else []
    )
    prompts = (
        prompts_resp.get("result", {}).get("prompts", [])
        if isinstance(prompts_resp, dict) and isinstance(prompts_resp.get("result"), dict)
        else []
    )
    resources = (
        resources_resp.get("result", {}).get("resources", [])
        if isinstance(resources_resp, dict) and isinstance(resources_resp.get("result"), dict)
        else []
    )
    server_info = (
        init_resp.get("result", {}).get("serverInfo", {})
        if isinstance(init_resp, dict) and isinstance(init_resp.get("result"), dict)
        else {}
    )

    reachable = any(resp is not None for resp in (init_resp, tools_resp, prompts_resp, resources_resp))
    return LiveMCPDiscovery(
        server_name=server_name,
        transport="stdio",
        reachable=reachable,
        tools=[t for t in tools if isinstance(t, dict)],
        prompts=[p for p in prompts if isinstance(p, dict)],
        resources=[r for r in resources if isinstance(r, dict)],
        server_info=server_info if isinstance(server_info, dict) else {},
        error=None if reachable else (proc.stderr.strip()[:200] or "No valid JSON-RPC response received"),
    )


def probe_http_mcp_server(
    server_name: str,
    url: str,
    headers: dict[str, str] | None = None,
    *,
    timeout: float = 5.0,
) -> LiveMCPDiscovery:
    """Probe a stateless MCP 2026-07-28 HTTP server via POST JSON-RPC."""
    base_headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "MCP-Protocol-Version": "2026-07-28",
    }
    if headers:
        for k, v in headers.items():
            if not v.strip().startswith("${"):
                base_headers[k] = v

    def _call(method: str, req_id: int) -> dict[str, Any] | None:
        req_headers = dict(base_headers)
        req_headers["Mcp-Method"] = method
        payload = json.dumps({"jsonrpc": "2.0", "id": req_id, "method": method, "params": {}}).encode("utf-8")
        req = urllib.request.Request(url, data=payload, headers=req_headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
            parsed = json.loads(raw)
            return parsed if isinstance(parsed, dict) else None
        except (urllib.error.URLError, OSError, json.JSONDecodeError):
            return None

    tools_resp = _call("tools/list", 1)
    prompts_resp = _call("prompts/list", 2)
    resources_resp = _call("resources/list", 3)

    reachable = any(r is not None for r in (tools_resp, prompts_resp, resources_resp))
    tools = (
        tools_resp.get("result", {}).get("tools", [])
        if isinstance(tools_resp, dict) and isinstance(tools_resp.get("result"), dict)
        else []
    )
    prompts = (
        prompts_resp.get("result", {}).get("prompts", [])
        if isinstance(prompts_resp, dict) and isinstance(prompts_resp.get("result"), dict)
        else []
    )
    resources = (
        resources_resp.get("result", {}).get("resources", [])
        if isinstance(resources_resp, dict) and isinstance(resources_resp.get("result"), dict)
        else []
    )
    return LiveMCPDiscovery(
        server_name=server_name,
        transport="streamable-http",
        reachable=reachable,
        tools=[t for t in tools if isinstance(t, dict)],
        prompts=[p for p in prompts if isinstance(p, dict)],
        resources=[r for r in resources if isinstance(r, dict)],
        error=None if reachable else f"Unable to reach HTTP MCP server at {url}",
    )


def audit_mcp_app_resource(
    uri: str,
    *,
    html: str = "",
    csp: str = "",
    sandbox_flags: str | list[str] | None = None,
    source_label: str = "mcp-app",
) -> list[AuditFinding]:
    """Audit an MCP Apps ui:// interactive iframe resource for XSS, CSP, and postMessage flaws (MCP-011)."""
    findings: list[AuditFinding] = []
    file_label = f"{source_label}::{uri}"

    if csp and _UNSAFE_CSP_RE.search(csp):
        findings.append(
            AuditFinding(
                rule_id="MCP-011",
                severity=Severity.HIGH,
                message=f"Unsafe CSP directive in MCP App '{uri}' permits unsafe-inline/unsafe-eval or wildcard origins",
                file=file_label,
                snippet=csp[:100],
            )
        )

    if sandbox_flags is not None:
        flags_str = " ".join(sandbox_flags) if isinstance(sandbox_flags, list) else str(sandbox_flags)
        if "allow-same-origin" in flags_str and "allow-scripts" in flags_str:
            findings.append(
                AuditFinding(
                    rule_id="MCP-011",
                    severity=Severity.CRITICAL,
                    message=(
                        f"MCP App '{uri}' combines 'allow-scripts' and 'allow-same-origin' iframe sandbox flags, "
                        "allowing sandbox escape"
                    ),
                    file=file_label,
                    snippet=flags_str[:100],
                )
            )

    if html:
        if _WILDCARD_POSTMESSAGE_RE.search(html):
            findings.append(
                AuditFinding(
                    rule_id="MCP-011",
                    severity=Severity.HIGH,
                    message=f"MCP App '{uri}' uses wildcard targetOrigin '*' in postMessage()",
                    file=file_label,
                )
            )
        if _INLINE_SCRIPT_EXFIL_RE.search(html):
            findings.append(
                AuditFinding(
                    rule_id="MCP-011",
                    severity=Severity.CRITICAL,
                    message=f"MCP App '{uri}' contains suspicious inline script exfiltration or password phishing form",
                    file=file_label,
                )
            )
        if _POISON_RE.search(html):
            findings.append(
                AuditFinding(
                    rule_id="MCP-005",
                    severity=Severity.CRITICAL,
                    message=f"Prompt injection or hidden unicode detected inside MCP App '{uri}' HTML content",
                    file=file_label,
                )
            )

    return findings


def audit_mcp_server_card(card_path_or_data: Path | dict[str, Any], *, target_name: str = "server-card.json") -> AuditReport:
    """Audit an MCP Server Card (/.well-known/mcp/server-card.json) for transport, auth, poisoning, and MCP Apps risks."""
    if isinstance(card_path_or_data, Path):
        if not card_path_or_data.is_file():
            raise SecurityAuditError(f"MCP Server Card not found: {card_path_or_data}")
        target_name = card_path_or_data.name
        try:
            data = json.loads(card_path_or_data.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise SecurityAuditError(f"Invalid MCP Server Card JSON: {exc}") from exc
    else:
        data = card_path_or_data

    if not isinstance(data, dict):
        raise SecurityAuditError("MCP Server Card root must be a JSON object")

    findings: list[AuditFinding] = []
    server_name = str(data.get("name", target_name))
    endpoint = str(data.get("endpoint", data.get("url", ""))).strip()
    if endpoint:
        parsed = urlparse(endpoint)
        host = (parsed.hostname or "").lower()
        if (parsed.scheme or "").lower() in ("http", "ws") and host not in ("localhost", "127.0.0.1", "::1"):
            findings.append(
                AuditFinding(
                    rule_id="MCP-009",
                    severity=Severity.HIGH,
                    message=f"MCP Server Card '{server_name}' declares unencrypted endpoint '{endpoint}'",
                    file=target_name,
                    snippet=endpoint,
                )
            )

    desc = str(data.get("description", ""))
    if desc and _POISON_RE.search(desc):
        findings.append(
            AuditFinding(
                rule_id="MCP-005",
                severity=Severity.CRITICAL,
                message=f"Prompt poisoning detected in MCP Server Card '{server_name}' description",
                file=target_name,
                snippet=desc[:90],
            )
        )

    for tool in data.get("tools", []) if isinstance(data.get("tools"), list) else []:
        if not isinstance(tool, dict):
            continue
        t_name = str(tool.get("name", "unnamed"))
        t_desc = str(tool.get("description", ""))
        if _POISON_RE.search(t_desc):
            findings.append(
                AuditFinding(
                    rule_id="MCP-005",
                    severity=Severity.CRITICAL,
                    message=f"Tool poisoning detected in Server Card tool '{t_name}'",
                    file=f"{target_name}::{t_name}",
                    snippet=t_desc[:90],
                )
            )
        meta = tool.get("_meta", {})
        if isinstance(meta, dict) and isinstance(meta.get("ui"), dict):
            ui_meta = meta["ui"]
            ui_uri = str(ui_meta.get("resourceUri", ""))
            if ui_uri.startswith("ui://"):
                findings.extend(
                    audit_mcp_app_resource(
                        ui_uri,
                        html=str(ui_meta.get("html", "")),
                        csp=str(ui_meta.get("csp", "")),
                        sandbox_flags=ui_meta.get("sandbox"),
                        source_label=target_name,
                    )
                )

    for res in data.get("resources", []) if isinstance(data.get("resources"), list) else []:
        if not isinstance(res, dict):
            continue
        res_uri = str(res.get("uri", ""))
        if res_uri.startswith("ui://"):
            findings.extend(
                audit_mcp_app_resource(
                    res_uri,
                    html=str(res.get("text", res.get("html", ""))),
                    csp=str(res.get("csp", "")),
                    sandbox_flags=res.get("sandbox"),
                    source_label=target_name,
                )
            )

    findings.extend(audit_mcp_extensions_config(server_name, data, file_label=target_name))

    return AuditReport(target=target_name, findings=findings)


_PRIVATE_OR_META_HOSTS = (
    "169.254.169.254",
    "metadata.google.internal",
    "10.",
    "192.168.",
    "172.16.",
    "172.17.",
    "172.18.",
    "172.19.",
    "172.20.",
    "172.21.",
    "172.22.",
    "172.23.",
    "172.24.",
    "172.25.",
    "172.26.",
    "172.27.",
    "172.28.",
    "172.29.",
    "172.30.",
    "172.31.",
)


def _is_unsafe_upload_url(upload_url: str, server_endpoint: str = "") -> tuple[str | None, Severity]:
    """Check an MCP File Upload destination URL for non-TLS, SSRF, or cross-origin credential risks."""
    parsed = urlparse(upload_url.strip())
    scheme = (parsed.scheme or "").lower()
    host = (parsed.hostname or "").lower()
    if not scheme or not host:
        return None, Severity.INFO
    if host in ("169.254.169.254", "metadata.google.internal") or any(
        host.startswith(prefix) for prefix in _PRIVATE_OR_META_HOSTS[2:]
    ):
        return f"Upload target '{upload_url}' points to a private or cloud metadata address (SSRF risk)", Severity.CRITICAL
    if scheme in ("http", "ws") and host not in ("localhost", "127.0.0.1", "::1"):
        return f"Upload target '{upload_url}' uses unencrypted HTTP on a remote host (require HTTPS)", Severity.HIGH
    if server_endpoint:
        srv_host = (urlparse(server_endpoint).hostname or "").lower()
        if srv_host and host != srv_host and host not in ("localhost", "127.0.0.1", "::1"):
            return (
                f"Upload target host '{host}' differs from MCP server origin '{srv_host}'; "
                "ensure MCP credentials are not forwarded across origins",
                Severity.MEDIUM,
            )
    return None, Severity.INFO


def audit_mcp_extensions_config(
    server_name: str,
    server_cfg: dict[str, Any],
    *,
    file_label: str = "mcp.json",
) -> list[AuditFinding]:
    """Audit MCP Tasks (MCP-012), MCP Events (MCP-013), and MCP File Uploads (MCP-014) config blocks."""
    findings: list[AuditFinding] = []
    caps = server_cfg.get("capabilities", {})
    caps_map = caps if isinstance(caps, dict) else {}
    ext_map = caps_map.get("extensions", {}) if isinstance(caps_map.get("extensions"), dict) else {}
    server_endpoint = str(server_cfg.get("url", server_cfg.get("endpoint", ""))).strip()

    # MCP-012: MCP Tasks (SEP-2663 / SEP-3570)
    tasks_cfg = caps_map.get("tasks") or ext_map.get("io.modelcontextprotocol/tasks") or server_cfg.get("tasks")
    if isinstance(tasks_cfg, dict):
        if "list" in tasks_cfg and tasks_cfg.get("list") is not False:
            findings.append(
                AuditFinding(
                    rule_id="MCP-012",
                    severity=Severity.HIGH,
                    message=(
                        f"MCP server '{server_name}' exposes deprecated 'tasks/list' capability; "
                        "removed in 2026-07-28 SEP-2663 due to cross-tenant task metadata leakage"
                    ),
                    file=file_label,
                    snippet="capabilities.tasks.list",
                )
            )
        ttl_present = "ttl" in tasks_cfg or "ttlMs" in tasks_cfg or "maxTtlMs" in tasks_cfg
        ttl_val = tasks_cfg.get("maxTtlMs", tasks_cfg.get("ttlMs", tasks_cfg.get("ttl")))
        if ttl_present and (ttl_val is None or (isinstance(ttl_val, (int, float)) and ttl_val <= 0)):
            findings.append(
                AuditFinding(
                    rule_id="MCP-012",
                    severity=Severity.HIGH,
                    message=(
                        f"MCP server '{server_name}' configures unlimited task TTL ({ttl_val!r}); "
                        "cap maxTtlMs to prevent abandoned-task resource exhaustion and stale result retention"
                    ),
                    file=file_label,
                    snippet=f"ttl={ttl_val!r}",
                )
            )
        id_strategy = str(tasks_cfg.get("taskIdStrategy", tasks_cfg.get("idStrategy", ""))).lower()
        if id_strategy in ("sequential", "increment", "timestamp", "hash"):
            findings.append(
                AuditFinding(
                    rule_id="MCP-012",
                    severity=Severity.CRITICAL,
                    message=(
                        f"MCP server '{server_name}' uses predictable taskIdStrategy '{id_strategy}'; "
                        "task IDs act as bearer capabilities and require >=128-bit CSPRNG entropy"
                    ),
                    file=file_label,
                    snippet=f"taskIdStrategy: {id_strategy}",
                )
            )

    # MCP-013: MCP Events (SEP-3415, io.modelcontextprotocol/events)
    events_cfg = caps_map.get("events") or ext_map.get("io.modelcontextprotocol/events") or server_cfg.get("events")
    if isinstance(events_cfg, dict):
        webhook_url = str(events_cfg.get("webhookUrl", events_cfg.get("endpoint", ""))).strip()
        if webhook_url:
            parsed_ev = urlparse(webhook_url)
            ev_host = (parsed_ev.hostname or "").lower()
            if (parsed_ev.scheme or "").lower() in ("http", "ws") and ev_host not in ("localhost", "127.0.0.1", "::1"):
                findings.append(
                    AuditFinding(
                        rule_id="MCP-013",
                        severity=Severity.HIGH,
                        message=f"MCP Events server '{server_name}' uses unencrypted event endpoint '{webhook_url}'",
                        file=file_label,
                        snippet=webhook_url[:90],
                    )
                )
        if events_cfg.get("requireAuth") is False or events_cfg.get("verifySignature") is False:
            findings.append(
                AuditFinding(
                    rule_id="MCP-013",
                    severity=Severity.HIGH,
                    message=(
                        f"MCP Events server '{server_name}' disables event authentication or signature verification "
                        "(allows spoofed upstream events / indirect prompt injection)"
                    ),
                    file=file_label,
                )
            )

    # MCP-014: MCP File Uploads (io.modelcontextprotocol/files, x-mcp-file)
    files_cfg = ext_map.get("io.modelcontextprotocol/files") or server_cfg.get("files")
    if isinstance(files_cfg, dict):
        if files_cfg.get("forwardCredentials") is True:
            findings.append(
                AuditFinding(
                    rule_id="MCP-014",
                    severity=Severity.CRITICAL,
                    message=(
                        f"MCP File Uploads on '{server_name}' sets forwardCredentials=true; "
                        "never forward MCP Authorization credentials to external upload destinations"
                    ),
                    file=file_label,
                    snippet="forwardCredentials: true",
                )
            )
        upload_url = str(files_cfg.get("uploadUrl", "")).strip()
        if upload_url:
            reason, sev = _is_unsafe_upload_url(upload_url, server_endpoint)
            if reason:
                findings.append(
                    AuditFinding(
                        rule_id="MCP-014",
                        severity=sev,
                        message=f"MCP File Upload on '{server_name}': {reason}",
                        file=file_label,
                        snippet=upload_url[:90],
                    )
                )

    for tool in server_cfg.get("tools", []) if isinstance(server_cfg.get("tools"), list) else []:
        if not isinstance(tool, dict):
            continue
        t_name = str(tool.get("name", "unnamed"))
        schema = tool.get("inputSchema", {})
        if not isinstance(schema, dict):
            continue
        props = schema.get("properties", {})
        if not isinstance(props, dict):
            continue
        for prop_name, prop_def in props.items():
            if not isinstance(prop_def, dict):
                continue
            x_file = prop_def.get("x-mcp-file")
            if isinstance(x_file, dict):
                if x_file.get("forwardCredentials") is True:
                    findings.append(
                        AuditFinding(
                            rule_id="MCP-014",
                            severity=Severity.CRITICAL,
                            message=(
                                f"Tool '{t_name}' parameter '{prop_name}' enables x-mcp-file forwardCredentials=true"
                            ),
                            file=f"{file_label}::{t_name}",
                        )
                    )
                u_url = str(x_file.get("uploadUrl", "")).strip()
                if u_url:
                    reason, sev = _is_unsafe_upload_url(u_url, server_endpoint)
                    if reason:
                        findings.append(
                            AuditFinding(
                                rule_id="MCP-014",
                                severity=sev,
                                message=f"Tool '{t_name}' x-mcp-file parameter '{prop_name}': {reason}",
                                file=f"{file_label}::{t_name}",
                                snippet=u_url[:90],
                            )
                        )

    return findings

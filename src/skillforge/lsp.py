"""Language Server Protocol (LSP) daemon for SKILL.md authoring.

Provides real-time diagnostics, YAML frontmatter validation, security linting,
and completion for Cursor, VS Code, and other LSP-compatible editors.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

import yaml

from skillforge.security import SkillAuditor

LSP_VERSION = "3.17"


class DiagnosticSeverity:
    ERROR = 1
    WARNING = 2
    INFORMATION = 3
    HINT = 4


class SkillLanguageServer:
    """Lightweight stdio Language Server for SKILL.md documents."""

    def __init__(self) -> None:
        self.documents: dict[str, str] = {}
        self.is_shutdown = False
        self.auditor = SkillAuditor()

    def uri_to_path(self, uri: str) -> Path | None:
        """Convert a file:// URI to a local Path object."""
        try:
            parsed = urlparse(uri)
            if parsed.scheme == "file":
                path_str = unquote(parsed.path)
                # On Windows, path may start with /C:/
                if re.match(r"^/[a-zA-Z]:", path_str):
                    path_str = path_str[1:]
                return Path(path_str)
        except Exception:
            pass
        return None

    def diagnose_text(self, text: str, file_path: Path | None = None) -> list[dict[str, Any]]:
        """Compute LSP diagnostics for a SKILL.md document."""
        diagnostics: list[dict[str, Any]] = []
        lines = text.splitlines()

        # 1. Frontmatter Validation
        if not text.startswith("---"):
            diagnostics.append(
                {
                    "range": {
                        "start": {"line": 0, "character": 0},
                        "end": {"line": 0, "character": min(10, len(lines[0]) if lines else 0)},
                    },
                    "severity": DiagnosticSeverity.ERROR,
                    "code": "FMT-001",
                    "source": "skillforge",
                    "message": "Missing required YAML frontmatter opening delimiter (---).",
                }
            )
        else:
            # Find closing delimiter
            closing_idx = -1
            for idx, line in enumerate(lines[1:], start=1):
                if line.strip() == "---":
                    closing_idx = idx
                    break

            if closing_idx == -1:
                diagnostics.append(
                    {
                        "range": {
                            "start": {"line": 0, "character": 0},
                            "end": {"line": 0, "character": 3},
                        },
                        "severity": DiagnosticSeverity.ERROR,
                        "code": "FMT-002",
                        "source": "skillforge",
                        "message": "Unclosed YAML frontmatter. Expected matching '---'.",
                    }
                )
            else:
                fm_raw = "\n".join(lines[1:closing_idx])
                try:
                    meta = yaml.safe_load(fm_raw)
                    if not isinstance(meta, dict):
                        diagnostics.append(
                            {
                                "range": {
                                    "start": {"line": 1, "character": 0},
                                    "end": {"line": closing_idx, "character": 0},
                                },
                                "severity": DiagnosticSeverity.ERROR,
                                "code": "FMT-003",
                                "source": "skillforge",
                                "message": "YAML frontmatter must be a key-value mapping.",
                            }
                        )
                    else:
                        # Required: name
                        if "name" not in meta or not str(meta["name"]).strip():
                            diagnostics.append(
                                {
                                    "range": {
                                        "start": {"line": 0, "character": 0},
                                        "end": {"line": closing_idx, "character": 3},
                                    },
                                    "severity": DiagnosticSeverity.ERROR,
                                    "code": "FMT-004",
                                    "source": "skillforge",
                                    "message": "Required frontmatter field 'name' is missing.",
                                }
                            )
                        elif not re.fullmatch(r"^[a-z0-9][a-z0-9-]*$", str(meta["name"])):
                            diagnostics.append(
                                {
                                    "range": {
                                        "start": {"line": 0, "character": 0},
                                        "end": {"line": closing_idx, "character": 3},
                                    },
                                    "severity": DiagnosticSeverity.WARNING,
                                    "code": "FMT-005",
                                    "source": "skillforge",
                                    "message": f"Skill name '{meta['name']}' should be lowercase kebab-case.",
                                }
                            )

                        # Recommended: description
                        if "description" not in meta or not str(meta["description"]).strip():
                            diagnostics.append(
                                {
                                    "range": {
                                        "start": {"line": 0, "character": 0},
                                        "end": {"line": closing_idx, "character": 3},
                                    },
                                    "severity": DiagnosticSeverity.WARNING,
                                    "code": "FMT-006",
                                    "source": "skillforge",
                                    "message": "Missing recommended frontmatter field 'description'.",
                                }
                            )
                except yaml.YAMLError as y_err:
                    line_no = 1
                    col_no = 0
                    if hasattr(y_err, "problem_mark") and y_err.problem_mark:
                        line_no = y_err.problem_mark.line + 1
                        col_no = y_err.problem_mark.column
                    diagnostics.append(
                        {
                            "range": {
                                "start": {"line": line_no, "character": col_no},
                                "end": {"line": line_no, "character": col_no + 5},
                            },
                            "severity": DiagnosticSeverity.ERROR,
                            "code": "FMT-007",
                            "source": "skillforge",
                            "message": f"Invalid YAML frontmatter: {y_err}",
                        }
                    )

        # 2. Token Budget Warnings
        est_tokens = len(text) // 4
        if est_tokens > 5000:
            diagnostics.append(
                {
                    "range": {
                        "start": {"line": 0, "character": 0},
                        "end": {"line": 0, "character": 1},
                    },
                    "severity": DiagnosticSeverity.WARNING,
                    "code": "TOK-001",
                    "source": "skillforge",
                    "message": f"Skill content exceeds recommended token budget (~{est_tokens} tokens > 5000 limit). Consider progressive disclosure.",
                }
            )

        # 3. Security Checks (Line-by-line linting)
        security_patterns: list[tuple[str, str, int, re.Pattern[str]]] = [
            (
                "SEC-001",
                "Destructive command detected: recursive deletion of root or wildcard directory.",
                DiagnosticSeverity.ERROR,
                re.compile(r"\brm\s+-(?:r[fv]|f[rv]|[rf])\s+(?:/|[~*])", re.IGNORECASE),
            ),
            (
                "SEC-002",
                "Dangerous remote shell execution pipeline (curl/wget piped to shell).",
                DiagnosticSeverity.ERROR,
                re.compile(r"(?:curl|wget)\s+[^\n|]+\|\s*(?:ba|z|sh|python|perl)", re.IGNORECASE),
            ),
            (
                "SEC-003",
                "System tampering: direct modification of /etc/hosts or /etc/resolv.conf.",
                DiagnosticSeverity.ERROR,
                re.compile(r"(?:echo|cat|tee)\b.*>\s*/etc/(?:hosts|resolv\.conf)", re.IGNORECASE),
            ),
            (
                "SEC-004",
                "Prompt injection pattern: instruction to ignore previous constraints.",
                DiagnosticSeverity.WARNING,
                re.compile(r"ignore\s+(?:all\s+)?(?:previous|prior)\s+instructions", re.IGNORECASE),
            ),
            (
                "SEC-005",
                "Sensitive credential or secret key detected in plain text.",
                DiagnosticSeverity.WARNING,
                re.compile(r"(?:api[_-]?key|secret|token)\s*[:=]\s*['\"][A-Za-z0-9_-]{20,}['\"]", re.IGNORECASE),
            ),
            (
                "SEC-013",
                "Memory poisoning attempt: writing to AGENTS.md, CLAUDE.md, or git hooks.",
                DiagnosticSeverity.ERROR,
                re.compile(r"(?:>>?|\btee\b|\bcp\b|\bmv\b).*?(?:AGENTS\.md|CLAUDE\.md|\.cursorrules|\.git/hooks)", re.IGNORECASE),
            ),
            (
                "SEC-015",
                "Obfuscated execution payload detected (base64 decode into shell or eval).",
                DiagnosticSeverity.ERROR,
                re.compile(r"base64\s+-d\s*\|\s*(?:ba|z)?sh|b64decode\(.*?\)\s*\)|\bfrom_base64\b", re.IGNORECASE),
            ),
            (
                "SEC-016",
                "Destructive resource exhaustion pattern detected (fork bomb or disk wiper).",
                DiagnosticSeverity.ERROR,
                re.compile(r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:|dd\s+if=/dev/(?:zero|urandom)\s+of=/dev/[a-z]+", re.IGNORECASE),
            ),
        ]

        for line_idx, line in enumerate(lines):
            for rule_id, desc, sev, pat in security_patterns:
                m = pat.search(line)
                if m:
                    diagnostics.append(
                        {
                            "range": {
                                "start": {"line": line_idx, "character": m.start()},
                                "end": {"line": line_idx, "character": m.end()},
                            },
                            "severity": sev,
                            "code": rule_id,
                            "source": "skillforge",
                            "message": desc,
                        }
                    )

        # 4. Broken Relative References check
        if file_path and file_path.is_file():
            base_dir = file_path.parent
            for line_idx, line in enumerate(lines):
                for match in re.finditer(r"\[([^\]]+)\]\(([^)]+)\)", line):
                    link_target = match.group(2).strip()
                    if link_target.startswith(("http://", "https://", "mailto:", "#")):
                        continue
                    clean_path = link_target.split("#")[0].split("?")[0]
                    if clean_path:
                        target_path = (base_dir / clean_path).resolve()
                        if not target_path.exists():
                            diagnostics.append(
                                {
                                    "range": {
                                        "start": {"line": line_idx, "character": match.start(2)},
                                        "end": {"line": line_idx, "character": match.end(2)},
                                    },
                                    "severity": DiagnosticSeverity.WARNING,
                                    "code": "REF-001",
                                    "source": "skillforge",
                                    "message": f"Referenced local file does not exist: {link_target}",
                                }
                            )

        return diagnostics

    def handle_message(self, message: dict[str, Any]) -> dict[str, Any] | None:
        """Handle a single JSON-RPC message and return response dict if applicable."""
        msg_id = message.get("id")
        method = message.get("method")
        params = message.get("params", {})

        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "capabilities": {
                        "textDocumentSync": 1,  # Full sync
                        "hoverProvider": True,
                        "completionProvider": {
                            "triggerCharacters": [":", " ", "\n", "-"],
                        },
                    },
                    "serverInfo": {
                        "name": "skillforge-lsp",
                        "version": "0.7.0",
                    },
                },
            }

        if method == "initialized":
            return None

        if method == "shutdown":
            self.is_shutdown = True
            return {"jsonrpc": "2.0", "id": msg_id, "result": None}

        if method == "exit":
            return None

        if method == "textDocument/didOpen":
            doc = params.get("textDocument", {})
            uri = doc.get("uri", "")
            text = doc.get("text", "")
            self.documents[uri] = text
            fpath = self.uri_to_path(uri)
            diags = self.diagnose_text(text, fpath)
            return {
                "jsonrpc": "2.0",
                "method": "textDocument/publishDiagnostics",
                "params": {"uri": uri, "diagnostics": diags},
            }

        if method in ("textDocument/didChange", "textDocument/didSave"):
            doc = params.get("textDocument", {})
            uri = doc.get("uri", "")
            changes = params.get("contentChanges", [])
            if changes:
                text = changes[-1].get("text", "")
                self.documents[uri] = text
            else:
                text = self.documents.get(uri, "")
            fpath = self.uri_to_path(uri)
            diags = self.diagnose_text(text, fpath)
            return {
                "jsonrpc": "2.0",
                "method": "textDocument/publishDiagnostics",
                "params": {"uri": uri, "diagnostics": diags},
            }

        if method == "textDocument/didClose":
            doc = params.get("textDocument", {})
            uri = doc.get("uri", "")
            self.documents.pop(uri, None)
            return {
                "jsonrpc": "2.0",
                "method": "textDocument/publishDiagnostics",
                "params": {"uri": uri, "diagnostics": []},
            }

        if method == "textDocument/hover":
            doc = params.get("textDocument", {})
            uri = doc.get("uri", "")
            text = self.documents.get(uri, "")
            tokens = len(text) // 4
            word_count = len(text.split())
            line_count = len(text.splitlines())
            fpath = self.uri_to_path(uri)
            diags = self.diagnose_text(text, fpath)
            err_count = sum(1 for d in diags if d["severity"] == DiagnosticSeverity.ERROR)
            warn_count = sum(1 for d in diags if d["severity"] == DiagnosticSeverity.WARNING)

            info_text = (
                f"**SkillForge Agent Skill Analysis**\n\n"
                f"- **Lines**: {line_count}\n"
                f"- **Words**: {word_count}\n"
                f"- **Estimated Tokens**: {tokens:,}\n"
                f"- **Linter Status**: {err_count} errors, {warn_count} warnings\n"
                f"- **Security Score**: {max(0, 100 - (err_count * 20 + warn_count * 5))}/100"
            )
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "contents": {"kind": "markdown", "value": info_text},
                },
            }

        if method == "textDocument/completion":
            items = [
                {"label": "name", "kind": 10, "detail": "Unique kebab-case name", "insertText": "name: "},
                {"label": "description", "kind": 10, "detail": "Single-sentence role description", "insertText": "description: "},
                {"label": "version", "kind": 10, "detail": "SemVer version (e.g. 1.0.0)", "insertText": "version: 1.0.0\n"},
                {"label": "author", "kind": 10, "detail": "Author or organization", "insertText": "author: "},
                {"label": "tags", "kind": 10, "detail": "Discovery tags", "insertText": "tags:\n  - "},
                {"label": "allowed-tools", "kind": 10, "detail": "List of permitted tools", "insertText": "allowed-tools:\n  - "},
            ]
            return {"jsonrpc": "2.0", "id": msg_id, "result": {"isIncomplete": False, "items": items}}

        # Fallback for unhandled requests that require response
        if msg_id is not None:
            return {"jsonrpc": "2.0", "id": msg_id, "result": None}

        return None

    def run_stdio(self) -> None:
        """Run LSP event loop over standard input and output streams."""
        stdin = sys.stdin.buffer
        stdout = sys.stdout.buffer

        while not self.is_shutdown:
            # Read HTTP headers
            content_length: int | None = None
            while True:
                line = stdin.readline()
                if not line:
                    return
                line_str = line.decode("latin1").strip()
                if not line_str:
                    break
                if line_str.lower().startswith("content-length:"):
                    content_length = int(line_str.split(":", 1)[1].strip())

            if content_length is None or content_length <= 0:
                continue

            body_bytes = stdin.read(content_length)
            if not body_bytes:
                break

            try:
                msg = json.loads(body_bytes.decode("utf-8"))
            except Exception:
                continue

            response = self.handle_message(msg)
            if response is not None:
                resp_bytes = json.dumps(response).encode("utf-8")
                header = f"Content-Length: {len(resp_bytes)}\r\n\r\n".encode("latin1")
                stdout.write(header + resp_bytes)
                stdout.flush()

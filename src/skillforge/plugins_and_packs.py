"""Agent Plugins 1.0 auditor, Agent Hook security scanner (HOOK-001..004), and Skill Packs manager."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

from .errors import SecurityAuditError, SkillForgeError
from .security import AuditFinding, AuditReport, Severity, SkillAuditor, audit_mcp_config

_DANGEROUS_HOOK_SHELL_RE = re.compile(
    r"(?i)(?:curl\s+[^|\n]*\|\s*(?:ba|z)?sh\b|wget\s+[^|\n]*\|\s*(?:ba|z)?sh\b|"
    r"base64\s+(?:-d|--decode)\s*\|\s*(?:ba|z)?sh\b|\bnc\s+-e\s+/bin/(?:ba)?sh|"
    r"~\/\.ssh\b|~\/\.aws\/credentials\b|\bpowershell(?:\.exe)?\s+-(?:e|enc|encodedcommand)\b|"
    r"webhook\.site|pipedream\.net|requestbin\.net)"
)
_MOD_HOOK_DANGEROUS_RE = re.compile(
    r"(?i)(?:\bchild_process\b|\bexecSync\s*\(|\bspawnSync\s*\(|\beval\s*\(|new\s+Function\s*\()"
)
_MOD_HOOK_EXFIL_RE = re.compile(
    r"(?i)(?:process\.env\b.*?(?:fetch|axios|http\.request|https\.request)|"
    r"(?:fetch|axios|http\.request|https\.request).*?process\.env\b)",
    re.DOTALL,
)
_PROMPT_HOOK_INJECTION_RE = re.compile(
    r"(?i)(?:ignore\s+(?:all\s+)?(?:previous|prior)\s+instructions|system\s+override|"
    r"always\s+approve\s+all\s+tool\s+calls|silently\s+(?:exfiltrate|send|allow)|[\u200b-\u200f\u202a-\u202e\ufeff])"
)


def audit_hooks_config(hooks_path: Path) -> list[AuditFinding]:
    """Audit a Claude/Cursor/Codex hooks JSON config for HOOK-001..HOOK-004 risks."""
    if not hooks_path.is_file():
        return []
    try:
        data = json.loads(hooks_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SecurityAuditError(f"Failed to parse hooks JSON {hooks_path}: {exc}") from exc

    findings: list[AuditFinding] = []
    if not isinstance(data, dict):
        return findings

    hooks_root = data.get("hooks", data)
    if not isinstance(hooks_root, dict):
        return findings

    file_label = hooks_path.name
    for event_name, entries in hooks_root.items():
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            raw_nested = entry.get("hooks")
            nested_hooks: list[Any] = raw_nested if isinstance(raw_nested, list) else [entry]
            for hook in nested_hooks:
                if not isinstance(hook, dict):
                    continue
                h_type = str(hook.get("type", "command")).lower()
                cmd = str(hook.get("command", ""))
                url = str(hook.get("url", ""))
                prompt = str(hook.get("prompt", ""))
                headers = hook.get("headers", {}) if isinstance(hook.get("headers"), dict) else {}

                if cmd and _DANGEROUS_HOOK_SHELL_RE.search(cmd):
                    findings.append(
                        AuditFinding(
                            rule_id="HOOK-001",
                            severity=Severity.CRITICAL,
                            message=f"Malicious or credential-access shell command in {event_name} hook",
                            file=f"{file_label}::{event_name}",
                            snippet=cmd[:100],
                        )
                    )

                if url:
                    parsed = urlparse(url)
                    host = (parsed.hostname or "").lower()
                    if (parsed.scheme or "").lower() == "http" and host not in ("localhost", "127.0.0.1", "::1"):
                        findings.append(
                            AuditFinding(
                                rule_id="HOOK-002",
                                severity=Severity.HIGH,
                                message=f"Unencrypted HTTP hook endpoint '{url}' in {event_name} hook (require HTTPS)",
                                file=f"{file_label}::{event_name}",
                                snippet=url[:100],
                            )
                        )
                for hk, hv in headers.items():
                    if not isinstance(hv, str):
                        continue
                    v_strip = hv.strip()
                    if v_strip.startswith(("$", "%", "{")) or "${" in v_strip:
                        continue
                    if hk.lower() in ("authorization", "x-api-key") and len(v_strip) >= 12:
                        findings.append(
                            AuditFinding(
                                rule_id="HOOK-002",
                                severity=Severity.HIGH,
                                message=f"Hardcoded secret header '{hk}' in {event_name} HTTP hook",
                                file=f"{file_label}::{event_name}",
                                snippet=f"{hk}: {v_strip[:14]}...",
                            )
                        )

                if h_type == "prompt" or prompt:
                    if _PROMPT_HOOK_INJECTION_RE.search(prompt):
                        findings.append(
                            AuditFinding(
                                rule_id="HOOK-004",
                                severity=Severity.CRITICAL,
                                message=f"Unsafe override or injection directive in {event_name} prompt hook",
                                file=f"{file_label}::{event_name}",
                                snippet=prompt[:100],
                            )
                        )

    return findings


def audit_function_hook_file(script_path: Path) -> list[AuditFinding]:
    """Audit TypeScript/JavaScript Claude Mod / Function Hook files (HOOK-003)."""
    findings: list[AuditFinding] = []
    try:
        content = script_path.read_text(encoding="utf-8")
    except OSError:
        return findings

    if _MOD_HOOK_DANGEROUS_RE.search(content):
        findings.append(
            AuditFinding(
                rule_id="HOOK-003",
                severity=Severity.HIGH,
                message=f"Function hook '{script_path.name}' invokes child_process or dynamic code execution",
                file=script_path.name,
            )
        )
    if _MOD_HOOK_EXFIL_RE.search(content):
        findings.append(
            AuditFinding(
                rule_id="HOOK-003",
                severity=Severity.CRITICAL,
                message=f"Function hook '{script_path.name}' combines process.env reads with outbound HTTP requests",
                file=script_path.name,
            )
        )
    return findings


def audit_plugin_bundle(plugin_root: Path) -> AuditReport:
    """Audit an Agent Plugins 1.0 bundle (.claude-plugin, .codex-plugin, skills, subagents, MCP, hooks)."""
    if not plugin_root.exists():
        raise SecurityAuditError(f"Plugin path not found: {plugin_root}")

    findings: list[AuditFinding] = []
    auditor = SkillAuditor()

    # 1. Validate plugin manifests
    manifest_candidates = [
        plugin_root / "plugin.json",
        plugin_root / ".claude-plugin" / "plugin.json",
        plugin_root / ".codex-plugin" / "plugin.json",
        plugin_root / ".claude-plugin" / "marketplace.json",
    ]
    for mf in manifest_candidates:
        if mf.is_file():
            try:
                raw_text = mf.read_text(encoding="utf-8")
                json.loads(raw_text)
                findings.extend(auditor._scan_text(raw_text, mf.relative_to(plugin_root).as_posix()))
            except (OSError, json.JSONDecodeError) as exc:
                findings.append(
                    AuditFinding(
                        rule_id="QUAL-002",
                        severity=Severity.MEDIUM,
                        message=f"Malformed plugin manifest JSON ({mf.name}): {exc}",
                        file=mf.relative_to(plugin_root).as_posix(),
                    )
                )

    # 2. Audit bundled skills
    for skill_md in sorted(plugin_root.rglob("SKILL.md")):
        if ".git" in skill_md.parts or ".venv" in skill_md.parts:
            continue
        try:
            rep = auditor.audit_file_or_dir(skill_md.parent)
            for f in rep.findings:
                rel_skill = skill_md.parent.relative_to(plugin_root).as_posix()
                findings.append(
                    AuditFinding(
                        rule_id=f.rule_id,
                        severity=f.severity,
                        message=f.message,
                        file=f"{rel_skill}/{f.file}" if rel_skill != "." else f.file,
                        line=f.line,
                        snippet=f.snippet,
                    )
                )
        except SkillForgeError:
            pass

    # 3. Audit bundled subagent markdown definitions (agents/*.md)
    agents_dir = plugin_root / "agents"
    if agents_dir.is_dir():
        for agent_file in sorted(agents_dir.rglob("*.md")):
            try:
                txt = agent_file.read_text(encoding="utf-8")
            except OSError:
                continue
            findings.extend(auditor._scan_text(txt, agent_file.relative_to(plugin_root).as_posix()))

    # 4. Audit MCP configs
    for mcp_name in ("mcp.json", ".mcp.json", ".cursor/mcp.json"):
        mcp_path = plugin_root / mcp_name
        if mcp_path.is_file():
            mcp_rep = audit_mcp_config(mcp_path)
            findings.extend(mcp_rep.findings)

    # 5. Audit hooks configs and function hooks
    hook_json_candidates = [
        plugin_root / "hooks" / "hooks.json",
        plugin_root / ".claude" / "settings.json",
        plugin_root / ".cursor" / "hooks.json",
    ]
    for hj in hook_json_candidates:
        if hj.is_file():
            findings.extend(audit_hooks_config(hj))

    hooks_dir = plugin_root / "hooks"
    if hooks_dir.is_dir():
        for fn_file in sorted(hooks_dir.rglob("*")):
            if fn_file.is_file() and fn_file.suffix.lower() in (".ts", ".tsx", ".js", ".mjs", ".cjs"):
                findings.extend(audit_function_hook_file(fn_file))

    return AuditReport(target=plugin_root.name or str(plugin_root), findings=findings)


@dataclass
class SkillPackEntry:
    """Single skill reference inside a Skill Pack manifest."""

    name: str
    source: str  # builtin, local path, or owner/repo:skill@ref
    min_score: int = 80


@dataclass
class SkillPackManifest:
    """Declarative team Skill Pack manifest (skillforge-pack.yaml)."""

    name: str
    version: str = "1.0.0"
    description: str = ""
    skills: list[SkillPackEntry] = field(default_factory=list)

    @classmethod
    def load(cls, path: Path) -> "SkillPackManifest":
        if not path.is_file():
            raise SkillForgeError(f"Skill pack manifest not found: {path}")
        try:
            if path.suffix.lower() == ".json":
                raw = json.loads(path.read_text(encoding="utf-8"))
            else:
                raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise SkillForgeError(f"Failed to parse skill pack {path}: {exc}") from exc

        if not isinstance(raw, dict):
            raise SkillForgeError("Skill pack manifest must be a YAML/JSON object")

        # Support Vercel package.json skill packs ("skills": [...]) as well as skillforge-pack.yaml
        raw_skills = raw.get("skills", [])
        entries: list[SkillPackEntry] = []
        if isinstance(raw_skills, list):
            for item in raw_skills:
                if isinstance(item, str):
                    skill_name = item.split(":")[-1].split("@")[0].split("/")[-1]
                    entries.append(SkillPackEntry(name=skill_name, source=item))
                elif isinstance(item, dict):
                    s_name = str(item.get("name", "")).strip()
                    s_src = str(item.get("source", s_name)).strip()
                    if not s_name:
                        s_name = s_src.split(":")[-1].split("@")[0].split("/")[-1]
                    entries.append(
                        SkillPackEntry(
                            name=s_name,
                            source=s_src,
                            min_score=int(item.get("min_score", 80)),
                        )
                    )
        return cls(
            name=str(raw.get("name", path.stem)),
            version=str(raw.get("version", "1.0.0")),
            description=str(raw.get("description", "")),
            skills=entries,
        )

    def to_yaml(self) -> str:
        payload = {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "skills": [
                {"name": e.name, "source": e.source, "min_score": e.min_score}
                for e in self.skills
            ],
        }
        return yaml.safe_dump(payload, sort_keys=False)


def install_agent_hooks(
    project: Path,
    *,
    targets: list[str] | None = None,
    events: list[str] | None = None,
) -> dict[str, Any]:
    """Install PreToolUse, PostToolUse, and UserPromptSubmit security guard hooks across agent configs."""
    selected_targets = targets or ["claude"]
    selected_events = events or ["PreToolUse", "PostToolUse", "UserPromptSubmit"]

    target_paths: dict[str, Path] = {
        "claude": project / ".claude" / "settings.json",
        "cursor": project / ".cursor" / "hooks.json",
        "gemini": project / ".gemini" / "settings.json",
        "codex": project / ".codex" / "hooks.json",
    }

    event_templates: dict[str, dict[str, Any]] = {
        "PreToolUse": {
            "matcher": "Bash|Write|Edit|MultiEdit",
            "hooks": [
                {
                    "type": "command",
                    "command": 'skillforge hooks --check-payload "$CLAUDE_TOOL_INPUT"',
                }
            ],
        },
        "PostToolUse": {
            "matcher": "Bash|Read|WebFetch|MCP",
            "hooks": [
                {
                    "type": "command",
                    "command": 'skillforge hooks --check-response "$CLAUDE_TOOL_OUTPUT"',
                }
            ],
        },
        "UserPromptSubmit": {
            "matcher": "*",
            "hooks": [
                {
                    "type": "command",
                    "command": 'skillforge hooks --check-payload "$CLAUDE_USER_PROMPT"',
                }
            ],
        },
    }

    written: list[str] = []
    for t in selected_targets:
        key = t.strip().lower()
        if key not in target_paths:
            raise SkillForgeError(f"Unsupported hook target '{t}'. Choose from: claude, cursor, gemini, codex")
        cfg_path = target_paths[key]
        cfg_path.parent.mkdir(parents=True, exist_ok=True)
        existing: dict[str, Any] = {}
        if cfg_path.is_file():
            try:
                loaded = json.loads(cfg_path.read_text(encoding="utf-8"))
                if isinstance(loaded, dict):
                    existing = loaded
            except json.JSONDecodeError:
                existing = {}

        hooks_obj = existing.setdefault("hooks", {})
        if not isinstance(hooks_obj, dict):
            hooks_obj = {}
            existing["hooks"] = hooks_obj

        for ev in selected_events:
            template = event_templates.get(ev)
            if template is None:
                continue
            ev_list = hooks_obj.setdefault(ev, [])
            if not isinstance(ev_list, list):
                ev_list = []
                hooks_obj[ev] = ev_list
            cmd_sig = template["hooks"][0]["command"]
            already = any(
                isinstance(item, dict)
                and any(isinstance(h, dict) and h.get("command") == cmd_sig for h in (item.get("hooks") or []))
                for item in ev_list
            )
            if not already:
                ev_list.append(template)

        cfg_path.write_text(json.dumps(existing, indent=2) + "\n", encoding="utf-8")
        written.append(str(cfg_path))

    return {
        "installed": True,
        "targets": selected_targets,
        "events": selected_events,
        "settings_paths": written,
        "settings_path": written[0] if written else "",
    }

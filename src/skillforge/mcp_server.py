"""MCP server exposing the SkillForge registry and security auditing tools."""

from __future__ import annotations

import json
import logging
import os
import sys
import time
from pathlib import Path
from typing import Literal

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

from .errors import SkillForgeError
from .policy import SecurityPolicy, apply_policy
from .registry import BuiltinRegistry, CompositeRegistry, LocalRegistry, Registry
from .security import SkillAuditor, audit_mcp_config as run_audit_mcp_config
from .skill import estimate_tokens, parse_skill
from .telemetry import record_telemetry_event

LOGGER = logging.getLogger("skillforge.mcp")
if not LOGGER.handlers:
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
    LOGGER.addHandler(handler)
    LOGGER.setLevel(logging.INFO)
    LOGGER.propagate = False
    READ_ONLY = ToolAnnotations(
        read_only_hint=True,
        destructive_hint=False,
        idempotent_hint=True,
        open_world_hint=False,
    )
    CHARACTER_LIMIT = 25_000


def create_mcp_server(registry: Registry) -> MCPServer:
    """Create an MCP server bound to a SkillForge registry."""
    server = MCPServer(
        "skillforge_mcp",
        description="Discover, read, validate, and security-audit portable SkillForge skills.",
    )

    @server.tool(name="search_skills", annotations=READ_ONLY)
    def search_skills(query: str, limit: int = 50) -> str:
        """Search skills by name or description."""
        try:
            if limit < 1 or limit > 100:
                return json.dumps({"error": "limit must be between 1 and 100"})
            return json.dumps(
                [
                    {"name": skill.name, "description": skill.description}
                    for skill in registry.search(query)[:limit]
                ]
            )
        except SkillForgeError as exc:
            return json.dumps({"error": str(exc)})

    @server.tool(name="get_skill", annotations=READ_ONLY)
    def get_skill(name: str) -> str:
        """Get the complete SKILL.md document for a safe skill name."""
        started = time.perf_counter()
        try:
            document = registry.get(name).render()
            result_doc = document[:CHARACTER_LIMIT] + "\n\n<!-- response truncated -->\n" if len(document) > CHARACTER_LIMIT else document
            elapsed_ms = (time.perf_counter() - started) * 1000.0
            record_telemetry_event(
                event_type="mcp.get_skill",
                skill_name=name,
                tokens_loaded=estimate_tokens(result_doc),
                duration_ms=elapsed_ms,
                status="ok",
            )
            return result_doc
        except SkillForgeError as exc:
            elapsed_ms = (time.perf_counter() - started) * 1000.0
            record_telemetry_event(
                event_type="mcp.get_skill",
                skill_name=name,
                tokens_loaded=0,
                duration_ms=elapsed_ms,
                status="error",
            )
            return json.dumps({"error": str(exc)})

    @server.tool(name="get_skill_resource", annotations=READ_ONLY)
    def get_skill_resource(name: str, resource_path: str) -> str:
        """Read a bundled progressive-disclosure file (e.g. 'references/guide.md' or 'scripts/run.py') from a skill package."""
        started = time.perf_counter()
        try:
            package = registry.get_package(name)
            normalized = resource_path.strip().replace("\\", "/")
            if ".." in normalized.split("/"):
                return json.dumps({"error": "Invalid resource_path: path traversal is not allowed"})
            clean_path = normalized.removeprefix("./").lstrip("/")
            content: str | None = None
            if clean_path.startswith("references/"):
                rel = clean_path[len("references/") :]
                if rel in package.references:
                    content = package.references[rel]
            elif clean_path.startswith("scripts/"):
                rel = clean_path[len("scripts/") :]
                if rel in package.scripts:
                    content = package.scripts[rel]
            elif clean_path.startswith("assets/"):
                rel = clean_path[len("assets/") :]
                if rel in package.assets:
                    try:
                        content = package.assets[rel].decode("utf-8")
                    except UnicodeDecodeError:
                        return json.dumps({"error": f"Asset '{resource_path}' is binary and cannot be returned as text"})

            if content is not None:
                trimmed = content[:CHARACTER_LIMIT] if len(content) > CHARACTER_LIMIT else content
                elapsed_ms = (time.perf_counter() - started) * 1000.0
                record_telemetry_event(
                    event_type="mcp.get_skill_resource",
                    skill_name=name,
                    tokens_loaded=estimate_tokens(trimmed),
                    duration_ms=elapsed_ms,
                    status="ok",
                )
                return trimmed

            return json.dumps(
                {
                    "error": f"Resource '{resource_path}' not found in skill '{name}'",
                    "available_references": sorted(f"references/{k}" for k in package.references),
                    "available_scripts": sorted(f"scripts/{k}" for k in package.scripts),
                    "available_assets": sorted(f"assets/{k}" for k in package.assets),
                }
            )
        except SkillForgeError as exc:
            elapsed_ms = (time.perf_counter() - started) * 1000.0
            record_telemetry_event(
                event_type="mcp.get_skill_resource",
                skill_name=name,
                tokens_loaded=0,
                duration_ms=elapsed_ms,
                status="error",
            )
            return json.dumps({"error": str(exc)})

    @server.tool(name="validate_skill", annotations=READ_ONLY)
    def validate_skill(content: str) -> str:
        """Validate SKILL.md content without writing it to disk."""
        try:
            skill = parse_skill(content)
            return json.dumps({"valid": True, "name": skill.name, "description": skill.description})
        except SkillForgeError as exc:
            return json.dumps({"valid": False, "error": str(exc)})

    @server.tool(name="audit_skill", annotations=READ_ONLY)
    def audit_skill(content: str) -> str:
        """Audit SKILL.md content for prompt injection, zero-width unicode, and security issues."""
        try:
            report = SkillAuditor().audit_content(content)
            return json.dumps(report.to_dict())
        except SkillForgeError as exc:
            return json.dumps({"passed": False, "error": str(exc)})

    @server.tool(name="audit_mcp_config", annotations=READ_ONLY)
    def audit_mcp_config_tool(config_path: str) -> str:
        """Audit an mcp.json configuration file for plaintext secrets, shell wrappers, and poisoning."""
        try:
            report = run_audit_mcp_config(Path(config_path))
            return json.dumps(report.to_dict())
        except SkillForgeError as exc:
            return json.dumps({"passed": False, "error": str(exc)})

    @server.tool(name="check_policy", annotations=READ_ONLY)
    def check_policy(content: str, policy_path: str = ".skillforge-policy.yaml") -> str:
        """Audit SKILL.md content against a .skillforge-policy.yaml gate."""
        try:
            policy = SecurityPolicy.load(Path(policy_path))
            report = SkillAuditor().audit_content(content)
            evaluated = apply_policy(report, policy)
            payload = evaluated.report.to_dict()
            payload["policy_passed"] = evaluated.passed
            payload["min_score"] = evaluated.min_score
            payload["suppressed_count"] = len(evaluated.suppressed_findings)
            payload["expired_suppressions"] = len(evaluated.expired_suppressions)
            return json.dumps(payload)
        except SkillForgeError as exc:
            return json.dumps({"policy_passed": False, "error": str(exc)})

    @server.tool(name="skills_list", annotations=READ_ONLY)
    def skills_list_tool(cursor: str | None = None, limit: int = 50) -> str:
        """SEP-2640 (io.modelcontextprotocol/skills) skills/list returning SHA-256 file manifests."""
        from .mcp_skills_ext import MCPSkillsProtocolError, skills_list as run_skills_list

        try:
            return json.dumps(run_skills_list(registry, cursor=cursor, limit=limit))
        except MCPSkillsProtocolError as exc:
            return json.dumps({"error": {"code": exc.code, "message": str(exc)}})

    @server.tool(name="skills_get", annotations=READ_ONLY)
    def skills_get_tool(uri: str) -> str:
        """SEP-2640 (io.modelcontextprotocol/skills) skills/get returning manifest for a skill URI."""
        from .mcp_skills_ext import MCPSkillsProtocolError, skills_get as run_skills_get

        try:
            return json.dumps(run_skills_get(registry, uri))
        except MCPSkillsProtocolError as exc:
            return json.dumps({"error": {"code": exc.code, "message": str(exc)}})

    @server.tool(name="read_skill_directory", annotations=READ_ONLY)
    def read_skill_directory_tool(uri: str) -> str:
        """SEP-2640 resources/directory/read listing direct children of a skill directory URI."""
        from .mcp_skills_ext import MCPSkillsProtocolError, resources_directory_read

        try:
            return json.dumps(resources_directory_read(registry, uri))
        except MCPSkillsProtocolError as exc:
            return json.dumps({"error": {"code": exc.code, "message": str(exc)}})

    @server.tool(name="get_server_capabilities", annotations=READ_ONLY)
    def get_server_capabilities_tool() -> str:
        """Return MCP 2026-07-28 server/discover capabilities declaring io.modelcontextprotocol/skills."""
        from .mcp_skills_ext import server_capabilities_metadata

        return json.dumps(server_capabilities_metadata(directory_read=True))

    @server.resource("skill://{name}", mime_type="text/markdown")
    def skill_resource(name: str) -> str:
        """Read a skill by its skill:// URI."""
        return registry.get(name).render()

    @server.resource("skill://{name}/SKILL.md", mime_type="text/markdown")
    def skill_md_resource(name: str) -> str:
        """Read a skill SKILL.md via SEP-2640 canonical URI."""
        return registry.get(name).render()

    return server


def registry_from_environment() -> Registry:
    """Build explicit local-plus-built-in registry from environment."""
    local = LocalRegistry(Path(os.environ.get("SKILLFORGE_REGISTRY_PATH", ".skillforge")))
    return CompositeRegistry((local, BuiltinRegistry()))


def run_mcp_server(transport: Literal["stdio", "sse", "streamable-http"] = "stdio") -> None:
    """Run the SkillForge MCP server over the configured MCP transport."""
    create_mcp_server(registry_from_environment()).run(transport)

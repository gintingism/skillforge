"""MCP server exposing the local SkillForge registry."""

from __future__ import annotations

import json
import logging
import os
import sys
from pathlib import Path

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

from .errors import SkillForgeError
from .registry import BuiltinRegistry, CompositeRegistry, LocalRegistry, Registry
from .skill import parse_skill

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
        description="Discover, read, and validate portable SkillForge skills.",
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
        try:
            document = registry.get(name).render()
            if len(document) > CHARACTER_LIMIT:
                return document[:CHARACTER_LIMIT] + "\n\n<!-- response truncated -->\n"
            return document
        except SkillForgeError as exc:
            return json.dumps({"error": str(exc)})

    @server.tool(name="validate_skill", annotations=READ_ONLY)
    def validate_skill(content: str) -> str:
        """Validate SKILL.md content without writing it to disk."""
        try:
            skill = parse_skill(content)
            return json.dumps({"valid": True, "name": skill.name, "description": skill.description})
        except SkillForgeError as exc:
            return json.dumps({"valid": False, "error": str(exc)})

    @server.resource("skill://{name}", mime_type="text/markdown")
    def skill_resource(name: str) -> str:
        """Read a skill by its skill:// URI."""
        return registry.get(name).render()

    return server


def registry_from_environment() -> Registry:
    """Build explicit local-plus-built-in registry from environment."""
    local = LocalRegistry(Path(os.environ.get("SKILLFORGE_REGISTRY_PATH", ".skillforge")))
    return CompositeRegistry((local, BuiltinRegistry()))


def run_mcp_server() -> None:
    """Run the SkillForge MCP server over protocol-safe stdio."""
    create_mcp_server(registry_from_environment()).run("stdio")

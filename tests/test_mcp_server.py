import asyncio
import logging
import sys
from pathlib import Path

import pytest

from skillforge.mcp_server import create_mcp_server
from skillforge.registry import LocalRegistry
from skillforge.skill import Skill, SkillPackage


def make_registry(tmp_path: Path) -> LocalRegistry:
    registry = LocalRegistry(tmp_path / "registry")
    registry.publish_package(
        SkillPackage(
            skill=Skill("demo", "A demo skill", "# Demo\nSee `references/guide.md`.\n"),
            references={"guide.md": "# Deep Guide\n"},
        )
    )
    return registry


def test_server_initialization_exposes_tools_and_resource(tmp_path: Path) -> None:
    server = create_mcp_server(make_registry(tmp_path))
    tools = asyncio.run(server.list_tools())
    resources = asyncio.run(server.list_resource_templates())
    assert {tool.name for tool in tools} == {
        "search_skills",
        "get_skill",
        "get_skill_resource",
        "validate_skill",
        "audit_skill",
    }
    assert all(tool.annotations is not None and tool.annotations.read_only_hint is True for tool in tools)
    assert any(resource.uri_template == "skill://{name}" for resource in resources)


def test_mcp_tool_behavior_and_resource(tmp_path: Path) -> None:
    server = create_mcp_server(make_registry(tmp_path))
    search = asyncio.run(server.call_tool("search_skills", {"query": "demo"}))
    assert '"name": "demo"' in search.content[0].text
    fetched = asyncio.run(server.call_tool("get_skill", {"name": "demo"}))
    assert "A demo skill" in fetched.content[0].text
    disclosed = asyncio.run(
        server.call_tool("get_skill_resource", {"name": "demo", "resource_path": "references/guide.md"})
    )
    assert "# Deep Guide" in disclosed.content[0].text
    traversal = asyncio.run(
        server.call_tool("get_skill_resource", {"name": "demo", "resource_path": "../secret.txt"})
    )
    assert "traversal" in traversal.content[0].text.lower()
    validated = asyncio.run(server.call_tool("validate_skill", {"content": Skill("demo", "A demo", "").render()}))
    assert '"valid": true' in validated.content[0].text
    audited = asyncio.run(server.call_tool("audit_skill", {"content": Skill("demo", "A demo skill when needed", "").render()}))
    assert '"passed": true' in audited.content[0].text
    content = asyncio.run(server.read_resource("skill://demo"))
    assert "name: demo" in content[0].content


@pytest.mark.parametrize("name", ["../escape", "bad/name", ""])
def test_mcp_invalid_names_return_actionable_errors(tmp_path: Path, name: str) -> None:
    server = create_mcp_server(make_registry(tmp_path))
    result = asyncio.run(server.call_tool("get_skill", {"name": name}))
    assert "safe" in result.content[0].text.lower() or "required" in result.content[0].text.lower()


def test_mcp_missing_skill_is_reported(tmp_path: Path) -> None:
    server = create_mcp_server(make_registry(tmp_path))
    result = asyncio.run(server.call_tool("get_skill", {"name": "missing"}))
    assert "not found" in result.content[0].text.lower()


def test_mcp_logs_are_configured_for_stderr(caplog: pytest.LogCaptureFixture, tmp_path: Path) -> None:
    logger = logging.getLogger("skillforge.mcp")
    assert logger.name == "skillforge.mcp"
    assert any(handler.stream is sys.stderr for handler in logger.handlers)
    assert make_registry(tmp_path).get("demo").name == "demo"

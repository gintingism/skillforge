"""OpenAPI and Swagger specification importer for portable agent skills."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import yaml

from .errors import SkillForgeError
from .skill import Skill, SkillPackage


def _sanitize_name(raw_name: str) -> str:
    """Sanitize API title into a valid skill name."""
    clean = re.sub(r"[^a-z0-9_-]", "-", raw_name.lower())
    clean = re.sub(r"-+", "-", clean).strip("-")
    if not clean:
        clean = "api-service"
    if "--" in clean:
        clean = clean.replace("--", "-")
    return clean[:64]


def import_openapi(
    spec_path: Path,
    output_dir: Path,
    skill_name: str | None = None,
) -> SkillPackage:
    """Parse an OpenAPI or Swagger specification into a progressive disclosure skill package."""
    if not spec_path.is_file():
        raise SkillForgeError(f"OpenAPI specification not found: {spec_path}")

    raw_text = spec_path.read_text(encoding="utf-8")
    try:
        if spec_path.suffix.lower() in (".yaml", ".yml"):
            spec = yaml.safe_load(raw_text)
        else:
            try:
                spec = json.loads(raw_text)
            except json.JSONDecodeError:
                spec = yaml.safe_load(raw_text)
    except Exception as exc:
        raise SkillForgeError(f"Failed to parse OpenAPI document {spec_path}: {exc}") from exc

    if not isinstance(spec, dict):
        raise SkillForgeError(f"Invalid OpenAPI root: expected mapping, got {type(spec).__name__}")

    info = spec.get("info", {})
    if not isinstance(info, dict):
        info = {}

    title = str(info.get("title", spec_path.stem))
    api_version = str(info.get("version", "1.0.0"))
    api_desc = str(info.get("description", "")).strip()

    name = _sanitize_name(skill_name or title)

    # Detect base URL
    base_url = "https://api.example.com"
    servers = spec.get("servers")
    if isinstance(servers, list) and servers and isinstance(servers[0], dict):
        base_url = str(servers[0].get("url", base_url))
    elif "host" in spec:
        schemes = spec.get("schemes", ["https"])
        scheme = schemes[0] if schemes else "https"
        host = spec.get("host", "api.example.com")
        base_path = spec.get("basePath", "")
        base_url = f"{scheme}://{host}{base_path}".rstrip("/")

    # Parse paths and endpoints
    paths = spec.get("paths", {})
    endpoints: list[dict[str, Any]] = []

    if isinstance(paths, dict):
        for path_str, path_item in sorted(paths.items()):
            if not isinstance(path_item, dict):
                continue
            for method in ("get", "post", "put", "delete", "patch", "options", "head"):
                op = path_item.get(method)
                if not isinstance(op, dict):
                    continue
                summary = str(op.get("summary") or op.get("description") or "").splitlines()[0] if op.get("summary") or op.get("description") else ""
                op_id = str(op.get("operationId") or f"{method}_{path_str}")
                params = op.get("parameters", [])
                req_body = op.get("requestBody")
                responses = op.get("responses", {})

                endpoints.append({
                    "method": method.upper(),
                    "path": path_str,
                    "summary": summary[:80],
                    "operation_id": op_id,
                    "parameters": params if isinstance(params, list) else [],
                    "request_body": req_body if isinstance(req_body, dict) else None,
                    "responses": responses if isinstance(responses, dict) else {},
                })

    # Build description
    short_desc = f"Interact with the {title} API (v{api_version}). Use when sending requests, querying endpoints, or integrating {title} services."
    if len(short_desc) > 1024:
        short_desc = short_desc[:1020] + "..."

    # Build SKILL.md body
    body_lines = [
        f"# {title} Agent Skill",
        "",
        f"API Version: `{api_version}`",
        f"Base URL: `{base_url}`",
        "",
    ]
    if api_desc:
        body_lines.extend([api_desc[:300], ""])

    body_lines.extend([
        "## Authentication",
        "",
        "Verify required API keys or Bearer tokens in your environment before executing requests:",
        "```bash",
        "export API_KEY=\"<your-api-key>\"",
        "```",
        "",
        "## Endpoints Summary",
        "",
        "| Method | Path | Summary |",
        "| :--- | :--- | :--- |",
    ])

    for ep in endpoints[:50]:  # Keep top 50 in summary to protect token budget
        body_lines.append(f"| `{ep['method']}` | `{ep['path']}` | {ep['summary']} |")

    if len(endpoints) > 50:
        body_lines.append(f"| ... | ... | *(Total {len(endpoints)} endpoints defined)* |")

    body_lines.extend([
        "",
        "## Progressive Disclosure",
        "",
        "Detailed request bodies, parameters, and response schemas are documented in:",
        "- `references/endpoints.md`",
        "",
    ])

    # Build references/endpoints.md
    ref_lines = [
        f"# {title} API Endpoints Reference",
        "",
        f"Full endpoint definitions generated from OpenAPI specification.",
        "",
    ]

    for ep in endpoints:
        ref_lines.append(f"### {ep['method']} {ep['path']}")
        if ep["summary"]:
            ref_lines.append(f"**Summary:** {ep['summary']}")
        ref_lines.append(f"**Operation ID:** `{ep['operation_id']}`\n")

        params = ep["parameters"]
        if params:
            ref_lines.append("**Parameters:**")
            for p in params:
                if isinstance(p, dict):
                    p_name = p.get("name", "unknown")
                    p_in = p.get("in", "query")
                    p_req = "required" if p.get("required") else "optional"
                    ref_lines.append(f"- `{p_name}` ({p_in}, {p_req})")
            ref_lines.append("")

        responses = ep["responses"]
        if responses:
            ref_lines.append("**Responses:**")
            for code, resp in responses.items():
                if isinstance(resp, dict):
                    desc = resp.get("description", "")
                    ref_lines.append(f"- `{code}`: {desc}")
            ref_lines.append("")

        ref_lines.append("---\n")

    skill = Skill(
        name=name,
        description=short_desc,
        body="\n".join(body_lines),
        compatibility="claude-code cursor antigravity windsurf",
        allowed_tools="Bash",
        metadata={
            "api_version": api_version,
            "endpoints_count": len(endpoints),
            "source": "openapi",
        },
    )

    package = SkillPackage(
        skill=skill,
        references={"endpoints.md": "\n".join(ref_lines)},
    )

    target_dir = output_dir / name
    package.save(target_dir)
    return package

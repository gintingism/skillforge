"""Official MCP Skills extension (io.modelcontextprotocol/skills, SEP-2640) implementation.

Provides deterministic skill file manifests with SHA-256 digests and raw byte sizes,
skills/list, skills/get, resources/directory/read, and host-side manifest integrity verification.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any

from .errors import SkillForgeError
from .registry import Registry
from .skill import SkillPackage, parse_skill

MCP_SKILLS_EXTENSION_ID = "io.modelcontextprotocol/skills"
MAX_SKILL_FILES = 512
MAX_SKILL_BYTES = 16 * 1024 * 1024
DEFAULT_TTL_MS = 300_000
DEFAULT_CACHE_SCOPE = "public"


class MCPSkillsProtocolError(SkillForgeError):
    """Protocol-level error conforming to SEP-2640 JSON-RPC error codes."""

    def __init__(self, message: str, code: int = -32602) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class ManifestVerificationResult:
    """Result of verifying fetched skill files against a SEP-2640 manifest."""

    valid: bool
    skill_uri: str
    verified_files: int
    issues: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "skill_uri": self.skill_uri,
            "verified_files": self.verified_files,
            "issues": self.issues,
        }


def _sha256_prefixed(data: bytes) -> str:
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def _frontmatter_dict(pkg: SkillPackage) -> dict[str, Any]:
    skill = pkg.skill
    fm: dict[str, Any] = {
        "name": skill.name,
        "description": skill.description,
    }
    if skill.license:
        fm["license"] = skill.license
    if skill.compatibility:
        fm["compatibility"] = skill.compatibility
    if skill.allowed_tools:
        fm["allowed-tools"] = skill.allowed_tools
    if skill.metadata:
        fm["metadata"] = dict(skill.metadata)
    return fm


def package_file_bytes(pkg: SkillPackage) -> dict[str, bytes]:
    """Return mapping of relative POSIX path -> exact raw bytes served for a skill package."""
    files: dict[str, bytes] = {
        "SKILL.md": pkg.skill.render().encode("utf-8"),
    }
    for rel, content in sorted(pkg.scripts.items()):
        files[f"scripts/{rel}"] = content.encode("utf-8")
    for rel, content in sorted(pkg.references.items()):
        files[f"references/{rel}"] = content.encode("utf-8")
    for rel, data in sorted(pkg.assets.items()):
        files[f"assets/{rel}"] = data
    return files


def build_skill_entry(pkg: SkillPackage, *, scheme: str = "skill") -> dict[str, Any]:
    """Build a complete SEP-2640 skill entry with per-file SHA-256 digests and sizes."""
    name = pkg.skill.name
    files = package_file_bytes(pkg)
    if len(files) > MAX_SKILL_FILES:
        raise MCPSkillsProtocolError(
            f"Skill '{name}' exceeds SEP-2640 512-file limit ({len(files)} files)",
            code=-32603,
        )

    total_bytes = sum(len(raw) for raw in files.values())
    if total_bytes > MAX_SKILL_BYTES:
        raise MCPSkillsProtocolError(
            f"Skill '{name}' exceeds SEP-2640 16 MiB limit ({total_bytes} bytes)",
            code=-32603,
        )

    resources: list[dict[str, Any]] = []
    for rel_path, raw in sorted(files.items()):
        resources.append(
            {
                "uri": f"{scheme}://{name}/{rel_path}",
                "digest": _sha256_prefixed(raw),
                "size": len(raw),
            }
        )

    return {
        "uri": f"{scheme}://{name}/SKILL.md",
        "frontmatter": _frontmatter_dict(pkg),
        "resources": resources,
    }


def server_capabilities_metadata(*, directory_read: bool = True) -> dict[str, Any]:
    """Return SEP-2640 server/discover capabilities declaration."""
    return {
        "capabilities": {
            "resources": {},
            "extensions": {
                MCP_SKILLS_EXTENSION_ID: {
                    "directoryRead": directory_read,
                }
            },
        }
    }


def skills_list(
    registry: Registry,
    *,
    cursor: str | None = None,
    limit: int = 50,
    ttl_ms: int = DEFAULT_TTL_MS,
    cache_scope: str = DEFAULT_CACHE_SCOPE,
) -> dict[str, Any]:
    """Execute SEP-2640 skills/list with pagination and cache directives."""
    all_skills = sorted(registry.search(""), key=lambda s: s.name)
    start_idx = 0
    if cursor is not None:
        try:
            start_idx = max(0, int(cursor))
        except ValueError as exc:
            raise MCPSkillsProtocolError(f"Invalid pagination cursor: {cursor}", code=-32602) from exc

    page = all_skills[start_idx : start_idx + max(1, min(limit, 100))]
    entries: list[dict[str, Any]] = []
    for skill in page:
        pkg = registry.get_package(skill.name)
        entries.append(build_skill_entry(pkg))

    response: dict[str, Any] = {
        "resultType": "complete",
        "skills": entries,
        "ttlMs": ttl_ms,
        "cacheScope": cache_scope,
    }
    next_idx = start_idx + len(page)
    if next_idx < len(all_skills):
        response["nextCursor"] = str(next_idx)
    return response


def _parse_skill_uri(uri: str) -> tuple[str, str]:
    """Extract (skill_name, rel_path) from a skill://<name>/<path> URI."""
    if not uri.startswith("skill://"):
        raise MCPSkillsProtocolError(f"Unsupported or invalid skill URI: {uri}", code=-32602)
    remainder = uri[len("skill://") :].strip("/")
    if not remainder:
        raise MCPSkillsProtocolError(f"Missing skill name in URI: {uri}", code=-32602)
    parts = remainder.split("/", 1)
    skill_name = parts[0]
    rel_path = parts[1] if len(parts) > 1 else ""
    if ".." in rel_path.split("/"):
        raise MCPSkillsProtocolError(f"Path traversal forbidden in URI: {uri}", code=-32602)
    return skill_name, rel_path


def skills_get(
    registry: Registry,
    uri: str,
    *,
    ttl_ms: int = DEFAULT_TTL_MS,
    cache_scope: str = DEFAULT_CACHE_SCOPE,
) -> dict[str, Any]:
    """Execute SEP-2640 skills/get for a specific skill URI."""
    skill_name, rel_path = _parse_skill_uri(uri)
    if rel_path and rel_path != "SKILL.md":
        raise MCPSkillsProtocolError(
            f"skills/get URI must point to SKILL.md (got '{uri}')",
            code=-32602,
        )
    try:
        pkg = registry.get_package(skill_name)
    except SkillForgeError as exc:
        raise MCPSkillsProtocolError(f"Unknown skill URI: {uri}", code=-32602) from exc

    return {
        "resultType": "complete",
        "skill": build_skill_entry(pkg),
        "ttlMs": ttl_ms,
        "cacheScope": cache_scope,
    }


def _guess_mime(rel_path: str) -> str:
    lower = rel_path.lower()
    if lower.endswith(".md"):
        return "text/markdown"
    if lower.endswith(".py"):
        return "text/x-python"
    if lower.endswith(".sh"):
        return "text/x-shellscript"
    if lower.endswith(".json"):
        return "application/json"
    if lower.endswith((".yaml", ".yml")):
        return "application/yaml"
    if lower.endswith(".svg"):
        return "image/svg+xml"
    return "application/octet-stream"


def resources_directory_read(
    registry: Registry,
    uri: str,
    *,
    ttl_ms: int = DEFAULT_TTL_MS,
    cache_scope: str = DEFAULT_CACHE_SCOPE,
) -> dict[str, Any]:
    """Execute SEP-2640 resources/directory/read listing direct children of a skill directory."""
    if uri.endswith("/"):
        raise MCPSkillsProtocolError("Directory URIs must not include a trailing slash", code=-32602)

    skill_name, rel_dir = _parse_skill_uri(uri)
    try:
        pkg = registry.get_package(skill_name)
    except SkillForgeError as exc:
        raise MCPSkillsProtocolError(f"Unknown skill directory URI: {uri}", code=-32602) from exc

    files = package_file_bytes(pkg)
    prefix = f"{rel_dir}/" if rel_dir else ""
    seen_dirs: set[str] = set()
    children: list[dict[str, str]] = []

    for rel_path in sorted(files.keys()):
        if prefix and not rel_path.startswith(prefix):
            continue
        sub = rel_path[len(prefix) :]
        if "/" in sub:
            child_dir = sub.split("/", 1)[0]
            if child_dir not in seen_dirs:
                seen_dirs.add(child_dir)
                child_rel = f"{prefix}{child_dir}"
                children.append(
                    {
                        "uri": f"skill://{skill_name}/{child_rel}",
                        "name": child_dir,
                        "mimeType": "inode/directory",
                    }
                )
        else:
            children.append(
                {
                    "uri": f"skill://{skill_name}/{rel_path}",
                    "name": sub,
                    "mimeType": _guess_mime(rel_path),
                }
            )

    if rel_dir and not children:
        raise MCPSkillsProtocolError(f"Directory not found: {uri}", code=-32602)

    return {
        "resultType": "complete",
        "resources": children,
        "ttlMs": ttl_ms,
        "cacheScope": cache_scope,
    }


def verify_skill_manifest(
    entry: dict[str, Any],
    fetched_files: dict[str, bytes],
) -> ManifestVerificationResult:
    """Verify fetched raw bytes against a retained SEP-2640 manifest (digest, size, frontmatter)."""
    skill_uri = str(entry.get("uri", ""))
    expected_fm = entry.get("frontmatter")
    resources = entry.get("resources")
    issues: list[str] = []

    if resources == "dynamic":
        issues.append("Skill declares dynamic resources without verifiable SHA-256 digests")
        return ManifestVerificationResult(valid=False, skill_uri=skill_uri, verified_files=0, issues=issues)

    if not isinstance(resources, list) or not resources:
        issues.append("Manifest resources list is empty or malformed")
        return ManifestVerificationResult(valid=False, skill_uri=skill_uri, verified_files=0, issues=issues)

    allowed_uris = {str(r.get("uri", "")) for r in resources if isinstance(r, dict)}
    for fetched_uri in sorted(fetched_files.keys()):
        if fetched_uri not in allowed_uris:
            issues.append(f"Fetched URI '{fetched_uri}' is outside the retained skill manifest")

    verified_count = 0
    for item in resources:
        if not isinstance(item, dict):
            continue
        uri = str(item.get("uri", ""))
        expected_digest = str(item.get("digest", ""))
        expected_size = item.get("size")
        if uri not in fetched_files:
            continue
        raw = fetched_files[uri]
        if isinstance(expected_size, int) and len(raw) != expected_size:
            issues.append(f"Size mismatch for '{uri}': expected {expected_size} bytes, got {len(raw)}")
            continue
        actual_digest = _sha256_prefixed(raw)
        if expected_digest and actual_digest != expected_digest:
            issues.append(f"SHA-256 digest mismatch for '{uri}': expected {expected_digest}, got {actual_digest}")
            continue
        verified_count += 1

    if skill_uri in fetched_files and isinstance(expected_fm, dict):
        try:
            parsed = parse_skill(fetched_files[skill_uri].decode("utf-8"))
            if parsed.name != expected_fm.get("name"):
                issues.append(
                    f"Frontmatter name mismatch: manifest='{expected_fm.get('name')}', SKILL.md='{parsed.name}'"
                )
            if parsed.description != expected_fm.get("description"):
                issues.append("Frontmatter description mismatch between manifest and fetched SKILL.md")
        except Exception as exc:
            issues.append(f"Failed to parse fetched SKILL.md frontmatter: {exc}")

    return ManifestVerificationResult(
        valid=len(issues) == 0 and verified_count > 0,
        skill_uri=skill_uri,
        verified_files=verified_count,
        issues=issues,
    )

"""CycloneDX v1.6 AIBOM and SPDX v2.3 Software Bill of Materials generator for agent skills."""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from skillforge import __version__
from skillforge.security import Severity, SkillAuditor
from skillforge.skill import SkillPackage


@dataclass(frozen=True, slots=True)
class SBOMComponentSummary:
    """Summary of an inventory component included in the SBOM."""

    bom_ref: str
    name: str
    version: str
    component_type: str
    sha256: str
    license_id: str | None
    pointer_tokens: int
    body_tokens: int
    audit_score: int
    finding_count: int


@dataclass
class SBOMReport:
    """Result of generating a CycloneDX or SPDX bill of materials."""

    format_name: str
    spec_version: str
    serial_number: str
    created_at: str
    components: list[SBOMComponentSummary] = field(default_factory=list)
    vulnerability_count: int = 0
    document: dict[str, Any] = field(default_factory=dict)

    def to_json(self, indent: int = 2) -> str:
        """Serialize the SBOM document to JSON string."""
        return json.dumps(self.document, indent=indent)

    def render_text(self) -> str:
        """Render a concise terminal summary of the generated SBOM."""
        lines = [
            f"SBOM Generation Report ({self.format_name} {self.spec_version})",
            f"  Serial Number:   {self.serial_number}",
            f"  Timestamp:       {self.created_at}",
            f"  Components:      {len(self.components)}",
            f"  Vulnerabilities: {self.vulnerability_count}",
        ]
        if self.components:
            lines.append("\nInventory:")
            for comp in self.components:
                lic = comp.license_id or "UNSPECIFIED"
                lines.append(
                    f"  * {comp.name}@{comp.version} [{comp.component_type}] "
                    f"sha256:{comp.sha256[:12]}... license:{lic} score:{comp.audit_score}/100"
                )
        return "\n".join(lines)


def _severity_to_cyclonedx(sev: Severity) -> str:
    mapping = {
        Severity.CRITICAL: "critical",
        Severity.HIGH: "high",
        Severity.MEDIUM: "medium",
        Severity.LOW: "low",
    }
    return mapping.get(sev, "info")


def _discover_mcp_components(project_root: Path) -> list[dict[str, Any]]:
    """Discover MCP servers declared in mcp.json or .cursor/mcp.json."""
    candidates = (
        project_root / "mcp.json",
        project_root / ".cursor" / "mcp.json",
        project_root / ".vscode" / "mcp.json",
        project_root / "claude_desktop_config.json",
    )
    mcp_items: list[dict[str, Any]] = []
    seen_names: set[str] = set()

    for candidate in candidates:
        if not candidate.is_file():
            continue
        try:
            raw = json.loads(candidate.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(raw, dict):
            continue
        servers = raw.get("mcpServers") or raw.get("servers")
        if not isinstance(servers, dict):
            continue

        for srv_name, srv_cfg in sorted(servers.items()):
            if srv_name in seen_names or not isinstance(srv_cfg, dict):
                continue
            seen_names.add(srv_name)
            cmd = str(srv_cfg.get("command", ""))
            args = srv_cfg.get("args", [])
            arg_str = " ".join(str(a) for a in args) if isinstance(args, list) else ""
            raw_spec = f"{srv_name}:{cmd}:{arg_str}".encode("utf-8")
            digest = hashlib.sha256(raw_spec).hexdigest()
            mcp_items.append(
                {
                    "name": srv_name,
                    "command": cmd,
                    "args": arg_str,
                    "sha256": digest,
                    "source_file": candidate.relative_to(project_root).as_posix(),
                }
            )
    return mcp_items


def generate_sbom(
    packages: dict[str, SkillPackage],
    project_root: Path | None = None,
    sbom_format: str = "cyclonedx",
) -> SBOMReport:
    """Generate a CycloneDX 1.6 AIBOM or SPDX 2.3 document for a set of skill packages."""
    fmt_Clean = sbom_format.strip().lower()
    if fmt_Clean not in ("cyclonedx", "spdx"):
        raise ValueError(f"Unsupported SBOM format '{sbom_format}'. Choose 'cyclonedx' or 'spdx'.")

    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    auditor = SkillAuditor()
    summaries: list[SBOMComponentSummary] = []
    cdx_components: list[dict[str, Any]] = []
    cdx_dependencies: list[dict[str, Any]] = []
    cdx_vulnerabilities: list[dict[str, Any]] = []

    spdx_packages: list[dict[str, Any]] = []
    spdx_relationships: list[dict[str, Any]] = []

    for skill_name, pkg in sorted(packages.items()):
        version = str(pkg.skill.metadata.get("version", "0.1.0"))
        sha256_hex = pkg.compute_sha256()
        bom_ref = f"pkg:skillforge/{skill_name}@{version}"
        spdx_id = f"SPDXRef-Skill-{skill_name}"
        audit_report = auditor.audit_package(pkg)

        summaries.append(
            SBOMComponentSummary(
                bom_ref=bom_ref,
                name=skill_name,
                version=version,
                component_type="agent-skill",
                sha256=sha256_hex,
                license_id=pkg.skill.license,
                pointer_tokens=pkg.skill.pointer_tokens,
                body_tokens=pkg.skill.body_tokens,
                audit_score=audit_report.score,
                finding_count=len(audit_report.findings),
            )
        )

        properties = [
            {"name": "skillforge:component_kind", "value": "SKILL.md"},
            {"name": "skillforge:pointer_tokens", "value": str(pkg.skill.pointer_tokens)},
            {"name": "skillforge:body_tokens", "value": str(pkg.skill.body_tokens)},
            {"name": "skillforge:total_tokens", "value": str(pkg.total_tokens)},
            {"name": "skillforge:audit_score", "value": str(audit_report.score)},
            {"name": "skillforge:script_count", "value": str(len(pkg.scripts))},
            {"name": "skillforge:reference_count", "value": str(len(pkg.references))},
        ]
        if pkg.skill.allowed_tools:
            properties.append({"name": "skillforge:allowed_tools", "value": pkg.skill.allowed_tools})

        comp_entry: dict[str, Any] = {
            "type": "application",
            "bom-ref": bom_ref,
            "name": skill_name,
            "version": version,
            "description": pkg.skill.description,
            "hashes": [{"alg": "SHA-256", "content": sha256_hex}],
            "purl": bom_ref,
            "properties": properties,
        }
        if pkg.skill.license:
            comp_entry["licenses"] = [{"license": {"id": pkg.skill.license}}]

        cdx_components.append(comp_entry)

        dep_refs = [
            f"pkg:skillforge/{dep}@{packages[dep].skill.metadata.get('version', '0.1.0')}"
            if dep in packages
            else f"pkg:skillforge/{dep}@unknown"
            for dep in pkg.skill.dependencies
        ]
        cdx_dependencies.append({"ref": bom_ref, "dependsOn": dep_refs})

        for finding in audit_report.findings:
            cdx_vulnerabilities.append(
                {
                    "id": finding.rule_id,
                    "source": {"name": "SkillForge Security Auditor"},
                    "ratings": [
                        {
                            "severity": _severity_to_cyclonedx(finding.severity),
                            "method": "other",
                        }
                    ],
                    "description": finding.message,
                    "affects": [{"ref": bom_ref}],
                }
            )

        spdx_packages.append(
            {
                "SPDXID": spdx_id,
                "name": skill_name,
                "versionInfo": version,
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "checksums": [{"algorithm": "SHA256", "checksumValue": sha256_hex}],
                "licenseDeclared": pkg.skill.license or "NOASSERTION",
                "description": pkg.skill.description,
                "primaryPackagePurpose": "APPLICATION",
            }
        )
        spdx_relationships.append(
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relatedSpdxElement": spdx_id,
                "relationshipType": "DESCRIBES",
            }
        )
        for dep in pkg.skill.dependencies:
            spdx_relationships.append(
                {
                    "spdxElementId": spdx_id,
                    "relatedSpdxElement": f"SPDXRef-Skill-{dep}",
                    "relationshipType": "DEPENDS_ON",
                }
            )

    if project_root is not None:
        for mcp_srv in _discover_mcp_components(project_root):
            srv_name = mcp_srv["name"]
            srv_sha = mcp_srv["sha256"]
            bom_ref = f"pkg:mcp/{srv_name}@local"
            summaries.append(
                SBOMComponentSummary(
                    bom_ref=bom_ref,
                    name=srv_name,
                    version="local",
                    component_type="mcp-server",
                    sha256=srv_sha,
                    license_id=None,
                    pointer_tokens=0,
                    body_tokens=0,
                    audit_score=100,
                    finding_count=0,
                )
            )
            cdx_components.append(
                {
                    "type": "service",
                    "bom-ref": bom_ref,
                    "name": srv_name,
                    "version": "local",
                    "description": f"MCP Server configured in {mcp_srv['source_file']}",
                    "hashes": [{"alg": "SHA-256", "content": srv_sha}],
                    "properties": [
                        {"name": "skillforge:component_kind", "value": "mcp-server"},
                        {"name": "skillforge:command", "value": mcp_srv["command"]},
                        {"name": "skillforge:source_file", "value": mcp_srv["source_file"]},
                    ],
                }
            )

    # Deterministic UUID5 based on component hashes so identical inputs produce stable serials
    seed_hash = hashlib.sha256(
        "|".join(f"{c.bom_ref}:{c.sha256}" for c in summaries).encode("utf-8")
    ).hexdigest()
    deterministic_uuid = str(uuid.uuid5(uuid.NAMESPACE_OID, seed_hash))

    if fmt_Clean == "cyclonedx":
        serial = f"urn:uuid:{deterministic_uuid}"
        doc: dict[str, Any] = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": serial,
            "version": 1,
            "metadata": {
                "timestamp": now_iso,
                "tools": {
                    "components": [
                        {
                            "type": "application",
                            "name": "skillforge",
                            "version": __version__,
                        }
                    ]
                },
            },
            "components": cdx_components,
            "dependencies": cdx_dependencies,
            "vulnerabilities": cdx_vulnerabilities,
        }
        return SBOMReport(
            format_name="CycloneDX",
            spec_version="1.6",
            serial_number=serial,
            created_at=now_iso,
            components=summaries,
            vulnerability_count=len(cdx_vulnerabilities),
            document=doc,
        )

    spdx_ns = f"https://skillforge.dev/spdx/{deterministic_uuid}"
    spdx_doc: dict[str, Any] = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "skillforge-aibom",
        "documentNamespace": spdx_ns,
        "creationInfo": {
            "created": now_iso,
            "creators": [f"Tool: skillforge-{__version__}"],
        },
        "packages": spdx_packages,
        "relationships": spdx_relationships,
    }
    return SBOMReport(
        format_name="SPDX",
        spec_version="2.3",
        serial_number=spdx_ns,
        created_at=now_iso,
        components=summaries,
        vulnerability_count=len(cdx_vulnerabilities),
        document=spdx_doc,
    )

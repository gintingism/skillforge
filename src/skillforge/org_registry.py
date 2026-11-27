"""Federated Trust & Curated Organization Subregistry for Agent Skills and MCP Servers.

Implements enterprise allowlist governance (registry-policy.yaml):
- Verified reverse-domain namespaces (e.g. com.acme/*) for internal packages
- Mirrored upstream preservation (prevents silently renaming io.github.* to internal namespaces)
- Duplicate upstream / credential-sprawl detection
- Quarantine -> Approved -> Revoked lifecycle with SHA-256 pinning and Server Card drift checks
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from .errors import SkillForgeError
from .security import SkillAuditor
from .skill import SkillPackage

VALID_STATUSES = frozenset({"quarantine", "approved", "revoked"})


@dataclass
class RegistryEntry:
    """Governed skill or MCP server entry inside an organization subregistry."""

    id: str  # e.g. "com.acme/db-migrator" or "io.github.modelcontextprotocol/filesystem"
    kind: str  # "skill" or "mcp"
    status: str = "quarantine"
    sha256: str = ""
    upstream: str = ""
    server_card_url: str = ""
    min_score: int = 85
    owner: str = ""
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "status": self.status,
            "sha256": self.sha256,
            "upstream": self.upstream,
            "server_card_url": self.server_card_url,
            "min_score": self.min_score,
            "owner": self.owner,
            "updated_at": self.updated_at,
        }


@dataclass
class OrgRegistryPolicy:
    """Declarative organization subregistry manifest (registry-policy.yaml)."""

    organization: str
    verified_namespaces: list[str] = field(default_factory=list)
    default_action: str = "deny"  # "deny" (strict allowlist) or "quarantine"
    min_audit_score: int = 85
    entries: list[RegistryEntry] = field(default_factory=list)

    @classmethod
    def load(cls, path: Path) -> "OrgRegistryPolicy":
        if not path.is_file():
            raise SkillForgeError(f"Organization registry policy not found: {path}")
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise SkillForgeError(f"Invalid registry policy YAML {path}: {exc}") from exc
        if not isinstance(raw, dict):
            raise SkillForgeError("Registry policy root must be a YAML mapping")

        entries: list[RegistryEntry] = []
        for item in raw.get("entries", []) if isinstance(raw.get("entries"), list) else []:
            if not isinstance(item, dict):
                continue
            status = str(item.get("status", "quarantine")).lower()
            if status not in VALID_STATUSES:
                raise SkillForgeError(f"Invalid entry status '{status}' for '{item.get('id')}'")
            entries.append(
                RegistryEntry(
                    id=str(item.get("id", "")).strip(),
                    kind=str(item.get("kind", "skill")).strip().lower(),
                    status=status,
                    sha256=str(item.get("sha256", "")).strip(),
                    upstream=str(item.get("upstream", "")).strip(),
                    server_card_url=str(item.get("server_card_url", "")).strip(),
                    min_score=int(item.get("min_score") or raw.get("min_audit_score") or 85),
                    owner=str(item.get("owner", "")).strip(),
                    updated_at=str(item.get("updated_at", datetime.now(timezone.utc).isoformat())),
                )
            )

        return cls(
            organization=str(raw.get("organization", "acme")).strip(),
            verified_namespaces=[str(ns).strip() for ns in (raw.get("verified_namespaces") or []) if str(ns).strip()],
            default_action=str(raw.get("default_action", "deny")).strip().lower(),
            min_audit_score=int(raw.get("min_audit_score", 85)),
            entries=entries,
        )

    def save(self, path: Path) -> Path:
        payload = {
            "organization": self.organization,
            "verified_namespaces": self.verified_namespaces,
            "default_action": self.default_action,
            "min_audit_score": self.min_audit_score,
            "entries": [e.to_dict() for e in self.entries],
        }
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
        return path

    def find_entry(self, entry_id: str) -> RegistryEntry | None:
        for e in self.entries:
            if e.id == entry_id:
                return e
        return None

    def set_status(self, entry_id: str, new_status: str) -> RegistryEntry:
        norm = new_status.strip().lower()
        if norm not in VALID_STATUSES:
            raise SkillForgeError(f"Invalid status '{new_status}'. Use: quarantine, approved, revoked")
        entry = self.find_entry(entry_id)
        if entry is None:
            raise SkillForgeError(f"Registry entry not found: {entry_id}")
        entry.status = norm
        entry.updated_at = datetime.now(timezone.utc).isoformat()
        return entry

    def validate_governance(self) -> list[str]:
        """Validate namespace integrity, duplicate upstream credential sprawl, and SHA-256 pinning."""
        issues: list[str] = []
        seen_ids: set[str] = set()
        upstream_map: dict[str, list[str]] = {}

        for entry in self.entries:
            if not entry.id or "/" not in entry.id:
                issues.append(f"Entry '{entry.id or '<empty>'}' must use reverse-domain namespace '<namespace>/<name>'")
                continue
            if entry.id in seen_ids:
                issues.append(f"Duplicate registry entry id: '{entry.id}'")
            seen_ids.add(entry.id)

            ns = entry.id.split("/", 1)[0]
            # Mirrored public upstreams must not be renamed into internal verified namespaces
            if entry.upstream and any(ns == vns.rstrip("/*") for vns in self.verified_namespaces):
                if "github.com" in entry.upstream.lower() and not entry.upstream.lower().startswith(f"https://github.com/{self.organization.lower()}/"):
                    issues.append(
                        f"Namespace chain broken for '{entry.id}': external upstream '{entry.upstream}' "
                        f"should preserve its upstream namespace instead of renaming under '{ns}/'"
                    )

            if entry.status == "approved" and not entry.sha256:
                issues.append(f"Approved entry '{entry.id}' is missing a pinned sha256 digest")

            if entry.upstream:
                upstream_map.setdefault(entry.upstream.lower(), []).append(entry.id)

        for up, ids in sorted(upstream_map.items()):
            if len(ids) > 1:
                issues.append(
                    f"Duplicate upstream '{up}' registered under multiple entries ({', '.join(ids)}); "
                    "consolidate to prevent credential sprawl"
                )

        return issues

    def evaluate_skill_package(self, entry_id: str, package: SkillPackage) -> dict[str, Any]:
        """Evaluate whether a local SkillPackage is permitted by this organization subregistry."""
        entry = self.find_entry(entry_id)
        actual_sha = package.compute_sha256()
        audit_rep = SkillAuditor().audit_package(package)
        reasons: list[str] = []

        if entry is None:
            allowed = False
            status = "unlisted"
            reasons.append(f"Entry '{entry_id}' is not listed in organization allowlist (default_action={self.default_action})")
        else:
            status = entry.status
            allowed = entry.status == "approved"
            if entry.status != "approved":
                reasons.append(f"Entry '{entry_id}' status is '{entry.status}' (must be 'approved')")
            if entry.sha256 and entry.sha256 != actual_sha:
                allowed = False
                reasons.append(f"SHA-256 drift: pinned={entry.sha256[:12]}..., actual={actual_sha[:12]}...")
            if not audit_rep.passed or audit_rep.score < max(self.min_audit_score, entry.min_score):
                allowed = False
                reasons.append(
                    f"Security audit failed gate (score={audit_rep.score}, required>={max(self.min_audit_score, entry.min_score)})"
                )

        return {
            "id": entry_id,
            "allowed": allowed,
            "status": status,
            "sha256": actual_sha,
            "audit_score": audit_rep.score,
            "reasons": reasons,
        }


def verify_server_card_drift(
    card_data: dict[str, Any],
    live_tool_names: list[str],
) -> list[str]:
    """Compare SEP-2127 MCP Server Card declared tools against live tools/list output."""
    declared = {
        str(t.get("name", "")).strip()
        for t in (card_data.get("tools") or [])
        if isinstance(t, dict) and str(t.get("name", "")).strip()
    }
    observed = {t.strip() for t in live_tool_names if t.strip()}
    issues: list[str] = []
    undeclared = sorted(observed - declared)
    missing = sorted(declared - observed)
    if undeclared:
        issues.append(f"Live MCP server exposes undeclared tool(s) absent from Server Card: {', '.join(undeclared)}")
    if missing:
        issues.append(f"Server Card declares tool(s) missing from live server: {', '.join(missing)}")
    return issues


def scaffold_org_registry(org: str = "acme", domain_ns: str = "com.acme") -> OrgRegistryPolicy:
    """Create a starter organization subregistry policy."""
    return OrgRegistryPolicy(
        organization=org,
        verified_namespaces=[f"{domain_ns}/*"],
        default_action="deny",
        min_audit_score=85,
        entries=[
            RegistryEntry(
                id=f"{domain_ns}/example-skill",
                kind="skill",
                status="quarantine",
                sha256="",
                owner="security-platform",
            )
        ],
    )

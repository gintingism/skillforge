"""Skill lifecycle check, audited updates, and vercel-labs/skills lockfile migration."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from .adapters import detect_adapters
from .errors import SkillForgeError
from .registry import BuiltinRegistry, GitRemoteRegistry, LocalRegistry, Registry
from .security import SkillAuditor
from .skill import SkillPackage


class LifecycleError(SkillForgeError):
    """Raised when lockfile check, update, or migration fails."""


@dataclass(frozen=True, slots=True)
class SkillStatusEntry:
    """Comparison state between local install, skillforge.lock, and upstream source."""

    name: str
    spec: str
    installed_sha256: str
    locked_sha256: str
    remote_sha256: str | None
    locked_commit: str | None
    remote_commit: str | None
    status: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "spec": self.spec,
            "installed_sha256": self.installed_sha256,
            "locked_sha256": self.locked_sha256,
            "remote_sha256": self.remote_sha256,
            "locked_commit": self.locked_commit,
            "remote_commit": self.remote_commit,
            "status": self.status,
        }


@dataclass
class CheckReport:
    """Consolidated report from checking locked skills for upstream updates or drift."""

    entries: list[SkillStatusEntry] = field(default_factory=list)
    updates_available: int = 0
    drift_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "total": len(self.entries),
            "updates_available": self.updates_available,
            "drift_count": self.drift_count,
            "entries": [e.to_dict() for e in self.entries],
        }

    def render_text(self) -> str:
        if not self.entries:
            return "No skills recorded in skillforge.lock."
        lines = [
            f"SkillForge Update Check ({len(self.entries)} locked skill(s)): "
            f"{self.updates_available} update(s) available, {self.drift_count} drift/missing"
        ]
        for e in self.entries:
            lines.append(f"  [{e.status:16s}] {e.name} (spec: {e.spec})")
        return "\n".join(lines)


def _fetch_upstream_package(
    spec: str,
    skill_name: str,
    local_registry: Registry | None = None,
    remote_fetcher: Callable[[str], SkillPackage] | None = None,
) -> SkillPackage:
    if remote_fetcher is not None:
        return remote_fetcher(spec)
    if spec.startswith("builtin:"):
        return BuiltinRegistry().get_package(spec.split(":", 1)[1])
    if local_registry is not None and "/" not in spec and ":" not in spec:
        return local_registry.get_package(spec or skill_name)
    return GitRemoteRegistry().fetch_skill(spec)


def _read_lockfile(lock_path: Path) -> dict[str, Any]:
    if not lock_path.is_file():
        raise LifecycleError(f"Lockfile not found: {lock_path}")
    try:
        data = json.loads(lock_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise LifecycleError(f"Invalid skillforge.lock JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise LifecycleError("skillforge.lock root must be a JSON object")
    return data


def check_lockfile_updates(
    project_root: Path,
    installed_packages: dict[str, SkillPackage],
    registry: Registry | None = None,
    remote_fetcher: Callable[[str], SkillPackage] | None = None,
) -> CheckReport:
    """Check installed skills and skillforge.lock against upstream sources."""
    lock_data = _read_lockfile(project_root / "skillforge.lock")
    local_reg = registry or LocalRegistry(project_root / ".skillforge")

    entries: list[SkillStatusEntry] = []
    updates = 0
    drifts = 0

    for name, raw_entry in sorted(lock_data.items()):
        spec = str(raw_entry.get("spec", name)) if isinstance(raw_entry, dict) else str(raw_entry)
        locked_sha = str(raw_entry.get("sha256", "")) if isinstance(raw_entry, dict) else ""
        locked_commit = raw_entry.get("commit") if isinstance(raw_entry, dict) else None

        local_pkg = installed_packages.get(name)
        installed_sha = local_pkg.compute_sha256() if local_pkg is not None else ""

        remote_sha: str | None = None
        remote_commit: str | None = None
        try:
            upstream_pkg = _fetch_upstream_package(
                spec=spec,
                skill_name=name,
                local_registry=local_reg,
                remote_fetcher=remote_fetcher,
            )
            remote_sha = upstream_pkg.compute_sha256()
            remote_commit = upstream_pkg.commit_sha
        except Exception:
            remote_sha = None

        if local_pkg is None:
            status = "MISSING_LOCAL"
            drifts += 1
        elif locked_sha and installed_sha != locked_sha:
            status = "LOCAL_DRIFT"
            drifts += 1
        elif remote_sha is not None and locked_sha and remote_sha != locked_sha:
            status = "UPDATE_AVAILABLE"
            updates += 1
        else:
            status = "UP_TO_DATE"

        entries.append(
            SkillStatusEntry(
                name=name,
                spec=spec,
                installed_sha256=installed_sha,
                locked_sha256=locked_sha,
                remote_sha256=remote_sha,
                locked_commit=str(locked_commit) if locked_commit else None,
                remote_commit=remote_commit,
                status=status,
            )
        )

    return CheckReport(entries=entries, updates_available=updates, drift_count=drifts)


def update_locked_skills(
    project_root: Path,
    skill_names: list[str] | None = None,
    min_score: int = 80,
    registry: Registry | None = None,
    remote_fetcher: Callable[[str], SkillPackage] | None = None,
) -> dict[str, Any]:
    """Fetch, security-audit, install, and lock updated versions of recorded skills."""
    lock_path = project_root / "skillforge.lock"
    lock_data = _read_lockfile(lock_path)
    local_reg = registry or LocalRegistry(project_root / ".skillforge")
    auditor = SkillAuditor()

    target_names = sorted(skill_names) if skill_names else sorted(lock_data.keys())
    updated: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    blocked: list[dict[str, Any]] = []

    adapters = detect_adapters(project_root, global_scope=False)

    for name in target_names:
        if name not in lock_data:
            raise LifecycleError(f"Skill '{name}' is not recorded in {lock_path}")
        raw_entry = lock_data[name]
        spec = str(raw_entry.get("spec", name)) if isinstance(raw_entry, dict) else str(raw_entry)
        old_sha = str(raw_entry.get("sha256", "")) if isinstance(raw_entry, dict) else ""

        upstream_pkg = _fetch_upstream_package(
            spec=spec,
            skill_name=name,
            local_registry=local_reg,
            remote_fetcher=remote_fetcher,
        )
        new_sha = upstream_pkg.compute_sha256()
        if old_sha and new_sha == old_sha:
            skipped.append({"name": name, "reason": "already up to date", "sha256": new_sha})
            continue

        audit_rep = auditor.audit_package(upstream_pkg)
        if not audit_rep.passed or audit_rep.score < min_score:
            blocked.append(
                {
                    "name": name,
                    "score": audit_rep.score,
                    "min_score": min_score,
                    "findings": [f.rule_id for f in audit_rep.findings],
                }
            )
            continue

        if adapters:
            for adapter in adapters:
                adapter.install(upstream_pkg, project_root)
        else:
            fallback_dir = project_root / ".agents" / "skills" / upstream_pkg.skill.name
            upstream_pkg.save(fallback_dir)

        lock_data[name] = {
            "spec": spec,
            "version": upstream_pkg.skill.metadata.get("version", "unknown"),
            "sha256": new_sha,
            "commit": upstream_pkg.commit_sha,
        }
        updated.append(
            {
                "name": name,
                "old_sha256": old_sha,
                "new_sha256": new_sha,
                "audit_score": audit_rep.score,
            }
        )

    lock_path.write_text(json.dumps(lock_data, indent=2), encoding="utf-8")
    return {
        "updated": updated,
        "skipped": skipped,
        "blocked": blocked,
        "passed": len(blocked) == 0,
    }


def migrate_vercel_lockfile(
    source_lock: Path,
    output_lock: Path | None = None,
    installed_packages: dict[str, SkillPackage] | None = None,
) -> dict[str, Any]:
    """Convert a vercel-labs/skills skills-lock.json manifest into skillforge.lock."""
    if not source_lock.is_file():
        raise LifecycleError(f"Source lockfile not found: {source_lock}")
    try:
        raw = json.loads(source_lock.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise LifecycleError(f"Failed to parse {source_lock}: {exc}") from exc

    if not isinstance(raw, dict):
        raise LifecycleError(f"Source lockfile {source_lock} must contain a JSON object")

    raw_skills_val = raw.get("skills")
    raw_skills: dict[str, Any] = raw_skills_val if isinstance(raw_skills_val, dict) else raw
    installed = installed_packages or {}
    converted: dict[str, Any] = {}

    for skill_name, meta in sorted(raw_skills.items()):
        if skill_name in ("version", "lockfileVersion"):
            continue
        if not isinstance(meta, dict):
            continue
        source_spec = str(meta.get("source") or meta.get("repo") or skill_name)
        pkg = installed.get(skill_name)
        sha = pkg.compute_sha256() if pkg is not None else str(meta.get("computedHash") or meta.get("sha256") or "")
        converted[skill_name] = {
            "spec": f"{source_spec}:{skill_name}" if "/" in source_spec and ":" not in source_spec else source_spec,
            "version": str(meta.get("version", "migrated")),
            "sha256": sha,
            "commit": meta.get("commit") or meta.get("sha"),
            "migrated_from": source_lock.name,
        }

    dest = output_lock or (source_lock.parent / "skillforge.lock")
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(converted, indent=2), encoding="utf-8")
    return {
        "source": str(source_lock),
        "output": str(dest),
        "migrated_count": len(converted),
        "skills": sorted(converted.keys()),
    }

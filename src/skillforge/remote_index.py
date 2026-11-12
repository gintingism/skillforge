"""Remote skill indexer and community repository registry.

Provides crawling, querying, and verification index for remote agent skills.
"""

from __future__ import annotations

import json
import re
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from skillforge.errors import SkillForgeError
from skillforge.security import SkillAuditor
from skillforge.skill import SkillPackage


class RemoteIndexError(SkillForgeError):
    """Raised when remote index querying or updating fails."""


@dataclass
class RemoteSkillRecord:
    """Metadata record for a skill listed in the remote registry index."""

    name: str
    description: str
    repository: str
    spec: str
    author: str = "community"
    version: str = "1.0.0"
    tags: list[str] = field(default_factory=list)
    verified: bool = False
    security_score: int = 100

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RemoteSkillRecord:
        return cls(
            name=data.get("name", "unnamed"),
            description=data.get("description", ""),
            repository=data.get("repository", ""),
            spec=data.get("spec", ""),
            author=data.get("author", "community"),
            version=data.get("version", "1.0.0"),
            tags=list(data.get("tags", [])),
            verified=bool(data.get("verified", False)),
            security_score=int(data.get("security_score", 100)),
        )


# Default trusted catalog seeds
DEFAULT_CURATED_INDEX: list[dict[str, Any]] = [
    {
        "name": "git-worktree-isolation",
        "description": "Isolate agent experiments in ephemeral git worktrees with automatic cleanup.",
        "repository": "https://github.com/gintingism/skillforge",
        "spec": "gintingism/skillforge:git-worktree-isolation",
        "author": "gintingism",
        "version": "1.0.0",
        "tags": ["git", "isolation", "workflow", "safety"],
        "verified": True,
        "security_score": 100,
    },
    {
        "name": "atomic-rollback-guard",
        "description": "Safe atomic file modifications with automatic rollback on error or lint failure.",
        "repository": "https://github.com/gintingism/skillforge",
        "spec": "gintingism/skillforge:atomic-rollback-guard",
        "author": "gintingism",
        "version": "1.0.0",
        "tags": ["safety", "rollback", "filesystem", "integrity"],
        "verified": True,
        "security_score": 100,
    },
    {
        "name": "lethal-trifecta-guard",
        "description": "Detects lethal trifecta: credential access + untrusted ingestion + outbound egress.",
        "repository": "https://github.com/gintingism/skillforge",
        "spec": "gintingism/skillforge:lethal-trifecta-guard",
        "author": "gintingism",
        "version": "1.0.0",
        "tags": ["security", "sec-014", "trifecta", "audit"],
        "verified": True,
        "security_score": 100,
    },
    {
        "name": "memory-hygiene-sentinel",
        "description": "Detects memory poisoning and unauthorized modifications to AGENTS.md / CLAUDE.md.",
        "repository": "https://github.com/gintingism/skillforge",
        "spec": "gintingism/skillforge:memory-hygiene-sentinel",
        "author": "gintingism",
        "version": "1.0.0",
        "tags": ["security", "memory", "sec-013", "persistence"],
        "verified": True,
        "security_score": 100,
    },
    {
        "name": "mcp-least-privilege-sentinel",
        "description": "Validates MCP configuration against wildcard roots and dangerous command flags.",
        "repository": "https://github.com/gintingism/skillforge",
        "spec": "gintingism/skillforge:mcp-least-privilege-sentinel",
        "author": "gintingism",
        "version": "1.0.0",
        "tags": ["mcp", "security", "config", "audit"],
        "verified": True,
        "security_score": 100,
    },
    {
        "name": "traceback-postmortem",
        "description": "Analyzes Python, Node.js, and Go stack traces to pinpoint root cause lines.",
        "repository": "https://github.com/gintingism/skillforge",
        "spec": "gintingism/skillforge:traceback-postmortem",
        "author": "gintingism",
        "version": "1.0.0",
        "tags": ["debugging", "postmortem", "analysis"],
        "verified": True,
        "security_score": 100,
    },
    {
        "name": "attention-anchor-ledger",
        "description": "Maintains persistent attention anchors across multi-turn context compaction.",
        "repository": "https://github.com/gintingism/skillforge",
        "spec": "gintingism/skillforge:attention-anchor-ledger",
        "author": "gintingism",
        "version": "1.0.0",
        "tags": ["attention", "context", "memory", "ledger"],
        "verified": True,
        "security_score": 100,
    },
    {
        "name": "supply-chain-lockfile-guard",
        "description": "Audits agent skill lockfiles for unpinned dependencies and integrity hash mismatches.",
        "repository": "https://github.com/gintingism/skillforge",
        "spec": "gintingism/skillforge:supply-chain-lockfile-guard",
        "author": "gintingism",
        "version": "1.0.0",
        "tags": ["supply-chain", "lockfile", "audit", "security"],
        "verified": True,
        "security_score": 100,
    },
]


class RemoteIndex:
    """Manages searching, caching, and building index of remote agent skills."""

    def __init__(self, cache_file: Path | None = None) -> None:
        self.cache_file = cache_file or (Path.home() / ".skillforge" / "remote_index.json")
        self._skills: list[RemoteSkillRecord] = []
        self._load_index()

    def _load_index(self) -> None:
        """Load index from cache file or fallback to curated default seeds."""
        if self.cache_file.is_file():
            try:
                data = json.loads(self.cache_file.read_text(encoding="utf-8"))
                self._skills = [RemoteSkillRecord.from_dict(item) for item in data.get("skills", [])]
                if self._skills:
                    return
            except Exception:
                pass

        # Fallback to curated seeds
        self._skills = [RemoteSkillRecord.from_dict(item) for item in DEFAULT_CURATED_INDEX]

    def save_index(self) -> None:
        """Persist index to cache file."""
        self.cache_file.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": "1.0",
            "count": len(self._skills),
            "skills": [s.to_dict() for s in self._skills],
        }
        self.cache_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def search(self, query: str, tag: str | None = None) -> list[RemoteSkillRecord]:
        """Search remote skills matching query in name, description, or tags."""
        terms = [t.casefold() for t in query.split() if t.strip()]
        results: list[RemoteSkillRecord] = []

        for skill in self._skills:
            if tag and tag.casefold() not in [t.casefold() for t in skill.tags]:
                continue

            searchable = f"{skill.name} {skill.description} {' '.join(skill.tags)} {skill.author}".casefold()
            if not terms or all(term in searchable for term in terms):
                results.append(skill)

        return results

    def add_or_update(self, record: RemoteSkillRecord) -> None:
        """Add or update an index record."""
        existing_idx = next((i for i, s in enumerate(self._skills) if s.spec == record.spec), None)
        if existing_idx is not None:
            self._skills[existing_idx] = record
        else:
            self._skills.append(record)

    def index_directory(self, repo_dir: Path, repo_url: str) -> list[RemoteSkillRecord]:
        """Scan a local directory/cloned repository for skills and add to index."""
        found: list[RemoteSkillRecord] = []
        auditor = SkillAuditor()

        for skill_md in repo_dir.rglob("SKILL.md"):
            try:
                package_dir = skill_md.parent
                package = SkillPackage.load(package_dir)
                audit_report = auditor.audit_package(package)

                rel_name = package.skill.name
                owner_repo = ""
                # Parse owner/repo if repo_url is standard github
                m = re.search(r"github\.com[/:]([^/]+/[^/.]+)", repo_url)
                if m:
                    owner_repo = m.group(1)
                    spec = f"{owner_repo}:{rel_name}"
                else:
                    spec = f"{repo_url}:{rel_name}"

                meta_tags = package.skill.metadata.get("tags", []) if isinstance(package.skill.metadata, dict) else []
                record = RemoteSkillRecord(
                    name=package.skill.name,
                    description=package.skill.description,
                    repository=repo_url,
                    spec=spec,
                    author=owner_repo.split("/")[0] if "/" in owner_repo else "unknown",
                    version="1.0.0",
                    tags=list(meta_tags),
                    verified=audit_report.score >= 90,
                    security_score=audit_report.score,
                )
                self.add_or_update(record)
                found.append(record)
            except Exception:
                continue

        self.save_index()
        return found

    def sync_from_url(self, url: str) -> int:
        """Fetch remote index JSON from a remote URL."""
        if not (url.startswith("https://") or url.startswith("http://")):
            raise RemoteIndexError(f"Index URL must use HTTP or HTTPS: {url}")

        try:
            req = urllib.request.Request(url, headers={"User-Agent": "SkillForge/0.5.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode("utf-8"))

            items = data.get("skills", [])
            for item in items:
                self.add_or_update(RemoteSkillRecord.from_dict(item))
            self.save_index()
            return len(items)
        except Exception as exc:
            raise RemoteIndexError(f"Failed to fetch remote index from {url}: {exc}") from exc

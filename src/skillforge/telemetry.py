"""Offline-only local skill usage telemetry and pointer-token waste analyzer."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .skill import SkillPackage

DEFAULT_TELEMETRY_REL = Path(".skillforge") / "telemetry.jsonl"


def is_telemetry_disabled() -> bool:
    """Honor DO_NOT_TRACK=1 and SKILLFORGE_DISABLE_TELEMETRY=1."""
    if os.environ.get("DO_NOT_TRACK", "").strip().lower() in ("1", "true", "yes"):
        return True
    if os.environ.get("SKILLFORGE_DISABLE_TELEMETRY", "").strip().lower() in ("1", "true", "yes"):
        return True
    return False


def resolve_telemetry_path(project_root: Path | None = None) -> Path:
    """Return configured JSONL telemetry file path."""
    env_path = os.environ.get("SKILLFORGE_TELEMETRY_PATH", "").strip()
    if env_path:
        return Path(env_path)
    base = project_root or Path(".")
    return base / DEFAULT_TELEMETRY_REL


@dataclass(frozen=True, slots=True)
class TelemetryEvent:
    """Single local OpenTelemetry-aligned usage record for a skill or MCP call."""

    timestamp: str
    event_type: str
    skill_name: str
    tokens_loaded: int
    duration_ms: float
    status: str

    def to_json_line(self) -> str:
        return json.dumps(
            {
                "timestamp": self.timestamp,
                "event_type": self.event_type,
                "skill_name": self.skill_name,
                "tokens_loaded": self.tokens_loaded,
                "duration_ms": round(self.duration_ms, 3),
                "status": self.status,
            }
        )


def record_telemetry_event(
    event_type: str,
    skill_name: str,
    tokens_loaded: int = 0,
    duration_ms: float = 0.0,
    status: str = "ok",
    log_path: Path | None = None,
) -> Path | None:
    """Append a usage event to the local JSONL ledger unless opted out."""
    if is_telemetry_disabled():
        return None
    target = log_path or resolve_telemetry_path()
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        ev = TelemetryEvent(
            timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            event_type=event_type,
            skill_name=skill_name,
            tokens_loaded=tokens_loaded,
            duration_ms=duration_ms,
            status=status,
        )
        with open(target, "a", encoding="utf-8") as handle:
            handle.write(ev.to_json_line() + "\n")
        return target
    except OSError:
        return None


def summarize_telemetry(
    log_path: Path,
    installed_packages: dict[str, SkillPackage] | None = None,
) -> dict[str, Any]:
    """Aggregate usage counts, loaded tokens, error rates, and unused pointer-token waste."""
    events: list[dict[str, Any]] = []
    if log_path.is_file():
        for raw_line in log_path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line:
                continue
            try:
                parsed = json.loads(line)
                if isinstance(parsed, dict):
                    events.append(parsed)
            except json.JSONDecodeError:
                continue

    per_skill: dict[str, dict[str, Any]] = {}
    for ev in events:
        name = str(ev.get("skill_name", "unknown"))
        stats = per_skill.setdefault(
            name,
            {
                "skill": name,
                "calls": 0,
                "errors": 0,
                "tokens_loaded": 0,
                "total_duration_ms": 0.0,
            },
        )
        stats["calls"] += 1
        if str(ev.get("status", "ok")) != "ok":
            stats["errors"] += 1
        stats["tokens_loaded"] += int(ev.get("tokens_loaded", 0) or 0)
        stats["total_duration_ms"] += float(ev.get("duration_ms", 0.0) or 0.0)

    ranked_usage: list[dict[str, Any]] = []
    for item in sorted(per_skill.values(), key=lambda x: (-x["calls"], x["skill"])):
        calls = max(1, item["calls"])
        ranked_usage.append(
            {
                "skill": item["skill"],
                "calls": item["calls"],
                "errors": item["errors"],
                "tokens_loaded": item["tokens_loaded"],
                "avg_duration_ms": round(item["total_duration_ms"] / calls, 2),
            }
        )

    unused_skills: list[dict[str, Any]] = []
    if installed_packages:
        used_names = set(per_skill.keys())
        for name, pkg in sorted(installed_packages.items()):
            if name not in used_names:
                unused_skills.append(
                    {
                        "skill": name,
                        "startup_pointer_tokens": pkg.skill.pointer_tokens,
                    }
                )

    return {
        "log_path": str(log_path),
        "total_events": len(events),
        "unique_skills_used": len(per_skill),
        "usage": ranked_usage,
        "unused_skills": unused_skills,
        "unused_pointer_tokens_per_turn": sum(u["startup_pointer_tokens"] for u in unused_skills),
    }


def render_telemetry_report(summary: dict[str, Any]) -> str:
    """Format telemetry summary as plain terminal output."""
    lines = [
        f"SkillForge Local Telemetry Report ({summary['log_path']})",
        f"  Total Events:       {summary['total_events']}",
        f"  Active Skills Used: {summary['unique_skills_used']}",
        f"  Unused Turn Overhead: ~{summary['unused_pointer_tokens_per_turn']} pointer tokens/turn",
    ]
    if summary["usage"]:
        lines.append("\nTop Used Skills:")
        for row in summary["usage"]:
            lines.append(
                f"  * {row['skill']}: {row['calls']} call(s), "
                f"~{row['tokens_loaded']} tok loaded, avg {row['avg_duration_ms']}ms, {row['errors']} error(s)"
            )
    if summary["unused_skills"]:
        lines.append("\nInstalled Skills With 0 Recorded Invocations:")
        for u in summary["unused_skills"]:
            lines.append(f"  - {u['skill']} ({u['startup_pointer_tokens']} startup pointer tokens/turn)")
    return "\n".join(lines)

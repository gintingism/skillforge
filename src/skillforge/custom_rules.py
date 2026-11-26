"""Declarative custom YAML / YARA-style rule packs for offline SkillForge security auditing."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .errors import SecurityAuditError
from .security import AuditFinding, AuditReport, Severity
from .skill import SkillPackage


@dataclass(frozen=True, slots=True)
class CustomRule:
    """Single user-defined offline detection rule (regex or YARA-style multi-string condition)."""

    id: str
    severity: Severity
    message: str
    patterns: tuple[re.Pattern[str], ...] = field(default_factory=tuple)
    strings: tuple[str, ...] = field(default_factory=tuple)
    condition: str = "any"  # "any" or "all"
    file_globs: tuple[str, ...] = field(default_factory=tuple)


def load_custom_rule_pack(path: Path) -> list[CustomRule]:
    """Load a YAML rule pack containing custom security rules."""
    if not path.is_file():
        raise SecurityAuditError(f"Custom rule pack not found: {path}")
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise SecurityAuditError(f"Failed to parse custom rule pack {path}: {exc}") from exc

    if not isinstance(raw, dict) or not isinstance(raw.get("rules"), list):
        raise SecurityAuditError("Custom rule pack YAML must contain a top-level 'rules' list")

    rules: list[CustomRule] = []
    for idx, entry in enumerate(raw["rules"]):
        if not isinstance(entry, dict):
            continue
        rule_id = str(entry.get("id", f"CUSTOM-{idx + 1:03d}")).strip()
        sev_raw = str(entry.get("severity", "HIGH")).strip().upper()
        try:
            severity = Severity(sev_raw)
        except ValueError as exc:
            raise SecurityAuditError(f"Invalid severity '{sev_raw}' in rule '{rule_id}'") from exc
        message = str(entry.get("message", f"Custom rule {rule_id} matched")).strip()
        condition = str(entry.get("condition", "any")).strip().lower()
        if condition not in ("any", "all"):
            raise SecurityAuditError(f"Invalid condition '{condition}' in rule '{rule_id}' (use 'any' or 'all')")

        compiled_patterns: list[re.Pattern[str]] = []
        raw_patterns = entry.get("patterns")
        if isinstance(entry.get("pattern"), str):
            raw_patterns = [entry["pattern"]]
        if isinstance(raw_patterns, list):
            for pat in raw_patterns:
                if isinstance(pat, str) and pat:
                    try:
                        compiled_patterns.append(re.compile(pat, re.IGNORECASE))
                    except re.error as exc:
                        raise SecurityAuditError(f"Invalid regex in rule '{rule_id}': {exc}") from exc

        raw_strings = entry.get("strings", [])
        str_list = tuple(str(s) for s in raw_strings if isinstance(s, str) and s) if isinstance(raw_strings, list) else ()
        raw_globs = entry.get("files", [])
        glob_list = tuple(str(g) for g in raw_globs if isinstance(g, str) and g) if isinstance(raw_globs, list) else ()

        if not compiled_patterns and not str_list:
            raise SecurityAuditError(f"Custom rule '{rule_id}' must define 'pattern', 'patterns', or 'strings'")

        rules.append(
            CustomRule(
                id=rule_id,
                severity=severity,
                message=message,
                patterns=tuple(compiled_patterns),
                strings=str_list,
                condition=condition,
                file_globs=glob_list,
            )
        )
    return rules


def evaluate_custom_rules(package: SkillPackage, rules: list[CustomRule]) -> list[AuditFinding]:
    """Evaluate declarative custom rules against SKILL.md, scripts, references, and text assets."""
    if not rules:
        return []

    files_map: dict[str, str] = {"SKILL.md": package.skill.render()}
    for rel, txt in sorted(package.scripts.items()):
        files_map[f"scripts/{rel}"] = txt
    for rel, txt in sorted(package.references.items()):
        files_map[f"references/{rel}"] = txt
    for rel, data in sorted(package.assets.items()):
        try:
            files_map[f"assets/{rel}"] = data.decode("utf-8")
        except UnicodeDecodeError:
            pass

    findings: list[AuditFinding] = []
    for rule in rules:
        for file_label, content in files_map.items():
            if rule.file_globs and not any(Path(file_label).match(g) for g in rule.file_globs):
                continue

            checks: list[tuple[bool, str]] = []
            for pat in rule.patterns:
                m = pat.search(content)
                checks.append((m is not None, m.group(0)[:80] if m else ""))
            lower_content = content.lower()
            for literal in rule.strings:
                hit = literal.lower() in lower_content
                checks.append((hit, literal[:80] if hit else ""))

            matched = all(flag for flag, _ in checks) if rule.condition == "all" else any(flag for flag, _ in checks)
            if matched:
                snippet = next((snip for flag, snip in checks if flag and snip), None)
                findings.append(
                    AuditFinding(
                        rule_id=rule.id,
                        severity=rule.severity,
                        message=rule.message,
                        file=file_label,
                        snippet=snippet,
                    )
                )
    return findings


def merge_custom_rule_findings(report: AuditReport, package: SkillPackage, rules: list[CustomRule]) -> AuditReport:
    """Append custom rule pack findings onto an existing AuditReport."""
    extra = evaluate_custom_rules(package, rules)
    if extra:
        report.findings.extend(extra)
    return report

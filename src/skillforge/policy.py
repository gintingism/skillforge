"""Policy-as-code evaluation and scoped rule suppression for security audits."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any

import yaml

from .errors import SkillForgeError
from .security import AuditFinding, AuditReport, Severity


class PolicyError(SkillForgeError):
    """Raised when a policy file cannot be parsed or fails validation."""


@dataclass(frozen=True, slots=True)
class SuppressionEntry:
    """A scoped audit rule suppression with a required justification and optional expiration."""

    rule_id: str
    target: str
    reason: str
    expires_at: str | None = None

    def is_expired(self, reference_date: date | None = None) -> bool:
        """Return True if expires_at is set and strictly earlier than reference_date."""
        if not self.expires_at:
            return False
        ref = reference_date or datetime.now(timezone.utc).date()
        exp = date.fromisoformat(self.expires_at)
        return ref > exp


@dataclass
class SecurityPolicy:
    """Declarative audit policy read from .skillforge-policy.yaml."""

    version: str = "1.0"
    min_score: int = 80
    disable_rules: set[str] = field(default_factory=set)
    severity_overrides: dict[str, Severity] = field(default_factory=dict)
    suppressions: list[SuppressionEntry] = field(default_factory=list)

    @staticmethod
    def default_template() -> str:
        """Return a starter .skillforge-policy.yaml template."""
        return (
            'version: "1.0"\n'
            "min_score: 80\n"
            "disable_rules: []\n"
            "severity_overrides: {}\n"
            "suppressions:\n"
            "  # Example scoped suppression with required reason and expiry date:\n"
            "  # - rule_id: SEC-012\n"
            '  #   target: "legacy-helper*"\n'
            '  #   reason: "Reviewed wrapper pending migration to references/"\n'
            '  #   expires_at: "2027-06-01"\n'
        )

    @classmethod
    def load(cls, path: Path) -> "SecurityPolicy":
        """Load and validate a YAML security policy file."""
        if not path.is_file():
            raise PolicyError(f"Policy file not found: {path}")
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            raise PolicyError(f"Failed to parse policy file {path}: {exc}") from exc

        if raw is None:
            return cls()
        if not isinstance(raw, dict):
            raise PolicyError(f"Policy file {path} must define a YAML mapping")

        version = str(raw.get("version", "1.0"))
        min_score_raw = raw.get("min_score", 80)
        if not isinstance(min_score_raw, int) or isinstance(min_score_raw, bool) or not (0 <= min_score_raw <= 100):
            raise PolicyError("Policy field 'min_score' must be an integer between 0 and 100")

        disable_raw = raw.get("disable_rules", [])
        if disable_raw is None:
            disable_raw = []
        if not isinstance(disable_raw, list):
            raise PolicyError("Policy field 'disable_rules' must be a list of rule IDs")
        disable_rules = {str(item).strip().upper() for item in disable_raw if str(item).strip()}

        overrides_raw = raw.get("severity_overrides", {})
        if overrides_raw is None:
            overrides_raw = {}
        if not isinstance(overrides_raw, dict):
            raise PolicyError("Policy field 'severity_overrides' must be a mapping of rule_id -> Severity")
        severity_overrides: dict[str, Severity] = {}
        for rule_key, sev_val in overrides_raw.items():
            clean_rule = str(rule_key).strip().upper()
            clean_sev = str(sev_val).strip().upper()
            try:
                severity_overrides[clean_rule] = Severity(clean_sev)
            except ValueError as exc:
                raise PolicyError(
                    f"Invalid severity '{sev_val}' in severity_overrides for '{clean_rule}'"
                ) from exc

        suppressions_raw = raw.get("suppressions", [])
        if suppressions_raw is None:
            suppressions_raw = []
        if not isinstance(suppressions_raw, list):
            raise PolicyError("Policy field 'suppressions' must be a list")

        suppressions: list[SuppressionEntry] = []
        for idx, entry in enumerate(suppressions_raw):
            if not isinstance(entry, dict):
                raise PolicyError(f"Suppression entry at index {idx} must be a mapping")
            rule_id = str(entry.get("rule_id", "")).strip().upper()
            target = str(entry.get("target", "*")).strip()
            reason = str(entry.get("reason", "")).strip()
            expires_raw = entry.get("expires_at")
            expires_at = str(expires_raw).strip() if expires_raw is not None and str(expires_raw).strip() else None

            if not rule_id:
                raise PolicyError(f"Suppression entry at index {idx} is missing 'rule_id'")
            if not reason:
                raise PolicyError(f"Suppression entry for '{rule_id}' must provide a non-empty 'reason'")
            if expires_at is not None:
                try:
                    date.fromisoformat(expires_at)
                except ValueError as exc:
                    raise PolicyError(
                        f"Suppression entry for '{rule_id}' has invalid ISO date '{expires_at}' (expected YYYY-MM-DD)"
                    ) from exc

            suppressions.append(
                SuppressionEntry(
                    rule_id=rule_id,
                    target=target or "*",
                    reason=reason,
                    expires_at=expires_at,
                )
            )

        return cls(
            version=version,
            min_score=min_score_raw,
            disable_rules=disable_rules,
            severity_overrides=severity_overrides,
            suppressions=suppressions,
        )


@dataclass
class PolicyEvaluationResult:
    """Evaluated audit report after applying policy suppressions, overrides, and score threshold."""

    report: AuditReport
    suppressed_findings: list[tuple[AuditFinding, SuppressionEntry]] = field(default_factory=list)
    expired_suppressions: list[SuppressionEntry] = field(default_factory=list)
    min_score: int = 80

    @property
    def passed(self) -> bool:
        """Pass only if active audit passes and resulting score meets min_score."""
        return self.report.passed and self.report.score >= self.min_score

    def to_dict(self) -> dict[str, Any]:
        """Serialize policy evaluation result to a dictionary."""
        data = self.report.to_dict()
        data["policy_passed"] = self.passed
        data["min_score"] = self.min_score
        data["suppressed_count"] = len(self.suppressed_findings)
        data["suppressed_findings"] = [
            {
                "rule_id": finding.rule_id,
                "file": finding.file,
                "reason": entry.reason,
                "target": entry.target,
                "expires_at": entry.expires_at,
            }
            for finding, entry in self.suppressed_findings
        ]
        data["expired_suppressions"] = [
            {
                "rule_id": entry.rule_id,
                "target": entry.target,
                "reason": entry.reason,
                "expires_at": entry.expires_at,
            }
            for entry in self.expired_suppressions
        ]
        return data

    def render_text(self) -> str:
        """Render terminal summary including active and suppressed findings."""
        lines = [self.report.render_text()]
        status = "PASSED" if self.passed else "FAILED"
        lines.append(
            f"Policy Gate: {status} (Score: {self.report.score}/100, Min Required: {self.min_score}, "
            f"Suppressed: {len(self.suppressed_findings)})"
        )
        if self.suppressed_findings:
            lines.append("Suppressed Findings:")
            for finding, entry in self.suppressed_findings:
                lines.append(
                    f"  [SUPPRESSED] {finding.rule_id} ({finding.file}) target='{entry.target}' reason='{entry.reason}'"
                )
        if self.expired_suppressions:
            lines.append("Expired Suppressions (re-activated):")
            for entry in self.expired_suppressions:
                lines.append(
                    f"  [EXPIRED] {entry.rule_id} target='{entry.target}' expired_at={entry.expires_at}"
                )
        return "\n".join(lines)


def apply_policy(
    report: AuditReport,
    policy: SecurityPolicy,
    reference_date: date | None = None,
) -> PolicyEvaluationResult:
    """Filter disabled/suppressed rules and override severities according to policy."""
    active_suppressions: list[SuppressionEntry] = []
    expired_suppressions: list[SuppressionEntry] = []

    for entry in policy.suppressions:
        if entry.is_expired(reference_date):
            expired_suppressions.append(entry)
        else:
            active_suppressions.append(entry)

    kept_findings: list[AuditFinding] = []
    suppressed_findings: list[tuple[AuditFinding, SuppressionEntry]] = []

    for finding in report.findings:
        rule_upper = finding.rule_id.upper()
        if rule_upper in policy.disable_rules:
            suppressed_findings.append(
                (
                    finding,
                    SuppressionEntry(
                        rule_id=rule_upper,
                        target=report.target,
                        reason="Disabled globally in policy disable_rules",
                    ),
                )
            )
            continue

        matched_entry: SuppressionEntry | None = None
        for entry in active_suppressions:
            if entry.rule_id != rule_upper:
                continue
            if fnmatchcase(report.target, entry.target) or fnmatchcase(finding.file, entry.target):
                matched_entry = entry
                break

        if matched_entry is not None:
            suppressed_findings.append((finding, matched_entry))
            continue

        new_severity = policy.severity_overrides.get(rule_upper, finding.severity)
        if new_severity != finding.severity:
            kept_findings.append(
                AuditFinding(
                    rule_id=finding.rule_id,
                    severity=new_severity,
                    message=finding.message,
                    file=finding.file,
                    line=finding.line,
                    snippet=finding.snippet,
                )
            )
        else:
            kept_findings.append(finding)

    filtered_report = AuditReport(
        target=report.target,
        findings=kept_findings,
        pointer_tokens=report.pointer_tokens,
        body_tokens=report.body_tokens,
        body_lines=report.body_lines,
    )
    return PolicyEvaluationResult(
        report=filtered_report,
        suppressed_findings=suppressed_findings,
        expired_suppressions=expired_suppressions,
        min_score=policy.min_score,
    )

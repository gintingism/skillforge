"""Skill evaluation and trigger accuracy test runner."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

from .errors import SkillForgeError
from .security import Severity, SkillAuditor
from .skill import SkillPackage


@dataclass(frozen=True, slots=True)
class TestCaseResult:
    """Result of an individual eval test case."""

    case_id: str
    prompt: str
    should_trigger: bool
    passed: bool
    reason: str


@dataclass
class EvalSuiteReport:
    """Summary of an evaluation suite run."""

    skill_name: str
    total_cases: int
    passed_cases: int
    failed_cases: int
    results: list[TestCaseResult] = field(default_factory=list)
    security_passed: bool = True
    security_error: str | None = None

    @property
    def passed(self) -> bool:
        return self.failed_cases == 0 and self.security_passed

    def to_dict(self) -> dict[str, Any]:
        return {
            "skill": self.skill_name,
            "passed": self.passed,
            "total_cases": self.total_cases,
            "passed_cases": self.passed_cases,
            "failed_cases": self.failed_cases,
            "security_passed": self.security_passed,
            "security_error": self.security_error,
            "results": [
                {
                    "case_id": r.case_id,
                    "prompt": r.prompt,
                    "should_trigger": r.should_trigger,
                    "passed": r.passed,
                    "reason": r.reason,
                }
                for r in self.results
            ],
        }

    def render_text(self) -> str:
        status_str = "PASSED" if self.passed else "FAILED"
        lines = [
            f"Skill Test Suite: {self.skill_name} ({self.total_cases} test cases)",
            f"Overall Status:   {status_str} ({self.passed_cases}/{self.total_cases} passed)",
        ]
        if not self.security_passed:
            lines.append(f"  Security Gate:  FAILED ({self.security_error})")
        else:
            lines.append("  Security Gate:  PASSED")

        lines.append("\nTest Cases:")
        for r in self.results:
            icon = "✓" if r.passed else "✗"
            expected = "should_trigger=True" if r.should_trigger else "should_trigger=False"
            lines.append(f"  {icon} [{r.case_id}] ({expected}): {r.reason}")
            if not r.passed:
                lines.append(f"      Prompt: {r.prompt[:80]}")

        return "\n".join(lines)


_STOPWORDS = frozenset({
    "use", "when", "for", "and", "the", "with", "this", "that", "you",
    "your", "will", "from", "are", "have", "been", "also", "into",
    "before", "after", "during", "while", "working", "tasks", "task",
    "skill", "skills", "agent", "agents", "using", "asked", "need",
    "needed", "doing", "executing", "operations", "actions", "make",
    "making", "existing", "new", "all", "any", "only", "across", "every",
})


def _normalize_token(word: str) -> str:
    """Normalize English technical word inflections to a canonical stem."""
    if len(word) <= 4:
        return word
    if word.endswith("ies") and len(word) > 5:
        return word[:-3] + "y"
    if word.endswith("ations") and len(word) > 8:
        return word[:-6] + "e"
    if word.endswith("ation") and len(word) > 7:
        return word[:-5] + "e"
    for suffix in ("ing", "ers", "er", "ed", "es", "s"):
        if word.endswith(suffix) and len(word) - len(suffix) >= 4:
            stem = word[: -len(suffix)]
            if len(stem) >= 4 and stem[-1] == stem[-2] and stem[-1] not in "lsz":
                stem = stem[:-1]
            return stem
    return word


def _tokenize_with_stems(text: str) -> set[str]:
    """Extract lowercase words and their normalized stems, excluding stopwords."""
    raw_words = [w for w in re.findall(r"\b[a-z]{3,}\b", text.lower()) if w not in _STOPWORDS]
    tokens = set(raw_words)
    for w in raw_words:
        stem = _normalize_token(w)
        if stem not in _STOPWORDS:
            tokens.add(stem)
    return tokens


def _extract_trigger_keywords(description: str, name: str) -> set[str]:
    """Extract domain trigger tokens from skill name and description."""
    return _tokenize_with_stems(f"{name} {description}")


def detect_trigger_collisions(
    packages: Mapping[str, SkillPackage],
    threshold: float = 0.5,
) -> list[dict[str, Any]]:
    """Detect high trigger-keyword overlap between active model-invoked skills."""
    skill_tokens: dict[str, set[str]] = {}
    for name, pkg in sorted(packages.items()):
        if pkg.skill.disable_model_invocation:
            continue
        raw = [
            _normalize_token(w)
            for w in re.findall(r"\b[a-z]{3,}\b", f"{pkg.skill.name} {pkg.skill.description}".lower())
            if w not in _STOPWORDS
        ]
        cleaned = {w for w in raw if w not in _STOPWORDS}
        if cleaned:
            skill_tokens[name] = cleaned

    names = sorted(skill_tokens)
    collisions: list[dict[str, Any]] = []
    for i, name_a in enumerate(names):
        for name_b in names[i + 1 :]:
            set_a = skill_tokens[name_a]
            set_b = skill_tokens[name_b]
            shared = sorted(set_a & set_b)
            min_len = min(len(set_a), len(set_b))
            if len(shared) >= 3 and min_len > 0:
                ratio = round(len(shared) / min_len, 2)
                if ratio >= threshold:
                    collisions.append(
                        {
                            "skill_a": name_a,
                            "skill_b": name_b,
                            "overlap_ratio": ratio,
                            "shared_triggers": shared,
                        }
                    )
    return collisions


def init_evals(package_dir: Path) -> Path:
    """Scaffold a starter evals/evals.json inside the skill directory."""
    evals_dir = package_dir / "evals"
    evals_dir.mkdir(parents=True, exist_ok=True)
    evals_file = evals_dir / "evals.json"

    skill_md = package_dir / "SKILL.md"
    name = package_dir.name
    desc = f"Use when working with {name} tasks"
    if skill_md.is_file():
        pkg = SkillPackage.load(package_dir)
        name = pkg.skill.name
        desc = pkg.skill.description

    starter_evals = [
        {
            "id": f"trigger_positive_core_{name}",
            "prompt": f"Please help me with {name} following our established workflow.",
            "should_trigger": True,
        },
        {
            "id": f"trigger_positive_task",
            "prompt": f"I need to execute a task: {desc[:60]}",
            "should_trigger": True,
        },
        {
            "id": "suppress_negative_unrelated_math",
            "prompt": "Calculate the Fibonacci sequence for n=30 in Python.",
            "should_trigger": False,
        },
        {
            "id": "suppress_negative_greeting",
            "prompt": "Hello there, what is the weather like in Tokyo today?",
            "should_trigger": False,
        },
    ]

    evals_file.write_text(json.dumps(starter_evals, indent=2), encoding="utf-8")
    return evals_file


def run_evals(package_dir: Path, evals_path: Path | None = None) -> EvalSuiteReport:
    """Run evaluation test suite against a skill package."""
    pkg = SkillPackage.load(package_dir)
    target_evals = evals_path or (package_dir / "evals" / "evals.json")

    if not target_evals.is_file():
        raise SkillForgeError(
            f"No evals found at {target_evals}. Run 'skillforge test {package_dir} --init' to scaffold one."
        )

    try:
        raw_cases = json.loads(target_evals.read_text(encoding="utf-8"))
    except Exception as exc:
        raise SkillForgeError(f"Failed to read evals JSON at {target_evals}: {exc}") from exc

    if not isinstance(raw_cases, list) or not raw_cases:
        raise SkillForgeError(f"Evals file {target_evals} must contain a non-empty array of test cases.")

    # 1. Security check
    auditor = SkillAuditor()
    audit_report = auditor.audit_package(pkg)
    sec_passed = audit_report.passed
    sec_error = None
    if not sec_passed:
        bad_rules = [f.rule_id for f in audit_report.findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
        sec_error = f"Security findings: {', '.join(bad_rules)}"

    # 2. Extract trigger keywords
    trigger_words = _extract_trigger_keywords(pkg.skill.description, pkg.skill.name)

    results: list[TestCaseResult] = []
    passed_count = 0
    failed_count = 0

    for idx, case in enumerate(raw_cases):
        if not isinstance(case, dict):
            continue
        case_id = str(case.get("id") or f"case_{idx + 1}")
        prompt = str(case.get("prompt", ""))
        should_trigger = bool(case.get("should_trigger", True))
        expected_kw = [str(k).lower() for k in case.get("expected_keywords", [])]
        forbidden_kw = [str(k).lower() for k in case.get("forbidden_keywords", [])]

        prompt_words = _tokenize_with_stems(prompt)
        matched_trigger = bool(prompt_words.intersection(trigger_words))

        case_passed = True
        reasons: list[str] = []

        if should_trigger and not matched_trigger:
            case_passed = False
            reasons.append("Prompt failed to match any skill trigger keyword (False Negative)")
        elif not should_trigger and matched_trigger:
            case_passed = False
            reasons.append("Prompt inadvertently matched skill triggers (False Positive)")
        else:
            reasons.append("Trigger activation matched expectation")

        for kw in expected_kw:
            if kw not in prompt.lower() and kw not in pkg.skill.body.lower():
                case_passed = False
                reasons.append(f"Missing expected keyword '{kw}'")

        for kw in forbidden_kw:
            if kw in prompt.lower() or kw in pkg.skill.body.lower():
                case_passed = False
                reasons.append(f"Contains forbidden keyword '{kw}'")

        if case_passed:
            passed_count += 1
        else:
            failed_count += 1

        results.append(
            TestCaseResult(
                case_id=case_id,
                prompt=prompt,
                should_trigger=should_trigger,
                passed=case_passed,
                reason="; ".join(reasons),
            )
        )

    return EvalSuiteReport(
        skill_name=pkg.skill.name,
        total_cases=len(results),
        passed_cases=passed_count,
        failed_cases=failed_count,
        results=results,
        security_passed=sec_passed,
        security_error=sec_error,
    )

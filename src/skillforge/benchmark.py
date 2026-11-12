"""Multi-model semantic trigger benchmark matrix for agent skills.

Evaluates skill activation precision, recall, F1 score, and false positive rate
across multiple routing profiles modeling major LLM agent hosts.
"""

from __future__ import annotations

import json
import math
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from .errors import SkillForgeError
from .evals import _STOPWORDS, _normalize_token, _tokenize_with_stems
from .skill import SkillPackage


@dataclass(frozen=True, slots=True)
class ProfileMetrics:
    """Quantitative trigger benchmark metrics for a single routing profile."""

    profile_name: str
    tp: int
    fp: int
    tn: int
    fn: int
    precision: float
    recall: float
    f1_score: float
    false_positive_rate: float
    latency_ms: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "profile": self.profile_name,
            "tp": self.tp,
            "fp": self.fp,
            "tn": self.tn,
            "fn": self.fn,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1_score": round(self.f1_score, 4),
            "false_positive_rate": round(self.false_positive_rate, 4),
            "latency_ms": round(self.latency_ms, 3),
        }


@dataclass
class SkillBenchmarkReport:
    """Cross-profile trigger benchmark report for a skill package."""

    skill_name: str
    total_cases: int
    profiles: list[ProfileMetrics] = field(default_factory=list)

    @property
    def macro_f1(self) -> float:
        if not self.profiles:
            return 0.0
        return sum(p.f1_score for p in self.profiles) / len(self.profiles)

    @property
    def max_fpr(self) -> float:
        if not self.profiles:
            return 0.0
        return max(p.false_positive_rate for p in self.profiles)

    @property
    def passed(self) -> bool:
        return self.macro_f1 >= 0.75 and self.max_fpr <= 0.25

    def to_dict(self) -> dict[str, Any]:
        return {
            "skill": self.skill_name,
            "passed": self.passed,
            "total_cases": self.total_cases,
            "macro_f1": round(self.macro_f1, 4),
            "max_false_positive_rate": round(self.max_fpr, 4),
            "profiles": [p.to_dict() for p in self.profiles],
        }

    def render_text(self) -> str:
        status = "PASSED" if self.passed else "FAILED"
        lines = [
            f"Skill Trigger Benchmark: {self.skill_name} ({self.total_cases} cases)",
            f"Overall Status:          {status} (Macro F1: {self.macro_f1:.2%}, Max FPR: {self.max_fpr:.2%})",
            "",
            f"  {'Profile':<24} {'Prec':>7} {'Recall':>7} {'F1':>7} {'FPR':>7} {'TP/FP/TN/FN':>14} {'Latency':>9}",
            "  " + "-" * 80,
        ]
        for p in self.profiles:
            counts = f"{p.tp}/{p.fp}/{p.tn}/{p.fn}"
            lines.append(
                f"  {p.profile_name:<24} {p.precision:>6.1%} {p.recall:>6.1%} "
                f"{p.f1_score:>6.1%} {p.false_positive_rate:>6.1%} {counts:>14} {p.latency_ms:>7.2f}ms"
            )
        return "\n".join(lines)


def _extract_bigrams(text: str) -> set[tuple[str, str]]:
    words = [
        _normalize_token(w)
        for w in re.findall(r"\b[a-z0-9]{2,}\b", text.lower())
        if w not in _STOPWORDS
    ]
    if len(words) < 2:
        return set()
    return {(words[i], words[i + 1]) for i in range(len(words) - 1)}


def _profile_lexical_stem(skill_name: str, description: str, prompt: str) -> bool:
    """Fast stem intersection matcher (Gemini Flash / lightweight router style)."""
    skill_tokens = _tokenize_with_stems(f"{skill_name.replace('-', ' ')} {description}")
    prompt_tokens = _tokenize_with_stems(prompt)
    if skill_name.lower() in prompt.lower():
        return True
    return len(skill_tokens & prompt_tokens) >= 1


def _profile_semantic_weighted(skill_name: str, description: str, prompt: str) -> bool:
    """Weighted semantic scorer (Claude Sonnet router style: stems + bigrams + trigger clauses)."""
    if skill_name.lower() in prompt.lower():
        return True
    name_parts = set(_tokenize_with_stems(skill_name.replace("-", " ")))
    desc_tokens = _tokenize_with_stems(description)
    prompt_tokens = _tokenize_with_stems(prompt)

    name_hits = len(name_parts & prompt_tokens)
    desc_hits = len(desc_tokens & prompt_tokens)
    bigram_hits = len(_extract_bigrams(f"{skill_name.replace('-', ' ')} {description}") & _extract_bigrams(prompt))

    score = (name_hits * 1.5) + (desc_hits * 0.8) + (bigram_hits * 2.0)
    return score >= 1.2


def _profile_strict_precision(skill_name: str, description: str, prompt: str) -> bool:
    """High-specificity router (GPT strict tool selector style: minimizes false positives)."""
    if skill_name.lower() in prompt.lower():
        return True
    skill_tokens = _tokenize_with_stems(f"{skill_name.replace('-', ' ')} {description}")
    prompt_tokens = _tokenize_with_stems(prompt)
    shared = skill_tokens & prompt_tokens
    if len(shared) >= 2:
        return True
    name_tokens = _tokenize_with_stems(skill_name.replace("-", " "))
    return bool(name_tokens and len(name_tokens & prompt_tokens) >= 1 and len(shared) >= 1)


_DEFAULT_PROFILES: dict[str, Callable[[str, str, str], bool]] = {
    "claude-sonnet-router": _profile_semantic_weighted,
    "gemini-flash-router": _profile_lexical_stem,
    "gpt-strict-router": _profile_strict_precision,
}


def _default_benchmark_cases(pkg: SkillPackage) -> list[dict[str, Any]]:
    """Generate a balanced 8-case positive and negative benchmark suite if evals.json is absent."""
    name = pkg.skill.name
    readable_name = name.replace("-", " ")
    desc = pkg.skill.description
    desc_Tokens = sorted(_tokenize_with_stems(desc))
    kw_sample = " ".join(desc_Tokens[:4]) if desc_Tokens else readable_name

    return [
        {
            "id": "pos_explicit_name",
            "prompt": f"Apply the {name} workflow to inspect our repository.",
            "should_trigger": True,
        },
        {
            "id": "pos_domain_description",
            "prompt": f"We need help with {readable_name}: {desc[:70]}",
            "should_trigger": True,
        },
        {
            "id": "pos_keywords_intent",
            "prompt": f"Please handle {kw_sample} in this module.",
            "should_trigger": True,
        },
        {
            "id": "pos_direct_request",
            "prompt": f"Run {readable_name} checks on the current changes.",
            "should_trigger": True,
        },
        {
            "id": "neg_fibonacci_math",
            "prompt": "Compute the 40th Fibonacci number using memoization in Rust.",
            "should_trigger": False,
        },
        {
            "id": "neg_weather_query",
            "prompt": "What is the average rainfall in Jakarta during November?",
            "should_trigger": False,
        },
        {
            "id": "neg_cooking_recipe",
            "prompt": "Give me a sourdough bread recipe with hydration percentages.",
            "should_trigger": False,
        },
        {
            "id": "neg_css_centering",
            "prompt": "How do I center a div vertically using CSS flexbox?",
            "should_trigger": False,
        },
    ]


def run_benchmark(
    package_dir: Path,
    evals_path: Path | None = None,
) -> SkillBenchmarkReport:
    """Execute the multi-profile trigger benchmark matrix on a skill package."""
    pkg = SkillPackage.load(package_dir)
    target_evals = evals_path or (package_dir / "evals" / "evals.json")

    if target_evals.is_file():
        try:
            cases = json.loads(target_evals.read_text(encoding="utf-8"))
        except Exception as exc:
            raise SkillForgeError(f"Failed to parse evals file {target_evals}: {exc}") from exc
        if not isinstance(cases, list) or not cases:
            raise SkillForgeError(f"Evals file {target_evals} must contain a non-empty list.")
    else:
        cases = _default_benchmark_cases(pkg)

    profile_results: list[ProfileMetrics] = []
    skill_name = pkg.skill.name
    description = pkg.skill.description

    for profile_name, matcher in _DEFAULT_PROFILES.items():
        tp = fp = tn = fn = 0
        start_ns = time.perf_counter_ns()

        for case in cases:
            if not isinstance(case, dict):
                continue
            prompt = str(case.get("prompt", ""))
            should_trigger = bool(case.get("should_trigger", True))
            triggered = matcher(skill_name, description, prompt)

            if should_trigger and triggered:
                tp += 1
            elif should_trigger and not triggered:
                fn += 1
            elif not should_trigger and triggered:
                fp += 1
            else:
                tn += 1

        elapsed_ms = (time.perf_counter_ns() - start_ns) / 1_000_000.0
        precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 1.0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

        profile_results.append(
            ProfileMetrics(
                profile_name=profile_name,
                tp=tp,
                fp=fp,
                tn=tn,
                fn=fn,
                precision=precision,
                recall=recall,
                f1_score=f1,
                false_positive_rate=fpr,
                latency_ms=elapsed_ms,
            )
        )

    return SkillBenchmarkReport(
        skill_name=skill_name,
        total_cases=len(cases),
        profiles=profile_results,
    )

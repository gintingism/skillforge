"""SLSA v1.0 Provenance and in-toto v1 Statement attestation generator and verifier."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import platform
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from skillforge import __version__
from skillforge.errors import SkillForgeError
from skillforge.security import SkillAuditor
from skillforge.signing import SkillSigner
from skillforge.skill import SkillPackage

PROVENANCE_FILENAME = "provenance.intoto.jsonl"
INTOTO_STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
SLSA_PROVENANCE_PREDICATE_TYPE = "https://slsa.dev/provenance/v1"
SKILLFORGE_BUILD_TYPE = "https://skillforge.dev/slsa/skill-package@v1"


class ProvenanceError(SkillForgeError):
    """Raised when provenance generation or verification fails."""


@dataclass
class ProvenanceVerificationResult:
    """Result of verifying a SLSA v1.0 provenance attestation."""

    valid: bool
    skill_name: str
    builder_id: str
    subject_count: int
    signature_verified: bool
    issues: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "skill_name": self.skill_name,
            "builder_id": self.builder_id,
            "subject_count": self.subject_count,
            "signature_verified": self.signature_verified,
            "issues": self.issues,
        }

    def render_text(self) -> str:
        status = "VALID" if self.valid else "INVALID"
        sig_status = "VERIFIED" if self.signature_verified else "UNSIGNED / NOT CHECKED"
        lines = [
            f"SLSA v1.0 Provenance Verification: {status}",
            f"  Skill:      {self.skill_name}",
            f"  Builder ID: {self.builder_id}",
            f"  Subjects:   {self.subject_count} file(s)",
            f"  Signature:  {sig_status}",
        ]
        if self.issues:
            lines.append("  Issues:")
            for issue in self.issues:
                lines.append(f"    - {issue}")
        return "\n".join(lines)


def _detect_builder_environment() -> tuple[str, dict[str, str]]:
    """Detect CI or local builder identity from environment variables."""
    if os.environ.get("GITHUB_ACTIONS") == "true":
        repo = os.environ.get("GITHUB_REPOSITORY", "unknown/repo")
        workflow = os.environ.get("GITHUB_WORKFLOW", "ci")
        run_id = os.environ.get("GITHUB_RUN_ID", "0")
        sha = os.environ.get("GITHUB_SHA", "")
        return (
            f"https://github.com/{repo}/actions/runs/{run_id}",
            {
                "ci_provider": "github-actions",
                "repository": repo,
                "workflow": workflow,
                "run_id": run_id,
                "commit_sha": sha,
            },
        )
    return (
        "https://skillforge.dev/builders/local-cli",
        {
            "ci_provider": "local",
            "python_version": platform.python_version(),
            "platform": platform.system().lower(),
        },
    )


def _canonical_statement_bytes(statement: dict[str, Any]) -> bytes:
    """Serialize an in-toto statement deterministically for HMAC signing."""
    return json.dumps(statement, sort_keys=True, separators=(",", ":")).encode("utf-8")


def generate_provenance(
    skill_dir: Path,
    signing_key: str | None = None,
    signer_id: str = "skillforge-attestor",
) -> dict[str, Any]:
    """Generate an in-toto v1 Statement with SLSA v1.0 Provenance for a skill package."""
    target_dir = skill_dir.parent if skill_dir.is_file() else skill_dir
    if not target_dir.is_dir() or not (target_dir / "SKILL.md").is_file():
        raise ProvenanceError(f"Skill directory with SKILL.md not found: {target_dir}")

    pkg = SkillPackage.load(target_dir)
    manifest = SkillSigner.compute_manifest(target_dir)
    # Exclude provenance file itself from the subject list
    manifest.pop(PROVENANCE_FILENAME, None)

    audit_report = SkillAuditor().audit_package(pkg)
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    builder_id, env_meta = _detect_builder_environment()

    subjects: list[dict[str, Any]] = [
        {
            "name": rel_path,
            "digest": {"sha256": file_sha},
        }
        for rel_path, file_sha in sorted(manifest.items())
    ]

    resolved_deps: list[dict[str, Any]] = [
        {
            "uri": f"pkg:skillforge/{dep}",
            "name": dep,
        }
        for dep in pkg.skill.dependencies
    ]

    statement: dict[str, Any] = {
        "_type": INTOTO_STATEMENT_TYPE,
        "subject": subjects,
        "predicateType": SLSA_PROVENANCE_PREDICATE_TYPE,
        "predicate": {
            "buildDefinition": {
                "buildType": SKILLFORGE_BUILD_TYPE,
                "externalParameters": {
                    "skill_name": pkg.skill.name,
                    "version": str(pkg.skill.metadata.get("version", "0.1.0")),
                    "license": pkg.skill.license or "UNSPECIFIED",
                    "allowed_tools": pkg.skill.allowed_tools or "",
                },
                "internalParameters": {
                    "skillforge_version": __version__,
                    "package_sha256": pkg.compute_sha256(),
                    "security_audit_score": audit_report.score,
                    "security_audit_passed": audit_report.passed,
                    "pointer_tokens": pkg.skill.pointer_tokens,
                    "body_tokens": pkg.skill.body_tokens,
                    **env_meta,
                },
                "resolvedDependencies": resolved_deps,
            },
            "runDetails": {
                "builder": {
                    "id": builder_id,
                    "version": {"skillforge": __version__},
                },
                "metadata": {
                    "invocationId": f"{pkg.skill.name}-{pkg.compute_sha256()[:12]}",
                    "startedOn": now_iso,
                    "finishedOn": now_iso,
                },
            },
        },
    }

    if signing_key is not None:
        if len(signing_key.strip()) < 16:
            raise ProvenanceError("Signing key must be at least 16 characters long.")
        canonical = _canonical_statement_bytes(statement)
        sig_hex = hmac.new(signing_key.encode("utf-8"), canonical, hashlib.sha256).hexdigest()
        return {
            "payloadType": "application/vnd.in-toto+json",
            "statement": statement,
            "signatures": [
                {
                    "keyid": signer_id,
                    "algorithm": "hmac-sha256",
                    "sig": sig_hex,
                }
            ],
        }

    return {
        "payloadType": "application/vnd.in-toto+json",
        "statement": statement,
        "signatures": [],
    }


def write_provenance(
    skill_dir: Path,
    envelope: dict[str, Any],
    output_path: Path | None = None,
) -> Path:
    """Write SLSA provenance envelope to provenance.intoto.jsonl or custom path."""
    target_dir = skill_dir.parent if skill_dir.is_file() else skill_dir
    dest = output_path or (target_dir / PROVENANCE_FILENAME)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(envelope, indent=2), encoding="utf-8")
    return dest


def verify_provenance(
    skill_dir: Path,
    provenance_path: Path | None = None,
    signing_key: str | None = None,
) -> ProvenanceVerificationResult:
    """Verify SLSA v1.0 provenance subject digests and optional HMAC signature against disk."""
    target_dir = skill_dir.parent if skill_dir.is_file() else skill_dir
    prov_file = provenance_path or (target_dir / PROVENANCE_FILENAME)

    if not prov_file.is_file():
        return ProvenanceVerificationResult(
            valid=False,
            skill_name=target_dir.name,
            builder_id="unknown",
            subject_count=0,
            signature_verified=False,
            issues=[f"Provenance file not found: {prov_file.name}"],
        )

    try:
        raw = json.loads(prov_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return ProvenanceVerificationResult(
            valid=False,
            skill_name=target_dir.name,
            builder_id="unknown",
            subject_count=0,
            signature_verified=False,
            issues=[f"Invalid provenance JSON: {exc}"],
        )

    statement = raw.get("statement") if isinstance(raw, dict) and "statement" in raw else raw
    if not isinstance(statement, dict):
        return ProvenanceVerificationResult(
            valid=False,
            skill_name=target_dir.name,
            builder_id="unknown",
            subject_count=0,
            signature_verified=False,
            issues=["Provenance document missing in-toto statement object."],
        )

    issues: list[str] = []
    if statement.get("_type") != INTOTO_STATEMENT_TYPE:
        issues.append(f"Unexpected statement _type: {statement.get('_type')}")
    if statement.get("predicateType") != SLSA_PROVENANCE_PREDICATE_TYPE:
        issues.append(f"Unexpected predicateType: {statement.get('predicateType')}")

    predicate = statement.get("predicate", {})
    build_def = predicate.get("buildDefinition", {}) if isinstance(predicate, dict) else {}
    ext_params = build_def.get("externalParameters", {}) if isinstance(build_def, dict) else {}
    run_details = predicate.get("runDetails", {}) if isinstance(predicate, dict) else {}
    builder = run_details.get("builder", {}) if isinstance(run_details, dict) else {}

    skill_name = str(ext_params.get("skill_name", target_dir.name))
    builder_id = str(builder.get("id", "unknown"))

    subjects = statement.get("subject", [])
    if not isinstance(subjects, list) or not subjects:
        issues.append("Provenance statement contains no subject artifacts.")
        subjects = []

    current_manifest = SkillSigner.compute_manifest(target_dir)
    current_manifest.pop(PROVENANCE_FILENAME, None)
    if provenance_path is not None and provenance_path.parent == target_dir:
        current_manifest.pop(provenance_path.name, None)

    recorded_map: dict[str, str] = {}
    for subj in subjects:
        if isinstance(subj, dict):
            name = str(subj.get("name", ""))
            digest_obj = subj.get("digest", {})
            sha = str(digest_obj.get("sha256", "")) if isinstance(digest_obj, dict) else ""
            if name and sha:
                recorded_map[name] = sha

    for rel_path, expected_sha in recorded_map.items():
        if rel_path not in current_manifest:
            issues.append(f"Subject file missing from disk: {rel_path}")
        elif current_manifest[rel_path] != expected_sha:
            issues.append(f"Subject digest mismatch for {rel_path}")

    for rel_path in current_manifest:
        if rel_path not in recorded_map:
            issues.append(f"Unattested file present in skill directory: {rel_path}")

    sig_verified = False
    signatures = raw.get("signatures", []) if isinstance(raw, dict) else []
    if signing_key is not None:
        if not signatures or not isinstance(signatures, list):
            issues.append("Signing key provided, but provenance envelope contains no signatures.")
        else:
            canonical = _canonical_statement_bytes(statement)
            expected_hmac = hmac.new(
                signing_key.encode("utf-8"), canonical, hashlib.sha256
            ).hexdigest()
            first_sig = signatures[0].get("sig", "") if isinstance(signatures[0], dict) else ""
            if hmac.compare_digest(expected_hmac, str(first_sig)):
                sig_verified = True
            else:
                issues.append("Provenance cryptographic HMAC signature mismatch.")

    return ProvenanceVerificationResult(
        valid=len(issues) == 0,
        skill_name=skill_name,
        builder_id=builder_id,
        subject_count=len(recorded_map),
        signature_verified=sig_verified,
        issues=issues,
    )

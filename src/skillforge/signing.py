"""Cryptographic signing and verification for skill packages and lockfiles.

Provides tamper-evident HMAC-SHA256 signatures over skill file manifests.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from skillforge.errors import SkillForgeError

SIGNATURE_FILENAME = "SKILL.sig"
LOCK_SIGNATURE_FILENAME = "skillforge.lock.sig"
IGNORED_PATTERNS = {
    SIGNATURE_FILENAME,
    LOCK_SIGNATURE_FILENAME,
    ".git",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".DS_Store",
    "Thumbs.db",
}


class SigningError(SkillForgeError):
    """Raised when signing or verification fails."""


@dataclass
class VerificationResult:
    """Result of verifying a skill signature."""

    valid: bool
    signer_id: str
    algorithm: str
    created_at: str
    file_count: int
    issues: list[str] = field(default_factory=list)

    @property
    def summary(self) -> str:
        if self.valid:
            return f"VALID (algorithm: {self.algorithm}, signer: {self.signer_id}, files: {self.file_count})"
        return f"INVALID ({len(self.issues)} issue(s): {'; '.join(self.issues)})"


class SkillSigner:
    """Handles cryptographic signing and tamper-verification of skills."""

    @staticmethod
    def generate_key() -> str:
        """Generate a cryptographically secure 256-bit hex secret key."""
        return secrets.token_hex(32)

    @staticmethod
    def _hash_file(file_path: Path) -> str:
        """Compute SHA-256 digest of a file in streaming chunks."""
        hasher = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        return hasher.hexdigest()

    @classmethod
    def compute_manifest(cls, skill_dir: Path) -> dict[str, str]:
        """Compute relative path to SHA-256 mapping for all files in a skill directory."""
        if not skill_dir.is_dir():
            raise SigningError(f"Target directory does not exist: {skill_dir}")

        manifest: dict[str, str] = {}
        for root, dirs, files in os.walk(skill_dir):
            # Prune ignored directory trees
            dirs[:] = [d for d in dirs if d not in IGNORED_PATTERNS and not d.startswith(".")]

            rel_root = Path(root).relative_to(skill_dir)
            for fname in files:
                if fname in IGNORED_PATTERNS or fname.endswith((".sig", ".pyc")):
                    continue
                file_rel = (rel_root / fname).as_posix() if rel_root != Path(".") else fname
                full_path = Path(root) / fname
                manifest[file_rel] = cls._hash_file(full_path)

        if not manifest:
            raise SigningError(f"No signable files found in {skill_dir}")

        return dict(sorted(manifest.items()))

    @classmethod
    def _canonical_bytes(cls, manifest: dict[str, str]) -> bytes:
        """Produce deterministic canonical JSON bytes for signature computation."""
        return json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")

    @classmethod
    def sign_skill(
        cls,
        skill_dir: Path,
        key: str,
        signer_id: str = "local-maintainer",
    ) -> dict[str, Any]:
        """Generate a cryptographic signature payload for a skill directory."""
        if not key or len(key.strip()) < 16:
            raise SigningError("Signing key must be at least 16 characters long.")

        manifest = cls.compute_manifest(skill_dir)
        canonical = cls._canonical_bytes(manifest)
        sig = hmac.new(key.encode("utf-8"), canonical, hashlib.sha256).hexdigest()

        now_iso = datetime.now(timezone.utc).isoformat()
        return {
            "version": "1.0",
            "algorithm": "hmac-sha256",
            "signer_id": signer_id,
            "created_at": now_iso,
            "manifest": manifest,
            "signature": sig,
        }

    @classmethod
    def write_signature(
        cls,
        skill_dir: Path,
        sig_data: dict[str, Any],
        sig_file: Path | None = None,
    ) -> Path:
        """Write signature payload to SKILL.sig or target path."""
        target = sig_file or (skill_dir / SIGNATURE_FILENAME)
        target.write_text(json.dumps(sig_data, indent=2), encoding="utf-8")
        return target

    @classmethod
    def verify_skill(
        cls,
        skill_dir: Path,
        key: str | None = None,
        sig_file: Path | None = None,
    ) -> VerificationResult:
        """Verify that skill files match the signature manifest and valid HMAC."""
        target_sig = sig_file or (skill_dir / SIGNATURE_FILENAME)
        if not target_sig.is_file():
            return VerificationResult(
                valid=False,
                signer_id="unknown",
                algorithm="none",
                created_at="",
                file_count=0,
                issues=[f"Signature file missing: {target_sig.name}"],
            )

        try:
            sig_data = json.loads(target_sig.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            return VerificationResult(
                valid=False,
                signer_id="unknown",
                algorithm="none",
                created_at="",
                file_count=0,
                issues=[f"Corrupt signature file: {exc}"],
            )

        expected_manifest: dict[str, str] = sig_data.get("manifest", {})
        expected_sig: str = sig_data.get("signature", "")
        signer_id: str = sig_data.get("signer_id", "unknown")
        algorithm: str = sig_data.get("algorithm", "hmac-sha256")
        created_at: str = sig_data.get("created_at", "")

        issues: list[str] = []

        try:
            current_manifest = cls.compute_manifest(skill_dir)
        except SigningError as err:
            return VerificationResult(
                valid=False,
                signer_id=signer_id,
                algorithm=algorithm,
                created_at=created_at,
                file_count=0,
                issues=[str(err)],
            )

        # Check for missing or modified files
        for rel_path, expected_hash in expected_manifest.items():
            if rel_path not in current_manifest:
                issues.append(f"Missing file: {rel_path}")
            elif current_manifest[rel_path] != expected_hash:
                issues.append(f"Content modified: {rel_path}")

        # Check for unexpected newly added files
        for rel_path in current_manifest:
            if rel_path not in expected_manifest:
                issues.append(f"Untracked/unverified file added: {rel_path}")

        # If secret key is provided, verify HMAC signature
        if key:
            canonical = cls._canonical_bytes(expected_manifest)
            computed_sig = hmac.new(key.encode("utf-8"), canonical, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(computed_sig, expected_sig):
                issues.append("Cryptographic signature mismatch: key or signature invalid.")

        is_valid = len(issues) == 0
        return VerificationResult(
            valid=is_valid,
            signer_id=signer_id,
            algorithm=algorithm,
            created_at=created_at,
            file_count=len(expected_manifest),
            issues=issues,
        )

    @classmethod
    def sign_lockfile(cls, lock_path: Path, key: str, signer_id: str = "lockfile-guard") -> Path:
        """Sign a skillforge.lock file."""
        if not lock_path.is_file():
            raise SigningError(f"Lockfile not found: {lock_path}")
        file_hash = cls._hash_file(lock_path)
        canonical = json.dumps({"lockfile_hash": file_hash}, sort_keys=True).encode("utf-8")
        sig = hmac.new(key.encode("utf-8"), canonical, hashlib.sha256).hexdigest()

        payload = {
            "version": "1.0",
            "algorithm": "hmac-sha256",
            "signer_id": signer_id,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "target_file": lock_path.name,
            "file_sha256": file_hash,
            "signature": sig,
        }
        sig_file = lock_path.parent / f"{lock_path.name}.sig"
        sig_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return sig_file

    @classmethod
    def verify_lockfile(cls, lock_path: Path, key: str | None = None) -> VerificationResult:
        """Verify signature for skillforge.lock."""
        sig_file = lock_path.parent / f"{lock_path.name}.sig"
        if not sig_file.is_file():
            return VerificationResult(
                valid=False,
                signer_id="unknown",
                algorithm="none",
                created_at="",
                file_count=1,
                issues=[f"Lockfile signature missing: {sig_file.name}"],
            )
        try:
            sig_data = json.loads(sig_file.read_text(encoding="utf-8"))
        except Exception as exc:
            return VerificationResult(
                valid=False,
                signer_id="unknown",
                algorithm="none",
                created_at="",
                file_count=1,
                issues=[f"Corrupt lock signature: {exc}"],
            )

        expected_hash = sig_data.get("file_sha256", "")
        current_hash = cls._hash_file(lock_path)
        issues: list[str] = []
        if current_hash != expected_hash:
            issues.append("Lockfile hash mismatch: content was altered after signing.")

        if key:
            canonical = json.dumps({"lockfile_hash": expected_hash}, sort_keys=True).encode("utf-8")
            computed = hmac.new(key.encode("utf-8"), canonical, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(computed, sig_data.get("signature", "")):
                issues.append("Lockfile cryptographic signature mismatch.")

        return VerificationResult(
            valid=len(issues) == 0,
            signer_id=sig_data.get("signer_id", "unknown"),
            algorithm=sig_data.get("algorithm", "hmac-sha256"),
            created_at=sig_data.get("created_at", ""),
            file_count=1,
            issues=issues,
        )

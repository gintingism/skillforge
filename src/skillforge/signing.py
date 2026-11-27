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
    def generate_ed25519_keypair() -> tuple[str, str]:
        """Generate a PEM-encoded (private_key_pem, public_key_pem) Ed25519 keypair."""
        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        except ImportError as exc:
            raise SigningError("Ed25519 requires the 'cryptography' package.") from exc

        private_key = Ed25519PrivateKey.generate()
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")
        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")
        return private_pem, public_pem

    @staticmethod
    def _sign_ed25519(private_key_pem: str, payload: bytes) -> str:
        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        except ImportError as exc:
            raise SigningError("Ed25519 requires the 'cryptography' package.") from exc

        try:
            loaded = serialization.load_pem_private_key(private_key_pem.encode("utf-8"), password=None)
        except Exception as exc:
            raise SigningError(f"Invalid Ed25519 private key PEM: {exc}") from exc
        if not isinstance(loaded, Ed25519PrivateKey):
            raise SigningError("Provided PEM key is not an Ed25519 private key.")
        return loaded.sign(payload).hex()

    @staticmethod
    def _verify_ed25519(public_key_pem: str, payload: bytes, signature_hex: str) -> bool:
        try:
            from cryptography.exceptions import InvalidSignature
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        except ImportError as exc:
            raise SigningError("Ed25519 requires the 'cryptography' package.") from exc

        try:
            loaded = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
        except Exception as exc:
            raise SigningError(f"Invalid Ed25519 public key PEM: {exc}") from exc
        if not isinstance(loaded, Ed25519PublicKey):
            raise SigningError("Provided PEM key is not an Ed25519 public key.")
        try:
            loaded.verify(bytes.fromhex(signature_hex), payload)
            return True
        except (InvalidSignature, ValueError):
            return False

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
        algorithm: str = "hmac-sha256",
    ) -> dict[str, Any]:
        """Generate a cryptographic signature payload for a skill directory."""
        manifest = cls.compute_manifest(skill_dir)
        canonical = cls._canonical_bytes(manifest)

        if algorithm == "ed25519":
            sig = cls._sign_ed25519(key, canonical)
        elif algorithm == "hmac-sha256":
            if not key or len(key.strip()) < 16:
                raise SigningError("Signing key must be at least 16 characters long.")
            sig = hmac.new(key.encode("utf-8"), canonical, hashlib.sha256).hexdigest()
        else:
            raise SigningError(f"Unsupported signing algorithm: {algorithm}")

        now_iso = datetime.now(timezone.utc).isoformat()
        return {
            "version": "1.0",
            "algorithm": algorithm,
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
        """Verify that skill files match the signature manifest and valid cryptographic signature."""
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

        if key:
            canonical = cls._canonical_bytes(expected_manifest)
            if algorithm == "ed25519":
                try:
                    if not cls._verify_ed25519(key, canonical, expected_sig):
                        issues.append("Ed25519 signature mismatch: public key or signature invalid.")
                except SigningError as exc:
                    issues.append(str(exc))
            elif algorithm == "hmac-sha256":
                computed_sig = hmac.new(key.encode("utf-8"), canonical, hashlib.sha256).hexdigest()
                if not hmac.compare_digest(computed_sig, expected_sig):
                    issues.append("Cryptographic signature mismatch: key or signature invalid.")
            else:
                issues.append(f"Unsupported signing algorithm: {algorithm}")

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
    def sign_lockfile(
        cls,
        lock_path: Path,
        key: str,
        signer_id: str = "lockfile-guard",
        algorithm: str = "hmac-sha256",
    ) -> Path:
        """Sign a skillforge.lock file."""
        if not lock_path.is_file():
            raise SigningError(f"Lockfile not found: {lock_path}")
        file_hash = cls._hash_file(lock_path)
        canonical = json.dumps({"lockfile_hash": file_hash}, sort_keys=True).encode("utf-8")

        if algorithm == "ed25519":
            sig = cls._sign_ed25519(key, canonical)
        elif algorithm == "hmac-sha256":
            if not key or len(key.strip()) < 16:
                raise SigningError("Signing key must be at least 16 characters long.")
            sig = hmac.new(key.encode("utf-8"), canonical, hashlib.sha256).hexdigest()
        else:
            raise SigningError(f"Unsupported signing algorithm: {algorithm}")

        payload = {
            "version": "1.0",
            "algorithm": algorithm,
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
        algorithm = sig_data.get("algorithm", "hmac-sha256")
        current_hash = cls._hash_file(lock_path)
        issues: list[str] = []
        if current_hash != expected_hash:
            issues.append("Lockfile hash mismatch: content was altered after signing.")

        if key:
            canonical = json.dumps({"lockfile_hash": expected_hash}, sort_keys=True).encode("utf-8")
            expected_sig = str(sig_data.get("signature", ""))
            if algorithm == "ed25519":
                try:
                    if not cls._verify_ed25519(key, canonical, expected_sig):
                        issues.append("Lockfile Ed25519 signature mismatch.")
                except SigningError as exc:
                    issues.append(str(exc))
            elif algorithm == "hmac-sha256":
                computed = hmac.new(key.encode("utf-8"), canonical, hashlib.sha256).hexdigest()
                if not hmac.compare_digest(computed, expected_sig):
                    issues.append("Lockfile cryptographic signature mismatch.")
            else:
                issues.append(f"Unsupported signing algorithm: {algorithm}")

        return VerificationResult(
            valid=len(issues) == 0,
            signer_id=sig_data.get("signer_id", "unknown"),
            algorithm=algorithm,
            created_at=sig_data.get("created_at", ""),
            file_count=1,
            issues=issues,
        )

    @classmethod
    def sign_sigstore_bundle(
        cls,
        skill_dir: Path,
        *,
        oidc_issuer: str = "https://token.actions.githubusercontent.com",
        oidc_identity: str | None = None,
        private_key_pem: str | None = None,
        rekor_log_id: str | None = None,
    ) -> tuple[dict[str, Any], str]:
        """Generate a Sigstore Bundle v0.3 DSSE envelope with OIDC identity and Rekor log metadata.

        Uses an ephemeral Ed25519 keypair when private_key_pem is omitted (mirroring keyless
        Fulcio short-lived signing) and embeds the verification public key alongside OIDC claims.
        Returns (bundle_dict, public_key_pem).
        """
        import base64

        manifest = cls.compute_manifest(skill_dir)
        canonical = cls._canonical_bytes(manifest)
        if private_key_pem is None:
            priv_pem, pub_pem = cls.generate_ed25519_keypair()
        else:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

            loaded = serialization.load_pem_private_key(private_key_pem.encode("utf-8"), password=None)
            if not isinstance(loaded, Ed25519PrivateKey):
                raise SigningError("Sigstore bundle requires an Ed25519 private key PEM.")
            priv_pem = private_key_pem
            pub_pem = loaded.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode("utf-8")

        resolved_identity = (
            oidc_identity
            or os.environ.get("GITHUB_WORKFLOW_REF")
            or f"https://github.com/{os.environ.get('GITHUB_REPOSITORY', 'local/skillforge')}"
        )
        sig_hex = cls._sign_ed25519(priv_pem, canonical)
        payload_b64 = base64.b64encode(canonical).decode("ascii")
        sig_b64 = base64.b64encode(bytes.fromhex(sig_hex)).decode("ascii")
        now_iso = datetime.now(timezone.utc).isoformat()
        log_hash = hashlib.sha256(canonical + bytes.fromhex(sig_hex)).hexdigest()

        bundle: dict[str, Any] = {
            "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
            "verificationMaterial": {
                "publicKey": {"pem": pub_pem},
                "oidcClaims": {
                    "issuer": oidc_issuer,
                    "subject": resolved_identity,
                },
                "tlogEntries": [
                    {
                        "logId": {"keyId": rekor_log_id or "rekor.sigstore.dev/local-offline-log"},
                        "integratedTime": int(datetime.now(timezone.utc).timestamp()),
                        "inclusionDigest": f"sha256:{log_hash}",
                    }
                ],
            },
            "dsseEnvelope": {
                "payloadType": "application/vnd.skillforge.manifest+json",
                "payload": payload_b64,
                "signatures": [
                    {
                        "keyid": resolved_identity,
                        "sig": sig_b64,
                    }
                ],
            },
            "created_at": now_iso,
        }
        return bundle, pub_pem

    @classmethod
    def verify_sigstore_bundle(
        cls,
        skill_dir: Path,
        bundle_path: Path,
        *,
        expected_issuer: str | None = None,
        expected_identity: str | None = None,
        public_key_pem: str | None = None,
    ) -> VerificationResult:
        """Verify a Sigstore Bundle v0.3 envelope, OIDC identity claims, Rekor digest, and skill files."""
        import base64

        if not bundle_path.is_file():
            return VerificationResult(
                valid=False,
                signer_id="unknown",
                algorithm="sigstore-bundle",
                created_at="",
                file_count=0,
                issues=[f"Sigstore bundle not found: {bundle_path.name}"],
            )
        try:
            bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            return VerificationResult(
                valid=False,
                signer_id="unknown",
                algorithm="sigstore-bundle",
                created_at="",
                file_count=0,
                issues=[f"Corrupt Sigstore bundle JSON: {exc}"],
            )

        issues: list[str] = []
        media_type = str(bundle.get("mediaType", ""))
        if "sigstore.bundle" not in media_type:
            issues.append(f"Unexpected Sigstore mediaType: {media_type}")

        vm = bundle.get("verificationMaterial", {}) if isinstance(bundle.get("verificationMaterial"), dict) else {}
        claims = vm.get("oidcClaims", {}) if isinstance(vm.get("oidcClaims"), dict) else {}
        issuer = str(claims.get("issuer", ""))
        subject = str(claims.get("subject", "unknown"))
        if expected_issuer and issuer != expected_issuer:
            issues.append(f"OIDC issuer mismatch: expected '{expected_issuer}', got '{issuer}'")
        if expected_identity and subject != expected_identity:
            issues.append(f"OIDC identity mismatch: expected '{expected_identity}', got '{subject}'")

        dsse = bundle.get("dsseEnvelope", {}) if isinstance(bundle.get("dsseEnvelope"), dict) else {}
        payload_b64 = str(dsse.get("payload", ""))
        sigs = dsse.get("signatures", []) if isinstance(dsse.get("signatures"), list) else []
        if not payload_b64 or not sigs:
            issues.append("Sigstore DSSE envelope missing payload or signatures")
            return VerificationResult(
                valid=False,
                signer_id=subject,
                algorithm="sigstore-bundle",
                created_at=str(bundle.get("created_at", "")),
                file_count=0,
                issues=issues,
            )

        try:
            canonical = base64.b64decode(payload_b64)
            expected_manifest: dict[str, str] = json.loads(canonical.decode("utf-8"))
            sig_bytes = base64.b64decode(str(sigs[0].get("sig", "")))
        except Exception as exc:
            issues.append(f"Failed to decode DSSE payload or signature: {exc}")
            return VerificationResult(
                valid=False,
                signer_id=subject,
                algorithm="sigstore-bundle",
                created_at=str(bundle.get("created_at", "")),
                file_count=0,
                issues=issues,
            )

        pub_pem = public_key_pem or str((vm.get("publicKey") or {}).get("pem", ""))
        if not pub_pem:
            issues.append("No public key available in Sigstore bundle verificationMaterial")
        elif not cls._verify_ed25519(pub_pem, canonical, sig_bytes.hex()):
            issues.append("Sigstore DSSE Ed25519 signature verification failed")

        tlog_entries = vm.get("tlogEntries", []) if isinstance(vm.get("tlogEntries"), list) else []
        if not tlog_entries:
            issues.append("Sigstore bundle missing Rekor transparency log entry")
        else:
            expected_inc = f"sha256:{hashlib.sha256(canonical + sig_bytes).hexdigest()}"
            recorded_inc = str(tlog_entries[0].get("inclusionDigest", ""))
            if recorded_inc and recorded_inc != expected_inc:
                issues.append("Rekor transparency inclusion digest mismatch")

        current_manifest = cls.compute_manifest(skill_dir)
        current_manifest.pop(bundle_path.name, None)
        for rel_path, expected_hash in expected_manifest.items():
            if rel_path not in current_manifest:
                issues.append(f"Missing file: {rel_path}")
            elif current_manifest[rel_path] != expected_hash:
                issues.append(f"Content modified: {rel_path}")
        for rel_path in current_manifest:
            if rel_path not in expected_manifest and not rel_path.endswith(".sigstore.json"):
                issues.append(f"Untracked/unverified file added: {rel_path}")

        return VerificationResult(
            valid=len(issues) == 0,
            signer_id=subject,
            algorithm="sigstore-bundle",
            created_at=str(bundle.get("created_at", "")),
            file_count=len(expected_manifest),
            issues=issues,
        )

    @classmethod
    def sign_sigstore_online(
        cls,
        skill_dir: Path,
        *,
        identity_token: str | None = None,
        staging: bool = False,
        signer_factory: Any = None,
    ) -> dict[str, Any]:
        """Sign a skill manifest online via live Sigstore Fulcio CA + Rekor v2 transparency log.

        Requires optional dependency: `pip install "agent-skillforge[sigstore]"`.
        """
        manifest = cls.compute_manifest(skill_dir)
        canonical = cls._canonical_bytes(manifest)

        if signer_factory is not None:
            bundle_obj = signer_factory(canonical, identity_token, staging)
            if isinstance(bundle_obj, dict):
                return bundle_obj
            return dict(json.loads(bundle_obj.to_json()))

        try:
            from sigstore.oidc import detect_credential  # type: ignore[import-not-found]
            from sigstore.sign import SigningContext  # type: ignore[import-not-found]
        except ImportError as exc:
            raise SigningError(
                "Live Sigstore Fulcio/Rekor signing requires the optional 'sigstore' package (>=4.5.0). "
                "Install with: pip install 'agent-skillforge[sigstore]'"
            ) from exc

        token = identity_token or detect_credential()
        if not token:
            raise SigningError(
                "No ambient OIDC credential found. Provide --identity-token or run inside GitHub Actions with id-token: write."
            )
        ctx = SigningContext.staging() if staging else SigningContext.production()
        with ctx.signer(token) as signer:
            bundle = signer.sign_artifact(canonical)
        parsed = json.loads(bundle.to_json())
        if isinstance(parsed, dict):
            parsed["skillforgeManifest"] = manifest
            return parsed
        raise SigningError("Unexpected Sigstore bundle serialization output.")

    @classmethod
    def verify_sigstore_online(
        cls,
        skill_dir: Path,
        bundle_path: Path,
        *,
        expected_issuer: str,
        expected_identity: str,
        staging: bool = False,
        verifier_factory: Any = None,
    ) -> VerificationResult:
        """Verify a live Sigstore Bundle v0.3 against Fulcio trust root, Rekor v2 log, and disk files."""
        if not bundle_path.is_file():
            return VerificationResult(
                valid=False,
                signer_id="unknown",
                algorithm="sigstore-online",
                created_at="",
                file_count=0,
                issues=[f"Sigstore bundle not found: {bundle_path.name}"],
            )
        try:
            raw_text = bundle_path.read_text(encoding="utf-8")
            bundle_dict = json.loads(raw_text)
        except (OSError, json.JSONDecodeError) as exc:
            return VerificationResult(
                valid=False,
                signer_id="unknown",
                algorithm="sigstore-online",
                created_at="",
                file_count=0,
                issues=[f"Invalid Sigstore bundle JSON: {exc}"],
            )

        current_manifest = cls.compute_manifest(skill_dir)
        current_manifest.pop(bundle_path.name, None)
        canonical = cls._canonical_bytes(current_manifest)
        issues: list[str] = []

        if verifier_factory is not None:
            ok, err_msg = verifier_factory(canonical, bundle_dict, expected_issuer, expected_identity, staging)
            if not ok:
                issues.append(str(err_msg or "Online Sigstore verification failed"))
        else:
            try:
                from sigstore.models import Bundle  # type: ignore[import-not-found]
                from sigstore.verify import Verifier  # type: ignore[import-not-found]
                from sigstore.verify.policy import Identity  # type: ignore[import-not-found]
            except ImportError as exc:
                raise SigningError(
                    "Live Sigstore Fulcio/Rekor verification requires 'sigstore>=4.5.0'. "
                    "Install with: pip install 'agent-skillforge[sigstore]'"
                ) from exc

            try:
                bundle_clean = {k: v for k, v in bundle_dict.items() if k != "skillforgeManifest"}
                bundle_model = Bundle.from_json(json.dumps(bundle_clean))
                verifier = Verifier.staging() if staging else Verifier.production()
                policy = Identity(identity=expected_identity, issuer=expected_issuer)
                verifier.verify_artifact(canonical, bundle_model, policy)
            except Exception as exc:
                issues.append(f"Live Sigstore verification failed: {exc}")

        return VerificationResult(
            valid=len(issues) == 0,
            signer_id=expected_identity,
            algorithm="sigstore-online",
            created_at=str(bundle_dict.get("created_at", "")),
            file_count=len(current_manifest),
            issues=issues,
        )

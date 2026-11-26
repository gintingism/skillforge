"""Agent2Agent (A2A) v1.0 Agent Card security auditor and Ed25519 JWS signer/verifier.

Audits /.well-known/agent-card.json documents for transport encryption (A2A-001),
authentication configuration (A2A-002), JWS cryptographic signatures per §8.4 (A2A-003),
prompt poisoning in card metadata/skills (A2A-004), and overbroad capabilities (A2A-005).
"""

from __future__ import annotations

import base64
import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .errors import SecurityAuditError
from .security import AuditFinding, AuditReport, Severity
from .signing import SkillSigner

_A2A_POISON_RE = re.compile(
    r"(?i)(?:ignore\s+(?:all\s+)?(?:previous|prior)\s+instructions|system\s+override|"
    r"<\s*IMPORTANT\b|do\s+not\s+mention|without\s+telling\s+the\s+user|"
    r"silently\s+(?:read|send|exfiltrate|forward)|~/.ssh|~/.aws|[\u200b-\u200f\u202a-\u202e\ufeff])"
)
_HARDCODED_SECRET_RE = re.compile(
    r"(?:ghp_[A-Za-z0-9]{36}|sk-ant-[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|AIzaSy[A-Za-z0-9_-]{33})"
)


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def _canonical_card_payload(card: dict[str, Any]) -> bytes:
    """Serialize Agent Card without the signatures array for canonical JWS signing."""
    unsigned = {k: v for k, v in card.items() if k != "signatures"}
    return json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_agent_card_jws(
    card: dict[str, Any],
    private_key_pem: str,
    *,
    key_id: str = "a2a-ed25519-1",
) -> dict[str, Any]:
    """Attach an A2A v1.0 §8.4 Ed25519 JWS signature entry to an Agent Card dict."""
    protected_header = {"alg": "EdDSA", "typ": "JWS", "kid": key_id}
    protected_b64 = _b64url_encode(json.dumps(protected_header, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    payload_b64 = _b64url_encode(_canonical_card_payload(card))
    signing_input = f"{protected_b64}.{payload_b64}".encode("ascii")
    sig_hex = SkillSigner._sign_ed25519(private_key_pem, signing_input)
    sig_b64 = _b64url_encode(bytes.fromhex(sig_hex))

    signed_card = dict(card)
    existing_sigs = list(signed_card.get("signatures", [])) if isinstance(signed_card.get("signatures"), list) else []
    existing_sigs.append(
        {
            "protected": protected_b64,
            "signature": sig_b64,
            "header": {"kid": key_id},
        }
    )
    signed_card["signatures"] = existing_sigs
    return signed_card


def verify_agent_card_jws(card: dict[str, Any], public_key_pem: str) -> tuple[bool, list[str]]:
    """Verify A2A v1.0 §8.4 Ed25519 JWS signatures on an Agent Card."""
    sigs = card.get("signatures")
    if not isinstance(sigs, list) or not sigs:
        return False, ["Agent Card has no JWS 'signatures' entries"]

    payload_b64 = _b64url_encode(_canonical_card_payload(card))
    issues: list[str] = []
    verified_any = False

    for idx, entry in enumerate(sigs):
        if not isinstance(entry, dict):
            issues.append(f"Signature entry #{idx} is not an object")
            continue
        protected_b64 = str(entry.get("protected", ""))
        sig_b64 = str(entry.get("signature", ""))
        if not protected_b64 or not sig_b64:
            issues.append(f"Signature entry #{idx} is missing 'protected' or 'signature'")
            continue
        try:
            header = json.loads(_b64url_decode(protected_b64).decode("utf-8"))
        except Exception as exc:
            issues.append(f"Signature entry #{idx} has invalid protected header: {exc}")
            continue
        alg = str(header.get("alg", ""))
        if alg.lower() == "none":
            issues.append(f"Signature entry #{idx} uses forbidden insecure alg='none'")
            continue
        if alg != "EdDSA":
            issues.append(f"Signature entry #{idx} uses unsupported JWS algorithm '{alg}' (expected 'EdDSA')")
            continue
        try:
            sig_bytes = _b64url_decode(sig_b64)
        except Exception as exc:
            issues.append(f"Signature entry #{idx} has malformed base64url signature: {exc}")
            continue
        signing_input = f"{protected_b64}.{payload_b64}".encode("ascii")
        if SkillSigner._verify_ed25519(public_key_pem, signing_input, sig_bytes.hex()):
            verified_any = True
        else:
            issues.append(f"Signature entry #{idx} failed cryptographic verification against public key")

    return verified_any and not issues, issues


def audit_agent_card(
    card_path_or_data: Path | dict[str, Any],
    *,
    public_key_pem: str | None = None,
    target_name: str = "agent-card.json",
) -> AuditReport:
    """Audit an A2A v1.0 Agent Card JSON file or object."""
    if isinstance(card_path_or_data, Path):
        if not card_path_or_data.is_file():
            raise SecurityAuditError(f"A2A Agent Card not found: {card_path_or_data}")
        target_name = card_path_or_data.name
        try:
            data = json.loads(card_path_or_data.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise SecurityAuditError(f"Invalid A2A Agent Card JSON: {exc}") from exc
    else:
        data = card_path_or_data

    if not isinstance(data, dict):
        raise SecurityAuditError("A2A Agent Card must be a JSON object")

    findings: list[AuditFinding] = []
    agent_name = str(data.get("name", "")).strip() or target_name

    # A2A-001: Check transport encryption on primary URL & supportedInterfaces
    urls_to_check: list[str] = []
    if isinstance(data.get("url"), str) and data["url"].strip():
        urls_to_check.append(data["url"].strip())
    interfaces = data.get("supportedInterfaces", [])
    if isinstance(interfaces, list):
        for iface in interfaces:
            if isinstance(iface, dict) and isinstance(iface.get("url"), str):
                urls_to_check.append(iface["url"].strip())

    for endpoint in urls_to_check:
        parsed = urlparse(endpoint)
        scheme = (parsed.scheme or "").lower()
        host = (parsed.hostname or "").lower()
        if scheme in ("http", "ws") and host not in ("localhost", "127.0.0.1", "::1"):
            findings.append(
                AuditFinding(
                    rule_id="A2A-001",
                    severity=Severity.HIGH,
                    message=f"Insecure unencrypted A2A endpoint '{endpoint}' on agent '{agent_name}' (require HTTPS/WSS)",
                    file=target_name,
                    snippet=endpoint,
                )
            )

    # A2A-002: Missing authentication or hardcoded secrets in securitySchemes / authentication
    sec_schemes = data.get("securitySchemes") or data.get("authentication")
    if not sec_schemes:
        findings.append(
            AuditFinding(
                rule_id="A2A-002",
                severity=Severity.MEDIUM,
                message=f"Agent Card '{agent_name}' declares no authentication or securitySchemes",
                file=target_name,
            )
        )
    else:
        raw_sec = json.dumps(sec_schemes)
        if _HARDCODED_SECRET_RE.search(raw_sec):
            findings.append(
                AuditFinding(
                    rule_id="A2A-002",
                    severity=Severity.CRITICAL,
                    message=f"Hardcoded secret or API key embedded in Agent Card '{agent_name}' securitySchemes",
                    file=target_name,
                )
            )
        if '"*"' in raw_sec and "scope" in raw_sec.lower():
            findings.append(
                AuditFinding(
                    rule_id="A2A-005",
                    severity=Severity.HIGH,
                    message=f"Overbroad wildcard OAuth scope '*' declared in Agent Card '{agent_name}'",
                    file=target_name,
                )
            )

    # A2A-003: JWS signature validation (§8.4)
    sigs = data.get("signatures")
    if not isinstance(sigs, list) or not sigs:
        findings.append(
            AuditFinding(
                rule_id="A2A-003",
                severity=Severity.MEDIUM,
                message=f"Unsigned A2A Agent Card '{agent_name}': missing JWS 'signatures' array (A2A v1.0 §8.4)",
                file=target_name,
            )
        )
    else:
        for idx, entry in enumerate(sigs):
            if not isinstance(entry, dict):
                findings.append(
                    AuditFinding(
                        rule_id="A2A-003",
                        severity=Severity.HIGH,
                        message=f"Malformed JWS signature entry #{idx} in Agent Card '{agent_name}'",
                        file=target_name,
                    )
                )
                continue
            prot = str(entry.get("protected", ""))
            if prot:
                try:
                    hdr = json.loads(_b64url_decode(prot).decode("utf-8"))
                    if str(hdr.get("alg", "")).lower() == "none":
                        findings.append(
                            AuditFinding(
                                rule_id="A2A-003",
                                severity=Severity.CRITICAL,
                                message=f"JWS signature #{idx} uses forbidden insecure alg='none' bypass",
                                file=target_name,
                            )
                        )
                except Exception:
                    findings.append(
                        AuditFinding(
                            rule_id="A2A-003",
                            severity=Severity.HIGH,
                            message=f"JWS signature #{idx} has corrupt base64url protected header",
                            file=target_name,
                        )
                    )
        if public_key_pem:
            ok, verify_issues = verify_agent_card_jws(data, public_key_pem)
            if not ok:
                findings.append(
                    AuditFinding(
                        rule_id="A2A-003",
                        severity=Severity.CRITICAL,
                        message=f"Agent Card JWS cryptographic verification failed: {'; '.join(verify_issues)}",
                        file=target_name,
                    )
                )

    # A2A-004: Prompt poisoning in top-level description and skills
    card_desc = str(data.get("description", ""))
    if card_desc and _A2A_POISON_RE.search(card_desc):
        findings.append(
            AuditFinding(
                rule_id="A2A-004",
                severity=Severity.CRITICAL,
                message=f"Prompt injection or hidden unicode detected in Agent Card '{agent_name}' description",
                file=target_name,
                snippet=card_desc[:90],
            )
        )

    skills_list = data.get("skills", [])
    if isinstance(skills_list, list):
        for sk in skills_list:
            if not isinstance(sk, dict):
                continue
            sk_name = str(sk.get("id", sk.get("name", "unnamed")))
            blob = " ".join(
                [
                    str(sk.get("name", "")),
                    str(sk.get("description", "")),
                    " ".join(str(ex) for ex in (sk.get("examples") or []) if isinstance(ex, str)),
                ]
            )
            if _A2A_POISON_RE.search(blob):
                findings.append(
                    AuditFinding(
                        rule_id="A2A-004",
                        severity=Severity.CRITICAL,
                        message=f"Prompt poisoning detected in A2A skill '{sk_name}' metadata",
                        file=f"{target_name}::{sk_name}",
                        snippet=blob[:90],
                    )
                )

    # A2A-005: Unauthenticated pushNotifications capability
    caps = data.get("capabilities", {})
    if isinstance(caps, dict) and caps.get("pushNotifications") is True and not sec_schemes:
        findings.append(
            AuditFinding(
                rule_id="A2A-005",
                severity=Severity.HIGH,
                message=f"Agent Card '{agent_name}' enables pushNotifications without declaring authentication",
                file=target_name,
            )
        )

    return AuditReport(target=agent_name, findings=findings)

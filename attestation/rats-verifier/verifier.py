# SPDX-FileCopyrightText: 2026 TALOS / LibreMobile OS Contributors
# SPDX-License-Identifier: Apache-2.0
"""Sovereign RATS Verifier Engine (RFC 9334 & RFC 9711)."""

from __future__ import annotations

import datetime
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

from .eat import EAToken
from .tpm import TPMQuote, compute_pcr_digest, verify_quote_signature


@dataclass
class TrustworthinessVector:
    """RFC 9334 Trustworthiness Vector appraisal result."""
    hardware_integrity: str = "UNKNOWN"    # SECURE_HARDWARE | UNKNOWN
    instance_identity: str = "UNTRUSTED"    # TRUSTED | UNTRUSTED
    executables: str = "UNKNOWN"            # APPROVED | MODIFIED | UNKNOWN
    configuration: str = "RESTRICTED"       # APPROVED | RESTRICTED


@dataclass
class AttestationResult:
    """Standardized RATS Attestation Result / Verdict."""
    verdict: str                            # AFFIRMED | CONTRAINDICATED | UNDETERMINED
    trustworthiness_vector: TrustworthinessVector
    timestamp: str
    nonce_matched: bool
    ak_verified: bool
    pcr_digest_matched: bool
    measurements_approved: bool
    reasons: List[str] = field(default_factory=list)
    eval_details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "verdict": self.verdict,
            "trustworthiness_vector": asdict(self.trustworthiness_vector),
            "timestamp": self.timestamp,
            "nonce_matched": self.nonce_matched,
            "ak_verified": self.ak_verified,
            "pcr_digest_matched": self.pcr_digest_matched,
            "measurements_approved": self.measurements_approved,
            "reasons": self.reasons,
            "eval_details": self.eval_details,
        }


class RATSVerifier:
    """
    Sovereign RATS Verifier appraisal engine.
    Evaluates EAT tokens against pinned AKs and Reference Integrity Measurements (RIM).
    """

    def __init__(
        self,
        pinned_aks: Dict[str, Dict[str, Any]],
        golden_rim: Optional[Dict[str, str]] = None,
    ) -> None:
        """
        Initialize verifier with pinned Attestation Keys and expected golden PCR values.
        
        TODO(operator): Configure enterprise root of trust and populate golden_rim
        from reproducible build attestation hashes (repro/attestation-<git-sha>.json).
        """
        self.pinned_aks = pinned_aks
        self.golden_rim = golden_rim or {}

    def verify(
        self,
        token: EAToken,
        expected_nonce: Optional[str] = None,
    ) -> AttestationResult:
        """Appraise an EAT token and return the formal Attestation Result."""
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        reasons: List[str] = []
        details: Dict[str, Any] = {}

        # 1. Nonce Freshness Check
        nonce_matched = True
        if expected_nonce is not None:
            expected_clean = expected_nonce.strip().lower()
            token_nonce = token.nonce.strip().lower()
            if token_nonce != expected_clean:
                nonce_matched = False
                reasons.append(f"Nonce mismatch: expected {expected_clean}, got {token_nonce}")

        quote = TPMQuote.from_dict(token.tpm_quote)
        details["quote_signer"] = quote.signer_name
        details["quote_sig_alg"] = quote.sig_alg
        details["quote_pcr_select"] = quote.pcr_select

        # Check nonce inside quote match token nonce
        if quote.nonce.strip().lower() != token.nonce.strip().lower():
            nonce_matched = False
            reasons.append("TPM quote nonce does not match EAT token nonce")

        # 2. Pinned AK Verification
        ak_verified = False
        signer_name = quote.signer_name
        if signer_name not in self.pinned_aks:
            reasons.append(f"Attestation Key '{signer_name}' is not pinned or trusted")
        else:
            pinned_ak = self.pinned_aks[signer_name]
            if verify_quote_signature(quote, pinned_ak):
                ak_verified = True
            else:
                reasons.append(f"Cryptographic signature check failed for AK '{signer_name}'")

        # 3. PCR Composite Digest Verification
        pcr_digest_matched = False
        try:
            computed_digest = compute_pcr_digest(token.measres, quote.pcr_select)
            details["computed_pcr_digest"] = computed_digest
            details["quote_pcr_digest"] = quote.pcr_digest
            if computed_digest == quote.pcr_digest:
                pcr_digest_matched = True
            else:
                reasons.append(
                    f"PCR composite digest mismatch: quote has {quote.pcr_digest}, computed {computed_digest}"
                )
        except Exception as err:
            reasons.append(f"Failed to compute PCR composite digest: {err}")

        # 4. Reference Integrity Measurements (RIM) Check
        measurements_approved = True
        if self.golden_rim:
            for pcr_str, expected_hash in self.golden_rim.items():
                measured = token.measres.get(str(pcr_str), "").lower()
                expected = expected_hash.lower()
                if measured != expected:
                    measurements_approved = False
                    reasons.append(
                        f"PCR {pcr_str} measurement discrepancy: expected {expected}, got {measured}"
                    )

        # 5. Security Posture & Trustworthiness Vector
        hw_integrity = "SECURE_HARDWARE" if (ak_verified and pcr_digest_matched) else "UNKNOWN"
        instance_id = "TRUSTED" if (ak_verified and nonce_matched) else "UNTRUSTED"
        executables = "APPROVED" if measurements_approved else "MODIFIED"
        config_status = "APPROVED"

        if token.dbgstat.lower() != "disabled-permanently":
            config_status = "RESTRICTED"
            reasons.append(f"Platform debug mode is active: {token.dbgstat}")

        vector = TrustworthinessVector(
            hardware_integrity=hw_integrity,
            instance_identity=instance_id,
            executables=executables,
            configuration=config_status,
        )

        # 6. Overall Verdict
        if not (nonce_matched and ak_verified and pcr_digest_matched and measurements_approved):
            verdict = "CONTRAINDICATED"
        elif config_status == "RESTRICTED":
            verdict = "UNDETERMINED"
        else:
            verdict = "AFFIRMED"

        return AttestationResult(
            verdict=verdict,
            trustworthiness_vector=vector,
            timestamp=now_iso,
            nonce_matched=nonce_matched,
            ak_verified=ak_verified,
            pcr_digest_matched=pcr_digest_matched,
            measurements_approved=measurements_approved,
            reasons=reasons,
            eval_details=details,
        )

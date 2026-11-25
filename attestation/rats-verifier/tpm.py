# SPDX-FileCopyrightText: 2026 TALOS / LibreMobile OS Contributors
# SPDX-License-Identifier: Apache-2.0
"""TPM 2.0 Quote Parsing and Cryptographic Verification (Pure Python Stdlib)."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass
class TPMQuote:
    """Represents a TPM 2.0 TPMS_ATTEST quote and TPMT_SIGNATURE."""
    magic: str
    attest_type: str
    signer_name: str
    nonce: str
    pcr_select: List[int]
    pcr_digest: str
    clock_info: Dict[str, Any]
    sig_alg: str
    signature: str
    raw_attest: str

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> TPMQuote:
        attest = data.get("attest_data", {})
        return cls(
            magic=str(attest.get("magic", "ff544347")),
            attest_type=str(attest.get("type", "8018")),
            signer_name=str(data.get("signer_name", "")),
            nonce=str(attest.get("nonce", "")),
            pcr_select=[int(x) for x in attest.get("pcr_select", [])],
            pcr_digest=str(attest.get("pcr_digest", "")).lower(),
            clock_info=dict(attest.get("clock_info", {})),
            sig_alg=str(data.get("sig_alg", "hmac-sha256")).lower(),
            signature=str(data.get("signature", "")),
            raw_attest=str(data.get("raw_attest", json.dumps(attest, sort_keys=True))),
        )


def compute_pcr_digest(measres: Dict[str, str], pcr_select: List[int]) -> str:
    """
    Compute composite TPM 2.0 PCR digest over selected PCRs.
    In TPM 2.0, composite pcrDigest is SHA256(concat(pcr_0_digest || pcr_1_digest ...)).
    """
    selected = sorted(pcr_select)
    concatenated = bytearray()
    for pcr_idx in selected:
        idx_str = str(pcr_idx)
        if idx_str not in measres:
            raise KeyError(f"PCR {pcr_idx} requested in quote selection but missing from measres")
        concatenated.extend(bytes.fromhex(measres[idx_str]))
    return hashlib.sha256(concatenated).hexdigest().lower()


def _verify_rsa_pkcs1v15_sha256(data: bytes, sig_bytes: bytes, n: int, e: int) -> bool:
    """Verify RSASSA-PKCS1-v1_5 signature with SHA-256 in pure Python stdlib."""
    k = (n.bit_length() + 7) // 8
    if len(sig_bytes) != k:
        return False
    s_int = int.from_bytes(sig_bytes, byteorder="big")
    if s_int >= n:
        return False
    m_int = pow(s_int, e, n)
    em = m_int.to_bytes(k, byteorder="big")

    # Expected PKCS1-v1_5 padding: 0x00 || 0x01 || PS (0xFF...) || 0x00 || T
    # T = SHA256 DigestInfo prefix || SHA256(data)
    sha256_prefix = bytes.fromhex("3031300d060960864801650304020105000420")
    h = hashlib.sha256(data).digest()
    t = sha256_prefix + h
    expected_pad_len = k - 3 - len(t)
    if expected_pad_len < 8:
        return False
    expected_em = b"\x00\x01" + (b"\xff" * expected_pad_len) + b"\x00" + t
    return hmac.compare_digest(em, expected_em)


def verify_quote_signature(quote: TPMQuote, pinned_ak: Dict[str, Any]) -> bool:
    """
    Verify TPM quote signature against a pinned Attestation Key (AK).
    
    TODO(operator): Provision hardware-backed Endorsement Key (EK) certificates
    and deploy production TPM 2.0 Attestation Keys (AK) signed by OEM/foundation CAs.
    """
    data_to_verify = quote.raw_attest.encode("utf-8")
    sig_alg = quote.sig_alg.lower()
    ak_type = pinned_ak.get("type", "").lower()

    if sig_alg in ("hmac-sha256", "hmac"):
        # Shared secret / test key verification
        secret = pinned_ak.get("secret", "").encode("utf-8")
        expected_sig = hmac.new(secret, data_to_verify, hashlib.sha256).hexdigest()
        return hmac.compare_digest(quote.signature.lower(), expected_sig.lower())

    elif sig_alg in ("rsassa-pkcs1v15", "rsa-sha256", "rsa"):
        # Asymmetric RSA verification
        if "n" not in pinned_ak or "e" not in pinned_ak:
            return False
        n = int(pinned_ak["n"], 16) if isinstance(pinned_ak["n"], str) else int(pinned_ak["n"])
        e = int(pinned_ak["e"], 16) if isinstance(pinned_ak["e"], str) else int(pinned_ak["e"])
        sig_bytes = bytes.fromhex(quote.signature)
        return _verify_rsa_pkcs1v15_sha256(data_to_verify, sig_bytes, n, e)

    return False

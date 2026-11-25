# SPDX-FileCopyrightText: 2026 TALOS / LibreMobile OS Contributors
# SPDX-License-Identifier: Apache-2.0
"""Automated Test Suite for Sovereign RATS Verifier (RFC 9334 & RFC 9711)."""

import json
import subprocess
import sys
from pathlib import Path
import pytest

from attestation.rats_verifier.eat import parse_eat, EAToken
from attestation.rats_verifier.tpm import TPMQuote, compute_pcr_digest, verify_quote_signature
from attestation.rats_verifier.verifier import RATSVerifier

VECTORS_DIR = Path(__file__).parent.parent / "attestation" / "rats-verifier" / "vectors"


@pytest.fixture
def pinned_aks():
    with open(VECTORS_DIR / "pinned_aks.json", "r", encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture
def golden_rim():
    with open(VECTORS_DIR / "golden_rim.json", "r", encoding="utf-8") as f:
        return json.load(f)


def test_valid_eat_token(pinned_aks, golden_rim):
    """Assert valid RFC 9334 token appraisal yields AFFIRMED verdict."""
    with open(VECTORS_DIR / "valid_eat_token.json", "r", encoding="utf-8") as f:
        token_data = json.load(f)

    token = parse_eat(token_data)
    verifier = RATSVerifier(pinned_aks=pinned_aks, golden_rim=golden_rim)

    nonce = token.nonce
    res = verifier.verify(token, expected_nonce=nonce)

    assert res.verdict == "AFFIRMED"
    assert res.nonce_matched is True
    assert res.ak_verified is True
    assert res.pcr_digest_matched is True
    assert res.measurements_approved is True
    assert res.trustworthiness_vector.hardware_integrity == "SECURE_HARDWARE"
    assert res.trustworthiness_vector.instance_identity == "TRUSTED"
    assert res.trustworthiness_vector.executables == "APPROVED"
    assert res.trustworthiness_vector.configuration == "APPROVED"
    assert len(res.reasons) == 0


def test_tampered_pcr_token(pinned_aks, golden_rim):
    """Assert PCR tampering fails both composite digest and RIM checks."""
    with open(VECTORS_DIR / "tampered_pcr_token.json", "r", encoding="utf-8") as f:
        token_data = json.load(f)

    token = parse_eat(token_data)
    verifier = RATSVerifier(pinned_aks=pinned_aks, golden_rim=golden_rim)

    res = verifier.verify(token, expected_nonce=token.nonce)

    assert res.verdict == "CONTRAINDICATED"
    assert res.pcr_digest_matched is False
    assert res.measurements_approved is False
    assert any("PCR composite digest mismatch" in r for r in res.reasons)
    assert any("PCR 10 measurement discrepancy" in r for r in res.reasons)


def test_mismatched_nonce_token(pinned_aks, golden_rim):
    """Assert stale or replayed nonce challenge fails appraisal."""
    with open(VECTORS_DIR / "expired_nonce_token.json", "r", encoding="utf-8") as f:
        token_data = json.load(f)

    token = parse_eat(token_data)
    verifier = RATSVerifier(pinned_aks=pinned_aks, golden_rim=golden_rim)

    # Relying party expected original nonce, but token has different nonce
    fresh_nonce = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    res = verifier.verify(token, expected_nonce=fresh_nonce)

    assert res.verdict == "CONTRAINDICATED"
    assert res.nonce_matched is False
    assert any("Nonce mismatch" in r for r in res.reasons)


def test_untrusted_ak_token(pinned_aks, golden_rim):
    """Assert quote signed by an unpinned AK is rejected immediately."""
    with open(VECTORS_DIR / "untrusted_ak_token.json", "r", encoding="utf-8") as f:
        token_data = json.load(f)

    token = parse_eat(token_data)
    verifier = RATSVerifier(pinned_aks=pinned_aks, golden_rim=golden_rim)

    res = verifier.verify(token, expected_nonce=token.nonce)

    assert res.verdict == "CONTRAINDICATED"
    assert res.ak_verified is False
    assert any("not pinned or trusted" in r for r in res.reasons)


def test_debug_mode_restriction(pinned_aks, golden_rim):
    """Assert enabled hardware debug status restricts configuration trustworthiness."""
    with open(VECTORS_DIR / "valid_eat_token.json", "r", encoding="utf-8") as f:
        token_data = json.load(f)

    token_data["dbgstat"] = "enabled"
    token = parse_eat(token_data)
    verifier = RATSVerifier(pinned_aks=pinned_aks, golden_rim=golden_rim)

    res = verifier.verify(token, expected_nonce=token.nonce)

    assert res.verdict == "UNDETERMINED"
    assert res.trustworthiness_vector.configuration == "RESTRICTED"
    assert any("Platform debug mode is active" in r for r in res.reasons)


def test_rsa_quote_verification():
    """Assert pure Python stdlib RSA PKCS#1 v1.5 verification against pinned (n, e)."""
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives import hashes

    # Generate RSA test keypair
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    pub_numbers = public_key.public_numbers()

    pinned_ak = {
        "type": "rsassa-pkcs1v15",
        "n": hex(pub_numbers.n),
        "e": hex(pub_numbers.e),
    }

    test_payload = b'{"magic": "ff544347", "nonce": "test_rsa_nonce"}'
    sig_bytes = private_key.sign(
        test_payload,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )

    quote = TPMQuote(
        magic="ff544347",
        attest_type="8018",
        signer_name="oem-rsa-ak",
        nonce="test_rsa_nonce",
        pcr_select=[0],
        pcr_digest="",
        clock_info={},
        sig_alg="rsassa-pkcs1v15",
        signature=sig_bytes.hex(),
        raw_attest=test_payload.decode("utf-8"),
    )

    # Pure stdlib verifier validates RSA signature
    assert verify_quote_signature(quote, pinned_ak) is True

    # Mutate signature byte -> should fail
    bad_sig = bytearray(sig_bytes)
    bad_sig[10] ^= 0xFF
    quote.signature = bad_sig.hex()
    assert verify_quote_signature(quote, pinned_ak) is False


def test_cli_execution():
    """Assert CLI returns 0 on valid token and 1 on tampered token."""
    cli_py = str(Path(__file__).parent.parent / "attestation" / "rats-verifier" / "cli.py")
    valid_token = str(VECTORS_DIR / "valid_eat_token.json")
    tampered_token = str(VECTORS_DIR / "tampered_pcr_token.json")
    aks = str(VECTORS_DIR / "pinned_aks.json")
    rim = str(VECTORS_DIR / "golden_rim.json")
    nonce = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"

    # Test valid token
    cmd_valid = [
        sys.executable, cli_py,
        "--token", valid_token,
        "--aks", aks,
        "--rim", rim,
        "--nonce", nonce,
    ]
    res_valid = subprocess.run(cmd_valid, capture_output=True, text=True)
    assert res_valid.returncode == 0
    assert "AFFIRMED" in res_valid.stdout

    # Test tampered token
    cmd_tampered = [
        sys.executable, cli_py,
        "--token", tampered_token,
        "--aks", aks,
        "--rim", rim,
        "--nonce", nonce,
    ]
    res_tampered = subprocess.run(cmd_tampered, capture_output=True, text=True)
    assert res_tampered.returncode == 1
    assert "CONTRAINDICATED" in res_tampered.stdout

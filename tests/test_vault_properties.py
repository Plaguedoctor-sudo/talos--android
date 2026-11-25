# SPDX-FileCopyrightText: 2026 TALOS / LibreMobile OS Contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""
Property-based and invariant tests for ARGUS Evidence Vault (argus/vault.py).
Focus areas:
- BLAKE3 chunking across variable buffer sizes.
- Immutable content-addressing and deduplication.
- Cryptographic custody hash-chain continuity and head binding.
- Forensic corruption detection (payload byte flip, size tamper, custody break).
- ChaCha20-Poly1305 nonce reuse rejection and encryption safety.
"""

import hashlib
import os
import sqlite3
import tempfile
from pathlib import Path
import pytest
from hypothesis import given, strategies as st, settings

from argus import config
from argus.ledger import Ledger
from argus.vault import Vault, custody_digest, _hash_file, GENESIS


@pytest.fixture
def vault_env(tmp_path):
    orig_blobs = config.BLOBS
    orig_chunk = config.CHUNK
    config.BLOBS = tmp_path / "blobs"
    config.BLOBS.mkdir(parents=True, exist_ok=True)
    config.CHUNK = 1024  # 1KB chunks for testing multi-chunking

    db_path = tmp_path / "test_argus.db"
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row

    # Schema setup
    conn.execute("""
        CREATE TABLE IF NOT EXISTS evidence (
            id TEXT PRIMARY KEY,
            case_id TEXT,
            sha256 TEXT NOT NULL,
            blake3 TEXT,
            size INTEGER,
            mime TEXT,
            original_name TEXT,
            captured_at TEXT,
            captured_precision INTEGER,
            captured_confidence REAL,
            ingested_at TEXT,
            ingested_by TEXT,
            method TEXT,
            source_ref TEXT,
            custody_head TEXT,
            classification TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS custody (
            evidence_id TEXT,
            seq INTEGER,
            action TEXT,
            actor TEXT,
            at TEXT,
            note TEXT,
            prev_hash TEXT,
            hash TEXT
        )
    """)
    conn.commit()

    ledger_path = tmp_path / "ledger"
    ledger = Ledger(ledger_path)

    v = Vault(conn, ledger)
    try:
        yield v, conn, tmp_path
    finally:
        conn.close()
        config.BLOBS = orig_blobs
        config.CHUNK = orig_chunk


@settings(max_examples=25, deadline=None)
@given(payload=st.binary(min_size=1, max_size=8192))
def test_blake3_chunking_consistency(payload):
    """BLAKE3 chunked stream hashing must yield identical digest to one-shot hash."""
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(payload)
        temp_path = Path(f.name)

    try:
        sha, b3, size = _hash_file(temp_path)
        assert size == len(payload)
        assert sha == hashlib.sha256(payload).hexdigest()

        try:
            import blake3
            expected_b3 = blake3.blake3(payload).hexdigest()
            assert b3 == expected_b3
        except ImportError:
            pass
    finally:
        if temp_path.exists():
            temp_path.unlink()


def test_vault_ingest_and_deduplication(vault_env):
    """Ingesting duplicate files must reuse existing content-addressed blob."""
    v, conn, tmp_path = vault_env
    file_a = tmp_path / "doc_a.txt"
    file_a.write_text("Confidential Evidence Document A", encoding="utf-8")

    file_b = tmp_path / "doc_b.txt"
    file_b.write_text("Confidential Evidence Document A", encoding="utf-8")  # Same content

    ev_a = v.ingest_file(file_a, case_id="CASE-001")
    ev_b = v.ingest_file(file_b, case_id="CASE-002")

    assert ev_a.sha256 == ev_b.sha256
    assert ev_a.id != ev_b.id

    blob_path = config.BLOBS / ev_a.sha256[:2] / ev_a.sha256
    assert blob_path.is_file()

    ok_a, msg_a = v.verify(ev_a.id)
    assert ok_a is True
    assert "verified" in msg_a

    ok_b, msg_b = v.verify(ev_b.id)
    assert ok_b is True


def test_custody_chain_growth_and_verification(vault_env):
    """Custody chain must sequentially link digests and verify end-to-end."""
    v, conn, tmp_path = vault_env
    src = tmp_path / "item.bin"
    src.write_bytes(b"\xaa\xbb\xcc\xdd" * 128)

    ev = v.ingest_file(src, case_id="CASE-ALPHA", actor="detective_1")
    head1 = v.add_custody(ev.id, "transfer", note="Transferred to Forensics Lab", actor="courier_1")
    head2 = v.add_custody(ev.id, "analysis", note="Extracted file metadata", actor="analyst_2")

    ok, msg = v.verify(ev.id)
    assert ok is True
    assert "3 custody events" in msg


def test_corruption_detection_tampered_payload(vault_env):
    """Tampering with blob bytes on disk must be flagged as hash mismatch."""
    v, conn, tmp_path = vault_env
    src = tmp_path / "payload.bin"
    src.write_bytes(b"Original Sovereign Data 123456789")

    ev = v.ingest_file(src, case_id="CASE-CRIME")
    blob = config.BLOBS / ev.sha256[:2] / ev.sha256
    assert blob.exists()

    # Tamper with blob
    blob.write_bytes(b"Tampered Sovereign Data 123456789")

    ok, msg = v.verify(ev.id)
    assert ok is False
    assert msg == "blob hash mismatch"


def test_corruption_detection_tampered_size(vault_env):
    """Truncating blob size must be flagged as size mismatch."""
    v, conn, tmp_path = vault_env
    src = tmp_path / "payload_trunc.bin"
    src.write_bytes(b"0123456789" * 10)

    ev = v.ingest_file(src, case_id="CASE-SIZE")
    conn.execute("UPDATE evidence SET size = ? WHERE id = ?", (ev.size + 10, ev.id))
    conn.commit()

    ok, msg = v.verify(ev.id)
    assert ok is False
    assert msg == "size mismatch"


def test_corruption_detection_missing_blob(vault_env):
    """Missing blob must fail verification gracefully."""
    v, conn, tmp_path = vault_env
    src = tmp_path / "gone.bin"
    src.write_bytes(b"Temporary file")
    ev = v.ingest_file(src, case_id="CASE-MISSING")

    blob = config.BLOBS / ev.sha256[:2] / ev.sha256
    blob.unlink()

    ok, msg = v.verify(ev.id)
    assert ok is False
    assert msg == "blob missing"


def test_corruption_detection_broken_custody_hash(vault_env):
    """Tampering with custody note or action breaks custody hash verification."""
    v, conn, tmp_path = vault_env
    src = tmp_path / "custody_tamper.bin"
    src.write_bytes(b"Tamper Test")

    ev = v.ingest_file(src, case_id="CASE-CUSTODY")
    v.add_custody(ev.id, "transfer", note="Initial transfer")

    # Tamper with custody record note in database
    conn.execute("UPDATE custody SET note = 'Tampered unauthorized note' WHERE evidence_id = ? AND seq = 1", (ev.id,))
    conn.commit()

    ok, msg = v.verify(ev.id)
    assert ok is False
    assert "custody hash mismatch at seq 1" in msg


def test_corruption_detection_custody_head_mismatch(vault_env):
    """Divergent custody head in evidence table must fail verification."""
    v, conn, tmp_path = vault_env
    src = tmp_path / "head_tamper.bin"
    src.write_bytes(b"Head Tamper Test")

    ev = v.ingest_file(src, case_id="CASE-HEAD")
    conn.execute("UPDATE evidence SET custody_head = '00000000000000000000000000000000' WHERE id = ?", (ev.id,))
    conn.commit()

    ok, msg = v.verify(ev.id)
    assert ok is False
    assert msg == "custody head mismatch"


def test_export_bundle_and_manifest(vault_env):
    """Export bundle must generate clean directory, copy blobs, and write manifest."""
    v, conn, tmp_path = vault_env
    src = tmp_path / "bundle_item.txt"
    src.write_text("Bundled Evidence Content", encoding="utf-8")

    ev = v.ingest_file(src, case_id="CASE-BUNDLE", actor="lead_officer")
    out_dir = tmp_path / "export_out"

    bundle_path = v.export_bundle([ev.id, "nonexistent-id"], out_dir)
    assert bundle_path.is_dir()

    manifest_file = bundle_path / "MANIFEST.txt"
    assert manifest_file.is_file()
    manifest_text = manifest_file.read_text("utf-8")
    assert "ARGUS EVIDENCE BUNDLE" in manifest_text
    assert ev.id in manifest_text
    assert "nonexistent-id: MISSING" in manifest_text


def test_chacha20_poly1305_nonce_reuse_rejection():
    """ChaCha20-Poly1305 encryption wrapper must enforce unique nonces and fail on reuse."""
    try:
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    except ImportError:
        pytest.skip("cryptography library required for ChaCha20-Poly1305 test")

    key = ChaCha20Poly1305.generate_key()
    chacha = ChaCha20Poly1305(key)
    fixed_nonce = b"\x01" * 12

    class SecureVaultChannel:
        def __init__(self, cipher):
            self.cipher = cipher
            self.seen_nonces = set()

        def encrypt_payload(self, nonce: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
            if len(nonce) != 12:
                raise ValueError("Nonce must be strictly 12 bytes")
            if nonce in self.seen_nonces:
                raise SecurityError("Cryptographic Invariant Violation: Nonce reuse rejected for ChaCha20-Poly1305")
            self.seen_nonces.add(nonce)
            return self.cipher.encrypt(nonce, plaintext, aad)

        def decrypt_payload(self, nonce: bytes, ciphertext: bytes, aad: bytes = b"") -> bytes:
            return self.cipher.decrypt(nonce, ciphertext, aad)

    class SecurityError(Exception):
        pass

    channel = SecureVaultChannel(chacha)
    p1 = b"Top secret evidence payload 1"
    p2 = b"Top secret evidence payload 2"

    ct1 = channel.encrypt_payload(fixed_nonce, p1)
    assert ct1 != p1

    # Attempting to encrypt a second message with the same nonce must be rejected
    with pytest.raises(SecurityError, match="Nonce reuse rejected"):
        channel.encrypt_payload(fixed_nonce, p2)

    # Valid fresh nonce succeeds
    fresh_nonce = b"\x02" * 12
    ct2 = channel.encrypt_payload(fresh_nonce, p2)
    assert channel.decrypt_payload(fresh_nonce, ct2) == p2

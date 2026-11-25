"""Ed25519 signers. Checkpoints sign the closing hash of a sealed segment."""
from __future__ import annotations
import pathlib
import cbor2
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization


class CheckpointSigner:
    def __init__(self, key_pem: bytes, out_dir):
        if len(key_pem) == 32:
            self.key = Ed25519PrivateKey.from_private_bytes(key_pem)
        else:
            self.key = serialization.load_pem_private_key(key_pem, None)
        self.out = pathlib.Path(out_dir)
        self.out.mkdir(parents=True, exist_ok=True)

    def public_key(self):
        return self.key.public_key()

    def __call__(self, seg_seq: int, closing_hash: bytes) -> pathlib.Path:
        sig = self.key.sign(closing_hash)
        p = self.out / f"cp-{seg_seq:06d}.cbor"
        p.write_bytes(cbor2.dumps({"seg_seq": seg_seq,
                                   "closing_hash": closing_hash,
                                   "sig": sig}, canonical=True))
        return p


class DeviceSigner:
    def __init__(self, key_pem: bytes):
        if not key_pem:
            self.key = None
        elif len(key_pem) == 32:
            self.key = Ed25519PrivateKey.from_private_bytes(key_pem)
        else:
            self.key = serialization.load_pem_private_key(key_pem, None)

    def sign(self, digest: bytes) -> bytes:
        if self.key is None:
            raise RuntimeError("DeviceSigner key not configured")
        return self.key.sign(digest)

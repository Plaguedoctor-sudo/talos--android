from __future__ import annotations
import pathlib
from blake3 import blake3
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from cryptography import x509


class Keyring:
    def __init__(self, path):
        path = pathlib.Path(path)
        self.keys, self.roots = {}, set()
        rf = path / "allowed_roots.txt"
        if rf.exists():
            self.roots = {l.strip() for l in rf.read_text().splitlines()
                          if l.strip() and not l.startswith("#")}
        for pem in path.glob("*.pem"):
            try:
                k = serialization.load_pem_public_key(pem.read_bytes())
            except Exception:
                continue
            if isinstance(k, Ed25519PublicKey):
                self.keys[fingerprint(k)] = k

    def get(self, fp):
        return self.keys.get(fp)


def fingerprint(pub):
    raw = pub.public_bytes(serialization.Encoding.Raw,
                           serialization.PublicFormat.Raw)
    return blake3(raw).hexdigest()[:16]


def load_pubkey(pem):
    k = serialization.load_pem_public_key(pem)
    if not isinstance(k, Ed25519PublicKey):
        raise ValueError("not ed25519")
    return k


def load_cert(data):
    try:
        return x509.load_pem_x509_certificate(data)
    except Exception:
        return x509.load_der_x509_certificate(data)


def cert_signed_by(cert, issuer):
    try:
        issuer.verify(cert.signature, cert.tbs_certificate_bytes)
        return True
    except Exception:
        return False


def verify_detached(pub, sig, digest):
    try:
        pub.verify(sig, digest)
        return True
    except Exception:
        return False

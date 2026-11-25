#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 TALOS / LibreMobile OS Contributors
# SPDX-License-Identifier: Apache-2.0
"""
TALOS Store Index Ed25519 Detached Signer & Verifier (store/sign-index.py).
Provides Ed25519 signing, verification, and keygen for store index manifests.
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path
from typing import Optional

try:
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives import serialization
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False


def keygen(out_dir: Path) -> None:
    """Generate Ed25519 keypair and write to keys directory."""
    if not HAVE_CRYPTO:
        raise RuntimeError("cryptography library required for Ed25519 key generation")

    out_dir.mkdir(parents=True, exist_ok=True)
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()

    priv_bytes = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_bytes = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    fingerprint = hashlib.sha256(pub_bytes).hexdigest()

    (out_dir / "fdroid-signing.sec").write_text(priv_bytes.hex() + "\n", encoding="utf-8")
    (out_dir / "fdroid-signing.pub").write_text(pub_bytes.hex() + "\n", encoding="utf-8")
    (out_dir / "fingerprint.txt").write_text(fingerprint + "\n", encoding="utf-8")

    print(f"✔ Generated Ed25519 signing keypair in {out_dir}")
    print(f"✔ Fingerprint (SHA-256): {fingerprint}")


def sign_index(index_path: Path, key_path: Path, sig_path: Path) -> None:
    """Sign index file using Ed25519 secret key and write detached signature."""
    if not HAVE_CRYPTO:
        raise RuntimeError("cryptography library required for Ed25519 signing")

    raw_data = index_path.read_bytes()
    key_hex = key_path.read_text(encoding="utf-8").strip()
    priv_bytes = bytes.fromhex(key_hex)
    priv = ed25519.Ed25519PrivateKey.from_private_bytes(priv_bytes)

    signature = priv.sign(raw_data)
    sig_path.parent.mkdir(parents=True, exist_ok=True)
    sig_path.write_text(signature.hex() + "\n", encoding="utf-8")
    print(f"✔ Successfully signed {index_path} -> {sig_path}")


def verify_index(index_path: Path, sig_path: Path, pubkey_path: Path) -> bool:
    """Verify Ed25519 detached signature against public key."""
    if not HAVE_CRYPTO:
        raise RuntimeError("cryptography library required for Ed25519 verification")

    raw_data = index_path.read_bytes()
    sig_hex = sig_path.read_text(encoding="utf-8").strip()
    pub_hex = pubkey_path.read_text(encoding="utf-8").strip()

    sig_bytes = bytes.fromhex(sig_hex)
    pub_bytes = bytes.fromhex(pub_hex)
    pub = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)

    try:
        pub.verify(sig_bytes, raw_data)
        fingerprint = hashlib.sha256(pub_bytes).hexdigest()
        print(f"✔ Signature VERIFIED: valid Ed25519 signature over {index_path.name}")
        print(f"✔ Signer Key Fingerprint: {fingerprint}")
        return True
    except Exception as err:
        sys.stderr.write(f"✖ Verification FAILED: {err}\n")
        return False


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="sign-index.py",
        description="TALOS Store Ed25519 Detached Signer & Verifier",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    kg_p = sub.add_parser("keygen", help="Generate Ed25519 keypair")
    kg_p.add_argument("--out-dir", default="store/keys", help="Output directory for keys")

    sign_p = sub.add_parser("sign", help="Sign store index file")
    sign_p.add_argument("--index", required=True, help="Path to index.json")
    sign_p.add_argument("--key", required=True, help="Path to fdroid-signing.sec")
    sign_p.add_argument("--output", required=True, help="Path to index.json.sig")

    ver_p = sub.add_parser("verify", help="Verify index detached signature")
    ver_p.add_argument("--index", required=True, help="Path to index.json")
    ver_p.add_argument("--sig", required=True, help="Path to index.json.sig")
    ver_p.add_argument("--pubkey", required=True, help="Path to fdroid-signing.pub")

    args = parser.parse_args(argv)

    if args.command == "keygen":
        keygen(Path(args.out_dir))
        return 0
    elif args.command == "sign":
        sign_index(Path(args.index), Path(args.key), Path(args.output))
        return 0
    elif args.command == "verify":
        ok = verify_index(Path(args.index), Path(args.sig), Path(args.pubkey))
        return 0 if ok else 1

    return 2


if __name__ == "__main__":
    sys.exit(main())

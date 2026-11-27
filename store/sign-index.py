#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 TALOS / LibreMobile OS Contributors
# SPDX-License-Identifier: Apache-2.0
"""
TALOS Store Index Ed25519 Detached Signer & Verifier (store/sign-index.py).
Provides Ed25519 signing, verification, and keygen for store index manifests.
Enforces strict separation of secret key material from repository trees.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import sys
from pathlib import Path
from typing import Optional

try:
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives import serialization
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_KEY_DIR = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "talos"
DEFAULT_KEY_PATH = DEFAULT_KEY_DIR / "store-signing.sec"


def _assert_outside_repo(target_path: Path) -> None:
    """Ensure secret key path does not reside within the repository tree."""
    resolved_target = target_path.resolve()
    resolved_repo = REPO_ROOT.resolve()

    if resolved_target == resolved_repo or resolved_repo in resolved_target.parents:
        raise RuntimeError(
            f"Security Violation: Refusing to store secret key inside repository tree: {target_path}. "
            "Secret keys must be provisioned outside the repository (e.g., ~/.config/talos/store-signing.sec)."
        )


def keygen(key_path: Path) -> None:
    """Generate Ed25519 keypair and write secret key safely outside repository."""
    if not HAVE_CRYPTO:
        raise RuntimeError("cryptography library required for Ed25519 key generation")

    _assert_outside_repo(key_path)

    key_path.parent.mkdir(parents=True, exist_ok=True)
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

    # Write secret key with restrictive permissions (0600)
    key_path.write_text(priv_bytes.hex() + "\n", encoding="utf-8")
    try:
        os.chmod(key_path, 0o600)
    except OSError:
        pass

    pub_path = key_path.with_suffix(".pub")
    pub_path.write_text(pub_bytes.hex() + "\n", encoding="utf-8")

    print("==========================================================================")
    print(f"✔ Generated Ed25519 release keypair outside repository:")
    print(f"  Secret Key: {key_path}")
    print(f"  Public Key:  {pub_path}")
    print(f"  Fingerprint (SHA-256): {fingerprint}")
    print("==========================================================================")
    print("ACTION REQUIRED FOR OPERATOR:")
    print("1. Update store/keys/fdroid-signing.pub with the public key hex:")
    print(f"   {pub_bytes.hex()}")
    print("2. Update store/keys/fingerprint.txt with the fingerprint:")
    print(f"   {fingerprint}")
    print("==========================================================================")


def _load_private_key_bytes(key_path: Path) -> bytes:
    """Load a 32-byte Ed25519 private key from raw binary bytes or UTF-8 hex text."""
    raw_key = key_path.read_bytes()
    if len(raw_key) == 32:
        return raw_key

    try:
        key_hex = raw_key.decode("utf-8").strip()
        priv_bytes = bytes.fromhex(key_hex)
    except (UnicodeDecodeError, ValueError) as err:
        raise ValueError(
            f"Invalid Ed25519 private key in {key_path}: expected 32 raw bytes or "
            f"64 UTF-8 hex characters (got {len(raw_key)} bytes): {err}"
        ) from err

    if len(priv_bytes) != 32:
        raise ValueError(
            f"Invalid Ed25519 private key length in {key_path}: expected 32 bytes, "
            f"got {len(priv_bytes)} bytes"
        )
    return priv_bytes


def sign_index(index_path: Path, key_path: Path, sig_path: Path) -> None:
    """Sign index file using Ed25519 secret key and write detached signature."""
    if not HAVE_CRYPTO:
        raise RuntimeError("cryptography library required for Ed25519 signing")

    if not key_path.exists():
        raise FileNotFoundError(f"Signing key not found at {key_path}. Run scripts/provision-store-key.sh first.")

    raw_data = index_path.read_bytes()
    priv_bytes = _load_private_key_bytes(key_path)
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

    kg_p = sub.add_parser("keygen", help="Generate Ed25519 keypair outside repo")
    kg_p.add_argument("--key-path", default=str(DEFAULT_KEY_PATH), help="Path for secret key (must be outside repo)")

    sign_p = sub.add_parser("sign", help="Sign store index file")
    sign_p.add_argument("--index", required=True, help="Path to index.json")
    sign_p.add_argument("--key", "--key-path", dest="key", default=str(DEFAULT_KEY_PATH), help="Path to private signing key")
    sign_p.add_argument("--output", required=True, help="Path to index.json.sig")

    ver_p = sub.add_parser("verify", help="Verify index detached signature")
    ver_p.add_argument("--index", required=True, help="Path to index.json")
    ver_p.add_argument("--sig", required=True, help="Path to index.json.sig")
    ver_p.add_argument("--pubkey", required=True, help="Path to fdroid-signing.pub")

    args = parser.parse_args(argv)

    if args.command == "keygen":
        keygen(Path(args.key_path))
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

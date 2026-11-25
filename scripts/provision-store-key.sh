#!/bin/bash
# SPDX-FileCopyrightText: 2026 TALOS / LibreMobile OS Contributors
# SPDX-License-Identifier: GPL-3.0-or-later
#
# scripts/provision-store-key.sh
# Safely generates an Ed25519 signing key outside the repository tree.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/talos"
KEY_PATH="${1:-$CONFIG_DIR/store-signing.sec}"

mkdir -p "$(dirname "$KEY_PATH")"
chmod 700 "$(dirname "$KEY_PATH")"

if [[ "$KEY_PATH" == "$REPO_ROOT"* ]]; then
    echo "ERROR: Refusing to write private signing key inside repository: $KEY_PATH" >&2
    echo "The secret key MUST be stored outside the repository tree." >&2
    exit 1
fi

if [ -f "$KEY_PATH" ]; then
    echo "Notice: Key already exists at $KEY_PATH"
else
    echo "[*] Generating release Ed25519 keypair at $KEY_PATH..."
    python3 "$REPO_ROOT/store/sign-index.py" keygen --key-path "$KEY_PATH"
fi

echo ""
echo "=========================================================================="
echo "KEY PROVISIONING INSTRUCTIONS FOR OPERATOR:"
echo "1. The secret key is securely stored OUTSIDE the repo at:"
echo "   $KEY_PATH"
echo "2. NEVER commit this secret key or copy it into the repository."
echo "3. Copy the public key hex into:"
echo "   $REPO_ROOT/store/keys/fdroid-signing.pub"
echo "4. Copy the SHA-256 fingerprint into:"
echo "   $REPO_ROOT/store/keys/fingerprint.txt"
echo "5. Rebuild and sign the store index with:"
echo "   make store-index SIGNING_KEY=$KEY_PATH"
echo "=========================================================================="

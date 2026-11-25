#!/bin/bash
# ==============================================================================
# TALOS Sovereign App Store Index Verifier (store/verify-index.sh)
# Validates Ed25519 detached signature and JSON manifest schema integrity.
#
# SPDX-License-Identifier: Apache-2.0
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KEYS_DIR="$SCRIPT_DIR/keys"
INDEX_DIR="$SCRIPT_DIR/index"

PUBKEY="$KEYS_DIR/fdroid-signing.pub"
FINGERPRINT_FILE="$KEYS_DIR/fingerprint.txt"
INDEX_FILE="$INDEX_DIR/index.json"
SIG_FILE="$INDEX_DIR/index.json.sig"

echo "=== TALOS Sovereign Store Index Verifier ==="

if [ ! -f "$INDEX_FILE" ]; then
    echo "Error: Index file not found at $INDEX_FILE" >&2
    exit 1
fi

# Hard failure if release key is UNPINNED
if [ -f "$FINGERPRINT_FILE" ]; then
    FP_CONTENT="$(cat "$FINGERPRINT_FILE")"
    if [[ "$FP_CONTENT" == *"UNPINNED"* ]]; then
        echo "Refusing to verify: release key not provisioned. See store/POLICY.md." >&2
        exit 1
    fi
fi

# Hard failure if index is unsigned
IS_SIGNED="$(python3 -c 'import json, sys; data = json.load(open(sys.argv[1])); print(data.get("signed", True))' "$INDEX_FILE" 2>/dev/null || echo "True")"
if [ "$IS_SIGNED" = "False" ]; then
    echo "Index is unsigned. Operator must provision a release key (store/POLICY.md)." >&2
    exit 1
fi

if [ ! -f "$SIG_FILE" ]; then
    echo "Error: Detached signature not found at $SIG_FILE" >&2
    exit 1
fi

if [ ! -f "$PUBKEY" ]; then
    echo "Error: Pinned public key not found at $PUBKEY" >&2
    exit 1
fi

# 1. Cryptographic Signature Verification
echo "[*] Verifying detached Ed25519 signature..."
python3 "$SCRIPT_DIR/sign-index.py" verify \
    --index "$INDEX_FILE" \
    --sig "$SIG_FILE" \
    --pubkey "$PUBKEY"

# 2. Key Fingerprint Match Check
EXPECTED_FP="$(cat "$FINGERPRINT_FILE" | tr -d '[:space:]')"
ACTUAL_FP="$(python3 -c 'import hashlib, sys; print(hashlib.sha256(bytes.fromhex(open(sys.argv[1]).read().strip())).hexdigest())' "$PUBKEY")"
if [ "$EXPECTED_FP" != "$ACTUAL_FP" ]; then
    echo "Error: Key fingerprint mismatch: expected $EXPECTED_FP, got $ACTUAL_FP" >&2
    exit 1
fi
echo "✔ Key fingerprint verified: $ACTUAL_FP"

# 3. Schema & Integrity Validation
echo "[*] Validating store index schema and privacy score integrity..."
python3 -c '
import json, sys

path = sys.argv[1]
with open(path, "r", encoding="utf-8") as f:
    data = json.load(f)

assert "repo" in data, "Missing repo block"
assert "score_metadata" in data, "Missing score_metadata block"
assert data["score_metadata"]["score_version"] == "1.0.0", "Invalid score_version"
assert "packages" in data and isinstance(data["packages"], list), "Invalid packages list"
assert len(data["packages"]) > 0, "No packages found in index"

for pkg in data["packages"]:
    pkg_id = pkg.get("id")
    assert pkg_id, "Package missing ID"
    assert "privacy_score" in pkg, f"Package {pkg_id} missing privacy_score"
    score_obj = pkg["privacy_score"]
    assert "total_score" in score_obj, f"Package {pkg_id} missing total_score"
    assert "grade" in score_obj, f"Package {pkg_id} missing grade"
    assert 0.0 <= score_obj["total_score"] <= 100.0, f"Score out of bounds for {pkg_id}"
    assert score_obj["grade"] in ("A+", "A", "B", "C", "D", "F"), f"Invalid grade for {pkg_id}"

pkg_count = len(data["packages"])
print(f"✔ Schema valid: verified {pkg_count} packages with privacy scores.")
' "$INDEX_FILE"

echo "=========================================================="
echo "✔ STORE VERIFICATION PASSED: Cryptographic signature & schema valid."
echo "=========================================================="

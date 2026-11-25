#!/bin/bash
# ==============================================================================
# TALOS Sovereign App Store Index Builder (store/build-index.sh)
# Fetches upstream mirror index, computes deterministic privacy scores,
# and generates a signed repository index (store/index/index.json + .sig).
#
# SPDX-License-Identifier: Apache-2.0
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

DATA_DIR="$SCRIPT_DIR/data"
KEYS_DIR="$SCRIPT_DIR/keys"
INDEX_DIR="$SCRIPT_DIR/index"
UPSTREAM_CACHE="$DATA_DIR/upstream-index.json"
TRACKERS_DB="$DATA_DIR/trackers.json"
POLICY_DIR="$REPO_ROOT/security/egress/policy"

SIGNING_KEY="$KEYS_DIR/fdroid-signing.sec"
PUBKEY="$KEYS_DIR/fdroid-signing.pub"
OUTPUT_INDEX="$INDEX_DIR/index.json"
OUTPUT_SIG="$INDEX_DIR/index.json.sig"

# Pinned Mirror URL
PINNED_MIRROR_URL="${FDROID_MIRROR_URL:-https://f-droid.org/repo/index-v1.json}"

mkdir -p "$INDEX_DIR"

echo "=== TALOS Sovereign Store Index Builder ==="
echo "[*] Pinned Upstream Mirror: $PINNED_MIRROR_URL"

# Step 1: Obtain upstream index (attempt fetch with timeout, fall back to pinned snapshot)
TEMP_INDEX="/tmp/upstream_index_fetch.json"
FETCH_SUCCESS=0

if [ -n "${FDROID_FETCH_ONLINE:-}" ]; then
    echo "[*] Attempting to fetch upstream index from mirror..."
    if curl --connect-timeout 5 --max-time 15 -fsSL "$PINNED_MIRROR_URL" -o "$TEMP_INDEX" 2>/dev/null; then
        echo "[+] Successfully fetched upstream index from $PINNED_MIRROR_URL"
        INPUT_INDEX="$TEMP_INDEX"
        FETCH_SUCCESS=1
    fi
fi

if [ "$FETCH_SUCCESS" -eq 0 ]; then
    echo "[*] Using pinned offline snapshot: $UPSTREAM_CACHE"
    INPUT_INDEX="$UPSTREAM_CACHE"
fi

# Step 2: Compute deterministic privacy scores
echo "[*] Computing deterministic privacy scores (Version: 1.0.0)..."
python3 "$SCRIPT_DIR/privacy-score.py" \
    --index "$INPUT_INDEX" \
    --trackers "$TRACKERS_DB" \
    --policy-dir "$POLICY_DIR" \
    --ref-date "2026-11-25" \
    --output "$OUTPUT_INDEX"

# Step 3: Sign index with pinned Ed25519 key
echo "[*] Signing repository index with Ed25519 key..."
if [ ! -f "$SIGNING_KEY" ]; then
    echo "[!] Signing key missing; generating local keypair..."
    python3 "$SCRIPT_DIR/sign-index.py" keygen --out-dir "$KEYS_DIR"
fi

python3 "$SCRIPT_DIR/sign-index.py" sign \
    --index "$OUTPUT_INDEX" \
    --key "$SIGNING_KEY" \
    --output "$OUTPUT_SIG"

echo "=========================================================="
echo "✔ Store index built and signed successfully."
echo "  Manifest:  $OUTPUT_INDEX"
echo "  Signature: $OUTPUT_SIG"
echo "=========================================================="

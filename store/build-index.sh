#!/bin/bash
# ==============================================================================
# TALOS Sovereign App Store Index Builder (store/build-index.sh)
# Fetches upstream mirror index, computes deterministic privacy scores,
# and generates a repository index (store/index/index.json + .sig).
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

CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/talos"
SIGNING_KEY="${SIGNING_KEY:-$CONFIG_DIR/store-signing.sec}"
PUBKEY="$KEYS_DIR/fdroid-signing.pub"
FINGERPRINT_FILE="$KEYS_DIR/fingerprint.txt"
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

# Step 3: Check release key pinning and sign or emit UNSIGNED
FP_CONTENT=""
if [ -f "$FINGERPRINT_FILE" ]; then
    FP_CONTENT="$(cat "$FINGERPRINT_FILE")"
fi

if [[ "$FP_CONTENT" == *"UNPINNED"* ]] || [ -z "$FP_CONTENT" ] || [ ! -f "$SIGNING_KEY" ]; then
    echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" >&2
    echo "WARNING: Store index generated UNSIGNED. Release key is UNPINNED." >&2
    echo "Operator must provision release key outside repo per store/POLICY.md." >&2
    echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" >&2

    # Inject unsigned metadata into index.json
    python3 -c '
import json, sys
path = sys.argv[1]
with open(path, "r", encoding="utf-8") as f:
    data = json.load(f)
data["signed"] = False
data["signature"] = None
with open(path, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2)
' "$OUTPUT_INDEX"
    rm -f "$OUTPUT_SIG"

    echo "=========================================================="
    echo "✔ Store index built UNSIGNED (operator release key unpinned)."
    echo "  Manifest:  $OUTPUT_INDEX"
    echo "=========================================================="
else
    # Pinned and key present: sign normally
    echo "[*] Signing repository index with provisioned Ed25519 key..."
    python3 "$SCRIPT_DIR/sign-index.py" sign \
        --index "$OUTPUT_INDEX" \
        --key "$SIGNING_KEY" \
        --output "$OUTPUT_SIG"

    python3 -c '
import json, sys
path = sys.argv[1]
with open(path, "r", encoding="utf-8") as f:
    data = json.load(f)
data["signed"] = True
with open(path, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2)
' "$OUTPUT_INDEX"

    echo "=========================================================="
    echo "✔ Store index built and signed successfully."
    echo "  Manifest:  $OUTPUT_INDEX"
    echo "  Signature: $OUTPUT_SIG"
    echo "=========================================================="
fi

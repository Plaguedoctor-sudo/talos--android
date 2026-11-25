#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 TALOS / LibreMobile OS Contributors
# SPDX-License-Identifier: GPL-3.0-or-later
# ==============================================================================
# TALOS / LibreMobile OS — Reproducibility Attestation Generator
# Builds twice under different working paths, asserts bit-for-bit equality,
# and publishes a machine-verifiable attestation JSON.
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

OUT_A="${REPO_ROOT}/out/a"
OUT_B="${REPO_ROOT}/out/b"

mkdir -p "${REPO_ROOT}/out" "${REPO_ROOT}/repro"

GIT_SHA="$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || echo "0000000000000000000000000000000000000000")"
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "$REPO_ROOT" log -1 --format=%ct 2>/dev/null || echo 1700000000)}"
export SOURCE_DATE_EPOCH
export TZ="UTC"
export LC_ALL="C"
export E2FSPROGS_FAKE_TIME="$SOURCE_DATE_EPOCH"

echo "========================================================================"
echo "    TALOS / LibreMobile OS — Dual-Build Reproducibility Attestation    "
echo "========================================================================"
echo "Git Commit SHA:     $GIT_SHA"
echo "SOURCE_DATE_EPOCH:  $SOURCE_DATE_EPOCH"
echo ""

# 1. First Build (Path A: local workspace)
echo ">>> [1/3] Executing Build A -> $OUT_A..."
"${REPO_ROOT}/scripts/repro-build.sh" "$OUT_A"

# 2. Second Build (Path B: isolated path to guarantee location-independence)
echo ""
echo ">>> [2/3] Executing Build B -> $OUT_B (verifying path-independence)..."
TMP_WORK_DIR="$(mktemp -d /tmp/talos-repro-b.XXXXXX)"
cleanup() {
    rm -rf "$TMP_WORK_DIR"
}
trap cleanup EXIT

# Copy source repository to temporary path (excluding build outputs)
tar --exclude="out" --exclude=".git" --exclude="*.img" -cf - -C "$REPO_ROOT" . | tar -xf - -C "$TMP_WORK_DIR"

# Run build from independent path
"${TMP_WORK_DIR}/scripts/repro-build.sh" "$OUT_B"

# 3. Diff and Verify Bit-for-Bit Identity
echo ""
echo ">>> [3/3] Performing bit-for-bit diff between Build A and Build B..."
if diff -r "$OUT_A" "$OUT_B"; then
    echo "✔ MATCH CONFIRMED: Build A and Build B are 100% bit-for-bit identical."
else
    echo "❌ MISMATCH DETECTED: Build outputs differ across independent paths."
    exit 1
fi

# 4. Generate Machine-Verifiable Attestation JSON
ATTESTATION_FILE="${REPO_ROOT}/repro/attestation-${GIT_SHA}.json"
ATTESTATION_LATEST="${REPO_ROOT}/repro/attestation-latest.json"

echo ">>> Publishing attestation record: $ATTESTATION_FILE..."
python3 -c '
import json, hashlib, subprocess, sys, os, shutil

repo_root = sys.argv[1]
git_sha = sys.argv[2]
epoch = int(sys.argv[3])
out_a = sys.argv[4]
out_file = sys.argv[5]
out_latest = sys.argv[6]

# Gather build environment toolchain versions
def cmd_version(cmd):
    try:
        res = subprocess.run(cmd, capture_output=True, text=True)
        return res.stdout.strip().split("\n")[0]
    except Exception as e:
        return f"unavailable ({e})"

env_tools = {
    "gcc": cmd_version(["gcc", "--version"]),
    "make": cmd_version(["make", "--version"]),
    "python3": cmd_version(["python3", "--version"]),
    "mke2fs": cmd_version(["mke2fs", "-V"]),
    "node": cmd_version(["node", "--version"]),
}

env_str = json.dumps(env_tools, sort_keys=True)
build_env_hash = hashlib.sha256(env_str.encode()).hexdigest()

# Load per-artifact SHA-256 hashes from SHA256SUMS.txt
per_artifact = {}
sums_path = os.path.join(out_a, "SHA256SUMS.txt")
if os.path.exists(sums_path):
    with open(sums_path, "r", encoding="utf-8") as f:
        for line in f:
            parts = line.strip().split(None, 1)
            if len(parts) == 2:
                per_artifact[parts[1]] = parts[0]

attestation = {
    "$schema": "https://talos.os/schemas/repro-attestation-v1.json",
    "git_sha": git_sha,
    "source_date_epoch": epoch,
    "build_env_hash": build_env_hash,
    "build_environment": env_tools,
    "diff_result": "IDENTICAL",
    "artifacts_verified_count": len(per_artifact),
    "per_artifact_sha256": per_artifact
}

with open(out_file, "w", encoding="utf-8") as f:
    json.dump(attestation, f, indent=2)

shutil.copyfile(out_file, out_latest)

print(f"✔ Attestation generated with {len(per_artifact)} verified artifacts.")
' "$REPO_ROOT" "$GIT_SHA" "$SOURCE_DATE_EPOCH" "$OUT_A" "$ATTESTATION_FILE" "$ATTESTATION_LATEST"

echo "========================================================================"
echo "✔ REPRODUCIBLE ATTESTATION COMPLETE & VERIFIED."
echo "========================================================================"

#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 TALOS / LibreMobile OS Contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""
TALOS / LibreMobile OS — Machine-Verifiable Attestation Verifier
Standard-library only script that verifies build outputs against a published
cryptographic reproducibility attestation JSON.
"""

import sys
import os
import json
import hashlib
from typing import Dict, Tuple

def compute_sha256(filepath: str) -> str:
    """Compute SHA-256 digest of a local file in 64KB chunks."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()

def verify_attestation(attestation_path: str, build_dir: str) -> int:
    if not os.path.isfile(attestation_path):
        print(f"❌ Error: Attestation file not found: {attestation_path}", file=sys.stderr)
        return 1
    if not os.path.isdir(build_dir):
        print(f"❌ Error: Build directory not found: {build_dir}", file=sys.stderr)
        return 1

    try:
        with open(attestation_path, "r", encoding="utf-8") as f:
            attestation = json.load(f)
    except Exception as e:
        print(f"❌ Error parsing attestation JSON: {e}", file=sys.stderr)
        return 1

    git_sha = attestation.get("git_sha", "unknown")
    epoch = attestation.get("source_date_epoch", "unknown")
    artifacts = attestation.get("per_artifact_sha256", {})

    print("========================================================================")
    print("    TALOS / LibreMobile OS — Reproducibility Attestation Verifier       ")
    print("========================================================================")
    print(f"Attestation File:   {attestation_path}")
    print(f"Target Build Dir:   {build_dir}")
    print(f"Referenced Commit:  {git_sha}")
    print(f"Source Date Epoch:  {epoch}")
    print(f"Artifacts to Audit: {len(artifacts)}")
    print("------------------------------------------------------------------------")
    print(f"{'Artifact':<45} {'Status':<10} {'Details'}")
    print("------------------------------------------------------------------------")

    passed = 0
    failed = 0
    missing = 0

    for rel_path, expected_hash in sorted(artifacts.items()):
        full_path = os.path.join(build_dir, rel_path)
        if not os.path.isfile(full_path):
            print(f"{rel_path:<45} {'MISSING':<10} File not found in build directory")
            missing += 1
            continue

        actual_hash = compute_sha256(full_path)
        if actual_hash == expected_hash:
            print(f"{rel_path:<45} {'PASS':<10} {actual_hash[:16]}... matches")
            passed += 1
        else:
            print(f"{rel_path:<45} {'FAIL':<10} Hash mismatch!")
            print(f"  Expected: {expected_hash}")
            print(f"  Actual:   {actual_hash}")
            failed += 1

    print("========================================================================")
    print(f"Verification Summary: {passed} passed, {failed} failed, {missing} missing.")
    print("========================================================================")

    if failed == 0 and missing == 0 and passed > 0:
        print("✔ ALL ARTIFACTS VERIFIED BIT-FOR-BIT AGAINST ATTESTATION.")
        return 0
    else:
        print("❌ ATTESTATION VERIFICATION FAILED.")
        return 1

def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <attestation.json> <build_directory>", file=sys.stderr)
        sys.exit(2)

    attestation_file = sys.argv[1]
    build_directory = sys.argv[2]
    code = verify_attestation(attestation_file, build_directory)
    sys.exit(code)

if __name__ == "__main__":
    main()

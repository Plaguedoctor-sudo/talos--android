#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 TALOS / LibreMobile OS Contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""
TALOS / LibreMobile OS — REUSE & SPDX Compliance Linter
Standard-library only script that verifies REUSE.toml annotations,
SPDX headers, and license file integrity across the codebase.
"""

import os
import sys
import fnmatch
from typing import List, Dict, Set

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
EXCLUDE_DIRS = {
    ".git", ".pytest_cache", "__pycache__", "node_modules",
    ".deps", "out", "build_tmp", "output", ".github"
}

def parse_simple_toml(path: str) -> Dict:
    """Parse key declarations from simple REUSE.toml."""
    annotations = []
    current = None
    if not os.path.isfile(path):
        return {"annotations": []}
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line.startswith("[[annotations]]"):
                current = {"path": []}
                annotations.append(current)
            elif current is not None:
                if line.startswith("path"):
                    # Parse array like: path = ["**"]
                    val = line.split("=", 1)[1].strip()
                    if "[" in val and "]" in val:
                        items = val.strip("[]").split(",")
                        current["path"] = [it.strip().strip("\"'") for it in items if it.strip()]
                elif line.startswith("SPDX-FileCopyrightText"):
                    current["copyright"] = line.split("=", 1)[1].strip().strip("\"'")
                elif line.startswith("SPDX-License-Identifier"):
                    current["license"] = line.split("=", 1)[1].strip().strip("\"'")
    return {"annotations": annotations}

def check_file_spdx(file_path: str) -> bool:
    """Check if file has embedded SPDX headers."""
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            head = f.read(2048)
            return "SPDX-License-Identifier:" in head or "SPDX-FileCopyrightText:" in head
    except Exception:
        return False

def matches_reuse_annotations(rel_path: str, annotations: List[Dict]) -> bool:
    """Check if relative path matches any REUSE.toml annotation pattern."""
    for ann in annotations:
        for pat in ann.get("path", []):
            if pat == "**" or pat == "*":
                return True
            if fnmatch.fnmatch(rel_path, pat) or fnmatch.fnmatch(os.path.basename(rel_path), pat):
                return True
            if pat.endswith("/**"):
                prefix = pat[:-3]
                if rel_path.startswith(prefix + "/") or rel_path == prefix:
                    return True
    return False

def main() -> int:
    print("========================================================================")
    print("       TALOS / LibreMobile OS — REUSE & SPDX Compliance Linter          ")
    print("========================================================================")

    reuse_toml = os.path.join(REPO_ROOT, "REUSE.toml")
    if not os.path.isfile(reuse_toml):
        print("❌ Error: REUSE.toml not found at repo root.", file=sys.stderr)
        return 1
    print(f"✔ REUSE manifest verified: {os.path.relpath(reuse_toml, REPO_ROOT)}")

    # Check LICENSES directory
    licenses_dir = os.path.join(REPO_ROOT, "LICENSES")
    if not os.path.isdir(licenses_dir):
        print("❌ Error: LICENSES/ directory not found.", file=sys.stderr)
        return 1
    required_licenses = ["GPL-3.0-or-later.txt", "Apache-2.0.txt"]
    for lic in required_licenses:
        lic_file = os.path.join(licenses_dir, lic)
        if not os.path.isfile(lic_file):
            print(f"❌ Error: Required license {lic} missing in LICENSES/", file=sys.stderr)
            return 1
    print(f"✔ Required license texts verified in LICENSES/ ({len(required_licenses)} licenses)")

    parsed_toml = parse_simple_toml(reuse_toml)
    annotations = parsed_toml.get("annotations", [])

    total_scanned = 0
    spdx_embedded = 0
    annotated = 0

    for root, dirs, files in os.walk(REPO_ROOT):
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS and not d.startswith(".")]
        for f in files:
            if f.endswith(".pyc") or f == ".DS_Store":
                continue
            full_path = os.path.join(root, f)
            rel_path = os.path.relpath(full_path, REPO_ROOT)
            total_scanned += 1

            has_inline = check_file_spdx(full_path)
            has_ann = matches_reuse_annotations(rel_path, annotations)

            if has_inline:
                spdx_embedded += 1
            if has_ann:
                annotated += 1

            if not has_inline and not has_ann:
                print(f"❌ Unlicensed file detected: {rel_path}", file=sys.stderr)
                return 1

    print("------------------------------------------------------------------------")
    print(f"Scanned Files:              {total_scanned}")
    print(f"Files with Inline SPDX:     {spdx_embedded}")
    print(f"Files with REUSE Coverage:  {annotated}")
    print("------------------------------------------------------------------------")
    print("✔ REUSE LINT PASSED: 100% of files have valid licensing attribution.")
    print("========================================================================")
    return 0

if __name__ == "__main__":
    sys.exit(main())

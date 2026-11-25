#!/bin/bash
# SPDX-FileCopyrightText: 2026 TALOS / LibreMobile OS Contributors
# SPDX-License-Identifier: GPL-3.0-or-later
#
# scripts/rewrite-history-for-key-removal.sh
#
# Removes committed secret key material from the entire Git commit history.
# TODO(operator): Execute this script with git-filter-repo installed to rewrite history.

set -euo pipefail

echo "=========================================================================="
echo "TALOS / LibreMobile OS — History Rewrite for Committed Key Removal"
echo "=========================================================================="

if ! command -v git-filter-repo >/dev/null 2>&1; then
    echo "ERROR: 'git-filter-repo' is not installed." >&2
    echo "Please install git-filter-repo (e.g., 'pip install git-filter-repo' or 'apt install git-filter-repo')." >&2
    echo "" >&2
    echo "Once installed, run the exact command below from the repository root:" >&2
    echo "  git filter-repo --path store/keys/fdroid-signing.sec --invert-paths" >&2
    exit 1
fi

echo "[*] Rewriting history to purge store/keys/fdroid-signing.sec across all commits..."
git filter-repo --path store/keys/fdroid-signing.sec --invert-paths

echo "✔ History rewrite complete. All references to store/keys/fdroid-signing.sec removed."
echo "NOTE: Coordinate with all repository collaborators before force-pushing rewritten branches."

#!/bin/bash
# SPDX-FileCopyrightText: 2026 TALOS / LibreMobile OS Contributors
# SPDX-License-Identifier: GPL-3.0-or-later
#
# scripts/pre-commit-key-guard.sh
# Git pre-commit hook preventing accidental staging of private cryptographic keys.

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
ALLOWLIST_FILE="$REPO_ROOT/.keyguard-allow"

# Dangerous patterns to block from commits
BLOCKED_PATTERNS=(
    '\.sec$'
    '\.pem$'
    '\.key$'
    'id_ed25519'
    'id_rsa'
    'id_ecdsa'
    'id_dsa'
)

STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACM || true)
if [ -z "$STAGED_FILES" ]; then
    exit 0
fi

FAILED=0

for file in $STAGED_FILES; do
    # Check if explicitly allowed
    if [ -f "$ALLOWLIST_FILE" ]; then
        if grep -Fxq "$file" "$ALLOWLIST_FILE" 2>/dev/null; then
            continue
        fi
        # Check wildcard pattern matching in allowlist
        while IFS= read -r pattern || [ -n "$pattern" ]; do
            [[ "$pattern" =~ ^[[:space:]]*# ]] && continue
            [[ -z "${pattern// }" ]] && continue
            if [[ "$file" == $pattern ]]; then
                continue 2
            fi
        done < "$ALLOWLIST_FILE"
    fi

    for pattern in "${BLOCKED_PATTERNS[@]}"; do
        if echo "$file" | grep -Eiq "$pattern"; then
            echo "❌ PRE-COMMIT KEY GUARD BLOCKED STAGED FILE: $file" >&2
            echo "   Reason: Matches prohibited secret key / certificate pattern: $pattern" >&2
            echo "   Cryptographic secret keys must NEVER be committed to Git." >&2
            FAILED=1
            break
        fi
    done

    # Also inspect staged blob content for PEM private key headers
    if git show ":$file" 2>/dev/null | grep -aEq -- '-----BEGIN [A-Z ]*PRIVATE KEY-----'; then
        echo "❌ PRE-COMMIT KEY GUARD BLOCKED STAGED BLOB: $file" >&2
        echo "   Reason: Contains PEM private key header." >&2
        FAILED=1
    fi
done

if [ $FAILED -ne 0 ]; then
    echo "" >&2
    echo "Aborting commit due to prohibited key material in staging area." >&2
    echo "If this is an authorized test fixture, list it in .keyguard-allow." >&2
    exit 1
fi

exit 0

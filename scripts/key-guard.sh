#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 TALOS / LibreMobile OS Contributors
# SPDX-License-Identifier: GPL-3.0-or-later
#
# scripts/key-guard.sh
# Checks all reachable Git trees for prohibited key file paths (respecting .keyguard-allow)
# and inspects all reachable Git blobs for PEM private key material.

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
ALLOWLIST_FILE="$REPO_ROOT/.keyguard-allow"

# 1. Check reachable trees for prohibited key filenames (artifact paths, not commit log)
PROHIBITED_FILES="$(git rev-list --all | xargs -r -n1 git ls-tree -r 2>/dev/null \
  | awk '{print $4}' | sort -u \
  | grep -E '\.(sec|pem|key)$|id_(ed25519|rsa|ecdsa|dsa)$' || true)"

if [[ -n "${PROHIBITED_FILES}" ]]; then
  VIOLATIONS=""
  while IFS= read -r file; do
    [[ -z "${file}" ]] && continue
    ALLOWED=false
    if [[ -f "${ALLOWLIST_FILE}" ]]; then
      while IFS= read -r pattern || [[ -n "${pattern}" ]]; do
        [[ "${pattern}" =~ ^[[:space:]]*# ]] && continue
        [[ -z "${pattern// }" ]] && continue
        # shellcheck disable=SC2053
        if [[ "${file}" == ${pattern} ]]; then
          ALLOWED=true
          break
        fi
      done < "${ALLOWLIST_FILE}"
    fi
    if [[ "${ALLOWED}" == false ]]; then
      VIOLATIONS="${VIOLATIONS}\n${file}"
    fi
  done <<< "${PROHIBITED_FILES}"

  if [[ -n "${VIOLATIONS}" ]]; then
    echo "FAIL: Prohibited key file paths present in reachable git trees:" >&2
    echo -e "${VIOLATIONS}" >&2
    exit 1
  fi
fi

# 2. Fail if any blob reachable from any ref contains PEM private key material.
leaked="$(git rev-list --all | xargs -r -n1 git ls-tree -r 2>/dev/null | awk '{print $3}' | sort -u \
  | xargs -r -n1 git cat-file -p 2>/dev/null \
  | grep -aE -- '-----BEGIN [A-Z ]*PRIVATE KEY-----' || true)"
if [[ -n "${leaked}" ]]; then
  echo "FAIL: PEM private key material present in reachable git blobs." >&2
  echo "${leaked}" | head -5 >&2
  exit 1
fi

echo "PASS: no PEM private key material in any reachable blob"

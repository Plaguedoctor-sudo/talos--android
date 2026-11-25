#!/bin/bash
# SPDX-FileCopyrightText: 2026 TALOS / LibreMobile OS Contributors
# SPDX-License-Identifier: Apache-2.0
#
# scripts/fuzz-smoke.sh
# Runs continuous smoke fuzzing against security-critical C parsers for 60s per target.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

SMOKE_DURATION="${SMOKE_DURATION:-60}"
FUZZ_OUT="out/fuzz"
CRASH_DIR="${FUZZ_OUT}/crashes"
mkdir -p "${CRASH_DIR}"

TARGETS=(
    "fuzz_telephony_ril"
    "fuzz_nft_policy"
    "fuzz_argf2"
    "fuzz_pif_json"
    "fuzz_battery_sysfs"
)

echo "========================================================================"
echo "TALOS / LibreMobile OS Security Parser Smoke Fuzzing Suite"
echo "Targets: ${#TARGETS[@]} | Duration per target: ${SMOKE_DURATION}s"
echo "Crash dump directory: ${CRASH_DIR}"
echo "========================================================================"

FAILED_TARGETS=()

for target in "${TARGETS[@]}"; do
    bin_path="${FUZZ_OUT}/${target}"
    if [ ! -x "${bin_path}" ]; then
        echo "Binary ${bin_path} not found. Building fuzz binaries..."
        make fuzz
    fi

    target_name="${target#fuzz_}"
    corpus_dir="fuzz/corpus/${target_name}"
    dict_file="fuzz/dict/${target_name}.dict"

    mkdir -p "${corpus_dir}"

    echo ""
    echo ">>> Running harness: ${target} [${corpus_dir}] (${SMOKE_DURATION}s) <<<"

    log_file="${FUZZ_OUT}/${target}_smoke.log"

    set +e
    if [ -f "${dict_file}" ]; then
        "${bin_path}" -max_total_time="${SMOKE_DURATION}" -dict="${dict_file}" "${corpus_dir}" > "${log_file}" 2>&1
    else
        "${bin_path}" -max_total_time="${SMOKE_DURATION}" "${corpus_dir}" > "${log_file}" 2>&1
    fi
    exit_code=$?
    set -e

    if [ ${exit_code} -ne 0 ]; then
        echo "❌ FAILED: ${target} exited with status ${exit_code}!"
        cat "${log_file}"
        cp "${log_file}" "${CRASH_DIR}/${target}_failure.log"
        FAILED_TARGETS+=("${target}")
    else
        echo "✔ PASSED: ${target} ran ${SMOKE_DURATION}s with 0 crashes."
        # Print summary line from log
        grep -E "(Session complete|Seed corpus loaded|Rate:)" "${log_file}" | tail -n 2 || true
    fi
done

echo ""
echo "========================================================================"
if [ ${#FAILED_TARGETS[@]} -eq 0 ]; then
    echo "✔ ALL ${#TARGETS[@]} FUZZING HARNESSES PASSED SMOKE TESTING (0 CRASHES)."
    echo "========================================================================"
    exit 0
else
    echo "❌ SMOKE FUZZING FAILED FOR: ${FAILED_TARGETS[*]}"
    echo "========================================================================"
    exit 1
fi

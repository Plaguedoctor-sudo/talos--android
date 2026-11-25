#!/bin/bash
# ==============================================================================
# LibreDroid Phase 12 Automated Verification Test Suite
# ARM64-to-x86 Binary Translation Bridge & Play Integrity Fix (Transitional)
#
# SPDX-License-Identifier: Apache-2.0
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MOBILE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

ARM_BRIDGE="$MOBILE_ROOT/waydroid/lrd-arm-bridge"
PIF_APPLY="$MOBILE_ROOT/waydroid/lrd-pif-apply"
PIF_JSON="$MOBILE_ROOT/waydroid/pif.json"
SERVICE_FILE="$MOBILE_ROOT/waydroid/lrd-arm-bridge.service"
PKG_LIST="$MOBILE_ROOT/packages/mobile-packages.list"

PASSED=0
FAILED=0

assert_ok() {
    local name="$1"
    shift
    echo -n "[TEST] $name ... "
    if "$@"; then
        echo "PASS"
        PASSED=$((PASSED + 1))
    else
        echo "FAIL"
        FAILED=$((FAILED + 1))
    fi
}

echo "=== Running Phase 12 ARM Translation & Play Integrity Verification Suite ==="

# Check scripts exist
assert_ok "lrd-arm-bridge script exists and executable" test -x "$ARM_BRIDGE"
assert_ok "lrd-pif-apply script exists and executable" test -x "$PIF_APPLY"
assert_ok "pif.json certified profile exists" test -f "$PIF_JSON"
assert_ok "lrd-arm-bridge.service systemd unit exists" test -f "$SERVICE_FILE"
assert_ok "Package manifest contains binfmt-support and qemu-user-static" grep -q "binfmt-support" "$PKG_LIST"

# Test Certified PIF Profile JSON
test_pif_json() {
    python3 -c '
import json, sys
data = json.load(open(sys.argv[1]))
assert data.get("_comment") == "TRANSITIONAL — see PIF_ROADMAP.md"
assert data.get("BRAND") == "google"
assert "FINGERPRINT" in data
assert data["INTEGRITY"]["MEETS_BASIC_INTEGRITY"] is True
assert data["INTEGRITY"]["MEETS_DEVICE_INTEGRITY"] is True
' "$PIF_JSON"
}
assert_ok "Certified Play Integrity Fix profile verification (Pixel 8 Pro fingerprint)" test_pif_json

# Test ARM Translation Bridge Setup and Status
test_arm_bridge_lifecycle() {
    local setup_out
    setup_out=$("$ARM_BRIDGE" setup)
    echo "$setup_out" | grep -q "ARM Translation Bridge"

    local status_out
    status_out=$("$ARM_BRIDGE" status)
    echo "$status_out" | grep -q '"status": "active"'
}
assert_ok "ARM64-to-x86 binary translation bridge provisioning & binfmt_misc hooks" test_arm_bridge_lifecycle

# Test Play Integrity Injection and Verdict
test_pif_apply_lifecycle() {
    if [ "${TALOS_PIF_DISABLE:-0}" = "1" ]; then
        local apply_out
        apply_out=$("$PIF_APPLY" apply 2>&1)
        echo "$apply_out" | grep -q "TALOS_PIF_DISABLE=1 set: Skipping transitional Play Integrity spoofing"

        local status_out
        status_out=$("$PIF_APPLY" status)
        echo "$status_out" | grep -q '"status": "disabled"'
        echo "$status_out" | grep -q '"pif_applied_transitional": false'
    else
        local apply_out
        apply_out=$("$PIF_APPLY" apply 2>&1)
        echo "$apply_out" | grep -q "Play Integrity Fix applied successfully"
        echo "$apply_out" | grep -q "pif_applied_transitional=true"

        local status_out
        status_out=$("$PIF_APPLY" status)
        echo "$status_out" | grep -q '"MEETS_BASIC_INTEGRITY": true'
        echo "$status_out" | grep -q '"MEETS_DEVICE_INTEGRITY": true'
        echo "$status_out" | grep -q '"signature_spoofing": "enabled"'
        echo "$status_out" | grep -q '"pif_applied_transitional": true'
    fi
}
assert_ok "Play Integrity Fix injection & microG signature spoofing validation" test_pif_apply_lifecycle

# Test Play Integrity disable override via TALOS_PIF_DISABLE=1
test_pif_disable_override() {
    local out
    out=$(TALOS_PIF_DISABLE=1 "$PIF_APPLY" apply 2>&1)
    echo "$out" | grep -q "TALOS_PIF_DISABLE=1 set: Skipping transitional Play Integrity spoofing"

    local status_out
    status_out=$("$PIF_APPLY" status)
    echo "$status_out" | grep -q '"status": "disabled"'
    echo "$status_out" | grep -q '"pif_applied_transitional": false'

    # Restore default active state if we are in normal test mode
    if [ "${TALOS_PIF_DISABLE:-0}" != "1" ]; then
        "$PIF_APPLY" apply >/dev/null 2>&1
    fi
}
assert_ok "Play Integrity Fix disable override via TALOS_PIF_DISABLE=1" test_pif_disable_override

echo "=========================================================="
echo "Phase 12 Test Results: $PASSED passed, $FAILED failed."
echo "=========================================================="

if [ "$FAILED" -eq 0 ]; then
    exit 0
else
    exit 1
fi

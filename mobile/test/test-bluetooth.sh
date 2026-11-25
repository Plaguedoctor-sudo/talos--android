#!/usr/bin/env bash
# ==============================================================================
# LibreDroid Sovereign Bluetooth & BLE Privacy Stack Verification Suite
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MOBILE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

BLUETOOTHD="$MOBILE_ROOT/bluetooth/lrd-bluetoothd"
BLUETOOTH_CTL="$MOBILE_ROOT/bluetooth/lrd-bluetooth"
SERVICE_FILE="$MOBILE_ROOT/bluetooth/lrd-bluetooth.service"
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

echo "=== Running Phase 13 Sovereign Bluetooth & BLE Privacy Verification Suite ==="

# 1. Check binaries and configuration
assert_ok "lrd-bluetoothd daemon binary exists and executable" test -x "$BLUETOOTHD"
assert_ok "lrd-bluetooth controller CLI exists and executable" test -x "$BLUETOOTH_CTL"
assert_ok "lrd-bluetooth.service systemd unit exists" test -f "$SERVICE_FILE"

# 2. Check package list contains required Bluetooth stack
test_packages() {
    grep -q "bluez" "$PKG_LIST" && \
    grep -q "bluez-tools" "$PKG_LIST" && \
    grep -q "rfkill" "$PKG_LIST"
}
assert_ok "Bluetooth package manifest entries (bluez, bluez-tools, rfkill)" test_packages

# 3. Start daemon for live socket interaction
killall -q lrd-bluetoothd 2>/dev/null || true
rm -f /tmp/libredroid/bluetooth.sock /run/libredroid/bluetooth.sock 2>/dev/null || true
echo "[*] Spawning lrd-bluetoothd test instance..."
"$BLUETOOTHD" >/dev/null 2>&1 &
DAEMON_PID=$!
sleep 0.4

cleanup() {
    kill "$DAEMON_PID" 2>/dev/null || true
    wait "$DAEMON_PID" 2>/dev/null || true
}
trap cleanup EXIT

# 4. Test adapter status and telemetry
test_status() {
    local out
    out=$("$BLUETOOTH_CTL" status)
    echo "$out" | grep -q '"powered":true' && \
    echo "$out" | grep -q '"privacy_mode":true' && \
    echo "$out" | grep -q '"adapter_name":"TALOS-Sovereign-ARM64"'
}
assert_ok "Bluetooth adapter status reporting (powered, privacy mode, adapter name)" test_status

# 5. Test Anti-Tracking BLE MAC Address Randomization (Sovereign Alibi Mode)
test_mac_randomization() {
    local out1 out2 mac1 mac2
    out1=$("$BLUETOOTH_CTL" privacy rotate)
    mac1=$(echo "$out1" | grep -oE '([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}')
    [ -n "$mac1" ]

    out2=$("$BLUETOOTH_CTL" privacy rotate)
    mac2=$(echo "$out2" | grep -oE '([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}')
    [ -n "$mac2" ]
    [ "$mac1" != "$mac2" ]
}
assert_ok "Anti-surveillance BLE MAC address rotation & privacy shield" test_mac_randomization

# 6. Test Bluetooth radio power toggle
test_power_toggle() {
    local off_out on_out
    off_out=$("$BLUETOOTH_CTL" power off)
    echo "$off_out" | grep -q '"powered":false'

    on_out=$("$BLUETOOTH_CTL" power on)
    echo "$on_out" | grep -q '"powered":true'
}
assert_ok "Bluetooth radio hardware power gating & kill-switch" test_power_toggle

# 7. Test device scan & discovery
test_discovery() {
    local scan_out stop_out
    scan_out=$("$BLUETOOTH_CTL" scan start)
    echo "$scan_out" | grep -q '"discovering":true'

    stop_out=$("$BLUETOOTH_CTL" scan stop)
    echo "$stop_out" | grep -q '"discovering":false'
}
assert_ok "Bluetooth device discovery and inquiry cycle" test_discovery

# 8. Test device enumeration & audio/input profile classification
test_devices() {
    local dev_out
    dev_out=$("$BLUETOOTH_CTL" devices)
    echo "$dev_out" | grep -q "B8:27:EB:11:22:33" && \
    echo "$dev_out" | grep -q "A2DP/HFP" && \
    echo "$dev_out" | grep -q "Sovereign Touch Keyboard"
}
assert_ok "Device inventory enumeration (A2DP audio sink, HID keyboard, BLE GATT)" test_devices

# 9. Test pairing and secure bonding
test_pairing() {
    local pair_out
    pair_out=$("$BLUETOOTH_CTL" pair "B8:27:EB:11:22:33")
    echo "$pair_out" | grep -q '"paired":true' && \
    echo "$pair_out" | grep -q '"trusted":true'
}
assert_ok "Secure device pairing and trust bonding" test_pairing

# 10. Test profile connection and disconnection
test_connection_lifecycle() {
    local conn_out disconn_out
    conn_out=$("$BLUETOOTH_CTL" connect "B8:27:EB:11:22:33")
    echo "$conn_out" | grep -q '"connected":true'

    disconn_out=$("$BLUETOOTH_CTL" disconnect "B8:27:EB:11:22:33")
    echo "$disconn_out" | grep -q '"connected":false'
}
assert_ok "A2DP/HFP wireless audio stream connection lifecycle" test_connection_lifecycle

# Stop daemon cleanly
cleanup
trap - EXIT

echo "=========================================================="
echo "Phase 13 Test Results: $PASSED passed, $FAILED failed."
echo "=========================================================="

if [ "$FAILED" -eq 0 ]; then
    exit 0
else
    exit 1
fi

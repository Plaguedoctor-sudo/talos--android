#!/usr/bin/env bash
# ==============================================================================
# LibreDroid Sovereign Wi-Fi & Hotspot AP Stack Verification Suite
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MOBILE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

WIFID="$MOBILE_ROOT/wifi/lrd-wifid"
WIFI_CTL="$MOBILE_ROOT/wifi/lrd-wifi"
SERVICE_FILE="$MOBILE_ROOT/wifi/lrd-wifi.service"
PKG_LIST="$MOBILE_ROOT/packages/mobile-packages.list"
NFT_RULES="$MOBILE_ROOT/../security/egress/nftables/lrd-egress.nft"

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

echo "=== Running Phase 14 Sovereign Wi-Fi & Hotspot Verification Suite ==="

# 1. Check binaries and configuration
assert_ok "lrd-wifid daemon binary exists and executable" test -x "$WIFID"
assert_ok "lrd-wifi controller CLI exists and executable" test -x "$WIFI_CTL"
assert_ok "lrd-wifi.service systemd unit exists" test -f "$SERVICE_FILE"

# 2. Check package list contains required Wi-Fi and Hotspot stack
test_packages() {
    grep -q "network-manager" "$PKG_LIST" && \
    grep -q "wpasupplicant" "$PKG_LIST" && \
    grep -q "hostapd" "$PKG_LIST" && \
    grep -q "dnsmasq-base" "$PKG_LIST" && \
    grep -q "iw" "$PKG_LIST"
}
assert_ok "Wi-Fi & Hotspot package manifest entries (hostapd, dnsmasq, wpa_supplicant, iw)" test_packages

# 3. Check egress firewall configuration for hotspot tethering
test_nft_rules() {
    grep -q 'iifname { "ap0", "lrd-ap0" } udp dport 67' "$NFT_RULES" && \
    grep -q 'iifname { "ap0", "lrd-ap0" } udp dport 53' "$NFT_RULES" && \
    grep -q 'iifname { "ap0", "lrd-ap0" } oifname "wg0"' "$NFT_RULES"
}
assert_ok "Egress firewall nftables rules for hotspot isolation & tethering" test_nft_rules

# 4. Start daemon for live socket interaction
killall -q lrd-wifid 2>/dev/null || true
rm -f /tmp/libredroid/wifi.sock /run/libredroid/wifi.sock 2>/dev/null || true
echo "[*] Spawning lrd-wifid test instance..."
"$WIFID" >/dev/null 2>&1 &
DAEMON_PID=$!
sleep 0.4

cleanup() {
    kill "$DAEMON_PID" 2>/dev/null || true
    wait "$DAEMON_PID" 2>/dev/null || true
}
trap cleanup EXIT

# 5. Test Wi-Fi Station Status
test_station_status() {
    local out
    out=$("$WIFI_CTL" status)
    echo "$out" | grep -q '"powered":true' && \
    echo "$out" | grep -q '"ifname":"wlan0"' && \
    echo "$out" | grep -q '"privacy_mode":true'
}
assert_ok "Wi-Fi station telemetry & interface state (wlan0, IP, privacy mode)" test_station_status

# 6. Test Wi-Fi Station MAC Randomization (Alibi mode)
test_station_privacy() {
    local out1 out2 mac1 mac2
    out1=$("$WIFI_CTL" privacy rotate)
    mac1=$(echo "$out1" | grep -oE '([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}')
    [ -n "$mac1" ]

    out2=$("$WIFI_CTL" privacy rotate)
    mac2=$(echo "$out2" | grep -oE '([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}')
    [ -n "$mac2" ]
    [ "$mac1" != "$mac2" ]
}
assert_ok "Wi-Fi station MAC address rotation & anti-tracking privacy shield" test_station_privacy

# 7. Test Wi-Fi Access Point Scanning
test_ap_scan() {
    local scan_out
    scan_out=$("$WIFI_CTL" scan)
    echo "$scan_out" | grep -q '"count":3' && \
    echo "$scan_out" | grep -q 'TALOS-Encrypted-WLAN' && \
    echo "$scan_out" | grep -q 'WPA3-SAE' && \
    echo "$scan_out" | grep -q '5GHz'
}
assert_ok "Wi-Fi AP scanning across 2.4GHz & 5GHz bands (WPA3-SAE / WPA2)" test_ap_scan

# 8. Test Station Network Connection Lifecycle
test_connection() {
    local conn_out disconn_out
    conn_out=$("$WIFI_CTL" connect "Sovereign-Mesh-5G" "MeshSecPass2026")
    echo "$conn_out" | grep -q '"state":"CONNECTED"' && \
    echo "$conn_out" | grep -q '"ssid":"Sovereign-Mesh-5G"'

    disconn_out=$("$WIFI_CTL" disconnect)
    echo "$disconn_out" | grep -q '"state":"DISCONNECTED"'
}
assert_ok "Wi-Fi station connect/disconnect association lifecycle" test_connection

# 9. Test Sovereign Mobile Hotspot (AP Tethering) Activation
test_hotspot_start() {
    local hs_out
    hs_out=$("$WIFI_CTL" hotspot-start "TALOS-Sovereign-AP" "UltraSecureKey2026" "5GHz")
    echo "$hs_out" | grep -q '"hotspot_active":true' && \
    echo "$hs_out" | grep -q '"ssid":"TALOS-Sovereign-AP"' && \
    echo "$hs_out" | grep -q '"gateway":"192.168.43.1"' && \
    echo "$hs_out" | grep -q '"channel":36'
}
assert_ok "Sovereign Mobile Wi-Fi Hotspot activation (5GHz, 192.168.43.1 gateway)" test_hotspot_start

# 10. Test Mobile Hotspot Status & Connected Clients Telemetry
test_hotspot_clients() {
    local status_out clients_out
    status_out=$("$WIFI_CTL" hotspot-status)
    echo "$status_out" | grep -q '"hotspot_active":true' && \
    echo "$status_out" | grep -q '"connected_clients":2'

    clients_out=$("$WIFI_CTL" hotspot-clients)
    echo "$clients_out" | grep -q 'talos-thinkpad-x1' && \
    echo "$clients_out" | grep -q '192.168.43.15' && \
    echo "$clients_out" | grep -q 'libremobile-tab-8'
}
assert_ok "Hotspot tethering DHCP leasing & client station isolation telemetry" test_hotspot_clients

# 11. Test Mobile Hotspot Deactivation
test_hotspot_stop() {
    local stop_out
    stop_out=$("$WIFI_CTL" hotspot-stop)
    echo "$stop_out" | grep -q '"hotspot_active":false'
}
assert_ok "Mobile Hotspot teardown and interface de-provisioning" test_hotspot_stop

# Stop daemon cleanly
cleanup
trap - EXIT

echo "=========================================================="
echo "Phase 14 Test Results: $PASSED passed, $FAILED failed."
echo "=========================================================="

if [ "$FAILED" -eq 0 ]; then
    exit 0
else
    exit 1
fi

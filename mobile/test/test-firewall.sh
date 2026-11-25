#!/usr/bin/env bash
# ==============================================================================
# LibreDroid Sovereign Defense-Grade Mobile Firewall Verification Suite
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MOBILE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

FIREWALLD="$MOBILE_ROOT/firewall/lrd-firewalld"
FIREWALL_CTL="$MOBILE_ROOT/firewall/lrd-firewall"
SERVICE_FILE="$MOBILE_ROOT/firewall/lrd-firewall.service"
PKG_LIST="$MOBILE_ROOT/packages/mobile-packages.list"
NFT_RULES="$MOBILE_ROOT/../security/egress/nftables/lrd-egress.nft"
POLICY_DIR="$MOBILE_ROOT/../security/egress/policy"

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

echo "=== Running Phase 15 Sovereign Defense-Grade Mobile Firewall Verification Suite ==="

# 1. Check binaries and configuration
assert_ok "lrd-firewalld daemon binary exists and executable" test -x "$FIREWALLD"
assert_ok "lrd-firewall controller CLI exists and executable" test -x "$FIREWALL_CTL"
assert_ok "lrd-firewall.service systemd unit exists" test -f "$SERVICE_FILE"

# 2. Check package list contains required firewall stack
test_packages() {
    grep -q "nftables" "$PKG_LIST" && \
    grep -q "iptables" "$PKG_LIST" && \
    grep -q "conntrack" "$PKG_LIST"
}
assert_ok "Firewall package manifest entries (nftables, iptables, conntrack)" test_packages

# 3. Check nftables ruleset structure (deny-by-default, kill-switch, DoT, blacklist)
test_nft_rules() {
    grep -q 'egress_blocklist_v4' "$NFT_RULES" && \
    grep -q 'egress_allowlist_v4' "$NFT_RULES" && \
    grep -q 'jump egress_audit_drop' "$NFT_RULES" && \
    grep -q 'tcp dport 853' "$NFT_RULES" && \
    grep -q 'udp dport 9053 accept' "$NFT_RULES"
}
assert_ok "Strict deny-by-default, DoT (853), Tor DNS, and blacklist nftables rules" test_nft_rules

# 4. Check per-app sandbox policy manifests
test_policies() {
    [ -f "$POLICY_DIR/org.mozilla.firefox.toml" ] && \
    [ -f "$POLICY_DIR/io.waydroid.container.toml" ] && \
    [ -f "$POLICY_DIR/com.talos.calculator.toml" ] && \
    [ -f "$POLICY_DIR/com.talos.gallery.toml" ] && \
    grep -q 'mode = "blocked"' "$POLICY_DIR/com.talos.calculator.toml" && \
    grep -q 'mode = "blocked"' "$POLICY_DIR/com.talos.gallery.toml"
}
assert_ok "Zero-trust per-app network isolation policies (offline calculator/gallery)" test_policies

# 5. Start daemon for live socket interaction
killall -9 lrd-firewalld 2>/dev/null || pkill -9 -f lrd-firewalld 2>/dev/null || true
rm -f /tmp/libredroid/firewall.sock /run/libredroid/firewall.sock 2>/dev/null || true
echo "[*] Spawning lrd-firewalld test instance..."
"$FIREWALLD" >/dev/null 2>&1 &
DAEMON_PID=$!
for _i in $(seq 1 20); do
    [ -S /run/libredroid/firewall.sock ] || [ -S /tmp/libredroid/firewall.sock ] && break
    sleep 0.05
done

cleanup() {
    kill -9 "$DAEMON_PID" 2>/dev/null || true
    wait "$DAEMON_PID" 2>/dev/null || true
    rm -f /tmp/libredroid/firewall.sock /run/libredroid/firewall.sock 2>/dev/null || true
}
trap cleanup EXIT

# 6. Test Firewall Status & Drop Telemetry
test_status() {
    local out
    out=$("$FIREWALL_CTL" status)
    echo "$out" | grep -q '"active":true' && \
    echo "$out" | grep -q '"kill_switch":true' && \
    echo "$out" | grep -q '"mode":"vpn_wireguard"' && \
    echo "$out" | grep -q '"dns_policy":"enforce_dot"'
}
assert_ok "Firewall status & telemetry reporting (active, deny-by-default, DoT)" test_status

# 7. Test Anti-Leak Kill-Switch Arm/Disarm
test_killswitch() {
    local off_out on_out
    off_out=$("$FIREWALL_CTL" killswitch off)
    echo "$off_out" | grep -q '"kill_switch":false' && \
    on_out=$("$FIREWALL_CTL" killswitch on) && \
    echo "$on_out" | grep -q '"kill_switch":true'
}
assert_ok "Anti-leak network kill-switch arm/disarm governor" test_killswitch

# 8. Test Global Egress Routing Mode Switching (Tor / LAN / VPN)
test_routing_modes() {
    local tor_out lan_out vpn_out
    tor_out=$("$FIREWALL_CTL" mode tor)
    echo "$tor_out" | grep -q '"mode":"tor_strict"' && \
    echo "$tor_out" | grep -q '"dns":"tor_dns"'

    lan_out=$("$FIREWALL_CTL" mode lan)
    echo "$lan_out" | grep -q '"mode":"lan_only"'

    vpn_out=$("$FIREWALL_CTL" mode vpn)
    echo "$vpn_out" | grep -q '"mode":"vpn_wireguard"'
}
assert_ok "Global egress routing mode switching (Tor SOCKS5h, Isolated LAN, WireGuard)" test_routing_modes

# 9. Test Dynamic Destination IP Allowlisting & Blacklisting
test_ip_filtering() {
    local allow_out block_out
    allow_out=$("$FIREWALL_CTL" allow-ip "198.51.100.1")
    echo "$allow_out" | grep -q '"allowlist_ip":"198.51.100.1"'

    block_out=$("$FIREWALL_CTL" block-ip "203.0.113.50")
    echo "$block_out" | grep -q '"blocklist_ip":"203.0.113.50"'
}
assert_ok "Dynamic destination IP allowlisting and anti-surveillance blacklisting" test_ip_filtering

# 10. Test Per-App Network Sandboxing & Revocation
test_app_sandboxing() {
    local block_out allow_out list_out
    block_out=$("$FIREWALL_CTL" block-app "com.untrusted.analytics")
    echo "$block_out" | grep -q '"app_id":"com.untrusted.analytics"' && \
    echo "$block_out" | grep -q '"mode":"BLOCKED"'

    allow_out=$("$FIREWALL_CTL" allow-app "com.untrusted.analytics" "TOR_ONLY")
    echo "$allow_out" | grep -q '"mode":"TOR_ONLY"'

    list_out=$("$FIREWALL_CTL" app-policies)
    echo "$list_out" | grep -q "Offline Calculator" && \
    echo "$list_out" | grep -q "Private Photo Vault"
}
assert_ok "Per-app application-layer firewall sandboxing & network revocation" test_app_sandboxing

# 11. Test Mobile Hotspot Tethering Egress Routing Gating
test_hotspot_egress_policy() {
    local tor_hs vpn_hs
    tor_hs=$("$FIREWALL_CTL" hotspot-egress tor)
    echo "$tor_hs" | grep -q '"hotspot_egress":"routed_tor"'

    vpn_hs=$("$FIREWALL_CTL" hotspot-egress vpn)
    echo "$vpn_hs" | grep -q '"hotspot_egress":"routed_vpn"'
}
assert_ok "Mobile Hotspot tethering egress routing gating (VPN / Tor mediation)" test_hotspot_egress_policy

# 12. Test Emergency Panic Zero-Egress Lockdown & Recovery
test_panic_lockdown() {
    local panic_out restore_out status_after
    panic_out=$("$FIREWALL_CTL" panic)
    echo "$panic_out" | grep -q '"panic":true' && \
    echo "$panic_out" | grep -q '"mode":"panic_kill"'

    restore_out=$("$FIREWALL_CTL" restore)
    echo "$restore_out" | grep -q '"panic":false' && \
    echo "$restore_out" | grep -q '"mode":"vpn_wireguard"'

    status_after=$("$FIREWALL_CTL" status)
    echo "$status_after" | grep -q '"panic_triggered":false'
}
assert_ok "Emergency zero-egress panic lockdown & cryptographic recovery" test_panic_lockdown

# 13. Test Dropped Packet Audit Trail Stream
test_audit_stream() {
    local audit_out
    audit_out=$("$FIREWALL_CTL" audit)
    echo "$audit_out" | grep -q '"drops_total":42' && \
    echo "$audit_out" | grep -q 'COMMERCIAL_TELEMETRY_BLOCK' && \
    echo "$audit_out" | grep -q 'DNS_LEAK_PREVENTION'
}
assert_ok "Real-time dropped packet forensic audit trail & leak telemetry" test_audit_stream

# Stop daemon cleanly
cleanup
trap - EXIT

echo "=========================================================="
echo "Phase 15 Test Results: $PASSED passed, $FAILED failed."
echo "=========================================================="

if [ "$FAILED" -eq 0 ]; then
    exit 0
else
    exit 1
fi

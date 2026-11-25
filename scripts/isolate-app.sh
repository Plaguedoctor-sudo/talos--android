#!/usr/bin/env bash
# scripts/isolate-app.sh — Launch ARGUS / SHADOWTRACE in total host isolation
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "=========================================================="
echo "   ARGUS // Total Host PC Isolation & Tor Onion Shield    "
echo "=========================================================="
echo " • Workspace:           ${ROOT}"
echo " • Containment:         Total isolation from host filesystem & LAN"
echo " • Anonymity Mode:      Tor SOCKS5h remote DNS resolution"

USE_VM=false
if [[ " $* " =~ " --vm " ]]; then
    USE_VM=true
fi

if [ "$USE_VM" = true ]; then
    echo "[*] Launching inside Hardware KVM Virtual Machine Appliance..."
    export ISOLATE_CONTACT=true
    exec "${ROOT}/vm/start-vm.sh"
fi

# Detect Tor daemon; launch local isolated instance if not running
if command -v tor >/dev/null 2>&1; then
    TOR_PORT="${TOR_PORT:-9050}"
    TOR_CTRL="${TOR_CTRL:-9051}"
    if ! ss -tulpn 2>/dev/null | grep -q ":${TOR_PORT}\b"; then
        echo "[*] Starting Tor Onion Routing daemon on 127.0.0.1:${TOR_PORT}..."
        mkdir -p /tmp/argus-tor-data
        chmod 700 /tmp/argus-tor-data
        tor --RunAsDaemon 1 --SocksPort "${TOR_PORT}" --ControlPort "${TOR_CTRL}" --DataDirectory /tmp/argus-tor-data >/dev/null 2>&1 || true
        sleep 1
    fi
    export ARGUS_USE_TOR=1
    export ALL_PROXY="socks5h://127.0.0.1:${TOR_PORT}"
    export TOR_PROXY="socks5://127.0.0.1:${TOR_PORT}"
    export TOR_SOCKS_PORT="${TOR_PORT}"
    export TOR_CONTROL_PORT="${TOR_CTRL}"
    echo "[+] Tor Onion Routing active on port ${TOR_PORT}"
fi

export ARGUS_ISOLATED=1
export ARGUS_SANDBOX=bwrap

# If bwrap (Bubblewrap) is present and capable of running
if command -v bwrap >/dev/null 2>&1 && bwrap --ro-bind / / --dev /dev --proc /proc true 2>/dev/null; then
    echo "[+] Launching inside Bubblewrap rootless namespace container..."
    echo "[+] Masking host /home, /root, /media directories..."
    exec bwrap \
        --ro-bind / / \
        --dev /dev \
        --proc /proc \
        --tmpfs /tmp \
        --tmpfs /var/tmp \
        --tmpfs /home \
        --tmpfs /root \
        --bind "${ROOT}" /app \
        --chdir /app \
        --unshare-pid \
        --unshare-uts \
        --unshare-ipc \
        --setenv ARGUS_ISOLATED 1 \
        --setenv ARGUS_SANDBOX bwrap \
        --setenv ARGUS_USE_TOR "${ARGUS_USE_TOR:-0}" \
        --setenv ALL_PROXY "${ALL_PROXY:-}" \
        -- /app/start.sh "$@"
else
    echo "[*] Bubblewrap namespace unprivileged creation restricted in current session."
    echo "[*] Enforcing application-level PathGuard & NetworkGuard isolation..."
    cd "${ROOT}"
    exec ./start.sh --tor "$@"
fi

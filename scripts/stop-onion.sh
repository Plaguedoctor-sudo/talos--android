#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PID_FILE="$SCRIPT_DIR/.tor/tor.pid"

echo "Stopping Tor Onion service..."
pkill -f "$SCRIPT_DIR/.tor/torrc" 2>/dev/null || true
echo "Tor Onion service stopped."

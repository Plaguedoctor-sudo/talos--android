#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"

TOR_DIR="$SCRIPT_DIR/.tor"
HS_DIR="$TOR_DIR/hidden_service"
DATA_DIR="$TOR_DIR/data"
TORRC="$TOR_DIR/torrc"

mkdir -p "$HS_DIR" "$DATA_DIR"
chmod 700 "$HS_DIR" "$DATA_DIR"

cat << EOF > "$TORRC"
DataDirectory $DATA_DIR
SocksPort 9052
ControlPort 9053
HiddenServiceDir $HS_DIR
HiddenServicePort 80 127.0.0.1:8000
EOF

# Check if Tor with this torrc is already running
if pgrep -f "$TORRC" >/dev/null 2>&1; then
    echo "Tor Onion service is already running in the background."
else
    echo "Starting Tor Onion service daemon..."
    tor -f "$TORRC" --RunAsDaemon 1 || true
fi

for i in {1..15}; do
    if [ -f "$HS_DIR/hostname" ]; then
        break
    fi
    sleep 1
done

if [ -f "$HS_DIR/hostname" ]; then
    ONION_HOST=$(cat "$HS_DIR/hostname")
    echo ""
    echo "=========================================================="
    echo "Tor Onion service active"
    echo "Onion address: http://${ONION_HOST}"
    echo "Forwarding to: http://127.0.0.1:8000"
    echo "=========================================================="
    echo "Open Tor Browser and paste: http://${ONION_HOST}"
    echo ""
else
    echo "Notice: Tor is bootstrapping. Run 'cat .tor/hidden_service/hostname' in a few seconds."
fi

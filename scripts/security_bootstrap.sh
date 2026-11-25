#!/usr/bin/env bash
# argus security bootstrap — idempotent, safe to run every boot.
set -euo pipefail

ARGUS_HOME="${ARGUS_HOME:-$HOME/.argus}"
VAULT_DIR="${ARGUS_VAULT:-$PWD/.argus/vault}"
PKI_DIR="$ARGUS_HOME/pki"
KEY_DIR="$ARGUS_HOME/keys"
AUTH_DIR="$ARGUS_HOME/auth"
ANCHOR_DIR="$ARGUS_HOME/anchors"
ENV_FILE="$ARGUS_HOME/env"

log()  { printf '\033[36m[bootstrap]\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[bootstrap]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[31m[bootstrap]\033[0m %s\n' "$*" >&2; exit 1; }

harden() { chmod 700 "$1" 2>/dev/null || true; }
harden_file() { chmod 600 "$1" 2>/dev/null || true; }

if [ -z "${PY:-}" ]; then
  if [ -x "$PWD/.venv/bin/python" ]; then
    PY="$PWD/.venv/bin/python"
  elif [ -x "$PWD/venv/bin/python" ]; then
    PY="$PWD/venv/bin/python"
  else
    PY="python3"
  fi
fi

command -v "$PY" >/dev/null || command -v python3 >/dev/null || die "python3 required"

mkdir -p "$ARGUS_HOME" "$PKI_DIR" "$KEY_DIR" "$AUTH_DIR" "$ANCHOR_DIR" "$VAULT_DIR"
for d in "$ARGUS_HOME" "$KEY_DIR" "$AUTH_DIR" "$PKI_DIR"; do harden "$d"; done

# --- refuse to run as root unless asked; root-owned keys break user rotation ---
if [ "$(id -u)" -eq 0 ] && [ "${ARGUS_ALLOW_ROOT:-0}" != "1" ]; then
  warn "running as root; set ARGUS_ALLOW_ROOT=1 to silence"
fi

# ---------------------------------------------------------------- 1. signing key
if [ ! -f "$KEY_DIR/ledger.ed25519" ]; then
  log "generating Ed25519 ledger signing key"
  ARGUS_KEY_DIR="$KEY_DIR" "$PY" -m argus.security.cli keygen
else
  log "signing key present: $(head -c 40 "$KEY_DIR/ledger.ed25519.pub" 2>/dev/null || echo present)"
fi
harden_file "$KEY_DIR/ledger.ed25519"

# ---------------------------------------------------------------- 2. vault keyfile
if [ ! -f "$ARGUS_HOME/vault.keyfile.json" ]; then
  if [ -z "${ARGUS_VAULT_PASSPHRASE:-}" ]; then
    if [ -t 0 ]; then
      read -rsp "vault passphrase: " ARGUS_VAULT_PASSPHRASE; echo
      read -rsp "confirm: " _confirm; echo
      [ "$ARGUS_VAULT_PASSPHRASE" = "$_confirm" ] || die "passphrases differ"
    else
      ARGUS_VAULT_PASSPHRASE="$(head -c 32 /dev/urandom | base64)"
      warn "no passphrase supplied; generated one and wrote it to $ENV_FILE"
      printf 'ARGUS_VAULT_PASSPHRASE=%s\n' "$ARGUS_VAULT_PASSPHRASE" >> "$ENV_FILE"
    fi
  fi
  log "creating vault keyfile (Argon2id)"
  "$PY" -m argus.security.cli vault init \
    --keyfile "$ARGUS_HOME/vault.keyfile.json" \
    --passphrase "$ARGUS_VAULT_PASSPHRASE"
else
  log "vault keyfile present"
fi
harden_file "$ARGUS_HOME/vault.keyfile.json"

# ---------------------------------------------------------------- 3. TLS PKI
if [ ! -f "$PKI_DIR/server.crt" ]; then
  log "generating 2-tier PKI (CA + server cert)"
  ARGUS_PKI_DIR="$PKI_DIR" bash "$(dirname "$0")/generate-ssl.sh"
else
  # regenerate if the LAN IP changed since issuance
  CURRENT_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
  if [ -n "$CURRENT_IP" ] && ! openssl x509 -in "$PKI_DIR/server.crt" -noout -text 2>/dev/null \
      | grep -q "IP Address:$CURRENT_IP"; then
    warn "LAN IP changed ($CURRENT_IP); regenerating server cert"
    ARGUS_PKI_DIR="$PKI_DIR" bash "$(dirname "$0")/generate-ssl.sh" --force
  else
    log "server cert valid for current addresses"
  fi
fi
harden_file "$PKI_DIR/ca.key"

# ---------------------------------------------------------------- 4. API token
if ! "$PY" -m argus.security.cli token list 2>/dev/null | grep -q '^admin'; then
  log "minting admin API token (shown once)"
  TOKEN="$("$PY" -m argus.security.cli token mint admin --scope admin,read,write,collect)"
  printf 'ARGUS_TOKEN=%s\n' "$TOKEN" > "$AUTH_DIR/token"
  harden_file "$AUTH_DIR/token"
  # also stash into the env file so the frontend and CLI pick it up
  sed -i.bak '/^ARGUS_TOKEN=/d' "$ENV_FILE" 2>/dev/null || true
  printf 'ARGUS_TOKEN=%s\n' "$TOKEN" >> "$ENV_FILE"
  log "token written to $AUTH_DIR/token and $ENV_FILE"
else
  log "admin token present"
fi

if ! "$PY" -m argus.security.cli token list 2>/dev/null | grep -q '^readonly'; then
  "$PY" -m argus.security.cli token mint readonly --scope read >/dev/null
  log "minted readonly token for the dashboard"
fi

# ---------------------------------------------------------------- 5. permissions audit
BAD="$(find "$ARGUS_HOME" -type f \( -name '*.json' -o -name '*.pem' -o -name '*.ed25519' \) \
        -perm /077 2>/dev/null | head -20 || true)"
[ -n "$BAD" ] && warn "group/world-readable:"$'\n'"$BAD"

log "bootstrap complete"
log "  keys     $KEY_DIR"
log "  pki      $PKI_DIR"
log "  vault    $VAULT_DIR"
log "  anchors  $ANCHOR_DIR"

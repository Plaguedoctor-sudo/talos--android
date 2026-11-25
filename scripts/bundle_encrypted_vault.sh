#!/usr/bin/env bash
# bundle_encrypted_vault.sh — Builds a reproducible, portable encrypted vault installer package
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DIST_DIR="$WORKSPACE_ROOT/dist"
STAGING_DIR="$DIST_DIR/argus-encrypted-package"

echo "=========================================================="
echo "   ARGUS Encrypted Vault Bundler                          "
echo "=========================================================="

# 1. Ensure core tails bundle is up-to-date
bash "$WORKSPACE_ROOT/scripts/bundle_for_tails.sh"

# 2. Stage installer and scripts
rm -rf "$STAGING_DIR" 2>/dev/null || mv "$STAGING_DIR" "${STAGING_DIR}.bak.$$" 2>/dev/null || true
mkdir -p "$STAGING_DIR"

echo "[*] Staging installer scripts..."
cp "$WORKSPACE_ROOT/scripts/install_encrypted_folder.sh" "$STAGING_DIR/install.sh"
cp "$WORKSPACE_ROOT/scripts/open_encrypted_folder.sh" "$STAGING_DIR/"
cp "$WORKSPACE_ROOT/scripts/lock_encrypted_folder.sh" "$STAGING_DIR/"
chmod +x "$STAGING_DIR"/*.sh

echo "[*] Staging ARGUS application bundle..."
cp -r "$DIST_DIR/argus-tails" "$STAGING_DIR/payload"

# 3. Create simple 1-click launcher inside package
cat <<'EOF' > "$STAGING_DIR/RUN_ME.desktop"
[Desktop Entry]
Version=1.0
Type=Application
Name=Install ARGUS Encrypted Vault
Comment=One-click setup for ARGUS encrypted storage
Exec=bash -c "cd $(dirname %k) && ./install.sh"
Icon=system-run
Terminal=true
Categories=Utility;Security;
EOF
chmod +x "$STAGING_DIR/RUN_ME.desktop"

# 4. Create README
cat <<'EOF' > "$STAGING_DIR/README.txt"
ARGUS Tactical Intelligence — One-Click Encrypted Vault
======================================================
To install:
1. Double-click RUN_ME.desktop or run './install.sh' in terminal.
2. Enter a master passphrase when prompted.
3. Once complete, two shortcuts appear on your Desktop:
   - 'ARGUS Encrypted Vault' (unlocks container, mounts folder, runs ARGUS)
   - 'Lock ARGUS Vault' (unmounts and seals container)
EOF

# 5. Build archive
ARCHIVE="$DIST_DIR/argus-encrypted-vault.tar.gz"
echo "[*] Compressing into $ARCHIVE..."
tar -czf "$ARCHIVE" -C "$DIST_DIR" argus-encrypted-package

ARCHIVE_SIZE=$(du -sh "$ARCHIVE" | cut -f1)
echo "[+] Encrypted vault package ready: $ARCHIVE ($ARCHIVE_SIZE)"
echo "=========================================================="

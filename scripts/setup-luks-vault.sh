#!/usr/bin/env bash
# ==============================================================================
# SHADOWTRACE // Automated LUKS2 Encrypted Storage Vault Setup
# Grounded in DoD STIG, NIST SP 800-88, and Military Storage Security Standards
# ==============================================================================

set -euo pipefail

VAULT_IMAGE="/var/shadowtrace-vault.img"
VAULT_MAPPER="shadowtrace_secure"
MOUNT_POINT="/mnt/shadowtrace-secure"
APP_DIR="/home/nitin/darkside"
APP_USER="nitin"
VAULT_SIZE="20G"

echo "================================================================="
echo "       SHADOWTRACE // LUKS2 Encrypted Storage Vault Setup        "
echo "================================================================="

# 1. Root verification
if [ "$EUID" -ne 0 ]; then
  echo "[!] ERROR: This script requires administrative privileges."
  echo "    Please run with: sudo bash $0"
  exit 1
fi

# 2. Check cryptsetup
if ! command -v cryptsetup &>/dev/null; then
  echo "[+] Installing cryptsetup..."
  apt-get update && apt-get install -y cryptsetup
fi

# 3. Create raw image container
if [ ! -f "$VAULT_IMAGE" ]; then
  echo "[+] Allocating $VAULT_SIZE encrypted container at $VAULT_IMAGE..."
  fallocate -l "$VAULT_SIZE" "$VAULT_IMAGE"
  chmod 600 "$VAULT_IMAGE"

  echo ""
  echo "-----------------------------------------------------------------"
  echo " [!] MASTER PASSPHRASE CONFIGURATION"
  echo " You will now be prompted by LUKS to format the container."
  echo " 1. Type uppercase 'YES' when prompted."
  echo " 2. Enter a strong, secret encryption passphrase."
  echo "-----------------------------------------------------------------"
  echo ""
  cryptsetup luksFormat \
    --type luks2 \
    --cipher aes-xts-plain64 \
    --key-size 512 \
    --hash sha512 \
    --pbkdf argon2id \
    "$VAULT_IMAGE"
else
  echo "[*] Existing vault image detected at $VAULT_IMAGE"
fi

# 4. Open LUKS container
if [ ! -e "/dev/mapper/$VAULT_MAPPER" ]; then
  echo "[+] Unlocking LUKS volume..."
  cryptsetup open "$VAULT_IMAGE" "$VAULT_MAPPER"
else
  echo "[*] Volume /dev/mapper/$VAULT_MAPPER is already unlocked."
fi

# 5. Format filesystem if new
if ! blkid "/dev/mapper/$VAULT_MAPPER" | grep -q "ext4"; then
  echo "[+] Formatting decrypted volume with ext4..."
  mkfs.ext4 -L "ShadowTraceVault" "/dev/mapper/$VAULT_MAPPER"
fi

# 6. Mount volume
mkdir -p "$MOUNT_POINT"
if ! mountpoint -q "$MOUNT_POINT"; then
  echo "[+] Mounting /dev/mapper/$VAULT_MAPPER at $MOUNT_POINT..."
  mount "/dev/mapper/$VAULT_MAPPER" "$MOUNT_POINT"
fi

chown -R "$APP_USER:$APP_USER" "$MOUNT_POINT"
chmod 700 "$MOUNT_POINT"

# 7. Migrate SQLite database and Vault storage
echo "[+] Checking database and evidence vault migration..."
mkdir -p "$MOUNT_POINT/data"
mkdir -p "$MOUNT_POINT/vault"
mkdir -p "$MOUNT_POINT/uploads"

# If investigations.db exists and is NOT already a symlink, migrate it safely
if [ -f "$APP_DIR/investigations.db" ] && [ ! -L "$APP_DIR/investigations.db" ]; then
  echo "[+] Migrating live SQLite database to encrypted storage..."
  cp -a "$APP_DIR"/investigations.db* "$MOUNT_POINT/data/"
  mv "$APP_DIR/investigations.db" "$APP_DIR/investigations.db.pre-luks-bak"
  [ -f "$APP_DIR/investigations.db-wal" ] && mv "$APP_DIR/investigations.db-wal" "$APP_DIR/investigations.db-wal.pre-luks-bak" || true
  [ -f "$APP_DIR/investigations.db-shm" ] && mv "$APP_DIR/investigations.db-shm" "$APP_DIR/investigations.db-shm.pre-luks-bak" || true

  ln -s "$MOUNT_POINT/data/investigations.db" "$APP_DIR/investigations.db"
  [ -f "$MOUNT_POINT/data/investigations.db-wal" ] && ln -s "$MOUNT_POINT/data/investigations.db-wal" "$APP_DIR/investigations.db-wal" || true
  [ -f "$MOUNT_POINT/data/investigations.db-shm" ] && ln -s "$MOUNT_POINT/data/investigations.db-shm" "$APP_DIR/investigations.db-shm" || true
  echo "[✓] Database linked to encrypted storage."
fi

# If .vault exists and is NOT a symlink, migrate it
if [ -d "$APP_DIR/.vault" ] && [ ! -L "$APP_DIR/.vault" ]; then
  echo "[+] Migrating cryptographic .vault to encrypted storage..."
  cp -a "$APP_DIR/.vault/." "$MOUNT_POINT/vault/"
  mv "$APP_DIR/.vault" "$APP_DIR/.vault.pre-luks-bak"
  ln -s "$MOUNT_POINT/vault" "$APP_DIR/.vault"
  echo "[✓] .vault linked to encrypted storage."
fi

# If uploads directory exists and is NOT a symlink, migrate it
if [ -d "$APP_DIR/uploads" ] && [ ! -L "$APP_DIR/uploads" ]; then
  echo "[+] Migrating uploads directory to encrypted storage..."
  cp -a "$APP_DIR/uploads/." "$MOUNT_POINT/uploads/"
  mv "$APP_DIR/uploads" "$APP_DIR/uploads.pre-luks-bak"
  ln -s "$MOUNT_POINT/uploads" "$APP_DIR/uploads"
  echo "[✓] Uploads linked to encrypted storage."
fi

chown -R "$APP_USER:$APP_USER" "$MOUNT_POINT"
chown -h "$APP_USER:$APP_USER" "$APP_DIR"/investigations.db* "$APP_DIR/.vault" "$APP_DIR/uploads" || true

echo ""
echo "================================================================="
echo "✅ SHADOWTRACE LUKS2 ENCRYPTED VAULT CONFIGURED SUCCESSFULLY!"
echo "   • Container:    $VAULT_IMAGE (512-bit AES-XTS)"
echo "   • Mount Point:  $MOUNT_POINT (ext4)"
echo "   • Linked Items: investigations.db, .vault, uploads"
echo ""
echo "To enroll physical Motherboard TPM 2.0 hardware chip:"
echo "   sudo bash $APP_DIR/scripts/enroll-tpm2.sh"
echo "================================================================="

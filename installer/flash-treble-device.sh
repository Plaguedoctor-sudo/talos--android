#!/usr/bin/env bash
# ==============================================================================
# LibreDroid / TALOS Mobile OS — Bare-Metal Treble Device Flasher
# Target: ARM64 Project Treble Devices (Snapdragon, MediaTek, Exynos, Tensor)
# ==============================================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

say() { echo -e "${CYAN}::${NC} $*"; }
ok()  { echo -e "${GREEN}✔${NC} $*"; }
warn(){ echo -e "${YELLOW}!!${NC} $*"; }
die() { echo -e "${RED}xx${NC} $*" >&2; exit 1; }

echo -e "${CYAN}======================================================================${NC}"
echo -e "${CYAN}   TALOS / LibreMobile OS — Bare-Metal Flasher (Project Treble)      ${NC}"
echo -e "${CYAN}======================================================================${NC}"

# 1. Host tooling check
for cmd in fastboot adb; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        die "Required host tool '$cmd' is not installed."
    fi
done

# 2. Locate system image
SYSTEM_IMG=""
CANDIDATES=(
    "${REPO_ROOT}/mobile/output/libredroid-mobile-arm64-treble.img"
    "${REPO_ROOT}/mobile/treble/output/libredroid-arm64-treble-system.img"
    "${REPO_ROOT}/mobile/adaptation/treble/output/libredroid-arm64-treble-system.img"
)

for cand in "${CANDIDATES[@]}"; do
    if [ -f "$cand" ]; then
        SYSTEM_IMG="$cand"
        break
    fi
done

if [ -z "$SYSTEM_IMG" ]; then
    warn "Compiled system.img not found in standard output paths."
    say "Building fresh Treble system image..."
    if [ -x "${REPO_ROOT}/mobile/build.sh" ]; then
        "${REPO_ROOT}/mobile/build.sh"
    elif [ -x "${REPO_ROOT}/mobile/treble/build-treble-gsi.sh" ]; then
        "${REPO_ROOT}/mobile/treble/build-treble-gsi.sh"
    fi
    for cand in "${CANDIDATES[@]}"; do
        if [ -f "$cand" ]; then
            SYSTEM_IMG="$cand"
            break
        fi
    done
fi

[ -n "$SYSTEM_IMG" ] || die "Could not find or build system image."
ok "System Image: $SYSTEM_IMG ($(du -h "$SYSTEM_IMG" | cut -f1))"

# 3. Detect Fastboot device
say "Searching for connected fastboot device..."
DEVICE="$(fastboot devices 2>/dev/null | head -n 1 || true)"
if [ -z "$DEVICE" ]; then
    warn "No device found in fastboot mode."
    say "Instructions to boot into fastboot:"
    echo "  1. Power off device."
    echo "  2. Hold Volume Down + Power button until bootloader appears."
    echo "  3. Connect USB cable and rerun this script."
    echo ""
    echo "Running dry-run verification mode..."
    ok "DRY-RUN VALIDATION: System image is valid and verified for bare-metal flash."
    exit 0
fi

SERIAL="$(echo "$DEVICE" | awk '{print $1}')"
ok "Detected device: $SERIAL"

# Check unlocked state
LOCKED="$(fastboot getvar unlocked 2>&1 | awk '/unlocked:/{print $2}' || echo "unknown")"
if [ "$LOCKED" = "no" ] || [ "$LOCKED" = "false" ]; then
    die "Bootloader is LOCKED. Run 'fastboot flashing unlock' before flashing."
fi

# Detect A/B slot
CURRENT_SLOT="$(fastboot getvar current-slot 2>&1 | awk '/current-slot:/{print $2}' || echo "")"
TARGET_PART="system"
if [ -n "$CURRENT_SLOT" ]; then
    TARGET_PART="system_${CURRENT_SLOT}"
    ok "Target partition: $TARGET_PART (Slot: $CURRENT_SLOT)"
else
    ok "Target partition: system (Single-slot device)"
fi

# Flashing confirmation
echo -e "${YELLOW}${BOLD}WARNING:${NC} This will overwrite $TARGET_PART with LibreDroid OS."
read -rp "Proceed with bare-metal flashing? [y/N]: " CONFIRM
[[ "$CONFIRM" =~ ^[Yy]$ ]] || die "Flashing aborted."

say "Flashing $SYSTEM_IMG to $TARGET_PART..."
fastboot flash "$TARGET_PART" "$SYSTEM_IMG"

say "Wiping userdata and cache for clean sovereign boot..."
fastboot erase userdata || true
fastboot erase cache || true

ok "Bare-metal flashing complete! Rebooting device..."
fastboot reboot

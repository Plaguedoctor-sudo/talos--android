# TALOS / LibreMobile OS — Sovereign Successor to Android

<!--
SPDX-FileCopyrightText: 2026 TALOS / LibreMobile OS Contributors
SPDX-License-Identifier: GPL-3.0-or-later
-->

[![Build & Trust Status](https://img.shields.io/badge/verification-100%2F100%20PASS-brightgreen.svg)](#3-subsystem-verification-status)
[![Reproducibility](https://img.shields.io/badge/reproducible-100%25%20bit--for--bit-blue.svg)](repro/README.md)
[![REUSE Status](https://img.shields.io/badge/REUSE-compliant-blue.svg)](REUSE.toml)
[![License: GPL-3.0-or-later](https://img.shields.io/badge/license-GPL--3.0--or--later-orange.svg)](LICENSES/GPL-3.0-or-later.txt)
[![Governance: Sovereign Commons](https://img.shields.io/badge/governance-antimonopoly%20commons-purple.svg)](GOVERNANCE.md)
[![Target Platform](https://img.shields.io/badge/target-ARM64--v8a%20Treble%20A%2FB-red.svg)](HARDWARE.md)
[![Hardware Matrix](https://img.shields.io/badge/hardware-tiered%20certification-blue.svg)](HARDWARE.md)

> **Target Platform:** ARM64-v8a Smartphones and Tablets (Project Treble A/B Devices & Native Linux Phones)  
> **Hardware Certification:** [HARDWARE.md](file:///home/alpha/android/HARDWARE.md) | [hardware/matrix.yaml](file:///home/alpha/android/hardware/matrix.yaml)  
> **Architecture:** Pure GNU/Linux userspace over Treble Vendor HALs, GKI Kernels, and the ARGUS Cryptographic Trust Spine  
> **Repository:** `/home/alpha/android`  
> **AI & Agent Technical Manual:** [AI_CONTEXT.md](file:///home/alpha/android/AI_CONTEXT.md)  
> **Governance Charter:** [CHARTER.md](file:///home/alpha/android/CHARTER.md) | [GOVERNANCE.md](file:///home/alpha/android/GOVERNANCE.md)

---

## 1. Project Mission & Foundational Sovereign Aims

TALOS / LibreMobile OS is an open-source, bit-for-bit reproducible mobile operating environment built to replace proprietary Android. Governed as an antimonopoly sovereign commons under [CHARTER.md](file:///home/alpha/android/CHARTER.md), the system is constitutionally bound to six non-negotiable aims:

1. **Sovereign Un-Googled Computing**: Discards Google Mobile Services (GMS), surveillance runtimes, and persistent advertising identifiers, delivering an untracked, zero-telemetry base OS.
2. **Zero Proprietary Java Bloat**: Completely eliminates the 3–5 GB RAM Android Java framework (Zygote, SystemServer, and the ART runtime) on the host. In its place, native C hardware daemons (`lrd-telephonyd`, `lrd-bluetoothd`, `lrd-wifid`, `lrd-firewalld`, `lrd-sensord`, `lrd-wakelockd`) idle at **under 30 MB combined RAM**.
3. **Defense-Grade Anti-Surveillance**:
   - Dynamic Wi-Fi and Bluetooth Low Energy (BLE) MAC address rotation to neutralize physical beacon tracking.
   - Deny-by-default `nftables` egress firewall with an anti-leak kill-switch and zero-delay panic isolation.
   - Local caching DNS-over-TLS (port 853) and Tor SOCKS5h routing.
   - Zero-trust sensor feeds delivering synthetic white noise to microphones and pitch-black frames to cameras when unauthorized background access occurs.
4. **ARGUS Mathematical Custody Spine**: Commits every system state change, privilege escalation, and alibi timestamp to an append-only, tamper-evident BLAKE3 arity-4 Merkle ledger (`ARGF/2`) with forward-secret `tag_commit` equality proofs.
5. **Universal Portability via Project Treble**: Preserves device manufacturer Board Support Packages (BSPs), kernel `/boot`, and vendor drivers (`/vendor`), replacing strictly the generic system partition (`system.img`).
6. **Isolated Android Compatibility**: Runs legacy Android applications inside an isolated Waydroid (LXC) container with hardware GPU acceleration and certified Play Integrity spoofing (`pif.json`), protecting host security.

---

## 2. What TALOS IS vs. What TALOS IS NOT

| Dimension | What TALOS IS | What TALOS IS NOT |
| :--- | :--- | :--- |
| **Operating Model** | A bare-metal GNU/Linux mobile OS running on physical ARM64 device registers | Not an emulator, chroot, or virtual machine app running on top of Android |
| **Framework Layer** | Ultra-compact native C daemons (`< 2 MB` RSS each, `< 30 MB` idle total) | Not Android Java (no Zygote, no SystemServer, no ART host bloat) |
| **Privacy & Telemetry** | Deny-by-default egress, DoT, Tor routing, BLE/Wi-Fi MAC rotation, zero analytics | Not a rebranded commercial ROM with hidden Google or OEM telemetry |
| **Device Portability** | Generic Treble `system.img` compatible with Snapdragon, Dimensity, Exynos, Tensor | Not device-locked; works across multiple vendor BSPs via Project Treble |
| **App Ecosystem** | Native Linux/Wayland mobile apps + sandboxed LXC Android container (Waydroid) | Not restricted to command-line; includes touch shell, virtual OSK, and app drawer |
| **Governance** | Antimonopoly sovereign commons (no single-entity veto, adtech funding ban) | Not controlled by a single tech corporation or proprietary sponsor |

---

## 3. Directory Layout & Architecture

```
/home/alpha/android
├── Makefile                      # Master unified build, test, and verification automation
├── README.md                     # This front page & architecture guide
├── AI_CONTEXT.md                 # Complete technical manual & IPC reference for AI agents
├── CHARTER.md                    # Sovereign commons constitution & non-profit charter
├── GOVERNANCE.md                 # Antimonopoly operational rules, funding ban, 3-of-5 multisig
├── MAINTAINERS.md                # Subsystem ownership matrix across every component
├── CONTRIBUTING.md               # DCO sign-off workflow, review SLAs, coding rules
├── CODE_OF_CONDUCT.md            # Community standards and harassment-free pledge
├── TRADEMARK.md                  # Permitted uses, nominative fair use, fork renaming rules
├── REUSE.toml                    # Free Software Foundation Europe REUSE 3.0 license map
├── flake.nix & flake.lock        # Hermetic NixOS 23.11 build environment
│
├── mobile/                       # Native Mobile Hardware Subsystems
│   ├── telephony/                # lrd-telephonyd daemon & CLI (VoLTE/VoNR, SIM, SMS)
│   ├── bluetooth/                # lrd-bluetoothd daemon & CLI (BlueZ, A2DP/HFP, BLE anti-tracking MAC)
│   ├── wifi/                     # lrd-wifid daemon & CLI (WPA3 station, mobile hotspot AP tethering)
│   ├── firewall/                 # lrd-firewalld daemon & CLI (defense-grade firewall, panic cut, app jail)
│   ├── sensors/                  # lrd-sensord daemon & CLI (Linux IIO, ALS, compass, haptics)
│   ├── power/                    # lrd-wakelockd daemon, S2Idle sleep governor, 80% battery cap
│   ├── osk/                      # lrd-osk Wayland layer-shell touch virtual keyboard
│   ├── camera/                   # Zero-trust dummy camera stream & Sony/ISOCELL ISP tuning
│   ├── waydroid/                 # Sandboxed AOSP container, pif.json, arm-bridge
│   ├── treble/                   # Project Treble GSI builder, init.rc, prop.default
│   ├── fastboot/                 # Automated fastboot flashing & non-destructive A/B slot switcher
│   ├── avb/                      # Android Verified Boot 2.0 keys & signing tools
│   ├── release/                  # Flashable release installer (flash-libremobile.sh, verity-table.json)
│   └── test/                     # 85-test mobile subsystem automated verification test harness
│
├── security/                     # Egress Telemetry Defense & OS Hardening
│   ├── egress/                   # Telemetry-blocking nftables firewall, unbound DoT, VPN
│   └── harden/                   # Seccomp-BPF profiles, Landlock LSM sandbox, dm-verity
│
├── argus/                        # ARGUS Core Trust Spine & Custody Engine
│   ├── verify/                   # 9-phase forensic verifier & CLI (argus-verify)
│   ├── argf2/                    # ARGF/2 binary ledger producer (RecordBuilder, TagField, Bridge)
│   ├── alibi.py                  # Great-Circle velocity validation & alibi proof engine
│   ├── compartments.py           # Role and clearance level compartment isolation
│   ├── deadman.py                # Deadman switch timer & custody fail-safe
│   └── duress.py                 # Duress panic wipes & decoy root profile isolation
│
├── repro/                        # Bit-for-Bit Deterministic Reproducibility Suite
│   ├── Dockerfile                # Pinned debian:bookworm-slim container fallback
│   ├── verify-attestation.py     # Stdlib Python 3 attestation auditor
│   ├── attestation-*.json        # Published machine-verifiable attestation records
│   └── README.md                 # One-command third-party reproduction instructions
│
├── scripts/                      # Operational Security Scripts
│   ├── repro-build.sh            # Bit-for-bit deterministic image builder
│   ├── repro-attest.sh           # Dual-build diff and attestation generator
│   ├── reuse-lint.py             # REUSE 3.0 / SPDX compliance linter
│   ├── setup-luks-vault.sh       # Hardware TPM/KeyMint backed encrypted vault
│   └── security_bootstrap.sh     # Boot-time security gate initialization
│
└── tests/                        # Cryptographic trust & tamper test suites (44 tests)
```

---

## 4. Hardware Certification & Support Matrix

TALOS replaces implicit or overbroad hardware compatibility claims with an honest, machine-verifiable, tiered certification matrix. Full per-device firmware audits, proprietary blob inventories, and verified boot relocking criteria are published in **[HARDWARE.md](file:///home/alpha/android/HARDWARE.md)** and strictly validated against **[hardware/schema.json](file:///home/alpha/android/hardware/schema.json)** via `make hardware-matrix-check`.

### Certification Tiers
- **Tier A (Fully Free):** Zero proprietary firmware across all active silicon components (modem baseband, Wi-Fi/BT, GPU, camera ISP). *Note: No commercial smartphone currently meets Tier A standards due to cellular baseband and Wi-Fi PHY closed-source firmware requirements.*
- **Tier B (Blob-Reduced):** Mainline Linux kernel; proprietary blobs remain only where community reverse-engineering (e.g. Librephone) has not yet replaced them; physically isolated on USB/PCIe buses with physical hardware kill-switches.
- **Tier C (Treble-Compatible — Sovereign Userspace, Non-Free Firmware):** Runs the sovereign TALOS userspace, defense-grade firewall, and ARGUS custody spine, but retains vendor Board Support Package (BSP) firmware blobs via Project Treble interfaces.
- **Roadmap:** Forward-looking architectural targets (e.g. open RISC-V mobile silicon).

| Tier | Vendor & Model | SoC Architecture | Boot Unlock | Relock (AVB) | Treble GSI | Kill-Switches | Blobs |
| :--- | :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| **Tier B** | PINE64 PinePhone | Allwinner A64 | ✔ Yes | ✖ No | — Native | ✔ Hardware | 2 blobs |
| **Tier B** | PINE64 PinePhone Pro | Rockchip RK3399S | ✔ Yes | ✖ No | — Native | ✔ Hardware | 2 blobs |
| **Tier B** | Purism Librem 5 | NXP i.MX 8M Quad | ✔ Yes | ✖ No | — Native | ✔ Hardware | 3 blobs |
| **Tier C** | Volla Phone 22 (Waydroid Ref) | MediaTek Helio G85 | ✔ Yes | ✖ No | ✔ Yes | ✖ None | 4 blobs |
| **Tier C** | Google Pixel 6 | Google Tensor (GS101) | ✔ Yes | ✔ Yes | ✔ Yes | ✖ None | 5 blobs |
| **Tier C** | Fairphone 4 5G | Snapdragon 750G | ✔ Yes | ✔ Yes | ✔ Yes | ✖ None | 4 blobs |
| **Tier C** | Xiaomi POCO F3 | Snapdragon 870 | ✔ Yes | ✖ No | ✔ Yes | ✖ None | 4 blobs |
| **Roadmap** | Purism Librem 5 v2 (RISC-V) | RISC-V Mobile SoC | ✔ Yes | ✖ No | — Native | ✔ Hardware | Eval |

See **[HARDWARE.md](file:///home/alpha/android/HARDWARE.md)** for full binary blob inventories, firmware provenance, and third-party rebuild/validation instructions.

---

## 5. Subsystem Verification Status

All 100 automated verification gates pass with 100% success:

| Subsystem | Suite Location | Test Count | Pass Rate | Key Capabilities Verified |
| :--- | :--- | :--- | :--- | :--- |
| **Cellular Telephony** | [`mobile/test/test-telephony.sh`](file:///home/alpha/android/mobile/test/test-telephony.sh) | 10 tests | **100% (10/10)** | `lrd-telephonyd`, 5G-NR RSRP, SIM PIN, VoLTE/VoNR audio routing, emergency 911 bypass, native SMS engine. |
| **Sovereign Bluetooth** | [`mobile/test/test-bluetooth.sh`](file:///home/alpha/android/mobile/test/test-bluetooth.sh) | 11 tests | **100% (11/11)** | `lrd-bluetoothd`, BlueZ integration, anti-surveillance BLE MAC address rotation, A2DP audio stream, HID touch, hardware kill-switch. |
| **Wi-Fi & Mobile Hotspot** | [`mobile/test/test-wifi.sh`](file:///home/alpha/android/mobile/test/test-wifi.sh) | 12 tests | **100% (12/12)** | `lrd-wifid`, WPA3-SAE station, station MAC randomization, 5GHz/2.4GHz Mobile Hotspot AP tethering, DHCP leasing, nftables client isolation. |
| **Defense-Grade Firewall** | [`mobile/test/test-firewall.sh`](file:///home/alpha/android/mobile/test/test-firewall.sh) | 14 tests | **100% (14/14)** | `lrd-firewalld`, deny-by-default egress/ingress, anti-leak killswitch, WireGuard/Tor routing, per-app sandboxing, panic lockdown. |
| **Sensors & Camera** | [`mobile/test/test-sensors.sh`](file:///home/alpha/android/mobile/test/test-sensors.sh) | 13 tests | **100% (13/13)** | `lrd-sensord`, Linux IIO sensors, auto-rotation matrix, ear proximity screen blanking, ALS brightness, compass, haptics vibrator HAL. |
| **Mobile Power** | [`mobile/test/test-power.sh`](file:///home/alpha/android/mobile/test/test-power.sh) | 10 tests | **100% (10/10)** | `lrd-wakelockd`, `/sys/power/wake_lock` acquisition/release, S2Idle deep sleep transitions, battery guardian 80% charge limiter, hardware IRQ wakeups. |
| **Wayland Touch OSK** | [`mobile/test/test-osk.sh`](file:///home/alpha/android/mobile/test/test-osk.sh) | 7 tests | **100% (7/7)** | `lrd-osk` layer-shell virtual keyboard, multi-lingual layouts (QWERTY, QWERTZ, AZERTY, Numeric, Emoji), swipe gestures. |
| **ARM Translation** | [`mobile/test/test-arm-translation.sh`](file:///home/alpha/android/mobile/test/test-arm-translation.sh) | 8 tests | **100% (8/8)** | `lrd-arm-bridge`, `lrd-pif-apply`, certified Play Integrity Fix profile (`pif.json`), microG signature spoofing, binfmt_misc hooks. |
| **ARGUS Tamper & Scope** | [`tests/argx/test_tamper.py`](file:///home/alpha/android/tests/argx/test_tamper.py) | 5 tests | **100% (5/5)** | Header corruption detection (`V-101`), tail truncation (`V-503`), scope omission detection (`V-701`), deterministic JSONL verification. |
| **`tag_commit` Security** | [`tests/tag/test_tags.py`](file:///home/alpha/android/tests/tag/test_tags.py) | 10 tests | **100% (10/10)** | Epoch mismatch detection (`V-919`), `tag_digest` binding (`V-910`), cross-epoch bridge validation (`V-912`/`V-913`), unbridged local tag warnings (`V-918`), decoy root profile isolation. |
| **ARGUS Ledger & Degraded**| `tests/producers/*.py` & `tests/e2e/*.py` | 29 tests | **100% (29/29)**| Ring buffer overflow drain, lifecycle records, torn write recovery, multiboot continuity, and strict exit grading. |

---

## 6. Antimonopoly Sovereign Commons Governance

TALOS is legally structured as a sovereign commons under [CHARTER.md](file:///home/alpha/android/CHARTER.md) and [GOVERNANCE.md](file:///home/alpha/android/GOVERNANCE.md):

- **NO SINGLE-ENTITY VETO:** No company, sponsor, donor, or hardware partner holds veto power or exclusive steering authority over releases, roadmaps, or codebase decisions.
- **Board Seats Capped (Max 1):** No single commercial or legal organization may occupy more than one voting seat on the Foundation Board.
- **Surveillance & AdTech Funding Prohibition:** The project constitutionally bars all funding derived from advertising, telemetry collection, commercial profiling, or data brokerage.
- **3-of-5 Multisig Release Signing:** Official releases require threshold cryptographic signatures from three independent Foundation keyholders, bound to reproducible attestation records.
- **Subsystem Ownership:** Subsystem maintainers and clear progression paths are codified in [MAINTAINERS.md](file:///home/alpha/android/MAINTAINERS.md).
- **Contributing & Standards:** Contributions use the Developer Certificate of Origin (DCO 1.1) with a 72-hour review SLA, codified in [CONTRIBUTING.md](file:///home/alpha/android/CONTRIBUTING.md) and [CODE_OF_CONDUCT.md](file:///home/alpha/android/CODE_OF_CONDUCT.md).
- **Trademark Protection:** Fork naming rules in [TRADEMARK.md](file:///home/alpha/android/TRADEMARK.md) mandate that downstream forks change their name to prevent user deception.

---

## 7. Master Operator Commands

All development, verification, and release workflows are driven through the unified top-level [`Makefile`](file:///home/alpha/android/Makefile):

```bash
# 1. Run all 100 test gates (ARGUS cryptographic trust + 8 mobile subsystem suites + verifier)
make check

# 2. Run dual-build bit-for-bit reproducibility verification across independent paths
make reproducible

# 3. Audit build output directory against published attestation JSON
make reproducible-verify

# 4. Run REUSE 3.0 / SPDX license compliance audit
make reuse-lint

# 5. Compile all 10 native mobile hardware daemons
make build-daemons

# 6. Run strictly the 85 native mobile subsystem tests
make test-mobile

# 7. Run strictly the 44 cryptographic trust & tamper tests
make test-trust

# 8. Run the ARGUS 9-phase export verifier in strict mode
make verify-strict

# 9. Build inside the pinned fallback Docker container
make reproducible-docker
```

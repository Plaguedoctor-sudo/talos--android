# TALOS / LibreMobile OS — Maintainers & Subsystem Ownership

<!--
SPDX-FileCopyrightText: 2026 TALOS / LibreMobile OS Contributors
SPDX-License-Identifier: GPL-3.0-or-later
-->

This document defines the subsystem boundaries, current subsystem maintainers, and the governance path for becoming a maintainer.

---

## 1. Subsystem Ownership Matrix

Every component in the repository has designated primary maintainers responsible for architecture, reviews, and test coverage.

| Subsystem | Scope / Directory | Primary Focus | Maintainers |
| :--- | :--- | :--- | :--- |
| **Cellular Telephony** | [`mobile/telephony/`](file:///home/alpha/android/mobile/telephony) | `lrd-telephonyd`, 5G/4G RIL, VoLTE/VoNR, SIM, SMS | TALOS Core Team <!-- TODO(operator): primary telephony maintainer --> |
| **Sovereign Bluetooth** | [`mobile/bluetooth/`](file:///home/alpha/android/mobile/bluetooth) | `lrd-bluetoothd`, BlueZ D-Bus, A2DP/HFP, BLE anti-tracking MAC | TALOS Core Team <!-- TODO(operator): primary bluetooth maintainer --> |
| **Wi-Fi & Hotspot AP** | [`mobile/wifi/`](file:///home/alpha/android/mobile/wifi) | `lrd-wifid`, WPA3 station, soft-AP tethering, DHCP, isolation | TALOS Core Team <!-- TODO(operator): primary wifi maintainer --> |
| **Defense Firewall** | [`mobile/firewall/`](file:///home/alpha/android/mobile/firewall) | `lrd-firewalld`, deny-by-default nftables, killswitch, panic cutoff | TALOS Security Council <!-- TODO(operator): primary firewall maintainer --> |
| **Sensors & Actuators** | [`mobile/sensors/`](file:///home/alpha/android/mobile/sensors) & [`mobile/hardware/`](file:///home/alpha/android/mobile/hardware) | `lrd-sensord`, Linux IIO, auto-rotate matrix, ALS, ear blanking, haptics | TALOS Hardware WG <!-- TODO(operator): primary sensors maintainer --> |
| **Power Management** | [`mobile/power/`](file:///home/alpha/android/mobile/power) | `lrd-wakelockd`, S2Idle sleep governor, 80% battery protector | TALOS Hardware WG <!-- TODO(operator): primary power maintainer --> |
| **Touch OSK & UI** | [`mobile/osk/`](file:///home/alpha/android/mobile/osk) & [`dist/`](file:///home/alpha/android/dist) | `lrd-osk` Wayland layer-shell virtual keyboard, touch web shell | TALOS UI/UX Team <!-- TODO(operator): primary UI maintainer --> |
| **Camera & Imaging** | [`mobile/camera/`](file:///home/alpha/android/mobile/camera) | `lrd-cam`, zero-trust stream blanker, MIPI-CSI2 ISP tuning | TALOS Hardware WG <!-- TODO(operator): primary camera maintainer --> |
| **Project Treble & Boot**| [`mobile/treble/`](file:///home/alpha/android/mobile/treble), [`mobile/fastboot/`](file:///home/alpha/android/mobile/fastboot), [`mobile/avb/`](file:///home/alpha/android/mobile/avb) | GSI builder, `init.libredroid.rc`, `prop.default`, AVB 2.0, dual-boot | TALOS Architecture Lead <!-- TODO(operator): primary treble maintainer --> |
| **Android Container** | [`mobile/waydroid/`](file:///home/alpha/android/mobile/waydroid) | Waydroid LXC sandbox, `lrd-arm-bridge`, `pif.json` Play Integrity | TALOS Compatibility WG <!-- TODO(operator): primary container maintainer --> |
| **Hardware Adaptation** | [`mobile/adaptation/`](file:///home/alpha/android/mobile/adaptation) & [`mobile/packages/`](file:///home/alpha/android/mobile/packages) | Device trees, Droidian/Halium rootfs overlays, pmaports | TALOS Device Porting Group <!-- TODO(operator): primary ports maintainer --> |
| **Release & Packaging** | [`mobile/release/`](file:///home/alpha/android/mobile/release) & [`installer/`](file:///home/alpha/android/installer) | dm-verity hash trees, fastboot installers, `SHA256SUMS.txt` | TALOS Release Team <!-- TODO(operator): primary release manager --> |
| **Egress Telemetry Defense** | [`security/egress/`](file:///home/alpha/android/security/egress) | `lrd-egress.nft`, Unbound DNS-over-TLS (port 853), per-app TOML | TALOS Security Council <!-- TODO(operator): primary network defense lead --> |
| **System Hardening** | [`security/harden/`](file:///home/alpha/android/security/harden) | `lrd-security-audit`, `lrd-verity-tool`, seccomp-bpf, Landlock LSM | TALOS Security Council <!-- TODO(operator): primary system hardening lead --> |
| **ARGUS Trust Engine** | [`argus/`](file:///home/alpha/android/argus) & [`argus/argf2/`](file:///home/alpha/android/argus/argf2) | BLAKE3 `ARGF/2` binary ledger, `tag_commit` equality, alibi velocity | ARGUS Core WG <!-- TODO(operator): primary cryptographer --> |
| **ARGUS Forensic Verifier**| [`argus/verify/`](file:///home/alpha/android/argus/verify) | 9-phase forensic verifier (`argus-verify`), findings catalog | ARGUS Core WG <!-- TODO(operator): primary verifier maintainer --> |
| **Halium & GKI Kernels**| [`halium/`](file:///home/alpha/android/halium) | Boot image v4 / GKI unpacker/repacker, GKI kernel configs | TALOS Kernel Group <!-- TODO(operator): primary kernel lead --> |
| **Security Scripts** | [`scripts/`](file:///home/alpha/android/scripts) | LUKS2 TPM vault, duress panic wipes, Tor hidden service | TALOS Security Council <!-- TODO(operator): primary scripts maintainer --> |
| **System Bridge** | [`server.js`](file:///home/alpha/android/server.js) & [`build.js`](file:///home/alpha/android/build.js) | Hardened loopback bridge (`127.0.0.1:3001`), bearer auth, asset pipeline | TALOS Core Team <!-- TODO(operator): primary bridge maintainer --> |
| **Reproducible Builds**| [`repro/`](file:///home/alpha/android/repro), [`flake.nix`](file:///home/alpha/android/flake.nix), [`.github/workflows/`](file:///home/alpha/android/.github/workflows) | Bit-for-bit compiler flags, attestation engine, Nix flake, CI matrix | TALOS Reproducibility Lead <!-- TODO(operator): primary repro lead --> |
| **Mobile Test Harness**| [`mobile/test/`](file:///home/alpha/android/mobile/test) & [`tests/`](file:///home/alpha/android/tests) | 85-test mobile test suite, 44-test ARGUS trust suite | TALOS QA WG <!-- TODO(operator): primary test lead --> |

---

## 2. Becoming a Maintainer

Maintainership in TALOS is meritocratic and grounded in demonstrated commitment to sovereign computing principles.

### Progression Path
1. **Contributor:** Anyone who submits pull requests, files reproducible bug reports, improves documentation, or tests hardware ports.
2. **Reviewer (Triager):** Contributors who have had at least five (5) non-trivial pull requests merged within a subsystem may be granted review triage privileges by that subsystem's maintainer.
3. **Subsystem Maintainer:**
   - **Nomination:** An existing maintainer or contributor nominates the candidate based on technical excellence, consistent participation, and adherence to the zero-dependency philosophy.
   - **Sponsorship:** The candidate must be endorsed by at least one existing subsystem maintainer.
   - **Vote:** The Technical Steering Council approves the appointment by a two-thirds (2/3) supermajority vote.
   - **Onboarding:** The maintainer provides a cryptographic Ed25519 public key and agrees to the [CHARTER.md](file:///home/alpha/android/CHARTER.md) antimonopoly obligations.

### Stepping Down & Inactivity
- A maintainer may step down at any time by notifying the TSC.
- If a maintainer is inactive (no reviews, commits, or responses) for six (6) consecutive months without prior notice, the TSC may vote to transition them to Emeritus Maintainer status.

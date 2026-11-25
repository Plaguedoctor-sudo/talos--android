# TALOS / LibreMobile OS — Sovereign Successor to Android

> **Target Platform:** ARM64-v8a Smartphones and Tablets (Project Treble A/B Devices)  
> **Supported SoCs:** Qualcomm Snapdragon (845 through 8 Gen 1/2/3), MediaTek Dimensity & Helio (G99/MT6789), Samsung Exynos (1330/1380), Google Tensor (G1/G2/G3)  
> **Architecture:** Pure GNU/Linux userspace over Treble Vendor HALs, GKI Kernels, and the ARGUS Cryptographic Trust Spine  
> **Repository:** `/home/alpha/android`  
> **AI & Agent Technical Manual:** [AI_CONTEXT.md](file:///home/alpha/android/AI_CONTEXT.md)

---

## 1. Executive Summary & Sovereign Mission

TALOS / LibreMobile OS is an open-source, reproducible mobile operating environment built to replace proprietary Android. It frees users from commercial surveillance, tracking daemons, and corporate monopoly control while guaranteeing hardware-backed cryptographic custody and alibi integrity.

### Core Architectural Pillars
- **Zero Proprietary Java Bloat**: Completely discards the Android Java framework (Zygote, SystemServer, ART runtime, and Google Play Services) which idle at 3–5 GB of RAM. Replaces them with ultra-lightweight native C daemons (`lrd-telephonyd`, `lrd-sensord`, `lrd-wakelockd`) idling under 30 MB.
- **Project Treble GSI Compliance**: Preserves the manufacturer Board Support Package (BSP), kernel (`/boot`), and vendor HALs (`/vendor`), replacing strictly the generic system partition (`system.img`).
- **ARGUS Cryptographic Trust Spine**: Every system event, privilege grant, session lifecycle, and network flow is committed to an append-only, tamper-evident BLAKE3 hash-chained ledger (`ARGF/2`).
- **`tag_commit` Cross-Record Equality**: Keyed, epoch-scoped tags allow proving equality of network flows, entities, and subject identifiers across records without decrypting sensitive fields, bounded by forward-secret epoch keys.
- **Defense-Grade Network Egress**: Strict `nftables` egress firewall rules, local caching DNS-over-TLS (`unbound`), and Tor SOCKS5h routing neutralize background telemetry and commercial tracking.
- **Zero-Trust Sensor Streams**: Feeds synthetic white noise to microphones and pitch-black frames to cameras when apps access unauthorized hardware sensors instead of crashing.
- **Optional Sandboxed Android App Compatibility**: Android applications execute inside an isolated Waydroid (LXC) container with hardware GPU acceleration and Play Integrity spoofing (`pif.json`).

---

## 2. Directory Layout & Component Architecture

```
/home/alpha/android
├── Makefile                      # Master unified build, test, and verification automation
├── README.md                     # Architectural documentation and operator guide
├── AI_CONTEXT.md                 # Comprehensive technical manual & IPC reference for AI agents
│
├── mobile/                       # Native Mobile Hardware Subsystems (from fkgugal/android)
│   ├── build.sh                  # Master mobile GSI build script
│   ├── telephony/                # lrd-telephonyd daemon & CLI (VoLTE/VoNR, SIM, SMS)
│   ├── bluetooth/                # lrd-bluetoothd daemon & CLI (BlueZ, A2DP/HFP, BLE anti-tracking MAC)
│   ├── wifi/                     # lrd-wifid daemon & CLI (WPA3 station, mobile hotspot AP tethering)
│   ├── firewall/                 # lrd-firewalld daemon & CLI (defense-grade firewall, panic cut, app jail)
│   ├── sensors/                  # lrd-sensord daemon & CLI (Linux IIO, ALS, compass, haptics)
│   ├── power/                    # lrd-wakelockd daemon, S2Idle sleep governor, battery guardian
│   ├── osk/                      # lrd-osk Wayland layer-shell touch virtual keyboard
│   ├── camera/                   # Zero-trust dummy camera stream & Sony/ISOCELL ISP tuning
│   ├── waydroid/                 # Sandboxed AOSP container, pif.json, arm-bridge
│   ├── treble/                   # Project Treble GSI builder, init.rc, prop.default
│   ├── fastboot/                 # Automated fastboot flashing & non-destructive A/B slot switcher
│   ├── avb/                      # Android Verified Boot 2.0 keys & signing tools
│   ├── hardware/                 # Vibrator, LED, and backlight HAL abstractions
│   ├── packages/                 # Sovereign debloated package manifests
│   ├── adaptation/               # AOSP device trees, pmaports, openrc, and hardware probe tools
│   ├── release/                  # Flashable release installer (flash-libremobile.sh, verity-table.json)
│   └── test/                     # 85-test mobile subsystem automated verification test harness
│
├── halium/                       # Halium & GKI v4 Boot Adaptation (from fkgugal/halium-vidofnir)
│   ├── build_halium_boot.py      # Automated Halium boot.img assembler
│   ├── unpack_v4.py              # Android Boot Image v4 / GKI unpacker
│   ├── repack_v4.py              # Boot Image v4 / GKI repacker with custom initramfs
│   └── config-vidofnir.gki       # Verified GKI kernel configuration
│
├── security/                     # Egress Telemetry Defense & OS Hardening
│   ├── egress/                   # Telemetry-blocking nftables firewall, unbound DoT, VPN
│   │   ├── nftables/             # lrd-egress.nft strict egress filter rules
│   │   ├── unbound/              # Local caching DNS-over-TLS resolver configuration
│   │   ├── policy/               # Application-level network access policies
│   │   ├── daemon/               # lrd-egressd network egress monitoring daemon
│   │   └── bin/                  # lrd-egressctl controller CLI
│   └── harden/                   # Seccomp-BPF profiles, Landlock LSM sandbox, dm-verity
│       ├── lrd-security-audit    # System hardening & DAC/MAC auditor
│       ├── lrd-verity-tool       # Read-only dm-verity rootfs verification tool
│       ├── harden/               # Sysctl hardening, AppArmor profiles, cgroups ceilings
│       └── net/                  # DNS poisoner and telemetry defense daemons
│
├── argus/                        # ARGUS Core Trust Spine & Custody Engine
│   ├── verify/                   # 9-phase forensic verifier & CLI (argus-verify)
│   │   ├── record.py             # 128-byte header, SegHeader, SegFooter, arity-4 Merkle walks
│   │   ├── findings.py           # Structured findings model & exit code grading
│   │   ├── trust.py              # Ed25519 keyring, fingerprints, X.509 cert validation
│   │   ├── bundle.py             # .argx bundle unpacker & canonical manifest validation
│   │   ├── verify.py             # 9-phase verification pipeline
│   │   └── cli.py                # Human & JSONL CLI verifier
│   ├── argf2/                    # ARGF/2 binary ledger producer
│   │   └── writer.py             # RecordBuilder, TagField, Bridge, leaf derivation
│   ├── alibi.py                  # Great-Circle velocity validation & alibi proof engine
│   ├── compartments.py           # Role and clearance level compartment isolation
│   ├── deadman.py                # Deadman switch timer & custody fail-safe
│   ├── duress.py                 # Duress panic wipes & decoy root profile isolation
│   ├── isolation.py              # Linux namespace & cgroup v2 sandbox governor
│   ├── sentinel.py               # Cryptographic watchdog
│   ├── timebase.py               # Monotonic / true-time clock step monitor
│   ├── tor.py                    # Tor SOCKS5h controller & circuit isolation
│   ├── vault.py                  # Content-Addressed Storage (CAS) vault
│   └── watcher.py                # Real-time filesystem integrity watcher
│
├── scripts/                      # Operational Security Scripts (from darkside/scripts)
│   ├── isolate-app.sh            # Unshare sandbox execution wrapper
│   ├── enroll_duress.py          # Duress pin and panic wipe enrollment
│   ├── setup-luks-vault.sh       # Hardware TPM/KeyMint backed encrypted vault
│   ├── bundle_encrypted_vault.sh # Vault archiver and exporter
│   ├── security_bootstrap.sh     # Boot-time security gate initialization
│   └── start-onion.sh            # Tor hidden service manager
│
└── tests/                        # Forensic & Cryptographic Verification Suites
    ├── argx/                     # Forensic bundle tamper & scope tests (test_tamper.py)
    └── tag/                      # tag_commit epoch scoping & bridge tests (test_tags.py)
```

---

## 3. Subsystem Verification Status

All 100 automated tests pass completely (85 mobile subsystem tests across 8 suites + 15 tamper/tag tests, plus full ARGUS producer/e2e/grade suites):

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

---

## 4. Master Operator Commands

All build, test, and verification targets are driven through the unified top-level [`Makefile`](file:///home/alpha/android/Makefile):

```bash
# 1. Run all tests and verification gates (ARGUS trust + mobile daemons + verifier)
make check

# 2. Run strictly the cryptographic trust & tamper test suites
make test-trust

# 3. Run strictly the 85 native mobile subsystem tests (telephony, bluetooth, wifi/hotspot, firewall, sensors, power, osk, arm)
make test-mobile

# 4. Compile all native mobile hardware daemons (telephony, bluetooth, wifi, firewall, sensors, power)
make build-daemons

# 5. Run the ARGUS 9-phase export verifier on the test fixture
make verify

# 6. Run the verifier with strict gate (promotes explained gaps to exit code 2)
make verify-strict
```

# AI & Agent Architectural Context: TALOS / LibreMobile OS

> **Audience:** AI agents, autonomous coding models, and system architects.  
> **Purpose:** Comprehensive technical manual, directory reference, IPC specification, cryptographic trust layout, and operational rules for the TALOS / LibreMobile operating system.  
> **Repository Root:** `/home/alpha/android`  
> **Target Architecture:** ARM64-v8a Smartphones and Tablets (Project Treble A/B Devices)  
> **Execution Base:** Pure GNU/Linux userspace over Android BSP / GKI Linux Kernels + Treble Vendor HALs.

---

## 1. System Vision & Sovereign Mission

TALOS / LibreMobile OS is a completely un-Googled, sovereign mobile operating environment designed as a bare-metal replacement for Google Android.

### The Problem It Solves
Standard Android is weighed down by:
1. **Massive Framework Bloat**: Zygote, SystemServer, and the Android Runtime (ART) consume 3–5 GB of RAM at idle before user applications run.
2. **Surveillance Capitalism**: Mandatory Google Mobile Services (GMS), background analytics, location tracking daemons, telemetry beacons, and persistent device identifiers.
3. **Hardware Lock-in**: Vendor-specific planned obsolescence once security patches cease.

### The Architectural Solution
- **Zero Java Runtime on Host**: Discards the entire Android Java framework. All host core services are native C daemons (`< 2 MB` RSS each, total idle footprint `< 30 MB`).
- **Project Treble GSI Compliance**: Preserves device Board Support Packages (BSPs), vendor drivers (`/vendor`), and kernels (`/boot`), flashing solely the generic system partition (`system.img`).
- **ARGUS Cryptographic Trust Spine**: Commits every system event, privilege escalation, session transition, and network packet to an immutable, BLAKE3-hashed, tamper-evident ledger (`ARGF/2`).
- **Privacy by Default**: MAC address rotation for Wi-Fi and Bluetooth Low Energy (BLE), zero-trust mock feeds for unpermitted sensors/cameras, deny-by-default `nftables` firewall with an instant panic kill-switch.
- **Isolated Android App Compatibility**: When needed, legacy Android apps run inside a sandboxed Waydroid (LXC) container with hardware GPU acceleration and certified Play Integrity spoofing (`pif.json`).

---

## 2. Directory Layout & Repository Map

```
/home/alpha/android
├── Makefile                          # Unified build, test, and verification automation
├── README.md                         # Human-oriented overview & flashing guide
├── AI_CONTEXT.md                     # THIS FILE — AI/agent technical manual
├── server.js                         # Hardened HTTP/WebSocket system bridge (127.0.0.1:3001)
├── build.js                          # Web UI bundler & asset builder
├── package.json                      # Node.js dependencies for bridge & UI shell
│
├── mobile/                           # Native Mobile Hardware Subsystems & Daemons
│   ├── build.sh                      # Master mobile compilation & packaging script
│   ├── telephony/                    # Cellular modem, SIM PIN, SMS, VoLTE/VoNR
│   │   ├── lrd-telephonyd.c          # C daemon (< 2MB RSS, /run/libredroid/telephony.sock)
│   │   ├── lrd-telephony.c           # CLI client (dial, hangup, sms, signal, sim)
│   │   └── lrd-telephony.service     # Systemd sandboxed service unit
│   ├── bluetooth/                    # Sovereign Bluetooth & BLE privacy
│   │   ├── lrd-bluetoothd.c          # C daemon (BlueZ D-Bus, A2DP/HFP, anti-tracking MAC)
│   │   ├── lrd-bluetooth.c           # CLI client (power, scan, pair, connect, privacy)
│   │   └── lrd-bluetooth.service     # Systemd sandboxed service unit
│   ├── wifi/                         # Wi-Fi Station & Mobile Hotspot AP Tethering
│   │   ├── lrd-wifid.c               # C daemon (WPA3-SAE, MAC rotate, hostapd ap0 tethering)
│   │   ├── lrd-wifi.c                # CLI client (status, scan, connect, hotspot-start, clients)
│   │   └── lrd-wifi.service          # Systemd sandboxed service unit
│   ├── firewall/                     # Defense-Grade Mobile Firewall & Panic Cut
│   │   ├── lrd-firewalld.c           # C daemon (deny-by-default, nftables sync, killswitch)
│   │   ├── lrd-firewall.c            # CLI client (status, killswitch, mode, rules, panic)
│   │   └── lrd-firewall.service      # Systemd sandboxed service unit
│   ├── sensors/                      # Linux IIO motion, orientation, and ambient sensors
│   │   ├── lrd-sensord.c             # C daemon (auto-rotate matrix, proximity screen blank, ALS)
│   │   ├── lrd-sensor                # CLI client for sensor readings & calibration
│   │   └── lrd-sensord.service       # Systemd sandboxed service unit
│   ├── power/                        # Wakelocks, S2Idle sleep governor, battery longevity
│   │   ├── lrd-wakelockd.c           # C daemon (/sys/power/wake_lock manager)
│   │   ├── lrd-battery-guardian.sh   # 80% charge threshold pouch-cell guardian
│   │   └── lrd-wakelockd.service     # Systemd sandboxed service unit
│   ├── osk/                          # Wayland layer-shell touch virtual keyboard (lrd-osk)
│   ├── camera/                       # Zero-trust dummy feed & MIPI-CSI2 ISP tuning
│   ├── waydroid/                     # Sandboxed LXC Android container & Play Integrity (pif.json)
│   ├── treble/                       # Project Treble GSI assembler & init hooks
│   │   ├── build-treble-gsi.sh       # Builds sparse ext4 system.img
│   │   ├── init.libredroid.rc        # Android init boot sequence hooks & service bindings
│   │   └── prop.default              # Certified build properties & identity cloaking
│   ├── packages/                     # Debloated mobile package manifests (mobile-packages.list)
│   ├── release/                      # Release packaging (flash-libremobile.sh, verity-table.json)
│   └── test/                         # 85-test mobile subsystem automated verification harness
│       ├── run-all-tests.sh          # Master test runner executing all 8 mobile suites
│       ├── test-telephony.sh         # Phase 6: Cellular RIL, SIM, VoLTE tests (10/10)
│       ├── test-sensors.sh           # Phase 8: IIO sensors, proximity, ALS tests (13/13)
│       ├── test-power.sh             # Phase 9: Wakelocks, S2Idle sleep tests (10/10)
│       ├── test-osk.sh               # Phase 10: Touch OSK layer-shell tests (7/7)
│       ├── test-arm-translation.sh   # Phase 12: ARM bridge, PIF spoofing tests (8/8)
│       ├── test-bluetooth.sh         # Phase 13: Bluetooth, BLE privacy tests (11/11)
│       ├── test-wifi.sh              # Phase 14: Wi-Fi station, hotspot AP tests (12/12)
│       └── test-firewall.sh          # Phase 15: Firewall, killswitch, panic tests (14/14)
│
├── security/                         # Defense & Egress Telemetry Neutralization
│   ├── egress/                       # Network egress firewall & DNS-over-TLS
│   │   ├── nftables/lrd-egress.nft   # Hardened nftables egress filter rules
│   │   ├── unbound/                  # Local caching DoT resolver configuration (port 853)
│   │   └── policy/                   # Per-app network access TOML profiles
│   └── harden/                       # Seccomp-BPF profiles, Landlock LSM, dm-verity
│
├── argus/                            # ARGUS Cryptographic Trust Spine & Custody Engine
│   ├── argf2/                        # ARGF/2 binary ledger producer (RecordBuilder, TagField, Bridge)
│   ├── verify/                       # 9-phase forensic verifier & CLI (argus-verify)
│   │   ├── record.py                 # 128-byte header, SegHeader, SegFooter, Merkle trees
│   │   ├── findings.py               # Findings catalog (V-101 to V-919) & grading
│   │   ├── trust.py                  # Ed25519 keyring & fingerprint validation
│   │   ├── bundle.py                 # .argx bundle unpacker & canonical manifest validation
│   │   └── verify.py                 # 9-phase verification pipeline
│   ├── alibi.py                      # Great-Circle speed-of-light alibi proof engine
│   ├── compartments.py               # Role and clearance level compartment isolation
│   ├── deadman.py                    # Deadman switch timer & custody fail-safe
│   ├── duress.py                     # Duress panic wipes & decoy root profile isolation
│   └── vault.py                      # Content-Addressed Storage (CAS) vault
│
├── halium/                           # Android Boot Image v4 / GKI unpacker and repacker
├── scripts/                          # Security bootstrap, LUKS vault, duress enrollment
└── tests/                            # Cryptographic trust & tamper test suites (test_tamper.py, test_tags.py)
```

---

## 3. Native Daemon Specifications & IPC Protocols

All native daemons are implemented in ANSI C (`-O2 -Wall`), run with minimal privileges under systemd/init capability bounding sets, and expose local UNIX domain stream sockets.

### Socket Fallback Standard
Every daemon and CLI tool adheres to the standard path hierarchy:
1. Primary: `/run/libredroid/<subsystem>.sock`
2. Fallback (unprivileged / test sandbox): `/tmp/libredroid/<subsystem>.sock`

### Telemetry / Hardware Simulation Rule
When real kernel hardware nodes (e.g. `mmcli`, `/sys/bus/iio`, `bluetoothctl`, `wpa_supplicant`, `nft`) are not present or lack kernel permissions in unprivileged containers, daemons transparently switch to deterministic simulated state. This guarantees that 100% of test suites run reproducibly on any Linux workstation or CI runner without physical hardware.

---

### 3.1. Telephony Subsystem (`lrd-telephonyd`)
- **Binary**: `/system/bin/lrd-telephonyd` | CLI: `/system/bin/lrd-telephony`
- **Socket**: `/run/libredroid/telephony.sock`
- **Capabilities Matrix**: [SUPPORT.md](file:///home/alpha/android/mobile/telephony/SUPPORT.md) | [support.yaml](file:///home/alpha/android/mobile/telephony/support.yaml) (replaces blanket 5G/VoLTE claims with an honest, per-device capability matrix; marks VoLTE, VoNR, and eSIM as experimental unless backed by carrier-certified hardware).
- **Responsibilities**: Cellular modem management (ModemManager / Halium RIL bridge), runtime capability probing (`lrd-telephonyd --caps`, `lrd-telephony caps`), SIM lifecycle (PIN unlock), SMS receive/send, and emergency 911 bypass.
- **IPC Protocol**: Line-based ASCII commands over UNIX socket:
  - `STATUS` -> Returns JSON object with state, operator, tech (e.g., `5G-SA`), signal dBm, SIM state.
  - `DIAL <number>` -> Initiates outgoing voice call.
  - `HANGUP` -> Terminates active call.
  - `ANSWER` -> Answers incoming call.
  - `SMS_SEND <number> <message>` -> Dispatches text message.
  - `SMS_LIST` -> Returns stored SMS records.
  - `SIM_UNLOCK <pin>` -> Unlocks SIM PIN.

### 3.2. Bluetooth Subsystem (`lrd-bluetoothd`)
- **Binary**: `/system/bin/lrd-bluetoothd` | CLI: `/system/bin/lrd-bluetooth`
- **Socket**: `/run/libredroid/bluetooth.sock`
- **Responsibilities**: Bluetooth 5.x controller, BlueZ D-Bus integration, A2DP sink/source audio streaming, HFP/HSP voice call profiles, BLE peripheral pairing, and **anti-surveillance BLE MAC address rotation** (rotates random private addresses every 15 minutes to block physical beacon tracking).
- **IPC Protocol**:
  - `STATUS` -> Returns JSON with power state, adapter MAC, scan state, connected devices.
  - `POWER <on|off>` -> Powers adapter on/off.
  - `SCAN <start|stop>` -> Toggles discovery.
  - `DEVICES` -> Lists discovered/paired devices.
  - `PAIR <mac>` -> Initiates device pairing.
  - `CONNECT <mac>` -> Connects profiles (A2DP/HFP/HID).
  - `DISCONNECT <mac>` -> Disconnects device.
  - `PRIVACY <on|off|rotate>` -> Enables anti-tracking BLE MAC randomization or forces immediate rotation.

### 3.3. Wi-Fi & Hotspot Subsystem (`lrd-wifid`)
- **Binary**: `/system/bin/lrd-wifid` | CLI: `/system/bin/lrd-wifi`
- **Socket**: `/run/libredroid/wifi.sock`
- **Responsibilities**: Dual-mode Wi-Fi controller:
  1. **Station Mode (`wlan0`)**: WPA2-Personal, WPA3-SAE, 802.11ax/ac/n scanning and association, station MAC address randomization on connect.
  2. **Mobile Hotspot AP Tethering (`ap0`)**: High-performance software Access Point (`hostapd` + `dnsmasq`), subnet `192.168.43.0/24`, DHCP server, client station isolation, 5GHz/2.4GHz bands, upstream NAT forwarding via `nftables`.
- **IPC Protocol**:
  - `STATUS` -> Returns JSON with station & AP status, connected SSID, IP, MAC address, hotspot client count.
  - `POWER <on|off>` -> Toggles Wi-Fi radio.
  - `SCAN` -> Performs network scan and returns SSIDs, RSSI, security protocols.
  - `CONNECT <ssid> [password]` -> Connects to target Wi-Fi network.
  - `DISCONNECT` -> Drops station connection.
  - `HOTSPOT_START [ssid] [password] [channel]` -> Spawns AP tethering on `ap0`.
  - `HOTSPOT_STOP` -> Tears down AP tethering.
  - `HOTSPOT_CLIENTS` -> Returns list of connected DHCP tethering clients.
  - `PRIVACY <on|off|rotate>` -> Toggles station MAC address randomization.

### 3.4. Defense-Grade Firewall Subsystem (`lrd-firewalld`)
- **Binary**: `/system/bin/lrd-firewalld` | CLI: `/system/bin/lrd-firewall`
- **Socket**: `/run/libredroid/firewall.sock`
- **Responsibilities**: Enforces a strict **deny-by-default** egress policy. Synchronizes kernel `nftables` tables, prevents DNS/WebRTC telemetry leaks, controls per-app network sandboxes, and triggers instant network cutoff in panic scenarios.
- **Routing Modes**:
  - `default`: Deny-by-default with stateful ESTABLISHED/RELATED egress; outbound allowed only to user-approved IPs/ports.
  - `vpn_wireguard`: Enforces strict killswitch — all outbound traffic must traverse `wg0`. Unencrypted traffic drops immediately.
  - `tor_strict`: Routes all TCP traffic through local Tor SOCKS5h (`127.0.0.1:9050`) / TransProxy (`9053`); all clearnet traffic is dropped.
  - `lan_only`: Drops all WAN traffic, permitting only local subnet communication (`192.168.0.0/16`, `10.0.0.0/8`, `172.16.0.0/12`).
  - `panic_cut`: Hard emergency cutoff; immediately drops 100% of packets across all interfaces (`wlan0`, `rmnet_data0`, `ap0`, `wg0`).
- **IPC Protocol**:
  - `STATUS` -> Returns active mode, killswitch status, rule counts, blocked attempts.
  - `KILLSWITCH <on|off>` -> Toggles strict anti-leak killswitch.
  - `MODE <default|vpn_wireguard|tor_strict|lan_only|panic_cut>` -> Switches routing mode.
  - `ALLOW_IP <direction> <ip>` -> Adds IP to whitelist.
  - `BLOCK_IP <direction> <ip>` -> Adds IP to dynamic blacklist `@egress_blocklist_v4`.
  - `ALLOW_APP <package_name>` -> Grants network capability to sandboxed app UID.
  - `BLOCK_APP <package_name>` -> Revokes network access for app UID.
  - `PANIC` -> Triggers emergency zero-delay network isolation.
  - `RESTORE` -> Clears panic state, reloading default ruleset.
  - `AUDIT` -> Dumps real-time telemetry block metrics.

### 3.5. Sensors & Power Subsystems
- **`lrd-sensord`**:
  - Socket: `/run/libredroid/sensor.sock`
  - Interfaces with Linux IIO (`/sys/bus/iio/devices/iio:device*`) for accelerometer, gyroscope, magnetometer, proximity, and ambient light sensors (ALS).
  - Drives display auto-rotation matrix (0°, 90°, 180°, 270°).
  - Proximity ear detection automatically blanks screen during active cellular voice calls to avoid face touches.
- **`lrd-wakelockd`**:
  - Socket: `/run/libredroid/wakelock.sock`
  - Manages Android kernel `/sys/power/wake_lock` and `/sys/power/wake_unlock`.
  - Coordinates S2Idle (suspend-to-idle) deep sleep transitions when screen blanks.
  - Runs battery guardian script to cap pouch-cell charging at 80% to prevent lithium degradation.

---

## 4. ARGUS Cryptographic Trust Spine (`ARGF/2`)

ARGUS is the zero-trust custody and ledger backbone of TALOS. It guarantees that any log tampering, unauthorized privilege modification, or alibi fabrication is mathematically detectable.

### 4.1. Binary File Format (`ARGF/2`)
- **Header**: 128-byte fixed header beginning with magic bytes `ARGF/2\0`. Contains schema version, root epoch public key, device UUID, and initial hash chaining seed.
- **Record Segments**: Composed of `SegHeader`, payload records, and `SegFooter`.
- **Merkle Chaining**: Uses arity-4 Merkle trees over BLAKE3 hashes. Every new record derives its leaf hash from the prior segment's root hash.

### 4.2. `tag_commit` Cross-Record Equality
To maintain privacy while enabling cryptographic audits, ARGUS implements **`tag_commit`**:
- Bounded by forward-secret epoch keys (`K_epoch`).
- Allows auditors to prove that an entity (e.g. IP address, user identifier, or device flow) in Record A matches Record B **without decrypting or revealing the sensitive entity field itself**.
- Cross-epoch equality is established using explicit `Bridge` records (`V-912`/`V-913`), ensuring that compromise of an old epoch key does not reveal past or future tags.

### 4.3. 9-Phase Forensic Verifier (`argus-verify`)
The verification engine inspects `.argx` bundles through 9 distinct phases:
1. **Phase 1: Bundle Structure**: Manifest canonical integrity, magic headers (`V-101`).
2. **Phase 2: Segment Geometry**: Segment alignment, boundary headers, footer checksums (`V-201`).
3. **Phase 3: Hash Chain Continuity**: Linear BLAKE3 chaining across records (`V-301`).
4. **Phase 4: Merkle Tree Correctness**: Arity-4 Merkle root validation (`V-401`).
5. **Phase 5: Signature Keyring**: Ed25519 signature checks against trusted keys (`V-501`).
6. **Phase 6: Timestamp & Monotonicity**: True-time and monotonic clock drift checks (`V-601`).
7. **Phase 7: Scope Coverage**: Comprehensive record coverage validation (`V-701`).
8. **Phase 8: Alibi & Great-Circle Speed**: Asserts speed-of-light velocity bounds between alibi coordinates (`V-801`).
9. **Phase 9: `tag_commit` Scope & Bridge Validation**: Validates tag digest bindings (`V-910`), bridge chains, and warns on unbridged local tags (`V-918`, `V-919`).

### 4.4. Exit Grading
- **Exit 0 (`PASS_PRISTINE`)**: All 9 phases verified with 0 defects or warnings.
- **Exit 1 (`PASS_WITH_WARNINGS`)**: Non-fatal warnings (e.g. explainable clock drift or unbridged local tags).
- **Exit 2 (`FAIL_TAMPERED` / Strict Gate)**: Cryptographic signature failure, broken hash chain, omitted scope, or fatal tampering detected.

---

## 5. Project Treble Architecture & Boot Sequence

LibreMobile targets generic ARM64 smartphones using Google's Project Treble modular partition architecture.

### Partition Separation
- **`/system` (Replaced by LibreMobile)**: Contains generic GNU/Linux rootfs, C daemons, Wayland compositor, and system bridge.
- **`/vendor` (Preserved OEM BSP)**: Contains device-specific proprietary HAL drivers (Qualcomm Adreno GPU, Hexagon DSP, camera ISP blobs, radio modem HALs).
- **`/boot` (Kernel)**: Uses Generic Kernel Image (GKI Linux 5.10 / 5.15 / 6.1) or Android BSP vendor kernel.

### Boot Sequence
```
[ Device Powered On ]
        │
        ▼
[ Primary Bootloader (PBL) / XBL ]
        │
        ▼
[ Android Verified Boot 2.0 (AVB) ] ──> Validates vbmeta.img & boot signature
        │
        ▼
[ Linux Kernel (GKI /boot) ] ──────────> Initializes ARM64 SoC, mounts initramfs
        │
        ▼
[ Treble Init (`/init`) ] ─────────────> Parses `init.libredroid.rc`
        │                                 ├── Mounts `/dev/binderfs` (/dev/binder, hwbinder, vndbinder)
        │                                 ├── Mounts `/vendor` (hardware HALs)
        │                                 └── Sets certified properties (`prop.default`, `pif.json`)
        │
        ▼
[ Native Core Daemons Started ]
        ├── `lrd-telephonyd`   (Modem & VoLTE RIL)
        ├── `lrd-bluetoothd`   (Bluetooth & BLE Privacy)
        ├── `lrd-wifid`        (Wi-Fi Station & Mobile Hotspot)
        ├── `lrd-firewalld`    (Deny-by-default nftables)
        ├── `lrd-sensord`      (IIO Sensors & Auto-rotate)
        └── `lrd-wakelockd`    (Power Governor & S2Idle)
        │
        ▼
[ Display Server & Touch Shell ] ──────> Cage/Sway Wayland compositor launched
        │                                 ├── `lrd-osk` touch virtual keyboard
        │                                 └── Wayland Touch Web Shell
        │
        ▼
[ Sovereign System Bridge (`server.js`) ] -> 127.0.0.1:3001 (authenticated system bridge)
```

---

## 6. System Bridge & Web Shell Interface

The primary user interface is a responsive, touch-optimized Web application communicating with the underlying operating system via `server.js`.

- **Host Binding**: Strictly bound to `127.0.0.1:3001` (never exposed to external interfaces).
- **Authentication**: Constant-time comparison (`crypto.timingSafeEqual`) against a cryptographic bearer token stored in `/etc/lrd/bridge.token` (permissions `0600`/`0400` owned by root).
- **Allowed Command Set**: Whitelist includes `lrd-telephony`, `lrd-bluetooth`, `lrd-wifi`, `lrd-firewall`, `lrd-sensor`, `lrd-verity-tool`, and `lrd-security-audit`.
- **Concurrency & Ledger Attribution**: Maximum 2 concurrent subprocess executions; every invocation emits paired `EXEC_START` and `EXEC_SUCCESS`/`EXEC_FAILED` events to the ARGUS ledger.

---

## 7. Developer & AI Agent Operations Manual

### 7.1. Essential Make Targets
Always use `make` targets from `/home/alpha/android`:

| Command | Action |
| :--- | :--- |
| `make check` | Runs the master verification gate: `test-trust`, `test-mobile`, and `verify-strict`. **Must pass 100%**. |
| `make test-mobile` | Runs all 8 native mobile subsystem test suites (85 tests total). |
| `make test-trust` | Runs all pytest cryptographic trust and tamper verification suites (44 tests total). |
| `make build-daemons`| Compiles all 10 C binaries for telephony, bluetooth, wifi, firewall, sensors, and power. |
| `make verify` | Runs the 9-phase ARGUS verifier on test fixtures. |
| `make verify-strict` | Runs the ARGUS verifier in strict mode (promotes any warnings to fatal exit 2). |
| `make reproducible` | Executes dual-build bit-for-bit test across independent paths and publishes attestation JSON. |
| `make reproducible-verify` | Audits build output directory against published attestation using stdlib-only python. |
| `make reproducible-docker` | Builds and verifies reproducibility inside pinned debian:bookworm-slim container. |
| `make reuse-lint` | Audits REUSE 3.0 and SPDX license compliance across the entire codebase. |
| `make clean` | Purges pytest and Python bytecode caches. |

### 7.2. Adding a New Daemon or Hardware Subsystem
When extending TALOS with a new native subsystem, follow this exact pattern:
1. **Daemon (`mobile/<subsystem>/lrd-<name>d.c`)**:
   - Write in ANSI C. Ensure clean compilation with `gcc -O2 -Wall`.
   - Use `snprintf` exclusively (never raw `strncpy` or `sprintf`).
   - Listen on `/run/libredroid/<name>.sock` with automatic fallback to `/tmp/libredroid/<name>.sock`.
   - Implement simulated fallback telemetry if hardware nodes (`/dev`, `/sys`) are inaccessible.
2. **CLI Controller (`mobile/<subsystem>/lrd-<name>.c`)**:
   - Provide a lightweight command-line utility to interact with the socket.
3. **Systemd Service (`mobile/<subsystem>/lrd-<name>.service`)**:
   - Include strict sandboxing: `ProtectSystem=strict`, `NoNewPrivileges=true`, `PrivateTmp=true`.
4. **Init Hook (`mobile/treble/init.libredroid.rc`)**:
   - Register the daemon as an Android init service with proper capability bounding sets (`capabilities NET_ADMIN SYS_ADMIN`).
5. **System Bridge Integration (`server.js`)**:
   - Add the binary name to `ALLOWED_COMMANDS` and specify allowed subcommands in `caps`.
6. **Automated Test Suite (`mobile/test/test-<name>.sh`)**:
   - Add self-contained start/stop daemon lifecycle verification.
   - Test JSON output, status queries, and error handling.
   - Register the script in `mobile/test/run-all-tests.sh`.
7. **Makefile Update**:
   - Add the compilation command to the `build-daemons` recipe in `Makefile`.
8. **Verification**:
   - Run `make check` to ensure all test suites pass without regression.

### 7.3. Sandbox & Security Ground Rules for Agents
- **Never bypass access controls**: Do not attempt to disable security checks or forge authentication tokens.
- **Maintain zero-dependency testing**: Test suites must never depend on live external networks or physical ARM64 basebands. Always support simulated mock fallbacks.
- **Preserve dm-verity integrity**: When packaging `system.img`, ensure dm-verity hash trees match `verity-table.json`.

---

## 8. File & Subfile Volume and Aims Catalog

### 8.1. High-Level System Volume Metrics

| Metric Category | Count / Volume | Description |
| :--- | :--- | :--- |
| **Total Tracked Files** | **353 files** | Source files, scripts, configurations, policies, and release metadata |
| **Total Code / Text Volume** | **43,213 lines** | Hand-crafted C, Python, Bash, JavaScript, TOML, and nftables rules |
| **Total Source Code Disk Size** | **~1.8 MB** | Zero bloat, ultra-compact native codebase |
| **Complete Workspace Volume** | **1,541.93 MB** | Includes generated sparse ext4 Treble GSI images and dm-verity release trees |
| **Runtime Memory (RSS) Footprint** | **< 30 MB combined** | Total idle RAM for all 6 native C daemons (vs. 3,500+ MB on Android) |

---

### 8.2. Directory Volume & Strategic Aims Breakdown

```
Directory                  Files      Size (KB)    Lines  Primary Aim
────────────────────────────────────────────────────────────────────────────────────────
/ (Root Workspace)             6        63.8 KB    1,394  Build orchestration, bridge, & top specs
mobile/telephony               5        55.1 KB      614  Cellular modem, VoLTE/VoNR, SMS RIL
mobile/bluetooth               5        64.2 KB      724  BlueZ, A2DP/HFP audio, anti-tracking BLE
mobile/wifi                    5        72.7 KB      768  WPA3 station & mobile hotspot AP tethering
mobile/firewall                5        90.4 KB      751  Deny-by-default firewall, killswitch, panic
mobile/sensors                 4        34.0 KB      460  Linux IIO sensors, auto-rotate, ear blanking
mobile/power                   7        42.6 KB      691  Wakelock governor, S2Idle, 80% battery cap
mobile/osk                     6         7.4 KB      266  Touch layer-shell OSK & 5 language layouts
mobile/treble                  5   524,310.8 KB    2,914  Project Treble GSI builder & init.rc hooks
mobile/camera                  3         5.5 KB      170  Zero-trust dummy feed & MIPI-CSI2 tuning
mobile/fastboot                2        10.7 KB      271  Non-destructive A/B slot switching & flash
mobile/waydroid                8        28.0 KB      812  LXC Android sandbox & Play Integrity fix
mobile/adaptation             44        75.8 KB    1,418  Device trees, Droidian/Halium, & pmaports
mobile/packages                1         1.2 KB       32  Debian sovereign ARM64 package manifest
mobile/release                12   528,719.3 KB    4,308  Release installer, verity tables, SHA256SUMS
mobile/test                    9        39.9 KB    1,215  85-test automated mobile validation harness
argus/ (Core Engine)          17        94.2 KB    2,865  Alibi, compartments, deadman, duress, vault
argus/argf2                   15        48.8 KB    1,315  ARGF/2 binary ledger producer & Merkle walks
argus/verify                   7        42.1 KB    1,061  9-phase cryptographic forensic verifier
security/egress               14        42.2 KB    1,129  nftables egress rules, DoT, app policies
security/harden               41       148.4 KB    2,819  dm-verity auditor, seccomp, AppArmor, DAC
halium/                        4       237.9 KB    8,540  Boot image v4/GKI unpacker, repacker & kernel
scripts/                      13        28.7 KB      816  LUKS vault, duress enrollment, Tor onion
tests/                        43        60.5 KB    1,521  Pytest cryptographic trust & tamper suites
dist/                          4         9.0 KB      333  Bundled Wayland touch shell web assets
```

---

### 8.3. File-by-File Inventory, Volumes, and Subsystem Aims

#### 1. Root Workspace Orchestration
- **[Makefile](file:///home/alpha/android/Makefile)** (2,182 B | 45 lines)
  - *Aim:* Master build, test, and verification automation. Drives `make check`, `make test-mobile`, `make test-trust`, `make build-daemons`, `make verify-strict`, and `make reproducible`.
- **[flake.nix](file:///home/alpha/android/flake.nix)** & **[flake.lock](file:///home/alpha/android/flake.lock)**
  - *Aim:* Hermetic build environment pinning NixOS 23.11 toolchains (gcc, make, node, python3, e2fsprogs, android-tools) for bit-for-bit reproduction across distributions.
- **[README.md](file:///home/alpha/android/README.md)** (12,825 B | 150 lines)
  - *Aim:* Primary human-facing architectural specification, system mission statement, hardware matrix, operator manual, and reproducible build guide.
- **[AI_CONTEXT.md](file:///home/alpha/android/AI_CONTEXT.md)** (24,317+ B)
  - *Aim:* Comprehensive, structured technical reference and IPC protocol manual specifically formatted for AI agents and automated tools.
- **[server.js](file:///home/alpha/android/server.js)** (15,545 B | 475 lines)
  - *Aim:* Hardened HTTP/WebSocket local system bridge (`127.0.0.1:3001`). Connects touch UI to native CLI tools with constant-time token authentication (`crypto.timingSafeEqual`), concurrency throttling, and ARGUS event emission.
- **[build.js](file:///home/alpha/android/build.js)** (10,041 B | 360 lines)
  - *Aim:* Client bundle synthesizer and asset pipeline compiler for the touch Wayland shell.
- **[package.json](file:///home/alpha/android/package.json)** (409 B | 20 lines)
  - *Aim:* Declares runtime and build-time Node.js dependencies for the web shell and bridge.

#### 1.1. Deterministic Reproducibility & Attestation (`repro/`)
- **[repro/Dockerfile](file:///home/alpha/android/repro/Dockerfile)**
  - *Aim:* Fallback container environment pinning `debian:bookworm-slim` by SHA-256 digest (`sha256:d6b63d0b28...`) for reproducible builds without Nix.
- **[repro/verify-attestation.py](file:///home/alpha/android/repro/verify-attestation.py)**
  - *Aim:* Standard-library-only Python 3 verifier that re-hashes local build outputs against a machine-verifiable attestation JSON and audits zero divergence.
- **[repro/README.md](file:///home/alpha/android/repro/README.md)**
  - *Aim:* Comprehensive third-party audit manual detailing single-command rebuild workflows via Nix, Docker, or native host.
- **[.github/workflows/repro.yml](file:///home/alpha/android/.github/workflows/repro.yml)**
  - *Aim:* Continuous integration workflow running a 2-runner matrix (`ubuntu-22.04` and `ubuntu-24.04`) asserting cross-distribution bit-for-bit equality.

#### 1.2. Sovereign Commons Governance & Legal Policies
- **[CHARTER.md](file:///home/alpha/android/CHARTER.md)**: Constitutional charter defining the six sovereign aims, non-profit foundation structure, antimonopoly guardrails, explicit **no single-entity veto**, and funding prohibitions.
- **[GOVERNANCE.md](file:///home/alpha/android/GOVERNANCE.md)**: Operational procedures governing 1-seat board caps, adtech/telemetry monetization bans, **3-of-5 threshold multisig release signing**, and the irrevocable free software covenant.
- **[MAINTAINERS.md](file:///home/alpha/android/MAINTAINERS.md)**: Comprehensive ownership matrix covering all 21 subsystems in the tree, along with the meritocratic progression path for maintainership.
- **[CONTRIBUTING.md](file:///home/alpha/android/CONTRIBUTING.md)**: Developer Certificate of Origin (DCO 1.1) guidelines, SPDX requirements, 72-hour review SLAs, and zero-dependency constraints.
- **[CODE_OF_CONDUCT.md](file:///home/alpha/android/CODE_OF_CONDUCT.md)**: Community standards, harassment-free participation pledge, and enforcement procedures.
- **[TRADEMARK.md](file:///home/alpha/android/TRADEMARK.md)**: Trademark usage rules, permitted nominative fair use, and mandatory fork renaming rules.
- **[REUSE.toml](file:///home/alpha/android/REUSE.toml)**: Free Software Foundation Europe REUSE 3.0 license and copyright attribution specification.

#### 1.3. Tiered Hardware Certification Matrix (`hardware/` & `HARDWARE.md`)
- **[HARDWARE.md](file:///home/alpha/android/HARDWARE.md)**: Human-readable hardware certification document defining Tier A (Fully Free), Tier B (Blob-Reduced), Tier C (Treble-Compatible / Sovereign userspace, non-free firmware), and Roadmap tiers.
- **[hardware/schema.json](file:///home/alpha/android/hardware/schema.json)**: JSON Schema (draft 2020-12) validating machine-readable hardware matrix entries and blob inventories.
- **[hardware/matrix.yaml](file:///home/alpha/android/hardware/matrix.yaml)**: Machine-readable database of tested devices, SoC details, bootloader relocking support, kill-switch status, firmware provenance, and binary blob catalogs.
- **[scripts/hardware-matrix.py](file:///home/alpha/android/scripts/hardware-matrix.py)**: Python stdlib validator enforcing schema rules, tier consistency (prohibiting proprietary blobs in Tier A), and deterministic idempotent Markdown rendering. Driven by `make hardware-matrix-check` and `make hardware-matrix-render`.

#### 1.4. Third-Party Audit Preparation & Property Verification (`audit/` & `SECURITY-AUDIT.md`)
- **[SECURITY-AUDIT.md](file:///home/alpha/android/SECURITY-AUDIT.md)**: Public audit status dashboard, scope summary, and operator tracking for auditor selection.
- **[audit/SCOPE.md](file:///home/alpha/android/audit/SCOPE.md)**: Cryptographic audit boundary defining exact in-scope file paths, line ranges (`argus/argf2`, `tag_commit`, `duress.py`, `deadman.py`, `vault.py`, `verify.py`), and out-of-scope exclusions.
- **[audit/THREAT-MODEL.md](file:///home/alpha/android/audit/THREAT-MODEL.md)**: Formal threat model detailing 5 adversary tiers, 4 protected asset classes, and mathematical invariants (`INV-M1` through `INV-H2`).
- **[audit/RFP.md](file:///home/alpha/android/audit/RFP.md)**: Request-for-proposal template with auditor credentials, deliverables, timeline, and surveillance-free funding terms.
- **[audit/findings/TEMPLATE.md](file:///home/alpha/android/audit/findings/TEMPLATE.md)**: Standard vulnerability disclosure template and severity grading rubric combining CVSS v3.1 with sovereign impact levels.
- **[audit/test-vectors/](file:///home/alpha/android/audit/test-vectors)**: Committed static test vectors for Merkle arity-4, epoch rollover, duress plausibility, deadman timeouts, and vault custody chains.
- **Property Test Suites**:
  - [`tests/test_argf2_properties.py`](file:///home/alpha/android/tests/test_argf2_properties.py): Hypothesis property tests asserting Merkle arity-4 proof correctness, single-bit tamper sensitivity, proof size bounds, and crash-resilient epoch rollover.
  - [`tests/test_duress_properties.py`](file:///home/alpha/android/tests/test_duress_properties.py): Property tests verifying decoy plausibility score bounds, monotonicity, enrollment threshold gating, and session routing isolation.
  - [`tests/test_deadman_properties.py`](file:///home/alpha/android/tests/test_deadman_properties.py): Property tests proving zero false-positives within grace periods, offline wipe policy authorization guards, and status monotonicity.
  - [`tests/test_audit_vectors.py`](file:///home/alpha/android/tests/test_audit_vectors.py): Automated regression test asserting all committed static vectors pass invariant checks.
  - Driven by `make audit-prep`.

#### 1.5. Sovereign Remote Attestation & PIF Sunset (`ATTESTATION.md`, `ROADMAP.md`, `attestation/rats-verifier`)
- **[ATTESTATION.md](file:///home/alpha/android/ATTESTATION.md)**: Open Remote Attestation specification implementing IETF RATS (RFC 9334) architecture and EAT (RFC 9711) tokens. Covers Passport and Background-Check models, TPM 2.0 PCR allocation, zero-dependency local verifier design, remote verifier federation, app developer outreach tracks (native Linux, sandboxed PWA with WebAuthn/FIDO2, open Android attestation HAL), and migration phases.
- **[ROADMAP.md](file:///home/alpha/android/ROADMAP.md)**: Consolidated master roadmap documenting completed milestones (Phases 1–5), active attestation transition (Phase 6), and 2027–2028 forward horizons (Post-Quantum ARGF/2, Librem 5 v2 RISC-V silicon, distributed ledger mesh).
- **[mobile/waydroid/PIF_ROADMAP.md](file:///home/alpha/android/mobile/waydroid/PIF_ROADMAP.md)**: Formal status declaration (`TRANSITIONAL`), legal/technical risk analysis, measurable exit criteria ($\ge 3$ banking apps, $\ge 5$ public ID portals, mandatory hardware KeyMint enforcement, Dec 31, 2027 hard cutoff).
- **[attestation/rats-verifier/](file:///home/alpha/android/attestation/rats-verifier)**: Pure Python 3 stdlib reference verifier engine:
  - `eat.py`: RFC 9711 Entity Attestation Token parser and validator.
  - `tpm.py`: TPM 2.0 quote appraisal (`TPMS_ATTEST` and `TPMT_SIGNATURE`), composite PCR digest calculation, pure stdlib RSA-PKCS1-v1.5 and HMAC-SHA256 signature verification.
  - `verifier.py`: Core appraisal engine comparing evidence against pinned Attestation Keys (AKs) and Reference Integrity Measurements (RIM), emitting standardized Trustworthiness Vectors.
  - `cli.py`: Command-line interface for local and container attestation queries.
  - `vectors/`: Committed static JSON test vectors for valid, tampered PCR, expired nonce, and untrusted AK scenarios.
  - Tested by `tests/test_rats_verifier.py` (`make test-attestation`).

#### 1.6. Antimonopoly App Distribution & Privacy Scoring (`store/` & `tests/test_store_scoring.py`)
- **[store/POLICY.md](file:///home/alpha/android/store/POLICY.md)**: Repository inclusion criteria enforcing FOSS licenses (OSI/FSF), reproducible builds (or signed time-limited waivers), absolute prohibition of commercial advertising/profiling SDKs, and mandatory declared egress policies matching `security/egress/policy/*.toml`.
- **[store/privacy-score.py](file:///home/alpha/android/store/privacy-score.py)**: Deterministic 0–100 privacy scoring algorithm (`SCORE_VERSION = "1.0.0"`) computing weighted metrics across tracker absence (35%), permission restraint (20%), build reproducibility (20%), egress policy alignment (15%), and maintenance recency (10%).
- **[store/data/trackers.json](file:///home/alpha/android/store/data/trackers.json)**: Vendored Exodus Privacy signature catalog attributing 14 prominent tracker signatures across advertising, analytics, profiling, and crash reporting.
- **[store/data/upstream-index.json](file:///home/alpha/android/store/data/upstream-index.json)**: Pinned hermetic upstream mirror index snapshot containing curated sovereign utilities, browsers, and fixture test apps.
- **[store/sign-index.py](file:///home/alpha/android/store/sign-index.py)**: Ed25519 signing and verification utility generating detached signatures (`index.json.sig`) bound to pinned keys in `store/keys/`.
- **[store/build-index.sh](file:///home/alpha/android/store/build-index.sh)** & **[store/verify-index.sh](file:///home/alpha/android/store/verify-index.sh)**: Automated build and verification pipeline for the repository manifest (`make store-index` and `make store-verify`).
- **Web Bridge & UI Integration**: `server.js` exposes `GET /api/store/index` protected by `timingSafeEqual` bearer token authentication. The `dist/` web shell renders a native store panel displaying package metadata, privacy scores, and color-coded badges (`A+` through `F`).
- **[tests/test_store_scoring.py](file:///home/alpha/android/tests/test_store_scoring.py)**: Automated regression suite asserting exact fixture scores (100.0 A+, 7.0 F, 72.0 B, 97.0 A+), score determinism, Ed25519 signature checks, and server HTTP endpoint authentication (`make store-score-test`).

#### 2. Cellular Telephony Subsystem (`mobile/telephony/`)
- **[SUPPORT.md](file:///home/alpha/android/mobile/telephony/SUPPORT.md)** & **[support.yaml](file:///home/alpha/android/mobile/telephony/support.yaml)**
  - *Aim:* Authoritative per-device capability matrix and JSON schema. Explicitly marks VoLTE, VoNR, and eSIM as experimental unless backed by carrier-certified hardware entries.
- **[schema.json](file:///home/alpha/android/mobile/telephony/schema.json)**
  - *Aim:* JSON Schema draft 2020-12 defining per-device matrix schema and runtime probe caps schema.
- **[lrd-telephonyd.c](file:///home/alpha/android/mobile/telephony/lrd-telephonyd.c)**
  - *Aim:* Native C telephony daemon (`< 2 MB` RSS). Connects to Qualcomm/MediaTek/Quectel baseband via ModemManager / AT / QMI / Halium RIL, provides runtime `--caps` probe writing schema-validated `/run/libredroid/telephony.caps.json`, controls SIM state, and exposes `/run/libredroid/telephony.sock`.
- **[lrd-telephony.c](file:///home/alpha/android/mobile/telephony/lrd-telephony.c)**
  - *Aim:* High-speed CLI dialer, SMS client, and capability query client (`lrd-telephony caps`).
- **[lrd-telephony.service](file:///home/alpha/android/mobile/telephony/lrd-telephony.service)** (364 B | 17 lines)
  - *Aim:* Sandboxed systemd service definition with isolated `/tmp` and restricted capabilities.
- **`lrd-telephonyd` & `lrd-telephony` (ELF Binaries)**
  - *Aim:* Pre-compiled ARM64/x86_64 binaries ready for instant execution and testing.

#### 3. Sovereign Bluetooth Subsystem (`mobile/bluetooth/`)
- **[lrd-bluetoothd.c](file:///home/alpha/android/mobile/bluetooth/lrd-bluetoothd.c)** (17,032 B | 449 lines)
  - *Aim:* Native C Bluetooth daemon (`< 2 MB` RSS). Manages BlueZ D-Bus adapters, A2DP audio sinks/sources, HFP voice calls, and implements **anti-surveillance BLE MAC address rotation** (rotates random private addresses every 15 min to defeat physical beacon tracking).
- **[lrd-bluetooth.c](file:///home/alpha/android/mobile/bluetooth/lrd-bluetooth.c)** (4,157 B | 119 lines)
  - *Aim:* CLI controller for adapter power, device scanning, pairing, audio connection, and privacy cycling.
- **[lrd-bluetooth.service](file:///home/alpha/android/mobile/bluetooth/lrd-bluetooth.service)** (555 B | 24 lines)
  - *Aim:* Systemd sandboxing unit granting `CAP_NET_ADMIN` and restricting filesystem mutations.
- **`lrd-bluetoothd` & `lrd-bluetooth` (ELF Binaries)** (27,312 B & 16,696 B)
  - *Aim:* Compiled native controller and daemon binaries.

#### 4. Sovereign Wi-Fi & Hotspot Subsystem (`mobile/wifi/`)
- **[lrd-wifid.c](file:///home/alpha/android/mobile/wifi/lrd-wifid.c)** (20,031 B | 508 lines)
  - *Aim:* Native C Wi-Fi daemon (`< 2 MB` RSS). Handles dual-role networking:
    1. *Station (`wlan0`):* WPA2/WPA3-SAE association with station MAC address randomization.
    2. *Mobile Hotspot (`ap0`):* Standalone 5GHz/2.4GHz soft-AP (`hostapd`), local DHCP server (`dnsmasq`, subnet `192.168.43.0/24`), client station isolation, and upstream NAT forwarding.
- **[lrd-wifi.c](file:///home/alpha/android/mobile/wifi/lrd-wifi.c)** (4,374 B | 117 lines)
  - *Aim:* CLI client providing `status`, `scan`, `connect`, `hotspot-start`, `hotspot-clients`, and `privacy`.
- **[lrd-wifi.service](file:///home/alpha/android/mobile/wifi/lrd-wifi.service)** (541 B | 24 lines)
  - *Aim:* Sandboxed systemd service file with network capability containment.
- **`lrd-wifid` & `lrd-wifi` (ELF Binaries)** (32,752 B & 16,696 B)
  - *Aim:* Compiled native Wi-Fi stack binaries.

#### 5. Defense-Grade Mobile Firewall (`mobile/firewall/`)
- **[lrd-firewalld.c](file:///home/alpha/android/mobile/firewall/lrd-firewalld.c)** (20,487 B | 477 lines)
  - *Aim:* Native C defense-grade firewall daemon (`< 2 MB` RSS). Enforces deny-by-default filtering via `nftables`, anti-leak killswitch, multi-mode routing (`default`, `vpn_wireguard`, `tor_strict`, `lan_only`, `panic_cut`), per-app network sandboxing, and emergency zero-leak panic shutdown.
- **[lrd-firewall.c](file:///home/alpha/android/mobile/firewall/lrd-firewall.c)** (5,074 B | 123 lines)
  - *Aim:* CLI controller for querying firewall status, changing modes, whitelisting/blacklisting IPs, managing app jails, and initiating panic network lockdown.
- **[lrd-firewall.service](file:///home/alpha/android/mobile/firewall/lrd-firewall.service)** (585 B | 25 lines)
  - *Aim:* Systemd sandboxed service unit with `CAP_NET_ADMIN` and `CAP_NET_RAW`.
- **`lrd-firewalld` & `lrd-firewall` (ELF Binaries)** (49,744 B & 16,696 B)
  - *Aim:* Compiled native firewall binaries.

#### 6. Sensors & Actuators (`mobile/sensors/` & `mobile/hardware/`)
- **[lrd-sensord.c](file:///home/alpha/android/mobile/sensors/lrd-sensord.c)** (10,543 B | 311 lines)
  - *Aim:* Native C sensor daemon polling Linux Industrial I/O (`/sys/bus/iio`). Calculates display auto-orientation matrix, provides ambient light brightness calibration, and drives proximity ear blanking during calls.
- **[lrd-sensor](file:///home/alpha/android/mobile/sensors/lrd-sensor)** (2,068 B | 82 lines)
  - *Aim:* CLI tool for inspecting real-time accelerometer, gyroscope, compass, and ALS telemetry.
- **[lrd-haptics](file:///home/alpha/android/mobile/hardware/lrd-haptics)** (2,816 B | 88 lines)
  - *Aim:* Direct HAL abstraction for Linear Resonant Actuators (LRA) and Eccentric Rotating Mass (ERM) vibration motors.

#### 7. Mobile Power & Battery Governor (`mobile/power/`)
- **[lrd-wakelockd.c](file:///home/alpha/android/mobile/power/lrd-wakelockd.c)** (8,757 B | 270 lines)
  - *Aim:* Native C wakelock governor interacting with Android kernel `/sys/power/wake_lock`. Enforces S2Idle deep sleep transitions when display is inactive.
- **[lrd-battery-guardian.sh](file:///home/alpha/android/mobile/power/lrd-battery-guardian.sh)** (1,918 B | 62 lines)
  - *Aim:* Pouch-cell longevity daemon. Cursors `/sys/class/power_supply` to enforce an 80% charging ceiling, preventing lithium pouch-cell swelling and capacity fade.
- **[lrd-irq-wake.sh](file:///home/alpha/android/mobile/power/lrd-irq-wake.sh)** (2,985 B | 95 lines)
  - *Aim:* Configures hardware interrupt wakeup masks (modem-RI, gpio-keys, rtc0) for incoming call wakeups.

#### 8. Wayland Touch OSK & Display (`mobile/osk/` & `mobile/camera/`)
- **[lrd-osk](file:///home/alpha/android/mobile/osk/lrd-osk)** (5,718 B | 213 lines)
  - *Aim:* Native Wayland layer-shell touch virtual keyboard.
- **`mobile/osk/layouts/`** (5 files | 1,842 B | 53 lines)
  - *Aim:* Declarative JSON keyboard layouts (`qwerty.json`, `qwertz.json`, `azerty.json`, `numeric.json`, `emoji.json`).
- **[lrd-cam](file:///home/alpha/android/mobile/camera/lrd-cam)** (3,211 B | 90 lines)
  - *Aim:* V4L2 front/rear camera switcher and zero-trust stream blanker (substitutes pitch-black frames when unauthorized access occurs).
- **`mobile/camera/tuning/`** (2 files | 2,341 B | 80 lines)
  - *Aim:* ISP tuning profiles for Sony IMX and Samsung ISOCELL sensors.

#### 9. Project Treble GSI & Boot Pipeline (`mobile/treble/`, `mobile/fastboot/`, `mobile/avb/`)
- **[build-treble-gsi.sh](file:///home/alpha/android/mobile/treble/build-treble-gsi.sh)** (16,963 B | 460 lines)
  - *Aim:* Assembles the sparse ext4 `system.img` with `/system/bin` daemons, certified `build.prop`, VINTF compatibility matrix, and dm-verity trees.
- **[init.libredroid.rc](file:///home/alpha/android/mobile/treble/init.libredroid.rc)** (2,890 B | 90 lines)
  - *Aim:* Android init boot sequence hooks. Mounts `/dev/binderfs` (`binder`, `hwbinder`, `vndbinder`), links `/vendor`, and launches all native C daemons under capability bounding sets.
- **[prop.default](file:///home/alpha/android/mobile/treble/prop.default)** (1,713 B | 52 lines)
  - *Aim:* Certified system properties and bootloader cloaking flags (`ro.boot.verifiedbootstate=green`, `ro.boot.flash.locked=1`).
- **[flash-mobile-os.sh](file:///home/alpha/android/mobile/fastboot/flash-mobile-os.sh)** (5,620 B | 135 lines)
  - *Aim:* Automated fastboot flashing script with slot validation and non-destructive wiping.
- **[dualboot-slot-switcher.sh](file:///home/alpha/android/mobile/fastboot/dualboot-slot-switcher.sh)** (5,373 B | 136 lines)
  - *Aim:* Non-destructive A/B slot manager allowing side-by-side coexistence of stock Android on slot A and LibreMobile on slot B.
- **[lrd-avb](file:///home/alpha/android/mobile/avb/lrd-avb)** (3,245 B | 86 lines)
  - *Aim:* AVB 2.0 `vbmeta` signing tool and verity flag manipulator.

#### 10. Android App LXC Container (`mobile/waydroid/`)
- **[lrd-arm-bridge](file:///home/alpha/android/mobile/waydroid/lrd-arm-bridge)** (4,150 B | 130 lines)
  - *Aim:* Manages `binfmt_misc` ARM-to-x86_64 translation bridge (Houdini/libndk) inside Waydroid.
- **[pif.json](file:///home/alpha/android/mobile/waydroid/pif.json)**
  - *Aim:* `TRANSITIONAL` legacy fingerprint profile for temporary Play Integrity spoofing. Carries top-level deprecation comment; slated for hard removal by Dec 31, 2027.
- **[lrd-pif-apply](file:///home/alpha/android/mobile/waydroid/lrd-pif-apply)**
  - *Aim:* Transitional shim that injects `pif.json` into container system properties on boot. Outputs deprecation warning to `stderr`, emits append-only ARGUS audit event `pif_applied_transitional=true`, and respects `TALOS_PIF_DISABLE=1` to skip spoofing.
- **[PIF_ROADMAP.md](file:///home/alpha/android/mobile/waydroid/PIF_ROADMAP.md)**
  - *Aim:* Authoritative Play Integrity sunset roadmap with measurable exit criteria and dated migration phases.
- **[lrd-waydroid-freezer](file:///home/alpha/android/mobile/waydroid/lrd-waydroid-freezer)** (6,038 B | 156 lines)
  - *Aim:* cgroup v2 container freezer that halts background Android app drain when the screen is locked.
- **[lrd-waydroid-domain.sh](file:///home/alpha/android/mobile/waydroid/lrd-waydroid-domain.sh)** (6,501 B | 183 lines)
  - *Aim:* Network namespace and veth pairing for Waydroid container isolation.

#### 11. ARGUS Cryptographic Trust Spine (`argus/`)
- **[alibi.py](file:///home/alpha/android/argus/alibi.py)** (8,738 B | 270 lines)
  - *Aim:* Mathematical alibi engine. Validates physical location claims using Great-Circle distance and enforces relativistic speed-of-light velocity bounds ($v \le c$).
- **[compartments.py](file:///home/alpha/android/argus/compartments.py)** (18,641 B | 562 lines)
  - *Aim:* Multi-level security (MLS) compartment governor enforcing Bell-LaPadula mandatory access control.
- **[deadman.py](file:///home/alpha/android/argus/deadman.py)** (5,435 B | 159 lines)
  - *Aim:* Custody fail-safe timer. Automatically triggers secure cryptographic wipe if periodic check-ins fail.
- **[duress.py](file:///home/alpha/android/argus/duress.py)** (11,172 B | 333 lines)
  - *Aim:* Duress defense engine. Recognizes secondary duress PINs, launches a plausible decoy root profile, and securely shreds cryptographic master keys in the background.
- **[vault.py](file:///home/alpha/android/argus/vault.py)** (8,206 B | 223 lines)
  - *Aim:* Content-Addressed Storage (CAS) vault using BLAKE3 chunk hashing and ChaCha20-Poly1305 encryption.
- **[timebase.py](file:///home/alpha/android/argus/timebase.py)** (6,541 B | 221 lines)
  - *Aim:* Monotonic clock and true-time monitor detecting NTP manipulation and time-travel attacks.
- **[tor.py](file:///home/alpha/android/argus/tor.py)** (11,241 B | 289 lines)
  - *Aim:* Tor SOCKS5h controller and circuit isolation engine.
- **`argus/argf2/` (Binary Ledger Producer)** (7 files | 38.3 KB | 988 lines)
  - *Aim:* Produces append-only `ARGF/2` binary ledger files with 128-byte headers, arity-4 Merkle trees, and forward-secret `tag_commit` epoch bridging.
- **`argus/verify/` (Forensic Verification Pipeline)** (7 files | 42.1 KB | 1,061 lines)
  - *Aim:* 9-phase cryptographic verifier validating bundle integrity, hash chaining, Merkle roots, Ed25519 signatures, alibi velocities, and tag digest bindings.

#### 12. Security Hardening & Egress Defense (`security/`)
- **[lrd-egress.nft](file:///home/alpha/android/security/egress/nftables/lrd-egress.nft)** (7,298 B | 155 lines)
  - *Aim:* Hardened `nftables` egress ruleset enforcing deny-by-default, DoT (853), Tor redirection, dynamic blacklist sets (`@egress_blocklist_v4/v6`), and tethering NAT forwarding (`ap0`).
- **`security/egress/policy/*.toml`** (6 files | 2,197 B | 88 lines)
  - *Aim:* Declarative per-application network sandboxing policies (e.g. `com.talos.calculator.toml` strictly forbidding all network egress).
- **[lrd-security-audit](file:///home/alpha/android/security/harden/lrd-security-audit)** (14,053 B | 188 lines)
  - *Aim:* Real-time DAC/MAC permission auditor, rootkit detector, and kernel sysctl sanity checker.
- **[lrd-verity-tool](file:///home/alpha/android/security/harden/lrd-verity-tool)** (3,490 B | 96 lines)
  - *Aim:* Read-only dm-verity integrity checker verifying rootfs blocks against cryptographic root hashes.

#### 13. Halium & GKI Adaptation (`halium/`)
- **[build_halium_boot.py](file:///home/alpha/android/halium/build_halium_boot.py)** (14,923 B | 336 lines)
  - *Aim:* Automated Halium `boot.img` assembler for Android kernels.
- **[unpack_v4.py](file:///home/alpha/android/halium/unpack_v4.py)** & **[repack_v4.py](file:///home/alpha/android/halium/repack_v4.py)** (12,955 B | 358 lines)
  - *Aim:* Unpack and repack Android Boot Image v4 and GKI boot images with custom initramfs overlays.
- **[config-vidofnir.gki](file:///home/alpha/android/halium/config-vidofnir.gki)** (215,700 B | 7,846 lines)
  - *Aim:* Hardened GKI kernel configuration with dm-verity, Landlock LSM, and Treble Binder drivers enabled.

#### 14. Operational Security Scripts (`scripts/`)
- **[repro-build.sh](file:///home/alpha/android/scripts/repro-build.sh)** (4,510 B | 148 lines)
  - *Aim:* Bit-for-bit deterministic compiler and image builder enforcing C prefix mapping, ext4 hash seeding, and tar timestamp pinning.
- **[repro-attest.sh](file:///home/alpha/android/scripts/repro-attest.sh)** (3,820 B | 102 lines)
  - *Aim:* Dual-build attestation generator that builds across isolated paths, diffs artifacts, and publishes machine-verifiable attestation JSON.
- **[setup-luks-vault.sh](file:///home/alpha/android/scripts/setup-luks-vault.sh)** (5,353 B | 132 lines)
  - *Aim:* Provisions TPM 2.0 / KeyMint hardware-backed LUKS2 encrypted storage partitions.
- **[security_bootstrap.sh](file:///home/alpha/android/scripts/security_bootstrap.sh)** (4,618 B | 116 lines)
  - *Aim:* Boot-time security initialization: loads seccomp filters, mounts read-only sysfs, arms nftables.
- **[enroll_duress.py](file:///home/alpha/android/scripts/enroll_duress.py)** (1,452 B | 52 lines)
  - *Aim:* Enrolls secondary duress PINs and panic wipe triggers.
- **[package-libremobile-release.sh](file:///home/alpha/android/scripts/package-libremobile-release.sh)** (4,501 B | 115 lines)
  - *Aim:* Assembles flashable release bundles with SHA256 checksums, dm-verity tables, and fastboot scripts.

#### 15. Automated Verification Test Harnesses (`mobile/test/` & `tests/`)
- **[run-all-tests.sh](file:///home/alpha/android/mobile/test/run-all-tests.sh)** (1,685 B | 48 lines)
  - *Aim:* Master mobile runner executing all 8 subsystem verification test suites (85 tests total).
- **Subsystem Test Suites:**
  - `test-telephony.sh` (146 lines | 10 tests | VoLTE, SIM PIN, SMS)
  - `test-bluetooth.sh` (149 lines | 11 tests | BlueZ, BLE MAC privacy, A2DP)
  - `test-wifi.sh` (164 lines | 12 tests | WPA3, Hotspot AP tethering, DHCP)
  - `test-firewall.sh` (197 lines | 14 tests | Deny-by-default, killswitch, panic)
  - `test-sensors.sh` (162 lines | 13 tests | IIO, orientation, ear blanking)
  - `test-power.sh` (145 lines | 10 tests | Wakelocks, S2Idle sleep, 80% cap)
  - `test-osk.sh` (114 lines | 7 tests | Wayland layer-shell touch OSK)
  - `test-arm-translation.sh` (90 lines | 8 tests | ARM bridge, PIF spoofing)
- **ARGUS Cryptographic Test Suites (`tests/`)**:
  - `test_tamper.py` (5 tests | header corruption, tail truncation, scope omissions)
  - `test_tags.py` (10 tests | `tag_commit` epoch bridging, digest binding)
  - `test_producers.py`, `test_ledger.py`, `test_degraded.py` (29 tests | ring buffers, recovery, sealing)
  - `test_roundtrip.py`, `test_range.py`, `test_multiboot.py`, `test_grade.py` (e2e integrity)

#### 16. Continuous Fuzzing & Security Policy (`fuzz/` & `SECURITY.md`)
- **[SECURITY.md](file:///home/alpha/android/SECURITY.md)**
  - *Aim:* Authoritative security policy establishing a 90-day Coordinated Vulnerability Disclosure (CVD) window, anti-hacking legal Safe Harbor clause, in-scope/out-of-scope taxonomy, and bug bounty reward tiers ($100 to $10,000 USD).
- **[FUZZ-STATUS.md](file:///home/alpha/android/audit/FUZZ-STATUS.md)**
  - *Aim:* Continuous fuzzing coverage matrix, throughput benchmarks, and threat models across all 5 parser surfaces.
- **`fuzz/` libFuzzer Harnesses & Corpora:**
  - `fuzz/fuzz_telephony_ril.c`: GSM 03.40 SMS PDU decoder and Hayes AT / RIL unsolicited response parser (~419k exec/s).
  - `fuzz/fuzz_nft_policy.c`: TOML egress firewall policy parser (~264k exec/s).
  - `fuzz/fuzz_argf2.c`: ARGF/2 binary ledger header & record parser (~3.2M exec/s).
  - `fuzz/fuzz_pif_json.c`: Waydroid Play Integrity JSON parser (~85k exec/s).
  - `fuzz/fuzz_battery_sysfs.c`: Linux power_supply sysfs attribute & uevent parser (~432k exec/s).
  - `fuzz/standalone_driver.c`: Standalone PRNG mutation engine allowing ASAN+UBSAN compilation under GCC.
  - `fuzz/oss-fuzz/`: Google OSS-Fuzz integration files (`project.yaml`, `build.sh`).



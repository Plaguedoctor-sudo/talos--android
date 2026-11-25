# TALOS Cellular Telephony Capability & Hardware Support Matrix

<!--
SPDX-FileCopyrightText: 2026 TALOS / LibreMobile OS Contributors
SPDX-License-Identifier: CC-BY-SA-4.0
-->

> **Notice:** This document replaces generalized 5G/VoLTE overclaims with an honest, machine-readable, per-device capability matrix. Telephony capabilities (especially VoLTE, VoNR, and eSIM) are heavily contingent on modem hardware, baseband firmware provenance, and carrier-specific IMS configuration.

---

## 1. Per-Device Telephony Capabilities

| Vendor & Model | Modem Hardware | Firmware Provenance | Data | Voice | SMS | MMS | VoLTE | VoNR (5G Voice) | eSIM | Emergency (911) |
| :--- | :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **PINE64 PinePhone** | Quectel EG25-G | `proprietary_signed` | ✔ Supported | ✔ Supported | ✔ Supported | ⚠️ Experimental | ⚠️ Experimental | ✖ Unsupported | ✖ Unsupported | ✔ Supported |
| **PINE64 PinePhone Pro** | Quectel EG25-G | `proprietary_signed` | ✔ Supported | ✔ Supported | ✔ Supported | ⚠️ Experimental | ⚠️ Experimental | ✖ Unsupported | ✖ Unsupported | ✔ Supported |
| **Purism Librem 5** | Broadmobi BM818 | `proprietary_signed` | ✔ Supported | ✔ Supported | ✔ Supported | ⚠️ Experimental | ⚠️ Experimental | ✖ Unsupported | ✖ Unsupported | ✔ Supported |
| **Volla Volla Phone 22** | MediaTek Helio G85 Baseband | `proprietary_signed` | ✔ Supported | ✔ Supported | ✔ Supported | ⚠️ Experimental | ⚠️ Experimental | ✖ Unsupported | ✖ Unsupported | ✔ Supported |
| **Google Pixel 6** | Shannon 5123 | `proprietary_signed` | ✔ Supported | ✔ Supported | ✔ Supported | ✔ Supported | ✔ Supported | ⚠️ Experimental | ✔ Supported | ✔ Supported |
| **Fairphone Fairphone 4 5G** | Snapdragon X51 5G | `proprietary_signed` | ✔ Supported | ✔ Supported | ✔ Supported | ✔ Supported | ✔ Supported | ⚠️ Experimental | ✔ Supported | ✔ Supported |
| **Xiaomi POCO F3** | Snapdragon X55 5G | `proprietary_signed` | ✔ Supported | ✔ Supported | ✔ Supported | ⚠️ Experimental | ✔ Supported | ⚠️ Experimental | ✖ Unsupported | ✔ Supported |
| **Purism Librem 5 v2 (RISC-V)** | Roadmap Evaluation Baseband | `community_opensource_eval` | ❓ Untested | ❓ Untested | ❓ Untested | ❓ Untested | ⚠️ Experimental | ⚠️ Experimental | ❓ Untested | ❓ Untested |

---

## 2. Experimental Capabilities & Verification Rules

- **VoLTE (Voice over LTE):** Marked as `⚠️ Experimental` across native Linux phones (PinePhone, Librem 5) and GSI targets until carrier-specific IMS profiles are verified. Only devices with tested, certified carrier configuration profiles (e.g. Pixel 6, Fairphone 4 5G) may be graded as `✔ Supported`.
- **VoNR (Voice over New Radio / 5G Voice):** Globally marked as `⚠️ Experimental` or `✖ Unsupported`. Commercial telecom carriers currently utilize EPS fallback (switching to LTE for voice calls) rather than pure 5G Standalone (SA) IMS voice slicing.
- **eSIM (Embedded SIM):** Requires physical eUICC silicon and an open Local Profile Assistant (LPA). Marked as `⚠️ Experimental` or `✖ Unsupported` on devices lacking open LPA stacks.
- **MMS (Multimedia Messaging Service):** Requires carrier APN routing and mobile data activation via `mmsd-tng`; currently experimental across all Linux devices.

---

## 3. Known Limitations & Carrier Certification Realities

### A. The VoLTE Carrier Certification Wall
Legacy 2G and 3G circuit-switched networks have been shut down across North America, East Asia, and large parts of Europe. Voice calls now require IMS (IP Multimedia Subsystem) over LTE (VoLTE). Carriers (such as AT&T, Verizon, T-Mobile, NTT Docomo) enforce strict IMEI whitelisting and proprietary carrier configuration bundles (`apns-conf.xml`, `mbn` blobs). Without carrier certification, devices may drop voice calls entirely even when LTE data functions normally.

### B. eSIM Provisioning Applet Limitations
While physical nanoSIM cards operate across all evaluated devices, eSIM provisioning requires an SGP.22 compliant Local Profile Assistant (LPA) communicating with remote SM-DP+ (Subscription Manager Data Preparation) servers over TLS. TALOS does not include proprietary Google Play Services LPA shims; native Linux LPA integration is experimental.

### C. Emergency Calling (E911 / 112 / 999) Fallbacks
When emergency numbers (911, 112, 999, 000, 110, 119) are dialed, `lrd-telephonyd` enforces high-priority execution, preempting any locked SIM restrictions. However, if circuit-switched 2G/3G networks are offline in your area and VoLTE emergency registration is uncertified by the local tower, emergency calls may fail. **Operators in mission-critical environments must verify emergency calling on their specific carrier.**

---

## 4. Runtime Capability Probe

TALOS includes an automated hardware modem capability probe in `lrd-telephonyd`:

```bash
# Probe modem hardware capabilities via AT/QMI/RIL and emit schema-validated JSON
lrd-telephonyd --caps

# Query runtime capabilities from the active telephony daemon via CLI
lrd-telephony caps
```

Output is written to `/run/libredroid/telephony.caps.json` (or `/tmp/libredroid/telephony.caps.json`) and validated against `mobile/telephony/schema.json`.

---

## 5. Device Notes & Firmware Details

### PINE64 PinePhone
- **Modem Model:** Quectel EG25-G
- **Firmware Status:** `proprietary_signed`
- **Notes:** USB-isolated LTE Cat 4 modem. VoLTE requires manual IMS profile activation. Alternative open-qti-eg25 community firmware available.

### PINE64 PinePhone Pro
- **Modem Model:** Quectel EG25-G
- **Firmware Status:** `proprietary_signed`
- **Notes:** USB-isolated LTE Cat 4 modem. VoLTE experimental; SMS and circuit-switched fallback/ALSA audio verified.

### Purism Librem 5
- **Modem Model:** Broadmobi BM818
- **Firmware Status:** `proprietary_signed`
- **Notes:** Removable M.2 key-B card with physical hardware kill-switch. Carrier-specific VoLTE profiles experimental.

### Volla Volla Phone 22
- **Modem Model:** MediaTek Helio G85 Baseband
- **Firmware Status:** `proprietary_signed`
- **Notes:** Waydroid reference test device running Halium RIL bridge. VoLTE requires vendor IMS RIL daemon.

### Google Pixel 6
- **Modem Model:** Shannon 5123
- **Firmware Status:** `proprietary_signed`
- **Notes:** 5G Sub-6/mmWave modem via Halium RIL bridge. VoLTE certified on major carriers; 5G Standalone (VoNR) experimental.

### Fairphone Fairphone 4 5G
- **Modem Model:** Snapdragon X51 5G
- **Firmware Status:** `proprietary_signed`
- **Notes:** Qualcomm 5G baseband with dual-SIM (physical nanoSIM + eSIM). VoLTE fully supported; VoNR experimental.

### Xiaomi POCO F3
- **Modem Model:** Snapdragon X55 5G
- **Firmware Status:** `proprietary_signed`
- **Notes:** Qualcomm Snapdragon 870 / X55 modem running generic Treble GSI. VoLTE supported; dual nanoSIM without eSIM.

### Purism Librem 5 v2 (RISC-V)
- **Modem Model:** Roadmap Evaluation Baseband
- **Firmware Status:** `community_opensource_eval`
- **Notes:** Forward-looking architectural roadmap target on open RISC-V mobile silicon. All cellular stacks in pre-silicon evaluation.


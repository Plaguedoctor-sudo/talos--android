# TALOS Hardware Certification Matrix

<!--
SPDX-FileCopyrightText: 2026 TALOS / LibreMobile OS Contributors
SPDX-License-Identifier: GPL-3.0-or-later
-->

> **Matrix Version:** 1.0.0  
> **Specification:** [hardware/schema.json](file:///home/alpha/android/hardware/schema.json)  
> **Machine-Readable Source:** [hardware/matrix.yaml](file:///home/alpha/android/hardware/matrix.yaml)  
> **Governance:** Sovereign Commons Anti-Monopoly Policy ([GOVERNANCE.md](file:///home/alpha/android/GOVERNANCE.md))

---

## 1. Tier Definitions & Certification Criteria

TALOS / LibreMobile OS rejects overbroad marketing claims such as "fully open" or "100% free" on hardware where binary blobs exist. Hardware support is classified into four explicit, verifiable tiers:

- **Tier A (Fully Free):**
  - **Zero proprietary firmware** in any active subsystem (SoC bootrom, CPU microcode, GPU, cellular modem DSP, Wi-Fi/Bluetooth, and camera ISP).
  - 100% auditable open-source userspace and kernel drivers.
  - Hardware schematics and component datasheets published under open licenses.
  - *Current Status:* No commercial smartphone currently meets Tier A standards due to cellular baseband and Wi-Fi PHY firmware constraints.

- **Tier B (Blob-Reduced):**
  - Native GNU/Linux userspace running on mainline Linux kernels.
  - Proprietary blobs remain **only** where community reverse-engineering (e.g., Librephone) has not yet replaced them.
  - Physical hardware kill-switches or hardware-isolated USB/PCIe buses isolate proprietary basebands from system memory.
  - Every non-free binary is explicitly inventoried in the device matrix.

- **Tier C (Treble-Compatible — Sovereign Userspace, Non-Free Firmware):**
  - Runs the sovereign TALOS GNU/Linux userspace, defense-grade firewall, and ARGUS custody spine.
  - Preserves manufacturer Board Support Packages (BSPs), vendor drivers (`/vendor`), and firmware blobs via Project Treble Generic System Image (GSI) interfaces.
  - Labeled honestly as **"Sovereign userspace, non-free firmware."**

- **Roadmap:**
  - Target architectures (e.g. RISC-V mobile silicon, open basebands) under active evaluation or co-development.

---

## 2. Hardware Matrix Summary

| Tier | Vendor | Model | SoC Architecture | Boot Unlock | Relock (AVB) | Treble GSI | Kill-Switches | Blob Count |
| :--- | :--- | :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| **Tier B** | PINE64 | PinePhone | Allwinner A64 | ✔ Yes | ✖ No | — Native | ✔ Hardware | 2 blobs |
| **Tier B** | PINE64 | PinePhone Pro | Rockchip RK3399S | ✔ Yes | ✖ No | — Native | ✔ Hardware | 2 blobs |
| **Tier B** | Purism | Librem 5 | NXP i.MX 8M Quad | ✔ Yes | ✖ No | — Native | ✔ Hardware | 3 blobs |
| **Tier C** | Fairphone | Fairphone 4 5G | Qualcomm Snapdragon 750G | ✔ Yes | ✔ Yes | ✔ Yes | ✖ None | 4 blobs |
| **Tier C** | Google | Pixel 6 | Google Tensor | ✔ Yes | ✔ Yes | ✔ Yes | ✖ None | 5 blobs |
| **Tier C** | Volla | Volla Phone 22 | MediaTek Helio G85 | ✔ Yes | ✖ No | ✔ Yes | ✖ None | 4 blobs |
| **Tier C** | Xiaomi | POCO F3 / Redmi K40 | Qualcomm Snapdragon 870 | ✔ Yes | ✖ No | ✔ Yes | ✖ None | 4 blobs |
| **Roadmap** | Purism | Librem 5 v2 (RISC-V) | TODO | ✔ Yes | ✖ No | — Native | ✔ Hardware | 2 blobs |

---

## 3. Subsystem Firmware Provenance & Blob Inventories

### Tier B Devices

#### PINE64 PinePhone

- **System on Chip (SoC):** `Allwinner A64 (Quad-core ARM Cortex-A53)`
- **Support Tier:** `Tier B`
- **Treble Compatible:** `No (Direct Mainline Kernel)`
- **Bootloader:** Unlockable: `Yes` | Verified Boot Relockable: `No`
- **Physical Hardware Kill-Switches:** Microphone, Camera, Cellular / Wi-Fi / BT Radios
- **Cellular Modem:** `Quectel EG25-G (LTE Cat-4)`

**Firmware Audit Status:**

| Subsystem | Firmware Status | Description / Driver |
| :--- | :--- | :--- |
| **Modem Baseband** | `replaced` | `Quectel EG25-G (LTE Cat-4)` |
| **Wi-Fi & Bluetooth** | `proprietary_signed` | RF controller firmware |
| **GPU / Display** | `free` | Graphics acceleration userspace |
| **Camera ISP** | `free` | Image signal processor pipeline |

**Proprietary Binary Blob Inventory:**

| Component | License | Source / Partition | Replaceable by Librephone |
| :--- | :--- | :--- | :---: |
| Realtek RTL8723CS Wi-Fi/Bluetooth Firmware | Proprietary Realtek | `linux-firmware / rtl_bt/rtl8723cs_xx.bin` | ✔ Candidate |
| Quectel EG25-G Hexagon DSP Baseband Blob | Proprietary Qualcomm Hexagon | `Quectel Stock Firmware (isolated via USB)` | ✖ Silicon Locked |

> **Operator Notes:** Hardware DIP kill-switches on rear chassis. Runs mainline Linux kernel with open-source Lima GPU driver. Modem userspace replaced with Biktor open-source firmware, though isolated Hexagon DSP blob remains.

---

#### PINE64 PinePhone Pro

- **System on Chip (SoC):** `Rockchip RK3399S (Hexa-core 2x A72 + 4x A53)`
- **Support Tier:** `Tier B`
- **Treble Compatible:** `No (Direct Mainline Kernel)`
- **Bootloader:** Unlockable: `Yes` | Verified Boot Relockable: `No`
- **Physical Hardware Kill-Switches:** Microphone, Camera, Cellular / Wi-Fi / BT Radios
- **Cellular Modem:** `Quectel EG25-G (LTE Cat-4)`

**Firmware Audit Status:**

| Subsystem | Firmware Status | Description / Driver |
| :--- | :--- | :--- |
| **Modem Baseband** | `replaced` | `Quectel EG25-G (LTE Cat-4)` |
| **Wi-Fi & Bluetooth** | `proprietary_signed` | RF controller firmware |
| **GPU / Display** | `free` | Graphics acceleration userspace |
| **Camera ISP** | `free` | Image signal processor pipeline |

**Proprietary Binary Blob Inventory:**

| Component | License | Source / Partition | Replaceable by Librephone |
| :--- | :--- | :--- | :---: |
| Broadcom/Cypress BCM43455 Wi-Fi/BT Firmware | Proprietary Cypress | `linux-firmware / brcm/brcmfmac43455-sdio.bin` | ✔ Candidate |
| Quectel EG25-G Hexagon DSP Baseband Blob | Proprietary Qualcomm Hexagon | `Quectel Stock Firmware (isolated via USB)` | ✖ Silicon Locked |

> **Operator Notes:** Mainline Linux kernel with open Panfrost Mali-T860 GPU driver and rkisp1 camera pipeline. Hardware kill switches for modem, Wi-Fi, mic, and cameras.

---

#### Purism Librem 5

- **System on Chip (SoC):** `NXP i.MX 8M Quad (Quad-core ARM Cortex-A53)`
- **Support Tier:** `Tier B`
- **Treble Compatible:** `No (Direct Mainline Kernel)`
- **Bootloader:** Unlockable: `Yes` | Verified Boot Relockable: `No`
- **Physical Hardware Kill-Switches:** Microphone, Camera, Cellular / Wi-Fi / BT Radios
- **Cellular Modem:** `Broadmobi BM818 / Gemalto PLS8-E (M.2 card over USB)`

**Firmware Audit Status:**

| Subsystem | Firmware Status | Description / Driver |
| :--- | :--- | :--- |
| **Modem Baseband** | `proprietary_signed` | `Broadmobi BM818 / Gemalto PLS8-E (M.2 card over USB)` |
| **Wi-Fi & Bluetooth** | `proprietary_signed` | RF controller firmware |
| **GPU / Display** | `free` | Graphics acceleration userspace |
| **Camera ISP** | `free` | Image signal processor pipeline |

**Proprietary Binary Blob Inventory:**

| Component | License | Source / Partition | Replaceable by Librephone |
| :--- | :--- | :--- | :---: |
| Redpine Signals RS9116 / SparkLAN Wi-Fi/BT Firmware | Proprietary Redpine Signals | `linux-firmware / rsi_91x.fw` | ✔ Candidate |
| Broadmobi BM818 / Gemalto PLS8 Baseband Firmware | Proprietary Qualcomm/Gemalto | `M.2 Modem Module (isolated via USB)` | ✖ Silicon Locked |
| NXP DDR PHY Memory Training Firmware | Proprietary NXP | `imx-atf / ddr-phy` | ✖ Silicon Locked |

> **Operator Notes:** Hardware slide switches for Cellular, Wi-Fi/Bluetooth, and Camera/Microphone. Free Etnaviv GPU userspace driver. All cellular traffic physically isolated on USB.

---

### Tier C Devices

#### Fairphone Fairphone 4 5G

- **System on Chip (SoC):** `Qualcomm Snapdragon 750G (SM7225)`
- **Support Tier:** `Tier C`
- **Treble Compatible:** `Yes (system.img replacement)`
- **Bootloader:** Unlockable: `Yes` | Verified Boot Relockable: `Yes`
- **Physical Hardware Kill-Switches:** None (Software isolation only)
- **Cellular Modem:** `Qualcomm Snapdragon X52 5G Baseband`

**Firmware Audit Status:**

| Subsystem | Firmware Status | Description / Driver |
| :--- | :--- | :--- |
| **Modem Baseband** | `proprietary_signed` | `Qualcomm Snapdragon X52 5G Baseband` |
| **Wi-Fi & Bluetooth** | `proprietary_signed` | RF controller firmware |
| **GPU / Display** | `proprietary_signed` | Graphics acceleration userspace |
| **Camera ISP** | `proprietary_signed` | Image signal processor pipeline |

**Proprietary Binary Blob Inventory:**

| Component | License | Source / Partition | Replaceable by Librephone |
| :--- | :--- | :--- | :---: |
| Qualcomm Hexagon DSP Modem Firmware | Proprietary Qualcomm | `modem / NON-HLOS.bin` | ✖ Silicon Locked |
| Qualcomm WCN3998 Wi-Fi/Bluetooth Firmware | Proprietary Qualcomm | `vendor/firmware/wlan/qca_cld/wlan.ko` | ✖ Silicon Locked |
| Adreno 619 Proprietary GPU Driver | Proprietary Qualcomm | `vendor/lib64/egl/libGLESv2_adreno.so` | ✔ Candidate |
| Qualcomm Spectra 355L ISP Tuning | Proprietary Qualcomm | `vendor/lib64/camera/com.qti.sensor.imx582.so` | ✖ Silicon Locked |

> **Operator Notes:** Modular repairable chassis. Supports AVB verified boot relocking with custom user signing keys. Runs TALOS userspace over Treble AOSP HALs.

---

#### Google Pixel 6

- **System on Chip (SoC):** `Google Tensor (GS101)`
- **Support Tier:** `Tier C`
- **Treble Compatible:** `Yes (system.img replacement)`
- **Bootloader:** Unlockable: `Yes` | Verified Boot Relockable: `Yes`
- **Physical Hardware Kill-Switches:** None (Software isolation only)
- **Cellular Modem:** `Samsung Shannon 5123 5G Baseband`

**Firmware Audit Status:**

| Subsystem | Firmware Status | Description / Driver |
| :--- | :--- | :--- |
| **Modem Baseband** | `proprietary_signed` | `Samsung Shannon 5123 5G Baseband` |
| **Wi-Fi & Bluetooth** | `proprietary_signed` | RF controller firmware |
| **GPU / Display** | `proprietary_signed` | Graphics acceleration userspace |
| **Camera ISP** | `proprietary_signed` | Image signal processor pipeline |

**Proprietary Binary Blob Inventory:**

| Component | License | Source / Partition | Replaceable by Librephone |
| :--- | :--- | :--- | :---: |
| Samsung Shannon 5123 5G Modem Firmware | Proprietary Samsung | `modem.img / vendor/firmware` | ✖ Silicon Locked |
| Broadcom BCM4389 Wi-Fi 6E / BT 5.2 Firmware | Proprietary Broadcom | `vendor/firmware/bcm4389.bin` | ✖ Silicon Locked |
| Mali-G78 MP20 Userspace Graphics Driver | Proprietary ARM | `vendor/lib64/egl/libGLES_mali.so` | ✖ Silicon Locked |
| Google TPU / EdgeTPU Camera Neural Accelerator | Proprietary Google Signed | `vendor/lib64/libedgetpu.so` | ✖ Silicon Locked |
| Titan M2 (Dauntless) Security Core Firmware | Proprietary Google Signed | `TODO(operator): Verify Google OpenTitan derivation vs proprietary build` | ✖ Silicon Locked |

> **Operator Notes:** Supports custom AVB 2.0 root-of-trust relocking via fastboot flash avb_custom_key. Runs generic ARM64 Treble system image over Google Tensor GKI kernel.

---

#### Volla Volla Phone 22

- **System on Chip (SoC):** `MediaTek Helio G85 (MT6769V/CZ)`
- **Support Tier:** `Tier C`
- **Treble Compatible:** `Yes (system.img replacement)`
- **Bootloader:** Unlockable: `Yes` | Verified Boot Relockable: `No`
- **Physical Hardware Kill-Switches:** None (Software isolation only)
- **Cellular Modem:** `MediaTek Integrated 4G LTE Baseband`

**Firmware Audit Status:**

| Subsystem | Firmware Status | Description / Driver |
| :--- | :--- | :--- |
| **Modem Baseband** | `proprietary_signed` | `MediaTek Integrated 4G LTE Baseband` |
| **Wi-Fi & Bluetooth** | `proprietary_signed` | RF controller firmware |
| **GPU / Display** | `proprietary_signed` | Graphics acceleration userspace |
| **Camera ISP** | `proprietary_signed` | Image signal processor pipeline |

**Proprietary Binary Blob Inventory:**

| Component | License | Source / Partition | Replaceable by Librephone |
| :--- | :--- | :--- | :---: |
| MediaTek Cellular Modem Firmware | Proprietary MediaTek | `vendor/firmware/md1img.img` | ✖ Silicon Locked |
| MediaTek Wi-Fi/BT Firmware (Consys) | Proprietary MediaTek | `vendor/firmware/WIFI_RAM_CODE_MT6769` | ✖ Silicon Locked |
| ARM Mali-G52 2EEMC2 GPU Drivers | Proprietary ARM | `vendor/lib64/egl/libGLES_mali.so` | ✖ Silicon Locked |
| MediaTek Camera ISP HAL | Proprietary MediaTek | `vendor/lib64/hw/camera.mt6769.so` | ✖ Silicon Locked |

> **Operator Notes:** Waydroid-capable reference device. Runs TALOS ARM64 system.img over Treble HALs with isolated Waydroid LXC container for Android compatibility.

---

#### Xiaomi POCO F3 / Redmi K40

- **System on Chip (SoC):** `Qualcomm Snapdragon 870 (SM8250-AC)`
- **Support Tier:** `Tier C`
- **Treble Compatible:** `Yes (system.img replacement)`
- **Bootloader:** Unlockable: `Yes` | Verified Boot Relockable: `No`
- **Physical Hardware Kill-Switches:** None (Software isolation only)
- **Cellular Modem:** `Qualcomm Snapdragon X55 5G Modem-RF`

**Firmware Audit Status:**

| Subsystem | Firmware Status | Description / Driver |
| :--- | :--- | :--- |
| **Modem Baseband** | `proprietary_signed` | `Qualcomm Snapdragon X55 5G Modem-RF` |
| **Wi-Fi & Bluetooth** | `proprietary_signed` | RF controller firmware |
| **GPU / Display** | `proprietary_signed` | Graphics acceleration userspace |
| **Camera ISP** | `proprietary_signed` | Image signal processor pipeline |

**Proprietary Binary Blob Inventory:**

| Component | License | Source / Partition | Replaceable by Librephone |
| :--- | :--- | :--- | :---: |
| Qualcomm Hexagon DSP Baseband Firmware | Proprietary Qualcomm | `modem.img / NON-HLOS.bin` | ✖ Silicon Locked |
| Qualcomm FastConnect 6800 Wi-Fi 6 / BT Firmware | Proprietary Qualcomm | `vendor/firmware/qca6800` | ✖ Silicon Locked |
| Adreno 650 Proprietary GPU Driver | Proprietary Qualcomm | `vendor/lib64/egl/libGLESv2_adreno.so` | ✔ Candidate |
| Spectra 480 Image Signal Processor Tuning | Proprietary Qualcomm | `vendor/lib64/camera/com.qti.sensor.imx582.so` | ✖ Silicon Locked |

> **Operator Notes:** High-performance Treble reference target. Runs TALOS generic system image over Qualcomm BSP. Freedreno open-source GPU userspace can optionally replace Adreno blob on mainline kernels.

---

### Roadmap Devices

#### Purism Librem 5 v2 (RISC-V)

- **System on Chip (SoC):** `TODO(operator): Target RISC-V 64-bit Mobile SoC (e.g. StarFive JH7110 or T-Head derivative)`
- **Support Tier:** `Roadmap`
- **Treble Compatible:** `No (Direct Mainline Kernel)`
- **Bootloader:** Unlockable: `Yes` | Verified Boot Relockable: `No`
- **Physical Hardware Kill-Switches:** Microphone, Camera, Cellular / Wi-Fi / BT Radios
- **Cellular Modem:** `TODO(operator): Modular M.2 Open-Firmware Modem candidate`

**Firmware Audit Status:**

| Subsystem | Firmware Status | Description / Driver |
| :--- | :--- | :--- |
| **Modem Baseband** | `replaced` | `TODO(operator): Modular M.2 Open-Firmware Modem candidate` |
| **Wi-Fi & Bluetooth** | `replaced` | RF controller firmware |
| **GPU / Display** | `free` | Graphics acceleration userspace |
| **Camera ISP** | `free` | Image signal processor pipeline |

**Proprietary Binary Blob Inventory:**

| Component | License | Source / Partition | Replaceable by Librephone |
| :--- | :--- | :--- | :---: |
| TODO(operator): Target Open-Silicon Baseband DSP or COTS M.2 Module | TODO(operator): Pending hardware partner evaluation | `TODO(operator): Upstream vendor specification` | ✔ Candidate |
| TODO(operator): Open SBI / U-Boot SPL bootloader payload | BSD-2-Clause / GPL-2.0-or-later | `TODO(operator): Upstream RISC-V firmware repository` | ✔ Candidate |

> **Operator Notes:** Roadmap hardware platform exploring RISC-V RV64GC cores with fully open bootROM and physical hardware kill switches.

---

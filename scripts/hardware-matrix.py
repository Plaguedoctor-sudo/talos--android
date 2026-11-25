#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 TALOS / LibreMobile OS Contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""TALOS Hardware Certification Matrix Validator & Deterministic Markdown Renderer.

Validates hardware/matrix.yaml against hardware/schema.json and tier consistency rules.
Generates an idempotent, human-readable HARDWARE.md certification matrix.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
DEFAULT_SCHEMA_PATH = REPO_ROOT / "hardware" / "schema.json"
DEFAULT_MATRIX_PATH = REPO_ROOT / "hardware" / "matrix.yaml"
DEFAULT_OUTPUT_PATH = REPO_ROOT / "HARDWARE.md"

VALID_FIRMWARE_STATUSES = {"free", "proprietary_signed", "proprietary_unsigned", "replaced"}
VALID_SUPPORT_LEVELS = {"Tier A", "Tier B", "Tier C", "Roadmap"}


def load_yaml(file_path: Path) -> Dict[str, Any]:
    """Load YAML data with standard library fallback if PyYAML is not present."""
    try:
        import yaml  # type: ignore
        with open(file_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
            if not isinstance(data, dict):
                raise ValueError(f"Root YAML element must be a dictionary, got {type(data).__name__}")
            return data
    except ImportError:
        # Minimal robust pure-stdlib YAML subset parser for matrix.yaml structure
        return _fallback_parse_yaml(file_path)


def _fallback_parse_yaml(file_path: Path) -> Dict[str, Any]:
    """Parse the structured subset of YAML used in hardware/matrix.yaml using Python stdlib."""
    with open(file_path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    result: Dict[str, Any] = {"devices": []}
    current_device: Optional[Dict[str, Any]] = None
    current_blob: Optional[Dict[str, Any]] = None
    in_kill_switches = False
    in_blob_inventory = False

    for raw_line in lines:
        line = raw_line.rstrip()
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        indent = len(line) - len(line.lstrip())

        if stripped.startswith("version:"):
            val = stripped.split(":", 1)[1].strip().strip('"\'')
            result["version"] = val
            continue

        if stripped == "devices:":
            continue

        if stripped.startswith("- vendor:"):
            in_kill_switches = False
            in_blob_inventory = False
            current_blob = None
            current_device = {}
            val = stripped.split(":", 1)[1].strip().strip('"\'')
            current_device["vendor"] = val
            result["devices"].append(current_device)
            continue

        if current_device is None:
            continue

        if stripped.startswith("kill_switches:"):
            in_kill_switches = True
            in_blob_inventory = False
            current_device["kill_switches"] = {}
            continue

        if in_kill_switches:
            if indent >= 6 and ":" in stripped:
                k, v = [x.strip() for x in stripped.split(":", 1)]
                current_device["kill_switches"][k] = (v.lower() == "true")
                continue
            else:
                in_kill_switches = False

        if stripped.startswith("blob_inventory:"):
            in_blob_inventory = True
            in_kill_switches = False
            current_device["blob_inventory"] = []
            continue

        if in_blob_inventory:
            if stripped.startswith("- component:"):
                current_blob = {}
                val = stripped.split(":", 1)[1].strip().strip('"\'')
                current_blob["component"] = val
                current_device["blob_inventory"].append(current_blob)
                continue
            elif current_blob is not None and indent >= 8 and ":" in stripped:
                k, v = [x.strip() for x in stripped.split(":", 1)]
                v_clean = v.strip('"\'')
                if k == "verified":
                    current_blob[k] = (v_clean.lower() == "true")
                elif k == "replaceable_by_librephone":
                    if v_clean.lower() == "true":
                        current_blob[k] = True
                    elif v_clean.lower() == "false":
                        current_blob[k] = False
                    else:
                        current_blob[k] = v_clean
                else:
                    current_blob[k] = v_clean
                continue
            elif indent < 6:
                in_blob_inventory = False
                current_blob = None

        if ":" in stripped:
            k, v = [x.strip() for x in stripped.split(":", 1)]
            v_clean = v.strip('"\'')
            if v_clean.lower() == "true":
                current_device[k] = True
            elif v_clean.lower() == "false":
                current_device[k] = False
            else:
                current_device[k] = v_clean

    return result


def validate_matrix(data: Dict[str, Any], schema: Dict[str, Any]) -> List[str]:
    """Validate matrix against JSON Schema and explicit Tier consistency rules."""
    errors: List[str] = []

    # Optional jsonschema library validation if present
    try:
        import jsonschema  # type: ignore
        validator = jsonschema.Draft202012Validator(schema)
        for err in validator.iter_errors(data):
            path = ".".join(str(p) for p in err.path) or "root"
            errors.append(f"JSON Schema error at {path}: {err.message}")
    except ImportError:
        pass

    # Core stdlib validation
    if not isinstance(data.get("version"), str):
        errors.append("Matrix missing string 'version' field.")

    devices = data.get("devices")
    if not isinstance(devices, list) or len(devices) == 0:
        errors.append("Matrix must contain a non-empty 'devices' array.")
        return errors

    req_fields = [
        "vendor", "model", "soc", "bootloader_unlock", "bootloader_relock",
        "kill_switches", "modem", "modem_firmware_status", "wifi_bt_firmware_status",
        "gpu_firmware_status", "camera_firmware_status", "blob_inventory",
        "treble_compatible", "talos_support_level"
    ]

    for idx, dev in enumerate(devices):
        dev_label = f"Device #{idx + 1} ({dev.get('vendor', 'Unknown')} {dev.get('model', 'Unknown')})"

        # Check required fields
        for field in req_fields:
            if field not in dev:
                errors.append(f"{dev_label}: missing required field '{field}'.")

        # Type checks
        if not isinstance(dev.get("bootloader_unlock"), bool):
            errors.append(f"{dev_label}: 'bootloader_unlock' must be a boolean.")
        if not isinstance(dev.get("bootloader_relock"), bool):
            errors.append(f"{dev_label}: 'bootloader_relock' must be a boolean.")
        if not isinstance(dev.get("treble_compatible"), bool):
            errors.append(f"{dev_label}: 'treble_compatible' must be a boolean.")

        ks = dev.get("kill_switches")
        if not isinstance(ks, dict):
            errors.append(f"{dev_label}: 'kill_switches' must be an object with mic, camera, radio booleans.")
        else:
            for k in ["mic", "camera", "radio"]:
                if not isinstance(ks.get(k), bool):
                    errors.append(f"{dev_label}: 'kill_switches.{k}' must be a boolean.")

        # Enum checks
        for fw_key in ["modem_firmware_status", "wifi_bt_firmware_status", "gpu_firmware_status", "camera_firmware_status"]:
            status = dev.get(fw_key)
            if status not in VALID_FIRMWARE_STATUSES:
                errors.append(f"{dev_label}: invalid '{fw_key}' value '{status}'. Allowed: {sorted(VALID_FIRMWARE_STATUSES)}")

        tier = dev.get("talos_support_level")
        if tier not in VALID_SUPPORT_LEVELS:
            errors.append(f"{dev_label}: invalid 'talos_support_level' '{tier}'. Allowed: {sorted(VALID_SUPPORT_LEVELS)}")

        # Blob inventory validation
        blobs = dev.get("blob_inventory")
        if not isinstance(blobs, list):
            errors.append(f"{dev_label}: 'blob_inventory' must be a list of blob objects.")
        else:
            for b_idx, b in enumerate(blobs):
                if not isinstance(b, dict):
                    errors.append(f"{dev_label} blob #{b_idx + 1}: entry must be a dictionary.")
                    continue
                for b_field in ["component", "license", "source", "replaceable_by_librephone", "verified"]:
                    if b_field not in b:
                        errors.append(f"{dev_label} blob #{b_idx + 1}: missing field '{b_field}'.")

                v = b.get("verified")
                if not isinstance(v, bool):
                    errors.append(f"{dev_label} blob #{b_idx + 1}: 'verified' must be a boolean.")
                elif v is True:
                    url = b.get("source_url")
                    if not url or not isinstance(url, str) or not (url.startswith("http://") or url.startswith("https://")):
                        errors.append(f"{dev_label} blob #{b_idx + 1}: verified is true, so 'source_url' must be a valid http(s) URL.")

                repl = b.get("replaceable_by_librephone")
                if repl not in (True, False, "unknown", "in_progress", "true", "false"):
                    errors.append(f"{dev_label} blob #{b_idx + 1}: invalid 'replaceable_by_librephone' value '{repl}'.")

                # STEP 4.3: Reject any entry where verified: false is combined with Tier A or "fully free" claim
                if v is False:
                    if tier.lower() in ("tier a", "tier-a"):
                        errors.append(
                            f"{dev_label}: Has unverified firmware blob '{b.get('component')}' (verified: false) "
                            f"combined with '{tier}'. Rule violation: Tier A strictly requires 100% verified free firmware."
                        )
                    notes_str = str(dev.get("notes", "")).lower()
                    if "fully free" in notes_str or "100% free" in notes_str:
                        errors.append(
                            f"{dev_label}: Marketing claim of 'fully free' prohibited with unverified blobs."
                        )

        # ACCEPTANCE GATE RULE:
        # Every device entry with any proprietary_* firmware is Tier B or C, never Tier A.
        # As of this release, NO device meets Tier A.
        if tier == "Tier A":
            errors.append(
                f"{dev_label}: Certified as '{tier}'. "
                f"Rule violation: As of this release, NO commercial device meets Tier A standards."
            )
        has_proprietary = any(
            str(dev.get(fw_key, "")).startswith("proprietary_")
            for fw_key in ["modem_firmware_status", "wifi_bt_firmware_status", "gpu_firmware_status", "camera_firmware_status"]
        )
        if has_proprietary and tier == "Tier A":
            errors.append(
                f"{dev_label}: Has proprietary firmware components, but is certified as '{tier}'. "
                f"Rule violation: Tier A is strictly reserved for devices with 100% free firmware in all active components."
            )

    return errors


def render_markdown(data: Dict[str, Any]) -> str:
    """Render a deterministic, human-readable Markdown certification matrix."""
    devices = data.get("devices", [])
    version = data.get("version", "1.0.0")

    lines: List[str] = []
    lines.append("# TALOS Hardware Certification Matrix")
    lines.append("")
    lines.append("<!--")
    lines.append("SPDX-FileCopyrightText: 2026 TALOS / LibreMobile OS Contributors")
    lines.append("SPDX-License-Identifier: GPL-3.0-or-later")
    lines.append("-->")
    lines.append("")
    lines.append(f"> **Matrix Version:** {version}  ")
    lines.append("> **Specification:** [hardware/schema.json](file:///home/alpha/android/hardware/schema.json)  ")
    lines.append("> **Machine-Readable Source:** [hardware/matrix.yaml](file:///home/alpha/android/hardware/matrix.yaml)  ")
    lines.append("> **Governance:** Sovereign Commons Anti-Monopoly Policy ([GOVERNANCE.md](file:///home/alpha/android/GOVERNANCE.md))")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## 1. Tier Definitions & Certification Criteria")
    lines.append("")
    lines.append(
        "> **Important Disclaimer:** A device is listed as Tier A only when EVERY active component's firmware has been independently verified as free software. As of this commit, NO device meets Tier A. Tier B and Tier C listings reflect the current honest state of each device's firmware."
    )
    lines.append("")
    lines.append("TALOS / LibreMobile OS rejects overbroad marketing claims such as \"fully open\" or \"100% free\" on hardware where binary blobs exist. Hardware support is classified into four explicit, verifiable tiers:")
    lines.append("")
    lines.append("- **Tier A (Fully Free):**")
    lines.append("  - **Zero proprietary firmware** in any active subsystem (SoC bootrom, CPU microcode, GPU, cellular modem DSP, Wi-Fi/Bluetooth, and camera ISP).")
    lines.append("  - 100% auditable open-source userspace and kernel drivers.")
    lines.append("  - Hardware schematics and component datasheets published under open licenses.")
    lines.append("  - *Current Status:* No commercial smartphone currently meets Tier A standards due to cellular baseband and Wi-Fi PHY firmware constraints.")
    lines.append("")
    lines.append("- **Tier B (Blob-Reduced):**")
    lines.append("  - Native GNU/Linux userspace running on mainline Linux kernels.")
    lines.append("  - Proprietary blobs remain **only** where community reverse-engineering (e.g., Librephone) has not yet replaced them.")
    lines.append("  - Physical hardware kill-switches or hardware-isolated USB/PCIe buses isolate proprietary basebands from system memory.")
    lines.append("  - Every non-free binary is explicitly inventoried in the device matrix.")
    lines.append("")
    lines.append("- **Tier C (Treble-Compatible — Sovereign Userspace, Non-Free Firmware):**")
    lines.append("  - Runs the sovereign TALOS GNU/Linux userspace, defense-grade firewall, and ARGUS custody spine.")
    lines.append("  - Preserves manufacturer Board Support Packages (BSPs), vendor drivers (`/vendor`), and firmware blobs via Project Treble Generic System Image (GSI) interfaces.")
    lines.append("  - Labeled honestly as **\"Sovereign userspace, non-free firmware.\"**")
    lines.append("")
    lines.append("- **Roadmap:**")
    lines.append("  - Target architectures (e.g. RISC-V mobile silicon, open basebands) under active evaluation or co-development.")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## 2. Hardware Matrix Summary")
    lines.append("")
    lines.append("| Tier | Vendor | Model | SoC Architecture | Boot Unlock | Relock (AVB) | Treble GSI | Kill-Switches | Blob Count |")
    lines.append("| :--- | :--- | :--- | :--- | :---: | :---: | :---: | :---: | :---: |")

    # Order devices deterministically: Tier B, Tier C, Roadmap, Tier A
    tier_order = {"Tier A": 1, "Tier B": 2, "Tier C": 3, "Roadmap": 4}
    sorted_devices = sorted(
        devices,
        key=lambda d: (tier_order.get(d.get("talos_support_level", ""), 99), d.get("vendor", ""), d.get("model", ""))
    )

    for dev in sorted_devices:
        tier = dev.get("talos_support_level", "Unknown")
        vendor = dev.get("vendor", "Unknown")
        model = dev.get("model", "Unknown")
        soc = dev.get("soc", "Unknown").split("(")[0].strip()
        unlock = "✔ Yes" if dev.get("bootloader_unlock") else "✖ No"
        relock = "✔ Yes" if dev.get("bootloader_relock") else "✖ No"
        treble = "✔ Yes" if dev.get("treble_compatible") else "— Native"
        ks = dev.get("kill_switches", {})
        has_ks = "✔ Hardware" if any(ks.values()) else "✖ None"
        blobs = len(dev.get("blob_inventory", []))

        lines.append(f"| **{tier}** | {vendor} | {model} | {soc} | {unlock} | {relock} | {treble} | {has_ks} | {blobs} blobs |")

    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## 3. Subsystem Firmware Provenance & Blob Inventories")
    lines.append("")

    current_tier = ""
    for dev in sorted_devices:
        tier = dev.get("talos_support_level", "Unknown")
        if tier != current_tier:
            current_tier = tier
            lines.append(f"### {current_tier} Devices")
            lines.append("")

        vendor = dev.get("vendor", "")
        model = dev.get("model", "")
        soc = dev.get("soc", "")
        lines.append(f"#### {vendor} {model}")
        lines.append("")
        lines.append(f"- **System on Chip (SoC):** `{soc}`")
        lines.append(f"- **Support Tier:** `{tier}`")
        lines.append(f"- **Treble Compatible:** `{'Yes (system.img replacement)' if dev.get('treble_compatible') else 'No (Direct Mainline Kernel)'}`")
        lines.append(f"- **Bootloader:** Unlockable: `{'Yes' if dev.get('bootloader_unlock') else 'No'}` | Verified Boot Relockable: `{'Yes' if dev.get('bootloader_relock') else 'No'}`")

        ks = dev.get("kill_switches", {})
        ks_desc = []
        if ks.get("mic"): ks_desc.append("Microphone")
        if ks.get("camera"): ks_desc.append("Camera")
        if ks.get("radio"): ks_desc.append("Cellular / Wi-Fi / BT Radios")
        lines.append(f"- **Physical Hardware Kill-Switches:** {', '.join(ks_desc) if ks_desc else 'None (Software isolation only)'}")
        lines.append(f"- **Cellular Modem:** `{dev.get('modem', 'N/A')}`")
        lines.append("")

        lines.append("**Firmware Audit Status:**")
        lines.append("")
        lines.append("| Subsystem | Firmware Status | Description / Driver |")
        lines.append("| :--- | :--- | :--- |")
        lines.append(f"| **Modem Baseband** | `{dev.get('modem_firmware_status')}` | `{dev.get('modem')}` |")
        lines.append(f"| **Wi-Fi & Bluetooth** | `{dev.get('wifi_bt_firmware_status')}` | RF controller firmware |")
        lines.append(f"| **GPU / Display** | `{dev.get('gpu_firmware_status')}` | Graphics acceleration userspace |")
        lines.append(f"| **Camera ISP** | `{dev.get('camera_firmware_status')}` | Image signal processor pipeline |")
        lines.append("")

        blobs = dev.get("blob_inventory", [])
        if blobs:
            lines.append("**Proprietary Binary Blob Inventory:**")
            lines.append("")
            lines.append("| Component | License | Source / Partition | Verification Status | Source URL | Replaceable by Librephone |")
            lines.append("| :--- | :--- | :--- | :---: | :---: | :---: |")
            for b in blobs:
                comp = b.get("component", "")
                lic = b.get("license", "")
                src = b.get("source", "")
                v = b.get("verified")
                if v is True:
                    v_str = "✅ Verified"
                elif v is False:
                    v_str = "⚠ Unverified"
                else:
                    v_str = "❓ Unknown"
                url = b.get("source_url") or "—"
                repl_val = b.get("replaceable_by_librephone")
                if repl_val is True or repl_val == "true":
                    repl = "✔ Candidate"
                elif repl_val == "in_progress":
                    repl = "⏳ In Progress"
                elif repl_val == "unknown":
                    repl = "❓ Unknown"
                else:
                    repl = "✖ Silicon Locked"
                lines.append(f"| {comp} | {lic} | `{src}` | {v_str} | {url} | {repl} |")
            lines.append("")
        else:
            lines.append("*No proprietary blobs required for this device configuration.*")
            lines.append("")

        notes = dev.get("notes")
        if notes:
            lines.append(f"> **Operator Notes:** {notes}")
            lines.append("")

        lines.append("---")
        lines.append("")

    return "\n".join(lines).strip() + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="TALOS Hardware Matrix Validator & Deterministic Renderer")
    parser.add_argument("--matrix", type=Path, default=DEFAULT_MATRIX_PATH, help="Path to matrix.yaml")
    parser.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA_PATH, help="Path to schema.json")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT_PATH, help="Path to output HARDWARE.md")
    parser.add_argument("--check", action="store_true", help="Validate matrix against schema and tier rules")
    parser.add_argument("--render", action="store_true", help="Render matrix into Markdown format")
    parser.add_argument("--verify", action="store_true", help="Verify that existing Markdown file matches render")

    args = parser.parse_args()

    if not args.check and not args.render and not args.verify:
        args.check = True
        args.render = True

    if not args.matrix.is_file():
        print(f"ERROR: Matrix file not found: {args.matrix}", file=sys.stderr)
        return 1
    if not args.schema.is_file():
        print(f"ERROR: Schema file not found: {args.schema}", file=sys.stderr)
        return 1

    try:
        matrix_data = load_yaml(args.matrix)
    except Exception as e:
        print(f"ERROR loading matrix YAML: {e}", file=sys.stderr)
        return 1

    try:
        with open(args.schema, "r", encoding="utf-8") as f:
            schema_data = json.load(f)
    except Exception as e:
        print(f"ERROR loading JSON schema: {e}", file=sys.stderr)
        return 1

    # Check / Validate
    errors = validate_matrix(matrix_data, schema_data)
    if errors:
        print("❌ HARDWARE MATRIX VALIDATION FAILED:", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1
    else:
        if args.check:
            device_count = len(matrix_data.get("devices", []))
            print(f"✔ Hardware matrix validated: {device_count} devices adhere to schema and Tier consistency rules.")

    # Render
    if args.render:
        markdown_content = render_markdown(matrix_data)
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(markdown_content)
        print(f"✔ Successfully rendered deterministic hardware matrix to {args.output}")

    # Verify
    if args.verify:
        markdown_content = render_markdown(matrix_data)
        if not args.output.is_file():
            print(f"ERROR: Output file does not exist: {args.output}", file=sys.stderr)
            return 1
        with open(args.output, "r", encoding="utf-8") as f:
            existing_content = f.read()
        if existing_content != markdown_content:
            print(f"ERROR: {args.output} is out of date with {args.matrix}. Run 'make hardware-matrix-render' to synchronize.", file=sys.stderr)
            return 1
        print(f"✔ Verified: {args.output} is byte-identical to matrix render.")

    return 0


if __name__ == "__main__":
    sys.exit(main())

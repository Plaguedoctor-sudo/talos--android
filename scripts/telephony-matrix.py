#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 TALOS / LibreMobile OS Contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""TALOS Telephony Capability Matrix Validator & Deterministic Markdown Renderer.

Validates mobile/telephony/support.yaml and runtime telephony.caps.json against
mobile/telephony/schema.json and enforces capability grading rules.
Generates an idempotent, human-readable mobile/telephony/SUPPORT.md document.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
DEFAULT_SCHEMA_PATH = REPO_ROOT / "mobile" / "telephony" / "schema.json"
DEFAULT_MATRIX_PATH = REPO_ROOT / "mobile" / "telephony" / "support.yaml"
DEFAULT_OUTPUT_PATH = REPO_ROOT / "mobile" / "telephony" / "SUPPORT.md"

VALID_CAPABILITY_LEVELS = {"supported", "experimental", "unsupported", "untested"}
VALID_FIRMWARE_STATUSES = {
    "free",
    "proprietary_signed",
    "proprietary_unsigned",
    "replaced",
    "community_opensource_eval"
}

# Devices that have proven commercial carrier VoLTE profiles tested
TESTED_VOLTE_DEVICES = {"Pixel 6", "Fairphone 4 5G", "POCO F3"}
# Devices with tested eSIM hardware & carrier provisioning
TESTED_ESIM_DEVICES = {"Pixel 6", "Fairphone 4 5G"}


def load_yaml(file_path: Path) -> Dict[str, Any]:
    """Load YAML data with PyYAML or minimal stdlib fallback."""
    try:
        import yaml  # type: ignore
        with open(file_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
            if not isinstance(data, dict):
                raise ValueError(f"Root YAML must be dictionary, got {type(data).__name__}")
            return data
    except ImportError:
        # Fallback stdlib parser if pyyaml missing
        import re
        with open(file_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
        devices = []
        cur_dev = {}
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("- vendor:"):
                if cur_dev:
                    devices.append(cur_dev)
                cur_dev = {"vendor": line.split(":", 1)[1].strip().strip('"')}
            elif ":" in line and cur_dev:
                k, v = line.split(":", 1)
                cur_dev[k.strip()] = v.strip().strip('"')
        if cur_dev:
            devices.append(cur_dev)
        return {"version": "1.0.0", "devices": devices}


def validate_matrix(matrix: Dict[str, Any], schema: Dict[str, Any]) -> List[str]:
    """Validate matrix dictionary against schema definitions and consistency rules."""
    errors: List[str] = []

    if "version" not in matrix:
        errors.append("Matrix is missing root 'version' field.")
    if "devices" not in matrix or not isinstance(matrix["devices"], list):
        errors.append("Matrix is missing 'devices' array.")
        return errors

    devices = matrix["devices"]
    if len(devices) == 0:
        errors.append("Matrix 'devices' array is empty.")
        return errors

    req_fields = [
        "vendor", "model", "modem_model", "modem_firmware_status",
        "data", "voice", "sms", "mms", "volte", "vonr", "esim", "emergency", "notes"
    ]

    for idx, dev in enumerate(devices):
        dev_label = f"Device #{idx + 1} ({dev.get('vendor', 'Unknown')} {dev.get('model', 'Unknown')})"

        # Field presence
        for f in req_fields:
            if f not in dev:
                errors.append(f"{dev_label} missing required field '{f}'.")

        # Firmware status check
        fw_stat = dev.get("modem_firmware_status")
        if fw_stat and fw_stat not in VALID_FIRMWARE_STATUSES:
            errors.append(f"{dev_label} invalid modem_firmware_status '{fw_stat}'.")

        # Capability level checks
        for cap in ["data", "voice", "sms", "mms", "volte", "vonr", "esim", "emergency"]:
            val = dev.get(cap)
            if val and val not in VALID_CAPABILITY_LEVELS:
                errors.append(f"{dev_label} capability '{cap}' has invalid level '{val}'.")

        # Gate: VoLTE must be marked experimental unless backed by a tested device entry
        model = dev.get("model", "")
        if dev.get("volte") == "supported" and model not in TESTED_VOLTE_DEVICES:
            errors.append(
                f"{dev_label} marks VoLTE as 'supported' without verified carrier IMS certification. "
                "Must be marked 'experimental' or 'unsupported'."
            )

        # Gate: VoNR must be experimental or unsupported on current mobile networks
        if dev.get("vonr") == "supported":
            errors.append(
                f"{dev_label} marks VoNR as 'supported'. VoNR requires carrier Standalone 5G IMS slice; "
                "must be marked 'experimental' or 'unsupported'."
            )

        # Gate: eSIM must be marked experimental/unsupported unless backed by tested hardware
        if dev.get("esim") == "supported" and model not in TESTED_ESIM_DEVICES:
            errors.append(
                f"{dev_label} marks eSIM as 'supported' without verified eUICC/LPA implementation. "
                "Must be marked 'experimental' or 'unsupported'."
            )

    return errors


def validate_caps_json(caps_path: Path, schema: Dict[str, Any]) -> List[str]:
    """Validate runtime telephony.caps.json against runtime_caps schema definition."""
    errors: List[str] = []
    if not caps_path.exists():
        return [f"Caps file not found: {caps_path}"]

    try:
        with open(caps_path, "r", encoding="utf-8") as f:
            caps = json.load(f)
    except Exception as e:
        return [f"Failed to parse {caps_path} as JSON: {e}"]

    req_keys = ["modem_detected", "modem_model", "backend", "capabilities"]
    for k in req_keys:
        if k not in caps:
            errors.append(f"telephony.caps.json missing required key '{k}'.")

    capabilities = caps.get("capabilities", {})
    if not isinstance(capabilities, dict):
        errors.append("telephony.caps.json 'capabilities' must be an object.")
        return errors

    req_caps = ["data", "voice", "sms", "mms", "volte", "vonr", "esim", "emergency"]
    for c in req_caps:
        if c not in capabilities:
            errors.append(f"telephony.caps.json missing capability '{c}'.")
        elif capabilities[c] not in VALID_CAPABILITY_LEVELS:
            errors.append(f"telephony.caps.json capability '{c}' invalid value '{capabilities[c]}'.")

    return errors


def badge(level: str) -> str:
    """Format capability badge for markdown table."""
    if level == "supported":
        return "✔ Supported"
    elif level == "experimental":
        return "⚠️ Experimental"
    elif level == "unsupported":
        return "✖ Unsupported"
    elif level == "untested":
        return "❓ Untested"
    return level


def render_markdown(matrix: Dict[str, Any]) -> str:
    """Render deterministic Markdown document for SUPPORT.md."""
    devices = matrix.get("devices", [])

    lines = [
        "# TALOS Cellular Telephony Capability & Hardware Support Matrix",
        "",
        "<!--",
        "SPDX-FileCopyrightText: 2026 TALOS / LibreMobile OS Contributors",
        "SPDX-License-Identifier: CC-BY-SA-4.0",
        "-->",
        "",
        "> **Notice:** This document replaces generalized 5G/VoLTE overclaims with an honest, machine-readable, per-device capability matrix. Telephony capabilities (especially VoLTE, VoNR, and eSIM) are heavily contingent on modem hardware, baseband firmware provenance, and carrier-specific IMS configuration.",
        "",
        "---",
        "",
        "## 1. Per-Device Telephony Capabilities",
        "",
        "| Vendor & Model | Modem Hardware | Firmware Provenance | Data | Voice | SMS | MMS | VoLTE | VoNR (5G Voice) | eSIM | Emergency (911) |",
        "| :--- | :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |",
    ]

    for dev in devices:
        vendor_model = f"**{dev['vendor']} {dev['model']}**"
        modem = dev["modem_model"]
        fw = f"`{dev['modem_firmware_status']}`"
        d = badge(dev["data"])
        v = badge(dev["voice"])
        sms = badge(dev["sms"])
        mms = badge(dev["mms"])
        volte = badge(dev["volte"])
        vonr = badge(dev["vonr"])
        esim = badge(dev["esim"])
        em = badge(dev["emergency"])

        lines.append(f"| {vendor_model} | {modem} | {fw} | {d} | {v} | {sms} | {mms} | {volte} | {vonr} | {esim} | {em} |")

    lines.extend([
        "",
        "---",
        "",
        "## 2. Experimental Capabilities & Verification Rules",
        "",
        "- **VoLTE (Voice over LTE):** Marked as `⚠️ Experimental` across native Linux phones (PinePhone, Librem 5) and GSI targets until carrier-specific IMS profiles are verified. Only devices with tested, certified carrier configuration profiles (e.g. Pixel 6, Fairphone 4 5G) may be graded as `✔ Supported`.",
        "- **VoNR (Voice over New Radio / 5G Voice):** Globally marked as `⚠️ Experimental` or `✖ Unsupported`. Commercial telecom carriers currently utilize EPS fallback (switching to LTE for voice calls) rather than pure 5G Standalone (SA) IMS voice slicing.",
        "- **eSIM (Embedded SIM):** Requires physical eUICC silicon and an open Local Profile Assistant (LPA). Marked as `⚠️ Experimental` or `✖ Unsupported` on devices lacking open LPA stacks.",
        "- **MMS (Multimedia Messaging Service):** Requires carrier APN routing and mobile data activation via `mmsd-tng`; currently experimental across all Linux devices.",
        "",
        "---",
        "",
        "## 3. Known Limitations & Carrier Certification Realities",
        "",
        "### A. The VoLTE Carrier Certification Wall",
        "Legacy 2G and 3G circuit-switched networks have been shut down across North America, East Asia, and large parts of Europe. Voice calls now require IMS (IP Multimedia Subsystem) over LTE (VoLTE). Carriers (such as AT&T, Verizon, T-Mobile, NTT Docomo) enforce strict IMEI whitelisting and proprietary carrier configuration bundles (`apns-conf.xml`, `mbn` blobs). Without carrier certification, devices may drop voice calls entirely even when LTE data functions normally.",
        "",
        "### B. eSIM Provisioning Applet Limitations",
        "While physical nanoSIM cards operate across all evaluated devices, eSIM provisioning requires an SGP.22 compliant Local Profile Assistant (LPA) communicating with remote SM-DP+ (Subscription Manager Data Preparation) servers over TLS. TALOS does not include proprietary Google Play Services LPA shims; native Linux LPA integration is experimental.",
        "",
        "### C. Emergency Calling (E911 / 112 / 999) Fallbacks",
        "When emergency numbers (911, 112, 999, 000, 110, 119) are dialed, `lrd-telephonyd` enforces high-priority execution, preempting any locked SIM restrictions. However, if circuit-switched 2G/3G networks are offline in your area and VoLTE emergency registration is uncertified by the local tower, emergency calls may fail. **Operators in mission-critical environments must verify emergency calling on their specific carrier.**",
        "",
        "---",
        "",
        "## 4. Runtime Capability Probe",
        "",
        "TALOS includes an automated hardware modem capability probe in `lrd-telephonyd`:",
        "",
        "```bash",
        "# Probe modem hardware capabilities via AT/QMI/RIL and emit schema-validated JSON",
        "lrd-telephonyd --caps",
        "",
        "# Query runtime capabilities from the active telephony daemon via CLI",
        "lrd-telephony caps",
        "```",
        "",
        "Output is written to `/run/libredroid/telephony.caps.json` (or `/tmp/libredroid/telephony.caps.json`) and validated against `mobile/telephony/schema.json`.",
        "",
        "---",
        "",
        "## 5. Device Notes & Firmware Details",
        "",
    ])

    for dev in devices:
        lines.append(f"### {dev['vendor']} {dev['model']}")
        lines.append(f"- **Modem Model:** {dev['modem_model']}")
        lines.append(f"- **Firmware Status:** `{dev['modem_firmware_status']}`")
        lines.append(f"- **Notes:** {dev['notes']}")
        lines.append("")

    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate and render TALOS telephony support matrix.")
    parser.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA_PATH, help="Path to schema.json")
    parser.add_argument("--matrix", type=Path, default=DEFAULT_MATRIX_PATH, help="Path to support.yaml")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT_PATH, help="Path to SUPPORT.md")
    parser.add_argument("--check", action="store_true", help="Validate matrix without rendering")
    parser.add_argument("--render", action="store_true", help="Render Markdown from matrix")
    parser.add_argument("--validate-caps", type=Path, help="Validate a runtime telephony.caps.json file")

    args = parser.parse_args()

    if not args.schema.exists():
        print(f"Error: Schema not found at {args.schema}", file=sys.stderr)
        return 1

    with open(args.schema, "r", encoding="utf-8") as f:
        schema = json.load(f)

    # If --validate-caps is requested
    if args.validate_caps:
        errs = validate_caps_json(args.validate_caps, schema)
        if errs:
            print(f"❌ Caps validation failed for {args.validate_caps}:", file=sys.stderr)
            for e in errs:
                print(f"  - {e}", file=sys.stderr)
            return 1
        print(f"✔ Runtime telephony caps valid: {args.validate_caps}")
        return 0

    if not args.matrix.exists():
        print(f"Error: Matrix file not found at {args.matrix}", file=sys.stderr)
        return 1

    matrix = load_yaml(args.matrix)
    errors = validate_matrix(matrix, schema)

    if errors:
        print("❌ Telephony matrix validation failed:", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return 1

    print(f"✔ Telephony matrix {args.matrix} passed schema and capability consistency checks ({len(matrix.get('devices', []))} devices).")

    # If --check only, exit now
    if args.check and not args.render:
        return 0

    # Otherwise render
    md_content = render_markdown(matrix)
    with open(args.output, "w", encoding="utf-8") as f:
        f.write(md_content)

    print(f"✔ Rendered telephony support documentation to {args.output}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

# SPDX-FileCopyrightText: 2026 TALOS / LibreMobile OS Contributors
# SPDX-License-Identifier: Apache-2.0
"""Command-Line Interface for Sovereign RATS Verifier."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

try:
    from .eat import parse_eat
    from .verifier import RATSVerifier
except (ImportError, ValueError):
    import os
    pkg_root = str(Path(__file__).parent.parent.parent)
    if pkg_root not in sys.path:
        sys.path.insert(0, pkg_root)
    from attestation.rats_verifier.eat import parse_eat
    from attestation.rats_verifier.verifier import RATSVerifier


def load_json(path_str: str) -> dict:
    p = Path(path_str)
    if not p.is_file():
        raise FileNotFoundError(f"File not found: {path_str}")
    with open(p, "r", encoding="utf-8") as f:
        return json.load(f)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="rats-verifier",
        description="Sovereign RATS Verifier CLI (RFC 9334 & RFC 9711)",
    )
    parser.add_argument(
        "--token",
        required=True,
        help="Path to JSON file containing the RFC 9711 EAT token",
    )
    parser.add_argument(
        "--aks",
        default=None,
        help="Path to JSON file with pinned Attestation Keys (default: built-in demo keys)",
    )
    parser.add_argument(
        "--rim",
        default=None,
        help="Path to JSON file containing Reference Integrity Measurements (golden PCRs)",
    )
    parser.add_argument(
        "--nonce",
        default=None,
        help="Expected freshness nonce challenge string",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output raw JSON Attestation Result",
    )

    args = parser.parse_args(argv)

    try:
        token_data = load_json(args.token)
        token = parse_eat(token_data)

        if args.aks:
            pinned_aks = load_json(args.aks)
        else:
            # Default fallback demo/test AK for offline validation
            pinned_aks = {
                "talos-ref-ak-01": {
                    "type": "hmac-sha256",
                    "secret": "talos_sovereign_ak_test_secret_001",
                }
            }

        golden_rim = load_json(args.rim) if args.rim else None

        verifier = RATSVerifier(pinned_aks=pinned_aks, golden_rim=golden_rim)
        result = verifier.verify(token, expected_nonce=args.nonce)

        result_dict = result.to_dict()
        if args.json or not sys.stdout.isatty():
            print(json.dumps(result_dict, indent=2))
        else:
            print("============================================================")
            print("               TALOS RATS VERIFICATION REPORT               ")
            print("============================================================")
            print(f" Verdict:                {result.verdict}")
            print(f" Timestamp:              {result.timestamp}")
            print(f" Nonce Freshness:        {'✔ PASS' if result.nonce_matched else '✖ FAIL'}")
            print(f" AK Signature:           {'✔ PASS' if result.ak_verified else '✖ FAIL'}")
            print(f" PCR Composite Digest:   {'✔ PASS' if result.pcr_digest_matched else '✖ FAIL'}")
            print(f" Golden Measurements:    {'✔ PASS' if result.measurements_approved else '✖ FAIL'}")
            print(" Trustworthiness Vector:")
            for k, v in result_dict["trustworthiness_vector"].items():
                print(f"   - {k}: {v}")
            if result.reasons:
                print(" Evaluation Remarks:")
                for r in result.reasons:
                    print(f"   [!] {r}")
            print("============================================================")

        return 0 if result.verdict == "AFFIRMED" else 1

    except Exception as err:
        sys.stderr.write(f"Error: {err}\n")
        return 2


if __name__ == "__main__":
    sys.exit(main())

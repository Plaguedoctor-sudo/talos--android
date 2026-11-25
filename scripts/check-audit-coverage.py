#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 TALOS / LibreMobile OS Contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Assert that every in-scope audit file meets the >=70% line coverage floor."""

import sys
from pathlib import Path

REQUIRED_FILES = [
    "argus/verify/record.py",
    "argus/argf2/ledger.py",
    "argus/argf2/writer.py",
    "argus/duress.py",
    "argus/deadman.py",
    "argus/vault.py",
    "argus/verify/verify.py",
]

MIN_COVERAGE = 70.0


def main():
    report_path = Path(sys.argv[1] if len(sys.argv) > 1 else "audit/coverage-report.txt")
    if not report_path.exists():
        print(f"Error: coverage report not found: {report_path}", file=sys.stderr)
        sys.exit(1)

    lines = report_path.read_text().splitlines()
    coverages = {}

    for line in lines:
        parts = line.split()
        if len(parts) >= 4 and parts[0].startswith("argus/"):
            fname = parts[0]
            cov_str = parts[3].rstrip("%")
            try:
                cov_val = float(cov_str)
                coverages[fname] = cov_val
            except ValueError:
                continue

    failed = False
    print("=== ARGUS Audit Scope Coverage Audit ===")
    for req in REQUIRED_FILES:
        if req not in coverages:
            print(f"FAIL: {req} missing from coverage report!", file=sys.stderr)
            failed = True
        elif coverages[req] < MIN_COVERAGE:
            print(f"FAIL: {req} coverage {coverages[req]}% < required {MIN_COVERAGE}%", file=sys.stderr)
            failed = True
        else:
            print(f"PASS: {req:30} {coverages[req]}% (>= {MIN_COVERAGE}%)")

    if failed:
        sys.exit(1)
    print(f"✔ All in-scope audit targets meet the >={MIN_COVERAGE:.0f}% line coverage floor.")


if __name__ == "__main__":
    main()

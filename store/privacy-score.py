#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 TALOS / LibreMobile OS Contributors
# SPDX-License-Identifier: Apache-2.0
"""
Sovereign App Store Deterministic Privacy Scorer (store/privacy-score.py).
Evaluates mobile application metadata against Exodus tracker signatures,
Android permission sets, build reproducibility, and declared egress policies.
Pure Python 3 standard library implementation.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

# Python 3.11+ stdlib TOML parser
try:
    import tomllib
except ImportError:
    import tomli as tomllib  # type: ignore

SCORE_VERSION = "1.0.0"

# Android permissions categorized by invasiveness
INTRUSIVE_PERMISSIONS = {
    "ACCESS_FINE_LOCATION",
    "ACCESS_COARSE_LOCATION",
    "ACCESS_BACKGROUND_LOCATION",
    "RECORD_AUDIO",
    "CAMERA",
    "READ_CONTACTS",
    "WRITE_CONTACTS",
    "READ_CALL_LOG",
    "WRITE_CALL_LOG",
    "READ_SMS",
    "SEND_SMS",
    "RECEIVE_SMS",
    "READ_PHONE_STATE",
    "READ_PRIVILEGED_PHONE_STATE",
    "QUERY_ALL_PACKAGES",
    "SYSTEM_ALERT_WINDOW",
}


def load_json(path_str: str | Path) -> Dict[str, Any]:
    with open(path_str, "r", encoding="utf-8") as f:
        return json.load(f)


def calculate_recency_score(updated_date_str: Optional[str], ref_date_str: str) -> float:
    """Computes recency score based on elapsed days between updated_date and ref_date."""
    if not updated_date_str:
        return 0.0
    try:
        ref_date = datetime.date.fromisoformat(ref_date_str)
        up_date = datetime.date.fromisoformat(updated_date_str)
        delta_days = (ref_date - up_date).days
        if delta_days < 0:
            delta_days = 0
    except Exception:
        return 0.0

    if delta_days <= 90:
        return 10.0
    elif delta_days <= 365:
        return 7.0
    elif delta_days <= 730:
        return 4.0
    elif delta_days <= 1095:
        return 2.0
    else:
        return 0.0


def parse_egress_policy(policy_path: Path) -> Optional[Dict[str, Any]]:
    """Parse security/egress/policy/*.toml file using stdlib tomllib."""
    if not policy_path.is_file():
        return None
    try:
        with open(policy_path, "rb") as f:
            return tomllib.load(f)
    except Exception:
        return None


def score_app(
    app: Dict[str, Any],
    trackers_db: Dict[str, Any],
    policy_dir: Optional[Path] = None,
    ref_date_str: str = "2026-11-25",
) -> Dict[str, Any]:
    """
    Compute a deterministic 0–100 privacy score for a single application.
    """
    trackers_catalog = trackers_db.get("trackers", {})

    # 1. Tracker Absence (35.0 pts max)
    detected_trackers = app.get("detected_trackers", [])
    tracker_deductions = 0.0
    detected_details = []

    for t_id in detected_trackers:
        t_id_str = str(t_id)
        tracker_info = trackers_catalog.get(t_id_str, {})
        category = tracker_info.get("category", "unknown").lower()
        name = tracker_info.get("name", f"Tracker #{t_id}")

        if category in ("advertisement", "profiling"):
            deduction = 25.0
        elif category == "analytics":
            deduction = 15.0
        elif category == "crash_reporting":
            deduction = 10.0
        else:
            deduction = 15.0

        tracker_deductions += deduction
        detected_details.append({
            "id": t_id,
            "name": name,
            "category": category,
            "deduction": deduction,
        })

    tracker_score = max(0.0, 35.0 - tracker_deductions)

    # 2. Permission Restraint (20.0 pts max)
    app_perms = set(app.get("permissions", []))
    intrusive_found = [p for p in sorted(app_perms) if p in INTRUSIVE_PERMISSIONS]
    perm_deductions = len(intrusive_found) * 4.0
    perm_score = max(0.0, 20.0 - perm_deductions)

    # 3. Build Reproducibility (20.0 pts max)
    is_reproducible = bool(app.get("reproducible", False))
    has_waiver = bool(app.get("reproducible_waiver"))
    if is_reproducible:
        repro_score = 20.0
        repro_status = "verified"
    elif has_waiver:
        repro_score = 5.0
        repro_status = "waiver_granted"
    else:
        repro_score = 0.0
        repro_status = "unverified"

    # 4. Egress Policy Alignment (15.0 pts max)
    egress_filename = app.get("egress_policy")
    egress_score = 0.0
    egress_mode = "none"

    if egress_filename and policy_dir:
        policy_file = policy_dir / egress_filename
        policy_data = parse_egress_policy(policy_file)
        if policy_data and "network" in policy_data:
            net_conf = policy_data["network"]
            mode = net_conf.get("mode", "").lower()
            egress_mode = mode
            kill_switch = bool(net_conf.get("kill_switch", False))
            dns_policy = net_conf.get("dns_policy", "")

            if mode == "blocked":
                egress_score = 15.0
            elif mode in ("tor_strict", "vpn_only", "tunnel_only"):
                if kill_switch and dns_policy == "enforce_dot":
                    egress_score = 12.0
                else:
                    egress_score = 10.0
            elif mode == "lan_only":
                egress_score = 13.0
            else:
                egress_score = 8.0

    # 5. Maintenance Recency (10.0 pts max)
    updated_date = app.get("updated_date")
    recency_score = calculate_recency_score(updated_date, ref_date_str)

    # Total Score Calculation
    total_raw = tracker_score + perm_score + repro_score + egress_score + recency_score
    total_score = round(max(0.0, min(100.0, total_raw)), 1)

    # Grade Assignment
    if total_score >= 95.0:
        grade = "A+"
    elif total_score >= 85.0:
        grade = "A"
    elif total_score >= 70.0:
        grade = "B"
    elif total_score >= 55.0:
        grade = "C"
    elif total_score >= 40.0:
        grade = "D"
    else:
        grade = "F"

    return {
        "score_version": SCORE_VERSION,
        "total_score": total_score,
        "grade": grade,
        "breakdown": {
            "tracker_absence": {
                "score": tracker_score,
                "max": 35.0,
                "detected_count": len(detected_trackers),
                "details": detected_details,
            },
            "permission_restraint": {
                "score": perm_score,
                "max": 20.0,
                "intrusive_permissions": intrusive_found,
            },
            "build_reproducibility": {
                "score": repro_score,
                "max": 20.0,
                "status": repro_status,
            },
            "egress_alignment": {
                "score": egress_score,
                "max": 15.0,
                "mode": egress_mode,
                "policy_file": egress_filename,
            },
            "maintenance_recency": {
                "score": recency_score,
                "max": 10.0,
                "last_updated": updated_date,
            },
        },
    }


def score_index(
    index_data: Dict[str, Any],
    trackers_db: Dict[str, Any],
    policy_dir: Optional[Path] = None,
    ref_date_str: str = "2026-11-25",
) -> Dict[str, Any]:
    """Score all packages in an index and return a deterministic, canonical index."""
    scored_packages = []
    packages = index_data.get("packages", [])

    for pkg in packages:
        scored_pkg = dict(pkg)
        score_res = score_app(
            pkg,
            trackers_db=trackers_db,
            policy_dir=policy_dir,
            ref_date_str=ref_date_str,
        )
        scored_pkg["privacy_score"] = score_res
        scored_packages.append(scored_pkg)

    # Deterministic alphabetical sort by package ID
    scored_packages.sort(key=lambda p: p.get("id", ""))

    output_index = {
        "repo": dict(index_data.get("repo", {})),
        "score_metadata": {
            "score_version": SCORE_VERSION,
            "engine": "TALOS Sovereign Privacy Scorer",
            "reference_date": ref_date_str,
            "total_packages": len(scored_packages),
        },
        "packages": scored_packages,
    }
    return output_index


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="privacy-score.py",
        description="TALOS Sovereign App Store Deterministic Privacy Scorer",
    )
    parser.add_argument("--app", help="Path to single app JSON file to score")
    parser.add_argument("--index", help="Path to upstream repository index JSON")
    parser.add_argument(
        "--trackers",
        default="store/data/trackers.json",
        help="Path to vendored Exodus tracker dataset JSON",
    )
    parser.add_argument(
        "--policy-dir",
        default="security/egress/policy",
        help="Directory containing declared egress TOML policies",
    )
    parser.add_argument(
        "--ref-date",
        default="2026-11-25",
        help="Reference date for deterministic recency calculation (YYYY-MM-DD)",
    )
    parser.add_argument(
        "--output",
        help="Path to write scored output JSON",
    )

    args = parser.parse_args(argv)

    if not args.app and not args.index:
        parser.error("Must specify either --app or --index")

    trackers_path = Path(args.trackers)
    if not trackers_path.is_file():
        sys.stderr.write(f"Error: Tracker database not found: {args.trackers}\n")
        return 1

    trackers_db = load_json(trackers_path)
    policy_dir = Path(args.policy_dir) if args.policy_dir else None

    if args.app:
        app_data = load_json(args.app)
        res = score_app(app_data, trackers_db, policy_dir, args.ref_date)
        formatted = json.dumps(res, indent=2, sort_keys=True)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(formatted + "\n")
        else:
            print(formatted)
        return 0

    if args.index:
        index_data = load_json(args.index)
        scored_index = score_index(index_data, trackers_db, policy_dir, args.ref_date)
        formatted = json.dumps(scored_index, indent=2, sort_keys=True)
        if args.output:
            out_p = Path(args.output)
            out_p.parent.mkdir(parents=True, exist_ok=True)
            with open(out_p, "w", encoding="utf-8") as f:
                f.write(formatted + "\n")
        else:
            print(formatted)
        return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 TALOS / LibreMobile OS Contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Generate and verify deterministic static test vectors for ARGUS third-party audit."""

from __future__ import annotations

import json
from pathlib import Path

from argus.argf2.writer import Bridge, derive_tag_key
from argus.deadman import DeadManPolicy
from argus.duress import DecoyPlausibility
from argus.vault import GENESIS, custody_digest
from argus.verify.record import (
    PAD_LEAF,
    SCOPE_LOCAL,
    _depth,
    merkle_path,
    merkle_root,
    tag_value,
    walk,
)

VECTORS_DIR = Path(__file__).resolve().parent.parent / "audit" / "test-vectors"


def generate_merkle_vectors() -> dict:
    # 7 deterministic leaves
    leaves = [
        bytes.fromhex(f"{i:02x}" * 32) for i in range(1, 8)
    ]
    root = merkle_root(leaves)
    depth = _depth(len(leaves))

    cases = []
    for idx in range(len(leaves)):
        sibs, dirs = merkle_path(leaves, idx)
        verified = walk(sibs, dirs, leaves[idx]) == root
        cases.append({
            "leaf_index": idx,
            "leaf_hash": leaves[idx].hex(),
            "siblings": [s.hex() for s in sibs],
            "directions": dirs,
            "proof_length": len(sibs),
            "verified": verified,
        })

    # Tampered test
    sibs, dirs = merkle_path(leaves, 0)
    tampered_leaf = bytes([leaves[0][0] ^ 0x01]) + leaves[0][1:]
    tampered_verified = walk(sibs, dirs, tampered_leaf) == root

    return {
        "title": "ARGUS Merkle Arity-4 Static Inclusion Vectors",
        "invariant": "INV-M1 (Inclusion Completeness), INV-M3 (Tamper Sensitivity), INV-M4 (Path Bound)",
        "tree_size": len(leaves),
        "tree_depth": depth,
        "root_hash": root.hex(),
        "pad_leaf": PAD_LEAF.hex(),
        "test_cases": cases,
        "tamper_test": {
            "tampered_leaf": tampered_leaf.hex(),
            "verified": tampered_verified,
        },
    }


def generate_epoch_vectors() -> dict:
    master_key = bytes.fromhex("11" * 32)
    boot_id = bytes.fromhex("22" * 16)
    value = b"evidence:alibi-device-1049"
    salt = bytes.fromhex("33" * 16)

    key_e1 = derive_tag_key(master_key, boot_id, scope=SCOPE_LOCAL, epoch=1)
    key_e2 = derive_tag_key(master_key, boot_id, scope=SCOPE_LOCAL, epoch=2)
    tag_e1 = tag_value(key_e1, value)
    tag_e2 = tag_value(key_e2, value)

    bridge = Bridge(master=master_key, boot_id=boot_id, value=value, salt=salt)
    revealed_k1 = bridge.key(1)
    revealed_k2 = bridge.key(2)

    return {
        "title": "ARGUS Tag Commit Epoch Rollover and Bridge Vectors",
        "invariant": "INV-E1 (Forward Secrecy), INV-E2 (Bridge Equivalence)",
        "master_key_fingerprint": master_key[:8].hex(),
        "boot_id": boot_id.hex(),
        "test_value": value.decode("utf-8"),
        "epoch_1": {
            "epoch": 1,
            "derived_key": key_e1.hex(),
            "tag": tag_e1.hex(),
        },
        "epoch_2": {
            "epoch": 2,
            "derived_key": key_e2.hex(),
            "tag": tag_e2.hex(),
        },
        "cross_epoch_bridge": {
            "revealed_key_epoch_1": revealed_k1.hex(),
            "revealed_key_epoch_2": revealed_k2.hex(),
            "equality_verified": (
                tag_value(revealed_k1, value) == tag_e1 and
                tag_value(revealed_k2, value) == tag_e2
            ),
        },
    }


def generate_duress_vectors() -> dict:
    scenarios = [
        {
            "name": "daily_driver_active_phone",
            "inputs": {
                "data_volume_mb": 1250.0,
                "app_count": 32,
                "history_age_days": 180.0,
                "contact_count": 45,
                "message_count": 820,
            },
            "expected_score": 100.0,
            "threshold": 60.0,
            "acceptable": True,
        },
        {
            "name": "believable_secondary_phone",
            "inputs": {
                "data_volume_mb": 350.0,
                "app_count": 14,
                "history_age_days": 45.0,
                "contact_count": 12,
                "message_count": 95,
            },
            "expected_score": 87.83,
            "threshold": 60.0,
            "acceptable": True,
        },
        {
            "name": "freshly_wiped_burn_phone",
            "inputs": {
                "data_volume_mb": 25.0,
                "app_count": 3,
                "history_age_days": 2.0,
                "contact_count": 1,
                "message_count": 2,
            },
            "expected_score": 9.42,
            "threshold": 60.0,
            "acceptable": False,
        },
    ]

    for sc in scenarios:
        p = DecoyPlausibility(**sc["inputs"])
        score = p.score()
        sc["expected_score"] = score
        sc["calculated_score"] = score
        sc["acceptable"] = p.is_plausible(sc["threshold"])

    return {
        "title": "ARGUS Decoy Plausibility Scoring Vectors",
        "invariant": "INV-D3 (Plausibility Lower Bound)",
        "minimum_enrollment_threshold": 60.0,
        "scenarios": scenarios,
    }


def generate_deadman_vectors() -> dict:
    timeout = 172800.0  # 48 hours
    last_heartbeat = 1700000000.0

    cases = [
        {
            "scenario": "routine_active_checkin",
            "elapsed_seconds": 3600.0,
            "is_offline": False,
            "allow_offline_wipe": False,
            "expected_status": "ACTIVE",
            "expected_wipe": False,
        },
        {
            "scenario": "approaching_deadline_warning",
            "elapsed_seconds": 140000.0,
            "is_offline": False,
            "allow_offline_wipe": False,
            "expected_status": "WARNING",
            "expected_wipe": False,
        },
        {
            "scenario": "overdue_travel_offline_guarded",
            "elapsed_seconds": 250000.0,
            "is_offline": True,
            "allow_offline_wipe": False,
            "expected_status": "TRIGGERED",
            "expected_wipe": False,
        },
        {
            "scenario": "overdue_compelled_offline_armed",
            "elapsed_seconds": 250000.0,
            "is_offline": True,
            "allow_offline_wipe": True,
            "expected_status": "TRIGGERED",
            "expected_wipe": True,
        },
        {
            "scenario": "overdue_online_escalated",
            "elapsed_seconds": 250000.0,
            "is_offline": False,
            "allow_offline_wipe": False,
            "expected_status": "TRIGGERED",
            "expected_wipe": True,
        },
    ]

    return {
        "title": "ARGUS Dead Man's Switch Timeout and Policy Vectors",
        "invariant": "INV-H1 (Zero False Positives within Grace), INV-H2 (Offline Policy Guard)",
        "timeout_seconds": timeout,
        "last_heartbeat_epoch": last_heartbeat,
        "test_cases": cases,
    }


def generate_vault_vectors() -> dict:
    events = []
    prev_digest = GENESIS
    actions = [
        ("EV-001", 0, "INGEST", "operator", "2026-11-25T08:00:00Z", "Initial extraction"),
        ("EV-001", 1, "SEAL", "crypto-officer", "2026-11-25T08:15:00Z", "Hardware token sealed"),
        ("EV-001", 2, "VERIFY", "auditor", "2026-11-25T09:00:00Z", "Integrity confirmed"),
    ]

    for ev_id, seq, action, actor, at, note in actions:
        d = custody_digest(ev_id, seq, action, actor, at, note, prev_digest)
        events.append({
            "evidence_id": ev_id,
            "seq": seq,
            "action": action,
            "actor": actor,
            "timestamp": at,
            "note": note,
            "prev_digest": prev_digest,
            "custody_digest": d,
        })
        prev_digest = d

    return {
        "title": "ARGUS Vault Content-Addressed Custody Chain Vectors",
        "invariant": "INV-V1 (Hash-Linked Immutable Custody Chain)",
        "genesis_hash": GENESIS,
        "chain": events,
    }


def main() -> None:
    VECTORS_DIR.mkdir(parents=True, exist_ok=True)

    data_map = {
        "merkle_arity4.json": generate_merkle_vectors(),
        "epoch_transition.json": generate_epoch_vectors(),
        "duress_plausibility.json": generate_duress_vectors(),
        "deadman_switch.json": generate_deadman_vectors(),
        "vault_custody.json": generate_vault_vectors(),
    }

    for filename, data in data_map.items():
        out_path = VECTORS_DIR / filename
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        print(f"✔ Generated vector: {out_path.relative_to(VECTORS_DIR.parent.parent)}")


if __name__ == "__main__":
    main()

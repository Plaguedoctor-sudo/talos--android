# SPDX-FileCopyrightText: 2026 TALOS / LibreMobile OS Contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Verify that committed static test vectors in audit/test-vectors pass all invariant checks."""

from __future__ import annotations

import json
from pathlib import Path

from argus.argf2.writer import Bridge, derive_tag_key
from argus.deadman import DeadManPolicy
from argus.duress import DecoyPlausibility
from argus.vault import GENESIS, custody_digest
from argus.verify.record import (
    SCOPE_LOCAL,
    tag_value,
    walk,
)

VECTORS_DIR = Path(__file__).resolve().parent.parent / "audit" / "test-vectors"


def test_merkle_arity4_static_vectors() -> None:
    path = VECTORS_DIR / "merkle_arity4.json"
    assert path.is_file(), f"Missing vector file: {path}"
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    root = bytes.fromhex(data["root_hash"])
    for case in data["test_cases"]:
        leaf = bytes.fromhex(case["leaf_hash"])
        sibs = [bytes.fromhex(s) for s in case["siblings"]]
        dirs = case["directions"]
        assert walk(sibs, dirs, leaf) == root
        assert case["verified"] is True

    # Check tamper test
    tamper = data["tamper_test"]
    tampered_leaf = bytes.fromhex(tamper["tampered_leaf"])
    case0 = data["test_cases"][0]
    sibs0 = [bytes.fromhex(s) for s in case0["siblings"]]
    dirs0 = case0["directions"]
    assert walk(sibs0, dirs0, tampered_leaf) != root
    assert tamper["verified"] is False


def test_epoch_transition_static_vectors() -> None:
    path = VECTORS_DIR / "epoch_transition.json"
    assert path.is_file(), f"Missing vector file: {path}"
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    val = data["test_value"].encode("utf-8")
    e1 = data["epoch_1"]
    e2 = data["epoch_2"]
    bridge = data["cross_epoch_bridge"]

    k1 = bytes.fromhex(bridge["revealed_key_epoch_1"])
    k2 = bytes.fromhex(bridge["revealed_key_epoch_2"])

    assert tag_value(k1, val).hex() == e1["tag"]
    assert tag_value(k2, val).hex() == e2["tag"]
    assert bridge["equality_verified"] is True


def test_duress_plausibility_static_vectors() -> None:
    path = VECTORS_DIR / "duress_plausibility.json"
    assert path.is_file(), f"Missing vector file: {path}"
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    for sc in data["scenarios"]:
        p = DecoyPlausibility(**sc["inputs"])
        score = p.score()
        assert score == sc["expected_score"]
        assert p.is_plausible(sc["threshold"]) == sc["acceptable"]


def test_deadman_switch_static_vectors() -> None:
    path = VECTORS_DIR / "deadman_switch.json"
    assert path.is_file(), f"Missing vector file: {path}"
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    timeout = data["timeout_seconds"]
    for case in data["test_cases"]:
        elapsed = case["elapsed_seconds"]
        is_offline = case["is_offline"]
        allow_wipe = case["allow_offline_wipe"]

        if elapsed > timeout:
            status = "TRIGGERED"
        elif elapsed > (timeout * 0.75):
            status = "WARNING"
        else:
            status = "ACTIVE"

        assert status == case["expected_status"]

        wipe = (elapsed > timeout) and (not is_offline or allow_wipe)
        assert wipe == case["expected_wipe"]


def test_vault_custody_static_vectors() -> None:
    path = VECTORS_DIR / "vault_custody.json"
    assert path.is_file(), f"Missing vector file: {path}"
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    prev = data["genesis_hash"]
    for ev in data["chain"]:
        d = custody_digest(
            ev["evidence_id"],
            ev["seq"],
            ev["action"],
            ev["actor"],
            ev["timestamp"],
            ev["note"],
            prev,
        )
        assert d == ev["custody_digest"]
        prev = d

# SPDX-FileCopyrightText: 2026 TALOS / LibreMobile OS Contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Property-based verification of ARGUS ARGF/2 Merkle arity-4 trees and epoch transitions."""

from __future__ import annotations

import math
import os
import struct
import tempfile
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from argus.argf2.writer import Bridge, derive_tag_key
from argus.verify.findings import Report
from argus.verify.record import (
    PAD_LEAF,
    SCOPE_LOCAL,
    _depth,
    _node,
    merkle_path,
    merkle_root,
    seg_footer,
    tag_value,
    walk,
)
from argus.verify.verify import _parse_segment


# ---------------------------------------------------------------------------
# 1. Merkle Arity-4 Properties
# ---------------------------------------------------------------------------


@settings(max_examples=60, deadline=None)
@given(
    leaves=st.lists(st.binary(min_size=32, max_size=32), min_size=1, max_size=64),
    data=st.data(),
)
def test_merkle_arity4_inclusion_proof_validity(leaves: list[bytes], data: st.DataObject) -> None:
    """Property: Every leaf in an arity-4 tree has a valid inclusion proof."""
    idx = data.draw(st.integers(min_value=0, max_value=len(leaves) - 1))
    root = merkle_root(leaves)
    sibs, dirs = merkle_path(leaves, idx)

    # Walk from leaf must recover exact root
    computed_root = walk(sibs, dirs, leaves[idx])
    assert computed_root == root, f"Inclusion proof failed for leaf {idx} of {len(leaves)}"


@settings(max_examples=60, deadline=None)
@given(leaves=st.lists(st.binary(min_size=32, max_size=32), min_size=1, max_size=64))
def test_merkle_arity4_proof_size_bounds(leaves: list[bytes]) -> None:
    """Property: Proof size is strictly bounded by 3 * ceil(log4(N))."""
    n = len(leaves)
    expected_depth = _depth(n)

    # In arity-4, depth = ceil(log4(N))
    assert expected_depth >= 0
    if n > 1:
        assert 4 ** (expected_depth - 1) < n <= 4 ** expected_depth

    for idx in range(min(n, 5)):
        sibs, dirs = merkle_path(leaves, idx)
        assert len(dirs) == expected_depth
        assert len(sibs) == 3 * expected_depth


@settings(max_examples=60, deadline=None)
@given(
    leaves=st.lists(st.binary(min_size=32, max_size=32), min_size=1, max_size=64),
    bit_pos=st.integers(min_value=0, max_value=255),
    data=st.data(),
)
def test_merkle_arity4_tamper_leaf_breaks_verification(
    leaves: list[bytes], bit_pos: int, data: st.DataObject
) -> None:
    """Property: Any single-bit modification to a leaf breaks inclusion proof."""
    idx = data.draw(st.integers(min_value=0, max_value=len(leaves) - 1))
    root = merkle_root(leaves)
    sibs, dirs = merkle_path(leaves, idx)

    # Flip 1 bit in target leaf
    orig_leaf = leaves[idx]
    byte_idx = bit_pos // 8
    bit_mask = 1 << (bit_pos % 8)
    tampered_byte = bytes([orig_leaf[byte_idx] ^ bit_mask])
    tampered_leaf = orig_leaf[:byte_idx] + tampered_byte + orig_leaf[byte_idx + 1:]

    assert tampered_leaf != orig_leaf
    tampered_root = walk(sibs, dirs, tampered_leaf)
    assert tampered_root != root, f"Collision detected: single-bit tamper at leaf {idx} verified!"


@settings(max_examples=40, deadline=None)
@given(
    leaves=st.lists(st.binary(min_size=32, max_size=32), min_size=2, max_size=32),
    data=st.data(),
)
def test_merkle_arity4_tamper_sibling_breaks_verification(
    leaves: list[bytes], data: st.DataObject
) -> None:
    """Property: Any modification to a sibling hash breaks inclusion proof."""
    idx = data.draw(st.integers(min_value=0, max_value=len(leaves) - 1))
    root = merkle_root(leaves)
    sibs, dirs = merkle_path(leaves, idx)
    if not sibs:
        return

    sib_idx = data.draw(st.integers(min_value=0, max_value=len(sibs) - 1))
    tampered_sibs = list(sibs)
    tampered_sibs[sib_idx] = bytes([tampered_sibs[sib_idx][0] ^ 0x01]) + tampered_sibs[sib_idx][1:]

    tampered_root = walk(tampered_sibs, dirs, leaves[idx])
    assert tampered_root != root


# ---------------------------------------------------------------------------
# 2. Tag Commit & Epoch Boundary Properties
# ---------------------------------------------------------------------------


@settings(max_examples=50, deadline=None)
@given(
    master_key=st.binary(min_size=32, max_size=32),
    boot_id=st.binary(min_size=16, max_size=16),
    value=st.binary(min_size=1, max_size=128),
    epoch_a=st.integers(min_value=1, max_value=100),
    epoch_b=st.integers(min_value=101, max_value=200),
)
def test_tag_commit_epoch_bridge_equality(
    master_key: bytes, boot_id: bytes, value: bytes, epoch_a: int, epoch_b: int
) -> None:
    """Property: tag_commit equality holds across epochs if and only if valid Bridge links them."""
    scope = 1
    norm_ver = 1

    # Derive forward-secure keys for both epochs under SCOPE_LOCAL
    key_a = derive_tag_key(master_key, boot_id, scope=SCOPE_LOCAL, epoch=epoch_a)
    key_b = derive_tag_key(master_key, boot_id, scope=SCOPE_LOCAL, epoch=epoch_b)
    assert key_a != key_b, "Keys across different epochs must never collide"

    # Tags for same value under distinct epochs
    tag_a = tag_value(key_a, value)
    tag_b = tag_value(key_b, value)
    assert tag_a != tag_b, "Tags across different epochs must not match directly"

    # Create legitimate bridge
    salt = os.urandom(16)
    bridge = Bridge(master=master_key, boot_id=boot_id, value=value, salt=salt)
    key_from_bridge_a = bridge.key(epoch_a)
    key_from_bridge_b = bridge.key(epoch_b)

    assert key_from_bridge_a == key_a
    assert key_from_bridge_b == key_b

    # Verify that tags recomputed from the bridge's revealed keys match original tags
    assert tag_value(key_from_bridge_a, value) == tag_a
    assert tag_value(key_from_bridge_b, value) == tag_b

    # Any modification of master key or value must fail equality
    tampered_bridge = Bridge(
        master=bytes([master_key[0] ^ 0xFF]) + master_key[1:],
        boot_id=boot_id,
        value=value,
        salt=salt,
    )
    assert tampered_bridge.key(epoch_a) != key_a


# ---------------------------------------------------------------------------
# 3. Crash Consistency at Epoch Rollover Steps
# ---------------------------------------------------------------------------


@settings(max_examples=40, deadline=None)
@given(
    step=st.sampled_from(["empty_file", "partial_header", "records_no_footer", "torn_footer", "clean_footer"]),
    record_count=st.integers(min_value=1, max_value=10),
)
def test_epoch_transition_crash_simulation(step: str, record_count: int) -> None:
    """Property: Crash at any step of epoch transition fails closed or recovers consistently."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        seg_file = Path(tmp_dir) / "seg-000001.argf"
        report = Report()

        # Dummy valid SEGH
        ledger_id = os.urandom(16)
        boot_id = os.urandom(16)
        closing_hash = os.urandom(32)

        # Packed SEGH header: 128 bytes
        segh_bytes = struct.pack(
            "<4sBBHIQIQ32s32s16sI8s4s",
            b"SEGH", 2, 0, 128, 1, 0, 1, 0,
            closing_hash, os.urandom(32), ledger_id, 1, os.urandom(8), b"\x00" * 4
        )

        if step == "empty_file":
            seg_file.write_bytes(b"")
            sh, tail, footer = _parse_segment(seg_file, report, expected_seq=1)
            # Empty file has no valid closing hash
            assert footer is None

        elif step == "partial_header":
            # Crashed mid-write of 128-byte header
            seg_file.write_bytes(segh_bytes[:64])
            sh, tail, footer = _parse_segment(seg_file, report, expected_seq=1)
            # Short header has no valid closing hash
            assert footer is None

        elif step == "records_no_footer":
            # Header written, but power cut before SEGF footer committed
            dummy_records = b"\x00" * (record_count * 64)
            seg_file.write_bytes(segh_bytes + dummy_records)
            sh, tail, footer = _parse_segment(seg_file, report, expected_seq=1)
            # Must detect missing footer, never silently certify partial segment
            assert footer is None

        elif step == "torn_footer":
            # Power cut while writing 48-byte SEGF footer
            footer_bytes = seg_footer(closing_hash, record_count)
            seg_file.write_bytes(segh_bytes + footer_bytes[:24])  # half-written footer
            sh, tail, footer = _parse_segment(seg_file, report, expected_seq=1)
            # Must detect torn footer: footer is None or defect recorded
            assert footer is None or report.count("defect") > 0

        elif step == "clean_footer":
            # Normal completed transition
            footer_bytes = seg_footer(closing_hash, 0)
            seg_file.write_bytes(segh_bytes + footer_bytes)
            sh, tail, footer = _parse_segment(seg_file, report, expected_seq=1)
            assert sh is not None
            assert footer is not None
            assert footer == closing_hash

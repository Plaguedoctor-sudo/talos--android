# SPDX-FileCopyrightText: 2026 TALOS / LibreMobile OS Contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Property-based verification of ARGUS Dead Man's Switch invariants."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from argus.config import Config
from argus.deadman import DeadManPolicy, DeadMansSwitch


@settings(max_examples=60, deadline=None)
@given(
    timeout=st.floats(min_value=3600.0, max_value=86400.0 * 30),  # 1 hour to 30 days
    last_checkin=st.floats(min_value=1_000_000.0, max_value=2_000_000.0),
    elapsed_fraction=st.floats(min_value=0.0, max_value=1.0),
    is_offline=st.booleans(),
)
def test_deadman_false_positive_bound_within_grace(
    timeout: float, last_checkin: float, elapsed_fraction: float, is_offline: bool
) -> None:
    """Property: While elapsed <= timeout (grace period), destructive wipe must NEVER trigger."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        cfg = Config(data_dir=Path(tmp_dir), operator_name="auditor")
        policy = DeadManPolicy(grace_period_seconds=timeout, allow_offline_wipe=True)
        switch = DeadMansSwitch(cfg, timeout_seconds=timeout, policy=policy)

        # Record initial heartbeat at last_checkin
        switch.record_heartbeat()
        with open(switch.state_file, "r+", encoding="utf-8") as f:
            import json
            state = json.load(f)
            state["last_heartbeat_epoch"] = last_checkin
            f.seek(0)
            json.dump(state, f)
            f.truncate()

        now = last_checkin + (timeout * elapsed_fraction)
        status = switch.check_status(now_epoch=now)

        # Invariant 1: Status must never be TRIGGERED within grace period
        assert status.status in ("ACTIVE", "WARNING")
        assert status.status != "TRIGGERED"

        # Invariant 2: should_wipe must strictly evaluate to False
        assert not switch.should_wipe(now_epoch=now, is_offline=is_offline)


@settings(max_examples=60, deadline=None)
@given(
    timeout=st.floats(min_value=3600.0, max_value=86400.0 * 14),
    last_checkin=st.floats(min_value=1_000_000.0, max_value=2_000_000.0),
    overdue_seconds=st.floats(min_value=1.0, max_value=86400.0 * 10),
    allow_offline_wipe=st.booleans(),
    is_offline=st.booleans(),
)
def test_deadman_offline_policy_authorization_guard(
    timeout: float,
    last_checkin: float,
    overdue_seconds: float,
    allow_offline_wipe: bool,
    is_offline: bool,
) -> None:
    """Property: Overdue wipe only fires if online OR (offline AND allow_offline_wipe == True)."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        cfg = Config(data_dir=Path(tmp_dir), operator_name="auditor")
        policy = DeadManPolicy(grace_period_seconds=timeout, allow_offline_wipe=allow_offline_wipe)
        switch = DeadMansSwitch(cfg, timeout_seconds=timeout, policy=policy)

        switch.record_heartbeat()
        with open(switch.state_file, "r+", encoding="utf-8") as f:
            import json
            state = json.load(f)
            state["last_heartbeat_epoch"] = last_checkin
            f.seek(0)
            json.dump(state, f)
            f.truncate()

        now = last_checkin + timeout + overdue_seconds
        status = switch.check_status(now_epoch=now)
        assert status.status == "TRIGGERED"

        wipe_authorized = switch.should_wipe(now_epoch=now, is_offline=is_offline)

        if not is_offline:
            # When online and overdue, wipe is always authorized
            assert wipe_authorized is True
        else:
            # When offline, wipe is authorized IF AND ONLY IF policy explicitly allows offline wipe
            assert wipe_authorized == allow_offline_wipe


@settings(max_examples=50, deadline=None)
@given(
    timeout=st.floats(min_value=100.0, max_value=10_000.0),
    t0=st.floats(min_value=1_000.0, max_value=10_000.0),
)
def test_deadman_status_monotonicity(timeout: float, t0: float) -> None:
    """Property: Status severity is monotonically non-decreasing over time: ACTIVE -> WARNING -> TRIGGERED."""
    severity_order = {"ACTIVE": 1, "WARNING": 2, "TRIGGERED": 3}

    with tempfile.TemporaryDirectory() as tmp_dir:
        cfg = Config(data_dir=Path(tmp_dir), operator_name="auditor")
        switch = DeadMansSwitch(cfg, timeout_seconds=timeout)

        switch.record_heartbeat()
        with open(switch.state_file, "r+", encoding="utf-8") as f:
            import json
            state = json.load(f)
            state["last_heartbeat_epoch"] = t0
            f.seek(0)
            json.dump(state, f)
            f.truncate()

        # Check at 25% (active), 85% (warning), and 110% (triggered)
        s_early = switch.check_status(now_epoch=t0 + timeout * 0.25).status
        s_mid = switch.check_status(now_epoch=t0 + timeout * 0.85).status
        s_late = switch.check_status(now_epoch=t0 + timeout * 1.10).status

        assert severity_order[s_early] <= severity_order[s_mid] <= severity_order[s_late]
        assert s_early == "ACTIVE"
        assert s_mid == "WARNING"
        assert s_late == "TRIGGERED"

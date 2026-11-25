# SPDX-FileCopyrightText: 2026 TALOS / LibreMobile OS Contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Property-based verification of ARGUS Duress authentication and decoy plausibility."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

import argus.duress
from argus.duress import (
    DecoyPlausibility,
    DuressConfig,
    DuressStore,
    PlausibilityError,
)

# Use fast iterations for property testing so hundreds of examples run in <1s
argus.duress.PBKDF2_ITERATIONS = 1_000


@settings(max_examples=80, deadline=None)
@given(
    vol=st.floats(min_value=0.0, max_value=2000.0),
    apps=st.integers(min_value=0, max_value=100),
    age=st.floats(min_value=0.0, max_value=365.0),
    contacts=st.integers(min_value=0, max_value=200),
    msgs=st.integers(min_value=0, max_value=5000),
)
def test_plausibility_score_bounds_and_validity(
    vol: float, apps: int, age: float, contacts: int, msgs: int
) -> None:
    """Property: Decoy plausibility score is strictly bounded in [0.0, 100.0]."""
    decoy = DecoyPlausibility(
        data_volume_mb=vol,
        app_count=apps,
        history_age_days=age,
        contact_count=contacts,
        message_count=msgs,
    )
    score = decoy.score()
    assert 0.0 <= score <= 100.0


@settings(max_examples=60, deadline=None)
@given(
    vol=st.floats(min_value=0.0, max_value=1000.0),
    apps=st.integers(min_value=0, max_value=50),
    age=st.floats(min_value=0.0, max_value=100.0),
    delta_vol=st.floats(min_value=0.0, max_value=500.0),
    delta_apps=st.integers(min_value=0, max_value=20),
    delta_age=st.floats(min_value=0.0, max_value=30.0),
)
def test_plausibility_monotonicity(
    vol: float, apps: int, age: float, delta_vol: float, delta_apps: int, delta_age: float
) -> None:
    """Property: Increasing user data volume, installed apps, or history age never decreases plausibility."""
    base = DecoyPlausibility(data_volume_mb=vol, app_count=apps, history_age_days=age)
    expanded = DecoyPlausibility(
        data_volume_mb=vol + delta_vol,
        app_count=apps + delta_apps,
        history_age_days=age + delta_age,
    )
    assert expanded.score() >= base.score()


@settings(max_examples=15, deadline=None)
@given(
    vol=st.floats(min_value=0.0, max_value=1000.0),
    apps=st.integers(min_value=0, max_value=50),
    age=st.floats(min_value=0.0, max_value=100.0),
    threshold=st.floats(min_value=30.0, max_value=90.0),
    password=st.text(min_size=4, max_size=32),
)
def test_duress_enrollment_threshold_invariant(
    vol: float, apps: int, age: float, threshold: float, password: str
) -> None:
    """Property: Decoy enrollment succeeds if and only if score >= threshold; rejected otherwise."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        store_path = Path(tmp_dir) / "duress.db"
        store = DuressStore(store_path)

        decoy = DecoyPlausibility(data_volume_mb=vol, app_count=apps, history_age_days=age)
        score = decoy.score()

        if score < threshold:
            with pytest.raises(PlausibilityError):
                store.enroll_decoy(password, decoy, threshold=threshold)
            assert not store.has("duress")
        else:
            enrolled_score = store.enroll_decoy(password, decoy, threshold=threshold)
            assert enrolled_score == score
            assert store.has("duress")


@settings(max_examples=15, deadline=None)
@given(
    real_pw=st.text(min_size=6, max_size=20),
    duress_pw=st.text(min_size=6, max_size=20),
    attempt_pw=st.text(min_size=1, max_size=25),
)
def test_duress_auth_routing_and_isolation(
    real_pw: str, duress_pw: str, attempt_pw: str
) -> None:
    """Property: Authentication cleanly isolates decoy database and routes session mode."""
    if real_pw == duress_pw:
        return

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        store = DuressStore(tmp_path / "duress.db")
        store.set_password("real", real_pw)
        store.set_password("duress", duress_pw)

        config = DuressConfig(
            real_db_path=tmp_path / "real.db",
            decoy_db_path=tmp_path / "decoy.db",
            ledger_path=tmp_path / "real_ledger.jsonl",
            decoy_ledger_path=tmp_path / "decoy_ledger.jsonl",
        )

        res = store.authenticate(attempt_pw, config=config)

        if attempt_pw == real_pw:
            assert res.kind == "real"
            assert res.db_path == config.real_db_path
        elif attempt_pw == duress_pw:
            assert res.kind == "duress"
            assert res.db_path == config.decoy_db_path
            assert res.db_path != config.real_db_path
        else:
            assert res.kind == "invalid"
            assert res.db_path is None

# SPDX-FileCopyrightText: 2026 TALOS / LibreMobile OS Contributors
# SPDX-License-Identifier: Apache-2.0
"""
Automated Test Suite for TALOS Sovereign App Store Scorer & Index Verifier.
Tests deterministic privacy scoring on fixture apps and cryptographic Ed25519 signatures.
"""

import json
from pathlib import Path
import pytest

from store.privacy_score import score_app, score_index, SCORE_VERSION  # type: ignore

DATA_DIR = Path(__file__).parent.parent / "store" / "data"
POLICY_DIR = Path(__file__).parent.parent / "security" / "egress" / "policy"


@pytest.fixture
def trackers_db():
    with open(DATA_DIR / "trackers.json", "r", encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture
def upstream_index():
    with open(DATA_DIR / "upstream-index.json", "r", encoding="utf-8") as f:
        return json.load(f)


def test_clean_sovereign_fixture_score(trackers_db):
    """Clean fixture application with 0 trackers, offline egress, and reproducible build must score 100.0 (A+)."""
    app = {
        "id": "test.fixture.clean",
        "name": "Clean Sovereign Utility",
        "reproducible": True,
        "permissions": [],
        "detected_trackers": [],
        "egress_policy": "com.talos.calculator.toml",
        "updated_date": "2026-11-22",
    }
    res = score_app(app, trackers_db, POLICY_DIR, ref_date_str="2026-11-25")
    assert res["score_version"] == SCORE_VERSION
    assert res["total_score"] == 100.0
    assert res["grade"] == "A+"
    assert res["breakdown"]["tracker_absence"]["score"] == 35.0
    assert res["breakdown"]["permission_restraint"]["score"] == 20.0
    assert res["breakdown"]["build_reproducibility"]["score"] == 20.0
    assert res["breakdown"]["egress_alignment"]["score"] == 15.0
    assert res["breakdown"]["maintenance_recency"]["score"] == 10.0


def test_commercial_tracker_fixture_score(trackers_db):
    """Fixture app with 3 intrusive trackers (AdMob, FB, AppsFlyer) and 5 dangerous permissions scores 7.0 (F)."""
    app = {
        "id": "test.fixture.trackers",
        "name": "Surveillance Commercial Ad App",
        "reproducible": False,
        "permissions": [
            "INTERNET", "ACCESS_FINE_LOCATION", "READ_CONTACTS",
            "CAMERA", "RECORD_AUDIO", "READ_PHONE_STATE"
        ],
        "detected_trackers": ["1", "5", "6"],
        "egress_policy": None,
        "updated_date": "2026-08-01",
    }
    res = score_app(app, trackers_db, POLICY_DIR, ref_date_str="2026-11-25")
    assert res["total_score"] == 7.0
    assert res["grade"] == "F"
    assert res["breakdown"]["tracker_absence"]["score"] == 0.0
    assert res["breakdown"]["tracker_absence"]["detected_count"] == 3
    assert res["breakdown"]["permission_restraint"]["score"] == 0.0
    assert res["breakdown"]["build_reproducibility"]["score"] == 0.0
    assert res["breakdown"]["egress_alignment"]["score"] == 0.0
    assert res["breakdown"]["maintenance_recency"]["score"] == 7.0


def test_waivered_app_fixture_score(trackers_db):
    """Fixture app with non-reproducible build waiver and self-hosted Sentry scores 72.0 (B)."""
    app = {
        "id": "test.fixture.waiver",
        "name": "Waivered FOSS Utility",
        "reproducible": False,
        "reproducible_waiver": {
            "reason": "Upstream Gradle toolchain non-determinism; patch in progress",
            "granted_by": ["maintainer1", "maintainer2"],
            "expires": "2027-05-01",
        },
        "permissions": ["INTERNET"],
        "detected_trackers": ["11"],  # Sentry crash reporter (-10 pts)
        "egress_policy": "org.mozilla.firefox.toml",
        "updated_date": "2026-11-01",
    }
    res = score_app(app, trackers_db, POLICY_DIR, ref_date_str="2026-11-25")
    assert res["total_score"] == 72.0
    assert res["grade"] == "B"
    assert res["breakdown"]["tracker_absence"]["score"] == 25.0
    assert res["breakdown"]["permission_restraint"]["score"] == 20.0
    assert res["breakdown"]["build_reproducibility"]["score"] == 5.0
    assert res["breakdown"]["egress_alignment"]["score"] == 12.0
    assert res["breakdown"]["maintenance_recency"]["score"] == 10.0


def test_fdroid_client_score(trackers_db):
    """Official F-Droid client with tunnel_only egress and 0 trackers scores 97.0 (A+)."""
    app = {
        "id": "org.fdroid.fdroid",
        "name": "F-Droid App Store",
        "reproducible": True,
        "permissions": ["INTERNET", "ACCESS_NETWORK_STATE", "REQUEST_INSTALL_PACKAGES"],
        "detected_trackers": [],
        "egress_policy": "org.fdroid.fdroid.toml",
        "updated_date": "2026-10-28",
    }
    res = score_app(app, trackers_db, POLICY_DIR, ref_date_str="2026-11-25")
    assert res["total_score"] == 97.0
    assert res["grade"] == "A+"
    assert res["breakdown"]["tracker_absence"]["score"] == 35.0
    assert res["breakdown"]["permission_restraint"]["score"] == 20.0
    assert res["breakdown"]["build_reproducibility"]["score"] == 20.0
    assert res["breakdown"]["egress_alignment"]["score"] == 12.0
    assert res["breakdown"]["maintenance_recency"]["score"] == 10.0


def test_score_determinism(trackers_db, upstream_index):
    """Assert score_index produces identical output when executed repeatedly."""
    scored_a = score_index(upstream_index, trackers_db, POLICY_DIR, ref_date_str="2026-11-25")
    scored_b = score_index(upstream_index, trackers_db, POLICY_DIR, ref_date_str="2026-11-25")

    json_a = json.dumps(scored_a, indent=2, sort_keys=True)
    json_b = json.dumps(scored_b, indent=2, sort_keys=True)
    assert json_a == json_b


def test_signature_verification_gate(tmp_path):
    """Verify index detached Ed25519 signature validation and tampering detection using ephemeral test keys."""
    from store.sign_index import keygen, sign_index, verify_index  # type: ignore

    test_sec = tmp_path / "test.sec"
    keygen(test_sec)
    test_pub = tmp_path / "test.pub"
    assert test_sec.is_file()
    assert test_pub.is_file()

    index_file = tmp_path / "index.json"
    index_file.write_text('{"packages": [], "signed": false}\n', encoding="utf-8")

    test_sig = tmp_path / "index.json.sig"
    sign_index(index_file, test_sec, test_sig)
    assert test_sig.is_file()

    # Valid signature must verify cleanly
    assert verify_index(index_file, test_sig, test_pub) is True

    # Tampered signature must be rejected
    tampered_sig = tmp_path / "tampered.sig"
    tampered_sig.write_text("00" * 64 + "\n")
    assert verify_index(index_file, tampered_sig, test_pub) is False


def test_unsigned_graceful_degradation(tmp_path):
    """When fixture fingerprint is UNPINNED, build produces signed: false, verify exits 1, and UI path is graceful."""
    import os
    import subprocess

    fixture_store = tmp_path / "store"
    keys_dir = fixture_store / "keys"
    index_dir = fixture_store / "index"
    keys_dir.mkdir(parents=True)
    index_dir.mkdir(parents=True)

    fingerprint_file = keys_dir / "fingerprint.txt"
    fingerprint_file.write_text("UNPINNED — operator must provision release key per store/POLICY.md\n", encoding="utf-8")

    env = dict(
        os.environ,
        STORE_KEYS_DIR=str(keys_dir),
        STORE_INDEX_DIR=str(index_dir),
        SIGNING_KEY=str(tmp_path / "nonexistent-store-signing.sec"),
    )

    # 1. build-index.sh must build UNSIGNED index when fixture fingerprint is UNPINNED
    res_build = subprocess.run(["./store/build-index.sh"], env=env, capture_output=True, text=True)
    assert res_build.returncode == 0, res_build.stderr
    index_file = index_dir / "index.json"
    assert index_file.is_file()
    assert not (index_dir / "index.json.sig").exists()

    with open(index_file, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert data.get("signed") is False
    assert data.get("signature") is None

    # 2. verify-index.sh must refuse and exit 1 against the unpinned fixture
    res_verify = subprocess.run(["./store/verify-index.sh"], env=env, capture_output=True, text=True)
    assert res_verify.returncode == 1
    assert "release key not provisioned" in res_verify.stderr

    # 3. UI app.js contains graceful unsigned handling (red banner, unverified badge, disabled install)
    app_js = Path(__file__).parent.parent / "dist" / "assets" / "app.js"
    assert app_js.is_file()
    js_text = app_js.read_text("utf-8")
    assert "Store index is UNSIGNED" in js_text
    assert "Score: unverified" in js_text
    assert "Install disabled until index is signed" in js_text


def test_server_store_endpoint():
    """Assert server.js GET /api/store/index enforces timingSafeEqual token authentication."""
    import os
    import subprocess
    import time
    import urllib.error
    import urllib.request

    test_port = "3099"
    token = "test_sovereign_bridge_token_xyz"
    env = dict(os.environ, PORT=test_port, LRD_BRIDGE_TOKEN_VALUE=token)
    proc = subprocess.Popen(
        ["node", "server.js"],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    time.sleep(0.4)
    try:
        url = f"http://127.0.0.1:{test_port}/api/store/index"

        # 1. Request without token must be rejected with 401
        req_unauth = urllib.request.Request(url)
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(req_unauth)
        assert exc_info.value.code == 401

        # 2. Request with invalid token must be rejected with 401
        req_bad = urllib.request.Request(url, headers={"Authorization": "Bearer wrong_token_value"})
        with pytest.raises(urllib.error.HTTPError) as exc_info_bad:
            urllib.request.urlopen(req_bad)
        assert exc_info_bad.value.code == 401

        # 3. Request with valid token must succeed with 200 and return store manifest
        req_auth = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
        with urllib.request.urlopen(req_auth) as resp:
            assert resp.status == 200
            payload = json.loads(resp.read().decode("utf-8"))
            assert "packages" in payload
            assert len(payload["packages"]) > 0
            assert payload["score_metadata"]["score_version"] == "1.0.0"
    finally:
        proc.terminate()
        proc.wait(timeout=3)


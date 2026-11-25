# SPDX-FileCopyrightText: 2026 TALOS / LibreMobile OS Contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""
Targeted tests to push line and branch coverage of ARGUS audit scope files
(argus/argf2/writer.py, argus/verify/verify.py, argus/verify/findings.py,
 argus/duress.py, and argus/deadman.py) above the 85% audit floor.
"""

import os
import struct
import tempfile
import pathlib
import pytest
import cbor2
from blake3 import blake3

from argus.argf2.writer import (
    normalize_host, derive_tag_key, derive_salt, genesis, entry_hash,
    Field, TagField, Bridge, RecordBuilder
)
from argus.verify.record import (
    Header, SegHeader, SegFooter, leaf, merkle_root, merkle_path,
    tag_value, tag_leaf, tag_digest, SCOPE_LOCAL, SCOPE_GLOBAL,
    SEGH_LEN, SEGF_LEN, HDR_LEN, SEG_MAGIC, SEGF_MAGIC
)
from argus.verify import findings as F
from argus.verify.bundle import Bundle
from argus.verify.trust import Keyring
from argus.verify.verify import (
    _entry_hash, _parse_segment, _walk_records, _phase_7c, _phase_7d, run
)
from argus.config import Config
from argus.duress import DuressStore, DuressConfig, hash_password, verify_password, DecoyPlausibility
from argus.deadman import DeadMansSwitch, DeadManPolicy


# ==============================================================================
# 1. argus/argf2/writer.py Tests
# ==============================================================================

def test_normalize_host():
    """Verify host normalization across string, bytes, port strippings."""
    assert normalize_host("example.com") == b"example.com"
    assert normalize_host(b"EXAMPLE.COM.") == b"example.com"
    assert normalize_host("api.talos.os:443") == b"api.talos.os"
    assert normalize_host(b"web.service.org:80") == b"web.service.org"
    assert normalize_host("custom.port.net:8443") == b"custom.port.net:8443"
    assert normalize_host("  SUB.DOMAIN.ORG:443.  ") == b"sub.domain.org"


def test_writer_cryptographic_helpers():
    """Verify derive_tag_key, derive_salt, genesis, entry_hash."""
    master = b"M" * 32
    boot_id = b"B" * 32
    build_hash = b"H" * 32

    # Global vs local tag keys
    gk = derive_tag_key(master, boot_id, SCOPE_GLOBAL, gen=2)
    assert len(gk) == 32
    lk = derive_tag_key(master, boot_id, SCOPE_LOCAL, epoch=5)
    assert len(lk) == 32
    assert gk != lk

    # Salt derivation
    salt = derive_salt(master, boot_id, seg_seq=1, nonce=42)
    assert len(salt) == 16

    # Genesis calculation
    gen = genesis(boot_id, build_hash, seg_seq=0)
    assert len(gen) == 32

    # Entry hash calculation
    h = Header(ver=2, cls=1, type=2, payload_len=0, seq=1, mono_ns=100, wall_ns=100,
               cgroup_id=0, uid=0, nonce=10, payload_root=b"R"*32, reserved=b"0"*8)
    eh = entry_hash(b"P"*32, h)
    assert len(eh) == 32


def test_record_builder_all_field_types():
    """Test RecordBuilder with sealed, open, and tag fields."""
    rb = RecordBuilder(cls=1, type_=0x0201)
    tag_key = b"K" * 32
    rb.set_tag_key(SCOPE_LOCAL, tag_key)
    rb.set_tag_key(SCOPE_GLOBAL, tag_key)

    rb.add("plain_field", b"sealed_content", cls="sealed")
    rb.add("open_field", b"public_content", cls="open")
    rb.add(Field("field_obj", b"obj_content", cls="sealed"))
    rb.add(TagField(b"tagged_val_1", SCOPE_LOCAL, norm_ver=1, epoch=2, of=0, key=tag_key))
    rb.add_tag(b"tagged_val_2", SCOPE_GLOBAL, norm_ver=1, epoch=2)

    salt = b"S" * 16
    h, body, openings = rb.build(seq=1, mono_ns=1000, salt=salt, nonce=99, epoch=2)
    assert h.seq == 1
    assert len(body) > 0
    assert len(openings) == 1
    assert openings[0]["name"] == "open_field"
    assert h.reserved != b"\0" * 8


def test_bridge_serialization():
    """Test Bridge cross-epoch key revelation and CBOR conversion."""
    master = b"M" * 32
    boot_id = b"B" * 32
    b = Bridge(master, boot_id, value=b"entity_val", salt=b"S"*16)
    k1 = b.key(1)
    k2 = b.key(2)
    assert len(k1) == 32
    assert len(k2) == 32
    assert k1 != k2

    cbor_dict = b.to_cbor(rec_a=10, fld_a=1, rec_b=20, fld_b=2)
    assert cbor_dict["record_seq_a"] == 10
    assert cbor_dict["field_a"] == 1
    assert "1" in cbor_dict["epoch_keys"]
    assert "2" in cbor_dict["epoch_keys"]


# ==============================================================================
# 2. argus/verify/verify.py & findings.py Coverage Tests
# ==============================================================================

def test_parse_segment_edge_cases(tmp_path):
    """Test _parse_segment with valid, malformed, AFTR, and plain segments."""
    rep = F.Report()

    # 1. Plain file without headers
    plain = tmp_path / "plain.seg"
    plain.write_bytes(b"some arbitrary raw data")
    sh, body, closing = _parse_segment(plain, rep, expected_seq=0)
    assert sh is not None
    assert body == b"some arbitrary raw data"
    assert closing is None

    # 2. Short segment with SEG_MAGIC but shorter than header + footer
    bad_short = tmp_path / "short.seg"
    bad_short.write_bytes(SEG_MAGIC + b"\x00" * 10)
    sh2, body2, closing2 = _parse_segment(bad_short, rep, expected_seq=1)
    assert rep.count(F.FATAL) > 0 or rep.count(F.DEFECT) > 0

    # 3. Valid ARGF/2 segment with Header and Footer
    valid_seg = tmp_path / "valid.seg"
    sh_obj = SegHeader(seg_seq=2, epoch=1, epoch_len=7, prev_seg_hash=b"P"*32, boot_id=b"B"*32)
    sf_obj = SegFooter(closing_hash=b"C"*32, record_count=0)
    valid_seg.write_bytes(sh_obj.encode() + sf_obj.encode())
    sh3, body3, closing3 = _parse_segment(valid_seg, rep, expected_seq=2)
    assert sh3.seg_seq == 2
    assert closing3 == b"C" * 32

    # 4. AFTR legacy segment
    aftr_seg = tmp_path / "aftr.seg"
    aftr_data = b"BODY_DATA" + b"AFTR" + b"X" * 32 + b"Y" * 36
    aftr_seg.write_bytes(aftr_data)
    sh4, body4, closing4 = _parse_segment(aftr_seg, rep, expected_seq=3)
    assert sh4.seg_seq == 3
    assert closing4 == b"X" * 32


def test_walk_records_edge_cases():
    """Test _walk_records with truncated header and malformed records."""
    rep = F.Report()
    # 1. Truncated header
    data = b"ARGF" + b"\x00" * 10
    headers = _walk_records(data, rep, seg_seq=0)
    assert len(headers) == 0
    assert rep.count(F.DEFECT) > 0

    # 2. Valid header followed by truncated payload
    rep2 = F.Report()
    h = Header(ver=2, cls=1, type=1, payload_len=50, seq=1, mono_ns=100, wall_ns=100,
               cgroup_id=0, uid=0, nonce=1, payload_root=b"R"*32, reserved=b"0"*8)
    data2 = h.encode() + b"short_payload"
    headers2 = _walk_records(data2, rep2, seg_seq=0)
    assert len(headers2) == 0
    assert rep2.count(F.DEFECT) > 0


def test_phase_7c_tag_validation():
    """Test _phase_7c with valid tags, invalid scopes, epoch mismatches, and digest mismatches."""
    sh = SegHeader(seg_seq=0, epoch=5, epoch_len=7)

    # 1. Valid local tag
    rep = F.Report()
    tag_val = b"\x11" * 16
    entry = {"cls": "tag", "scope": SCOPE_LOCAL, "v": tag_val, "epoch": 5, "norm_ver": 1, "i": 0, "name": "tag"}
    tl = tag_leaf(1, 0, b"tag", SCOPE_LOCAL, 1, 5, tag_val)
    td = tag_digest([tl])
    pld = cbor2.dumps([entry], canonical=True)
    h = Header(ver=2, cls=1, type=1, payload_len=len(pld), seq=1, mono_ns=100, wall_ns=100,
               cgroup_id=0, uid=0, nonce=1, payload_root=b"R"*32, reserved=td)
    data = h.encode() + pld

    tleaves, seen_of = _phase_7c(data, [h], sh, rep, seg_seq=0)
    assert len(tleaves) == 1
    assert rep.count(F.DEFECT) == 0

    # 2. Tag with wrong epoch and digest mismatch
    rep2 = F.Report()
    entry_bad = {"cls": "tag", "scope": SCOPE_LOCAL, "v": tag_val, "epoch": 999, "norm_ver": 0, "i": 0, "name": "tag"}
    pld2 = cbor2.dumps([entry_bad], canonical=True)
    h2 = Header(ver=2, cls=1, type=1, payload_len=len(pld2), seq=2, mono_ns=100, wall_ns=100,
                cgroup_id=0, uid=0, nonce=2, payload_root=b"R"*32, reserved=b"BAD_DIGS")
    data2 = h2.encode() + pld2
    _phase_7c(data2, [h2], sh, rep2, seg_seq=0)
    assert rep2.count(F.DEFECT) > 0
    assert rep2.count(F.NOTICE) > 0  # norm_ver notice


def test_phase_7d_bridge_validation(tmp_path):
    """Test _phase_7d bridge verification with missing and unparseable bridges."""
    rep = F.Report()
    proof_dir = tmp_path / "proofs"
    proof_dir.mkdir(parents=True)

    # 1. Unparseable bridge file
    bad_bridge = proof_dir / "bridge-000001.cbor"
    bad_bridge.write_bytes(b"NOT_CBOR")

    # 2. Bridge referencing missing record
    bridge_data = {
        "record_seq_a": 100, "field_a": 0,
        "record_seq_b": 200, "field_b": 0,
        "epoch_keys": {"1": b"K"*32, "2": b"K"*32}
    }
    good_bridge = proof_dir / "bridge-000002.cbor"
    good_bridge.write_bytes(cbor2.dumps(bridge_data))

    bridged = _phase_7d(proof_dir, seg_index={}, report=rep)
    assert (100, 200) in bridged
    assert rep.count(F.DEFECT) >= 2


def test_verifier_run_grade_paths(tmp_path):
    """Test verifier run() method across various fatal and anomaly conditions."""
    # Build minimal valid bundle
    bundle_dir = tmp_path / "test_bundle"
    keys_dir = bundle_dir / "keys"
    keys_dir.mkdir(parents=True)
    manifest_file = bundle_dir / "manifest.cbor"
    manifest_data = {"anchors": [], "segments": [], "argx_version": 1}
    manifest_file.write_bytes(cbor2.dumps(manifest_data, canonical=True))

    # Missing root key triggers Phase 2 Fatal
    b = Bundle(bundle_dir)
    keyring = Keyring(tmp_path)
    rep = run(b, keyring, strict=False, scope_check=False, require_open=[], min_reveal=None)
    assert rep.grade == "INDETERMINATE"
    assert rep.count(F.FATAL) > 0


def test_findings_exit_codes_and_sort():
    rep = F.Report()
    assert rep.exit_code(strict=False) == 0
    assert rep.exit_code(strict=True) == 0

    # Notice
    rep.add(F.NOTICE, "N-1", "notice")
    assert rep.exit_code(strict=False) == 0
    assert rep.exit_code(strict=True) == 2

    # Anomaly
    rep.add(F.ANOMALY, "A-1", "anomaly")
    assert rep.exit_code(strict=False) == 1
    assert rep.exit_code(strict=True) == 2

    # Defect
    rep.add(F.DEFECT, "D-1", "defect")
    assert rep.exit_code(strict=False) == 2
    assert rep.exit_code(strict=True) == 2

    # Fatal general
    rep.add(F.FATAL, "V-604", "fatal")
    assert rep.exit_code(strict=False) == 2

    # Fatal V-5
    rep.add(F.FATAL, "V-501", "checkpoint fatal")
    assert rep.exit_code(strict=False) == 3

    # Sorting
    f1 = F.Finding(F.DEFECT, "D-2", "desc", seg_seq=1, offset=10)
    f2 = F.Finding(F.DEFECT, "D-1", "desc", seg_seq=0, offset=5)
    f3 = F.Finding(F.FATAL, "F-1", "desc", seg_seq=None, offset=None)
    assert f1.sort_key() == (1, 10, "D-2")
    assert f3.sort_key() == (-1, -1, "F-1")
    rep.findings = [f1, f3, f2]
    ordered = rep.ordered()
    assert ordered[0] == f3
    assert ordered[1] == f2
    assert ordered[2] == f1


def test_verifier_phases_and_mutations(tmp_path):
    from tests.verify.test_grade import _make_roundtrip_bundle
    bundle, keyring, dev, keys, signer = _make_roundtrip_bundle(tmp_path / "phases", producer_mode="audit")

    # Run direct on valid bundle
    b = Bundle.open(bundle)
    kr = Keyring(keyring)
    rep = run(b, kr, strict=True, scope_check=True, require_open=[], min_reveal=0.0)
    assert rep.grade == "SEALED"
    assert rep.count(F.FATAL) == 0
    assert rep.count(F.DEFECT) == 0

    # Scope check with FULL scope declaring omissions
    b_scope = Bundle.open(bundle)
    omissions_file = bundle / "omissions.cbor"
    omissions_data = {"scope": "FULL", "omitted": [{"kind": "SEGMENT_RANGE"}]}
    omissions_file.write_bytes(cbor2.dumps(omissions_data))
    rep_sc = run(b_scope, kr, strict=False, scope_check=True, require_open=[], min_reveal=None)
    assert rep_sc.count(F.DEFECT) > 0

    # Missing segment file on disk
    segs = list((bundle / "segments").glob("*.seg"))
    if segs:
        segs[0].unlink()
    b_broken = Bundle.open(bundle)
    rep_broken = run(b_broken, kr, strict=False, scope_check=False, require_open=[], min_reveal=None)
    assert rep_broken.count(F.DEFECT) > 0


def test_verifier_coverage_edge_cases(tmp_path):
    """Cover remaining verify.py edge cases: openings, scope CASE, trust exceptions, missing cp."""
    from tests.verify.test_grade import _make_roundtrip_bundle, _remanifest
    bundle, keyring, dev, keys, signer = _make_roundtrip_bundle(tmp_path / "edge_cases", producer_mode="audit")

    # 1. Missing bundle.sig
    sig_file = bundle / "bundle.sig"
    sig_backup = sig_file.read_bytes()
    sig_file.unlink()
    # also remove parent sigs if any
    for s in (bundle.parent / "bundle.sig", bundle.parent / f"{bundle.name}.sig"):
        if s.exists():
            s.unlink()
    b = Bundle.open(bundle)
    kr = Keyring(keyring)
    rep = run(b, kr, strict=False, scope_check=False, require_open=[], min_reveal=None)
    assert rep.count(F.FATAL) > 0  # V-604 bundle.sig missing
    sig_file.write_bytes(sig_backup)

    # 2. Scope CASE
    m = cbor2.loads((bundle / "manifest.cbor").read_bytes())
    m["scope"] = "CASE"
    (bundle / "manifest.cbor").write_bytes(cbor2.dumps(m, canonical=True))
    _remanifest(bundle, dev)
    rep_case = run(Bundle.open(bundle), kr, strict=False, scope_check=False, require_open=[], min_reveal=None)
    assert rep_case.grade == "FILTERED"
    m["scope"] = "FULL"
    (bundle / "manifest.cbor").write_bytes(cbor2.dumps(m, canonical=True))
    _remanifest(bundle, dev)

    # 3. Missing checkpoint file
    m["anchors"].append({"seg_seq": 999, "file": "anchors/cp-missing.cbor"})
    (bundle / "manifest.cbor").write_bytes(cbor2.dumps(m, canonical=True))
    _remanifest(bundle, dev)
    rep_cp = run(Bundle.open(bundle), kr, strict=False, scope_check=False, require_open=[], min_reveal=None)
    assert rep_cp.count(F.DEFECT) > 0  # V-501 checkpoint missing
    m["anchors"].pop()
    (bundle / "manifest.cbor").write_bytes(cbor2.dumps(m, canonical=True))
    _remanifest(bundle, dev)

    # 4. Openings test vectors
    pdir = bundle / "proofs"
    pdir.mkdir(parents=True, exist_ok=True)
    # unparseable opening
    (pdir / "open-000001.cbor").write_bytes(b"NOT_CBOR")
    # opening for unexported segment
    (pdir / "open-000002.cbor").write_bytes(cbor2.dumps({"seg_seq": 888}))
    # opening for missing record
    (pdir / "open-000003.cbor").write_bytes(cbor2.dumps({"seg_seq": 0, "record_seq": 999}))
    # field out of range
    (pdir / "open-000004.cbor").write_bytes(cbor2.dumps({"seg_seq": 0, "record_seq": 1, "field": 999}))
    # root mismatch
    (pdir / "open-000005.cbor").write_bytes(cbor2.dumps({
        "seg_seq": 0, "record_seq": 1, "field": 0, "name": "bad",
        "value": b"x", "salt": b"y", "path": [], "path_dirs": []
    }))
    rep_open = run(Bundle.open(bundle), kr, strict=False, scope_check=False, require_open=[], min_reveal=None)
    assert rep_open.count(F.DEFECT) >= 4

    # 5. Unreadable attestation
    att_file = bundle / "attestation.cbor"
    att_backup = att_file.read_bytes()
    att_file.write_bytes(b"BAD_ATTESTATION")
    rep_att = run(b, kr, strict=False, scope_check=False, require_open=[], min_reveal=None)
    assert rep_att.count(F.NOTICE) > 0  # V-903 attestation unreadable
    att_file.write_bytes(att_backup)


def test_trust_and_bundle_edge_cases(tmp_path):
    """Cover trust.py and bundle.py edge cases."""
    from argus.verify.trust import load_pubkey, load_cert, cert_signed_by
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization

    # 1. Non-ed25519 key rejected by load_pubkey
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rsa_pem = rsa_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with pytest.raises(ValueError, match="not ed25519"):
        load_pubkey(rsa_pem)

    # 2. Keyring get method
    kr = Keyring(tmp_path)
    assert kr.get("nonexistent_fingerprint") is None

    # 3. Keyring skipping non-ed25519 pem file
    (tmp_path / "rsa.pem").write_bytes(rsa_pem)
    (tmp_path / "invalid.pem").write_bytes(b"NOT_A_PEM")
    kr2 = Keyring(tmp_path)
    assert len(kr2.keys) == 0

    # 4. Bundle tar archive opening and closing
    import tarfile
    bundle_dir = tmp_path / "b_dir"
    bundle_dir.mkdir()
    man_data = {"argx_version": 1, "files": []}
    (bundle_dir / "manifest.cbor").write_bytes(cbor2.dumps(man_data, canonical=True))
    tar_path = tmp_path / "bundle.tar"
    with tarfile.open(tar_path, "w") as tf:
        tf.add(bundle_dir / "manifest.cbor", arcname="manifest.cbor")

    b_tar = Bundle.open(tar_path)
    assert b_tar.manifest.get("argx_version") == 1
    assert "manifest.cbor" in b_tar.all_files()
    b_tar.close()




# ==============================================================================
# 3. argus/duress.py & argus/deadman.py Edge Cases
# ==============================================================================

def test_duress_edge_cases(tmp_path):
    """Cover duress store enrollment, authentication, and plausibility scoring."""
    store_file = tmp_path / "duress.db"
    ds = DuressStore(store_file)

    assert not ds.has("real")
    assert not ds.has("duress")

    # Enroll credentials
    ds.set_password("real", "real_master_secret")
    ds.set_password("duress", "coerced_duress_secret")
    assert ds.has("real")
    assert ds.has("duress")

    cfg = DuressConfig(
        real_db_path=tmp_path / "real.db",
        decoy_db_path=tmp_path / "decoy.db",
        ledger_path=tmp_path / "ledger",
    )

    # Authenticate real
    res_real = ds.authenticate("real_master_secret", config=cfg)
    assert res_real.kind == "real"
    assert res_real.db_path == cfg.real_db_path

    # Authenticate duress
    duress_called = []
    res_duress = ds.authenticate("coerced_duress_secret", config=cfg, on_duress=lambda: duress_called.append(True))
    assert res_duress.kind == "duress"
    assert res_duress.db_path == cfg.decoy_db_path
    assert len(duress_called) == 1

    # Authenticate invalid
    res_bad = ds.authenticate("invalid_attempt", config=cfg)
    assert res_bad.kind == "invalid"
    assert res_bad.db_path is None

    # Password hashing and verify edge cases
    salt_hex, hash_hex = hash_password("test_pass")
    assert verify_password("test_pass", salt_hex, hash_hex) is True
    assert verify_password("wrong_pass", salt_hex, hash_hex) is False
    assert verify_password("", salt_hex, hash_hex) is False
    assert verify_password("test_pass", "bad_hex", hash_hex) is False


def test_deadman_switch_edge_cases(tmp_path):
    """Cover deadman switch checkins, wipe conditions, and escalation protocol."""
    cfg = Config()
    cfg.data_dir = tmp_path / "deadman_data"
    cfg.ledger_path = tmp_path / "deadman_ledger"
    cfg.init_directories()

    key_buf = bytearray(b"0123456789ABCDEF0123456789ABCDEF")
    dm = DeadMansSwitch(cfg, timeout_seconds=60.0, session_key=key_buf)

    # Initial state without checkin
    assert dm.should_wipe(now_epoch=100.0) is False
    assert dm.check_status(now_epoch=100.0).status == "UNINITIALIZED"

    # Escalation on uninitialized returns NONE
    res_none = dm.execute_escalation_protocol()
    assert res_none["action"] == "NONE"

    # Record heartbeat
    dm.record_heartbeat(operator="security_officer", note="Daily checkin")

    import json
    with open(dm.state_file, "r+", encoding="utf-8") as f:
        st_data = json.load(f)
        st_data["last_heartbeat_epoch"] = 100.0
        f.seek(0)
        json.dump(st_data, f)
        f.truncate()

    # Active status
    st_active = dm.check_status(now_epoch=120.0)
    assert st_active.status == "ACTIVE"
    assert dm.should_wipe(now_epoch=120.0, is_offline=False) is False

    # Warning status (elapsed 50s > 60*0.75 = 45s)
    st_warn = dm.check_status(now_epoch=150.0)
    assert st_warn.status == "WARNING"
    assert dm.should_wipe(now_epoch=150.0, is_offline=False) is False

    # Triggered status (elapsed 70s > 60s)
    st_trig = dm.check_status(now_epoch=170.0)
    assert st_trig.status == "TRIGGERED"
    assert dm.should_wipe(now_epoch=170.0, is_offline=False) is True
    assert dm.should_wipe(now_epoch=170.0, is_offline=True) is False

    # Execute escalation protocol when triggered
    # (state epoch needs to be relative to current timebase for execute_escalation_protocol)
    with open(dm.state_file, "r+", encoding="utf-8") as f:
        st_data = json.load(f)
        st_data["last_heartbeat_epoch"] = 10.0  # long ago
        f.seek(0)
        json.dump(st_data, f)
        f.truncate()

    res_esc = dm.execute_escalation_protocol()
    assert res_esc["action"] == "ESCALATED"
    assert res_esc["status"] == "TRIGGERED"
    assert res_esc["report"].executed is True


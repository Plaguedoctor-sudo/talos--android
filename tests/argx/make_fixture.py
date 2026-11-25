#!/usr/bin/env python3
"""Generates the test fixture bundle for argus-verify and tag tests."""
from __future__ import annotations
import os, sys, pathlib, datetime, struct
import cbor2
from blake3 import blake3

deps = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.deps"))
if os.path.exists(deps) and deps not in sys.path:
    sys.path.insert(0, deps)
repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.x509.oid import NameOID

from argus.verify.trust import fingerprint
from argus.verify.record import (
    SegHeader, SegFooter, SCOPE_LOCAL, SCOPE_GLOBAL, tag_value, ledger_root
)
from argus.argf2.writer import (
    RecordBuilder, TagField, Bridge, entry_hash, genesis, derive_salt, derive_tag_key, NORM_VER
)


def make_cert(subject_name: str, priv: Ed25519PrivateKey, issuer_priv: Ed25519PrivateKey) -> bytes:
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_name)]))
    builder = builder.issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "TALOS Root CA")]))
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = builder.not_valid_before(now - datetime.timedelta(days=1))
    builder = builder.not_valid_after(now + datetime.timedelta(days=365))
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(priv.public_key())
    cert = builder.sign(private_key=issuer_priv, algorithm=None)
    return cert.public_bytes(serialization.Encoding.PEM)


def generate():
    here = pathlib.Path(__file__).parent
    fix_root = here / "fixtures"
    bundle_dir = fix_root / "basic.argx"
    keyring_dir = fix_root / "keyring"

    import shutil
    if bundle_dir.exists():
        shutil.rmtree(bundle_dir)

    for d in [
        bundle_dir / "keys",
        bundle_dir / "segments",
        bundle_dir / "anchors",
        bundle_dir / "proofs",
        keyring_dir,
    ]:
        d.mkdir(parents=True, exist_ok=True)

    # 1. Generate keys
    root_priv = Ed25519PrivateKey.generate()
    dev_priv = Ed25519PrivateKey.generate()
    cp_priv = Ed25519PrivateKey.generate()

    root_pub_pem = root_priv.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    dev_pub_pem = dev_priv.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    cp_pub_pem = cp_priv.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )

    dev_cert_pem = make_cert("TALOS Device", dev_priv, root_priv)
    cp_cert_pem = make_cert("TALOS Checkpoint", cp_priv, root_priv)

    (bundle_dir / "keys/root.pem").write_bytes(root_pub_pem)
    (bundle_dir / "keys/device.pem").write_bytes(dev_pub_pem)
    (bundle_dir / "keys/device.cert.pem").write_bytes(dev_cert_pem)
    (bundle_dir / "keys/checkpoint.pem").write_bytes(cp_pub_pem)
    (bundle_dir / "keys/checkpoint.cert.pem").write_bytes(cp_cert_pem)

    root_fp = fingerprint(root_priv.public_key())
    (keyring_dir / "root.pem").write_bytes(root_pub_pem)
    (keyring_dir / "device.pem").write_bytes(dev_pub_pem)
    (keyring_dir / "checkpoint.pem").write_bytes(cp_pub_pem)
    (keyring_dir / "allowed_roots.txt").write_text(f"{root_fp}\n")

    # 2. Base parameters
    boot_id = b"talos-boot-001"
    build_hash = b"\xaa" * 32
    master_key = b"\x55" * 32

    epoch_4 = 4
    epoch_5 = 5
    k_loc4 = derive_tag_key(master_key, boot_id, SCOPE_LOCAL, epoch=epoch_4)
    k_loc5 = derive_tag_key(master_key, boot_id, SCOPE_LOCAL, epoch=epoch_5)
    host_target = b"tracker.example.net"

    # 3. Segments
    # -------------------------------------------------------------
    # Segment 0 (Epoch 4)
    # -------------------------------------------------------------
    ledger_id = b"\xaa" * 32
    sh0 = SegHeader(ver=1, feed_ver=2, flags=0, seg_seq=0, epoch=epoch_4, epoch_len=7,
                    first_seq=0, prev_seg_hash=ledger_root(ledger_id), build_hash=build_hash,
                    boot_id=boot_id, record_count=2)
    seg0_data = bytearray(sh0.encode())
    prev = ledger_root(ledger_id)

    # Rec 0: SESSION_OPEN (0x0101)
    b0 = RecordBuilder(0x4B, 0x0101)
    b0.add("boot_id", boot_id, "sealed")
    b0.add("build", build_hash, "open")
    salt0 = derive_salt(master_key, boot_id, 0, 100)
    h0, body0, _ = b0.build(seq=0, mono_ns=1000, salt=salt0, nonce=100, epoch=epoch_4)
    seg0_data.extend(h0.encode())
    seg0_data.extend(body0)
    prev = entry_hash(prev, h0)

    # Rec 1: GRANT (0x0201)
    b1 = RecordBuilder(0x53, 0x0201)
    b1.add("cap", b"camera", "sealed")
    b1.add("scope", b"while-in-use", "sealed")
    salt1 = derive_salt(master_key, boot_id, 0, 101)
    h1, body1, _ = b1.build(seq=1, mono_ns=2000, salt=salt1, nonce=101, epoch=epoch_4)
    seg0_data.extend(h1.encode())
    seg0_data.extend(body1)
    prev = entry_hash(prev, h1)

    # Footer seg 0
    seg0_closing = prev
    sf0 = SegFooter(closing_hash=seg0_closing, record_count=2)
    seg0_data.extend(sf0.encode())
    (bundle_dir / "segments/000000.seg").write_bytes(bytes(seg0_data))

    # -------------------------------------------------------------
    # Segment 1 (Epoch 4): with Tag and GAP
    # -------------------------------------------------------------
    sh1 = SegHeader(ver=1, feed_ver=2, flags=0, seg_seq=1, epoch=epoch_4, epoch_len=7,
                    first_seq=2, prev_seg_hash=seg0_closing, build_hash=build_hash,
                    boot_id=boot_id, record_count=2)
    seg1_data = bytearray(sh1.encode())
    prev = seg0_closing

    # Rec 2: FLOW_OPEN (0x0301) with Tag on field 0
    b2 = RecordBuilder(0x4B, 0x0301)
    b2.set_tag_key(SCOPE_LOCAL, k_loc4)
    b2.add("host", host_target, "open")
    b2.add_tag(host_target, scope=SCOPE_LOCAL, norm_ver=NORM_VER, epoch=epoch_4, of=0)
    salt2 = derive_salt(master_key, boot_id, 1, 202)
    h2, body2, ops2 = b2.build(seq=2, mono_ns=3000, salt=salt2, nonce=202, epoch=epoch_4)
    seg1_data.extend(h2.encode())
    seg1_data.extend(body2)
    prev = entry_hash(prev, h2)

    # Save proof for rec 2, field 0 (the open host)
    p2 = ops2[0]
    proof2 = {
        "seg_seq": 1,
        "record_seq": 2,
        "field": p2["field"],
        "name": p2["name"],
        "class": "open",
        "value": p2["value"],
        "length": len(p2["value"]),
        "salt": p2["salt"],
        "path": p2["path"],
        "path_dirs": p2["path_dirs"],
    }
    (bundle_dir / "proofs/open-000001-000002-0.cbor").write_bytes(cbor2.dumps(proof2, canonical=True))

    # Rec 3: GAP (0x0F01)
    gap_body = cbor2.dumps({"class": "K", "count": 37, "reason": "RING_FULL"}, canonical=True)
    b3 = RecordBuilder(0x4B, 0x0F01)
    b3.add("gap", gap_body, "sealed")
    salt3 = derive_salt(master_key, boot_id, 1, 203)
    h3, body3, _ = b3.build(seq=3, mono_ns=4000, salt=salt3, nonce=203, epoch=epoch_4)
    seg1_data.extend(h3.encode())
    seg1_data.extend(body3)
    prev = entry_hash(prev, h3)

    # Footer seg 1
    seg1_closing = prev
    sf1 = SegFooter(closing_hash=seg1_closing, record_count=2)
    seg1_data.extend(sf1.encode())
    (bundle_dir / "segments/000001.seg").write_bytes(bytes(seg1_data))

    # -------------------------------------------------------------
    # Segment 2 (Epoch 5): with Tag, Open field, and CLOCK_STEP
    # -------------------------------------------------------------
    sh2 = SegHeader(ver=1, feed_ver=2, flags=0, seg_seq=2, epoch=epoch_5, epoch_len=7,
                    first_seq=4, prev_seg_hash=seg1_closing, build_hash=build_hash,
                    boot_id=boot_id, record_count=2)
    seg2_data = bytearray(sh2.encode())
    prev = seg1_closing

    # Rec 4: FLOW_CLOSE (0x0302) with Tag on field 0
    b4 = RecordBuilder(0x4B, 0x0302)
    b4.set_tag_key(SCOPE_LOCAL, k_loc5)
    b4.add("host", host_target, "open")
    b4.add_tag(host_target, scope=SCOPE_LOCAL, norm_ver=NORM_VER, epoch=epoch_5, of=0)
    salt4 = derive_salt(master_key, boot_id, 2, 304)
    h4, body4, ops4 = b4.build(seq=4, mono_ns=5000, salt=salt4, nonce=304, epoch=epoch_5)
    seg2_data.extend(h4.encode())
    seg2_data.extend(body4)
    prev = entry_hash(prev, h4)

    # Save proof for rec 4, field 0
    p4 = ops4[0]
    proof4 = {
        "seg_seq": 2,
        "record_seq": 4,
        "field": p4["field"],
        "name": p4["name"],
        "class": "open",
        "value": p4["value"],
        "length": len(p4["value"]),
        "salt": p4["salt"],
        "path": p4["path"],
        "path_dirs": p4["path_dirs"],
    }
    (bundle_dir / "proofs/open-000002-000004-0.cbor").write_bytes(cbor2.dumps(proof4, canonical=True))

    # Rec 5: CLOCK_STEP (0x0103)
    b5 = RecordBuilder(0x4B, 0x0103)
    b5.add("old", b"100000", "sealed")
    b5.add("new", b"105000", "sealed")
    salt5 = derive_salt(master_key, boot_id, 2, 305)
    h5, body5, _ = b5.build(seq=5, mono_ns=6000, salt=salt5, nonce=305, epoch=epoch_5)
    seg2_data.extend(h5.encode())
    seg2_data.extend(body5)
    prev = entry_hash(prev, h5)

    # Footer seg 2
    seg2_closing = prev
    sf2 = SegFooter(closing_hash=seg2_closing, record_count=2)
    seg2_data.extend(sf2.encode())
    (bundle_dir / "segments/000002.seg").write_bytes(bytes(seg2_data))

    # 4. Bridge proof across epoch 4 (rec 2, field 1) and epoch 5 (rec 4, field 1)
    bridge = Bridge(master_key, boot_id, host_target, salt2)
    bridge.key(epoch_4)
    bridge.key(epoch_5)
    bridge_cbor = bridge.to_cbor(rec_a=2, fld_a=1, rec_b=4, fld_b=1)
    (bundle_dir / "proofs/bridge-000001.cbor").write_bytes(cbor2.dumps(bridge_cbor, canonical=True))

    # 5. Checkpoints (anchors)
    def sign_cp(seg_seq: int, closing_hash: bytes) -> bytes:
        digest = blake3(struct.pack("<I", seg_seq) + closing_hash).digest()
        sig = cp_priv.sign(digest)
        cp_obj = {
            "seg_seq": seg_seq,
            "closing_hash": closing_hash,
            "sig": sig,
            "time_ns": 1000000,
        }
        return cbor2.dumps(cp_obj, canonical=True)

    (bundle_dir / "anchors/cp-000000.cbor").write_bytes(sign_cp(0, seg0_closing))
    (bundle_dir / "anchors/cp-000001.cbor").write_bytes(sign_cp(1, seg1_closing))
    (bundle_dir / "anchors/cp-000002.cbor").write_bytes(sign_cp(2, seg2_closing))
    (bundle_dir / "anchors/cp-000003.cbor").write_bytes(sign_cp(3, blake3(b"future-seg-3").digest()))

    # 6. Ancillary files
    cover_text = "ARGUS Chain of Custody Export Bundle\nScope: RANGE\n"
    (bundle_dir / "cover.txt").write_text(cover_text)

    attestation = {
        "build_hash": build_hash.hex(),
        "boot_id": boot_id.decode(),
        "conformance_level": "TIER_A",
        "session_open_digest": blake3(b"session-0").digest(),
        "producer_mode": "audit",
    }
    att_raw = cbor2.dumps(attestation, canonical=True)
    (bundle_dir / "attestation.cbor").write_bytes(att_raw)

    omissions = {
        "scope": "RANGE",
        "omitted": [
            {
                "kind": "SEGMENT_RANGE",
                "from_seg": 3,
                "to_seg": 100,
                "reason": "after_range",
                "bracketed_by": "cp-000003",
            }
        ],
        "chain_gaps_present": True,
    }
    om_raw = cbor2.dumps(omissions, canonical=True)
    (bundle_dir / "omissions.cbor").write_bytes(om_raw)

    redactions = {"policy": "default", "redacted_count": 0, "records": []}
    (bundle_dir / "redactions.cbor").write_bytes(cbor2.dumps(redactions, canonical=True))

    selfverify = {"grade": "GAPPED", "findings_count": 1, "verified_at_mono_ns": 7000}
    (bundle_dir / "selfverify.cbor").write_bytes(cbor2.dumps(selfverify, canonical=True))

    # 7. Manifest
    all_files_list = []
    for p in sorted(bundle_dir.rglob("*")):
        if p.is_file() and p.name not in ("manifest.cbor", "bundle.sig"):
            rel = p.relative_to(bundle_dir).as_posix()
            content = p.read_bytes()
            all_files_list.append({
                "path": rel,
                "size": len(content),
                "blake3": blake3(content).digest(),
            })

    def seg_entry(seq: int):
        f = bundle_dir / f"segments/{seq:06d}.seg"
        cnt = f.read_bytes()
        return {
            "seg_seq": seq,
            "first_seq": seq * 2,
            "last_seq": seq * 2 + 1,
            "expected_record_count": 2,
            "file": f"segments/{seq:06d}.seg",
            "blake3": blake3(cnt).digest(),
            "size": len(cnt),
        }

    manifest = {
        "argx_version": 1,
        "bundle_id": b"\x12\x34\x56\x78" * 4,
        "ledger_id": ledger_id,
        "created_mono_ns": 100000,
        "created_wall_ns": 1700000000000000000,
        "device": {
            "model_hash": "talos-phone-01",
            "build_hash": build_hash.hex(),
            "boot_id": boot_id.decode(),
        },
        "operator": {
            "label": "field-op-01",
            "key_fingerprint": root_fp,
        },
        "purpose": "demonstration and testing",
        "scope": "RANGE",
        "range": {"from_mono_ns": 1000, "to_mono_ns": 6000},
        "case_tags": None,
        "expected_record_count": 6,
        "segments": [seg_entry(0), seg_entry(1), seg_entry(2)],
        "anchors": [
            {"seg_seq": 0, "file": "anchors/cp-000000.cbor", "blake3": blake3((bundle_dir / "anchors/cp-000000.cbor").read_bytes()).digest()},
            {"seg_seq": 1, "file": "anchors/cp-000001.cbor", "blake3": blake3((bundle_dir / "anchors/cp-000001.cbor").read_bytes()).digest()},
            {"seg_seq": 2, "file": "anchors/cp-000002.cbor", "blake3": blake3((bundle_dir / "anchors/cp-000002.cbor").read_bytes()).digest()},
            {"seg_seq": 3, "file": "anchors/cp-000003.cbor", "blake3": blake3((bundle_dir / "anchors/cp-000003.cbor").read_bytes()).digest()},
        ],
        "payload_mode": "PARTIAL",
        "redaction_policy": "default",
        "files": all_files_list,
        "omissions_digest": blake3(om_raw).digest(),
        "attestation_digest": blake3(att_raw).digest(),
    }

    manifest_cbor = cbor2.dumps(manifest, canonical=True)
    (bundle_dir / "manifest.cbor").write_bytes(manifest_cbor)

    # 8. Signature
    manifest_hash = blake3(manifest_cbor).digest()
    sig = dev_priv.sign(manifest_hash)
    (fix_root / "basic.argx.sig").write_bytes(sig)
    (bundle_dir / "bundle.sig").write_bytes(sig)
    print("Fixture generated at:", bundle_dir)


if __name__ == "__main__":
    generate()

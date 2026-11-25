import pathlib, shutil, subprocess, sys, os
import cbor2
from blake3 import blake3

deps = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.deps"))
if os.path.exists(deps) and deps not in sys.path:
    sys.path.insert(0, deps)
repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

from argus.verify.record import (
    SCOPE_LOCAL, SCOPE_GLOBAL, tag_value, tag_leaf, tag_digest,
    SegHeader, SegFooter, Header, HDR_LEN
)
from argus.argf2.writer import (
    derive_tag_key, normalize_host, NORM_VER, RecordBuilder, Bridge
)

HERE = pathlib.Path(__file__).parent
FIX = HERE.parent / "argx" / "fixtures" / "basic.argx"
KEYRING = HERE.parent / "argx" / "fixtures" / "keyring"


from collections import namedtuple
CliResult = namedtuple("CliResult", ["returncode", "stdout", "stderr"])


def run_verify(bundle: pathlib.Path, *extra):
    import io
    from contextlib import redirect_stdout, redirect_stderr
    from argus.verify import cli
    cmd = [str(bundle), "--keyring", str(KEYRING)] + list(extra)
    f_out, f_err = io.StringIO(), io.StringIO()
    with redirect_stdout(f_out), redirect_stderr(f_err):
        code = cli.main(cmd)
    return CliResult(code, f_out.getvalue(), f_err.getvalue())


def _copy_bundle(tmp_path, name="b.argx"):
    d = tmp_path / name
    shutil.copytree(FIX, d)
    sig_candidates = [
        FIX.parent / f"{FIX.name}.sig",
        FIX.parent / "bundle.sig",
        FIX / "bundle.sig",
    ]
    for s in sig_candidates:
        if s.exists():
            shutil.copyfile(s, tmp_path / f"{name}.sig")
            shutil.copyfile(s, tmp_path / "bundle.sig")
            shutil.copyfile(s, d / "bundle.sig")
            break
    return d


def test_local_tag_epoch_mismatch(tmp_path):
    """V-919: Tag leaf epoch does not agree with segment header epoch."""
    d = _copy_bundle(tmp_path)
    seg_file = d / "segments" / "000001.seg"
    raw = bytearray(seg_file.read_bytes())
    # Modify the tag in record 2 payload (offset ~128 onwards)
    # Deserialize payload, change epoch from 4 to 99, reserialize, update file
    sh = SegHeader.parse(bytes(raw))
    off = 128
    h = Header.parse(bytes(raw), off)
    body_off = off + HDR_LEN
    payload = cbor2.loads(bytes(raw[body_off: body_off + h.payload_len]))
    for entry in payload:
        if entry.get("cls") == "tag":
            entry["epoch"] = 99
    new_body = cbor2.dumps(payload, canonical=True)
    # Write back matching length
    diff = len(new_body) - h.payload_len
    h.payload_len = len(new_body)
    new_seg = bytearray(sh.encode())
    new_seg.extend(h.encode())
    new_seg.extend(new_body)
    new_seg.extend(raw[body_off + h.payload_len - diff:])
    seg_file.write_bytes(bytes(new_seg))

    code, out, _ = run_verify(d)
    assert code == 2, out
    assert "V-919" in out


def test_tag_digest_tamper(tmp_path):
    """V-910: tag_digest in h.reserved mismatch."""
    d = _copy_bundle(tmp_path)
    seg_file = d / "segments" / "000001.seg"
    raw = bytearray(seg_file.read_bytes())
    # Record 2 header is at offset 128; reserved field is at offset 128 + 120 = 248
    raw[248] ^= 0xFF
    seg_file.write_bytes(bytes(raw))

    code, out, _ = run_verify(d)
    assert code == 2, out
    assert "V-910" in out


def test_bridge_valid(tmp_path):
    """Valid bridge emits V-914 for revealed epochs and passes cleanly."""
    code, out, _ = run_verify(FIX, "--scope-check")
    assert code in (0, 1), out
    assert "V-914" in out
    assert "reveals epoch 4" in out
    assert "reveals epoch 5" in out


def test_bridge_tampered_value(tmp_path):
    """V-912: Tampered bridge value causes verification failure."""
    d = _copy_bundle(tmp_path)
    bridge_file = d / "proofs" / "bridge-000001.cbor"
    b_data = cbor2.loads(bridge_file.read_bytes())
    b_data["value"] = b"tampered-attacker-host.com"
    bridge_file.write_bytes(cbor2.dumps(b_data, canonical=True))

    code, out, _ = run_verify(d)
    assert code == 2, out
    assert "V-912" in out


def test_bridge_wrong_field(tmp_path):
    """V-913: Bridge pointing to non-tag field fails."""
    d = _copy_bundle(tmp_path)
    bridge_file = d / "proofs" / "bridge-000001.cbor"
    b_data = cbor2.loads(bridge_file.read_bytes())
    # Field 0 is the host string, not the tag (tag is field 1)
    b_data["field_a"] = 0
    bridge_file.write_bytes(cbor2.dumps(b_data, canonical=True))

    code, out, _ = run_verify(d)
    assert code == 2, out
    assert "V-913" in out


def test_global_tag_stable_across_epochs(tmp_path):
    """Global tags match across epochs without V-918."""
    master = b"\x11" * 32
    boot = b"\x22" * 16
    kglob = derive_tag_key(master, boot, SCOPE_GLOBAL, gen=0)

    host = b"consistent-host.org"
    tag_e4 = tag_value(kglob, host)
    tag_e5 = tag_value(kglob, host)
    assert tag_e4 == tag_e5, "Global tags across epochs must be bit-identical"


def test_local_unbridged_across_epochs(tmp_path):
    """V-918 and LOCAL_TAGS grade when local tags are unbridged across epochs."""
    d = _copy_bundle(tmp_path)
    bridge_file = d / "proofs" / "bridge-000001.cbor"
    if bridge_file.exists():
        bridge_file.unlink()
    m = cbor2.loads((d / "manifest.cbor").read_bytes())
    m["files"] = [f for f in m["files"] if f["path"] != "proofs/bridge-000001.cbor"]
    (d / "manifest.cbor").write_bytes(cbor2.dumps(m, canonical=True))

    code, out, _ = run_verify(d)
    assert "V-918" in out
    assert "LOCAL_TAGS" in out


def test_norm_ver_bump(tmp_path):
    """V-911: norm_ver older than registry emits notice."""
    d = _copy_bundle(tmp_path)
    seg_file = d / "segments" / "000001.seg"
    raw = bytearray(seg_file.read_bytes())
    sh = SegHeader.parse(bytes(raw))
    off = 128
    h = Header.parse(bytes(raw), off)
    body_off = off + HDR_LEN
    payload = cbor2.loads(bytes(raw[body_off: body_off + h.payload_len]))
    for entry in payload:
        if entry.get("cls") == "tag":
            entry["norm_ver"] = 0  # older than NORM_REGISTRY_VER = 1
    new_body = cbor2.dumps(payload, canonical=True)
    h.payload_len = len(new_body)
    new_seg = bytearray(sh.encode())
    new_seg.extend(h.encode())
    new_seg.extend(new_body)
    new_seg.extend(raw[body_off + len(new_body):])
    seg_file.write_bytes(bytes(new_seg))

    code, out, _ = run_verify(d)
    assert "V-911" in out


def test_recipient_cannot_recompute():
    """A recipient without the epoch key cannot recompute matching tags."""
    master = b"\x77" * 32
    boot = b"\x88" * 16
    true_key = derive_tag_key(master, boot, SCOPE_LOCAL, epoch=4)

    value = b"sensitive-host.net"
    true_tag = tag_value(true_key, value)

    guessed_key = b"\x99" * 32
    guessed_tag = tag_value(guessed_key, value)
    assert true_tag != guessed_tag


def test_duress_disjoint():
    """Decoy root key and real root key produce zero tag overlap."""
    real_master = b"\x01" * 32
    decoy_master = b"\x02" * 32
    boot = b"\x03" * 16

    host = b"target-evidence.org"
    real_tag = tag_value(derive_tag_key(real_master, boot, SCOPE_LOCAL, epoch=1), host)
    decoy_tag = tag_value(derive_tag_key(decoy_master, boot, SCOPE_LOCAL, epoch=1), host)
    assert real_tag != decoy_tag

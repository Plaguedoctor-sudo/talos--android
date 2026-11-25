import os, pathlib, shutil, subprocess, sys, time
import cbor2
from blake3 import blake3
from cryptography.hazmat.primitives import serialization
from tests.e2e.test_roundtrip import _pki, BOOT, BUILD
from argus.argf2.ledger import LedgerWriter
from argus.argf2.writer import RecordBuilder
from argus.argf2.signers import CheckpointSigner
from argus.argf2.export import Exporter


def _setup_ledger_with_segments(tmp_path, num_records=12, rotate_bytes=350):
    keys, keyring, dev, cp = _pki(tmp_path)
    signer = CheckpointSigner(
        cp.private_bytes(serialization.Encoding.PEM,
                         serialization.PrivateFormat.PKCS8,
                         serialization.NoEncryption()),
        tmp_path / "ledger" / "anchors")

    wr = LedgerWriter(tmp_path / "ledger", b"\x33" * 32, BOOT, BUILD,
                      lambda: (0, 604800), signer=signer, rotate_bytes=rotate_bytes)
    wr.open_session(b"\x55" * 32)
    for i in range(num_records):
        b = RecordBuilder(0x4B, 0x0801)
        b.add("path_hash", f"record-{i:04d}".encode() + b"\x44" * 5, "open")
        wr.write(b, 0x4B)
        time.sleep(0.001)
    wr.seal()
    return keys, keyring, dev, signer


from collections import namedtuple
CliResult = namedtuple("CliResult", ["returncode", "stdout", "stderr"])


def _run_cli(bundle, keyring, *args):
    import io
    from contextlib import redirect_stdout, redirect_stderr
    from argus.verify import cli
    cmd_args = [str(bundle), "--keyring", str(keyring)] + list(args)
    f_out, f_err = io.StringIO(), io.StringIO()
    with redirect_stdout(f_out), redirect_stderr(f_err):
        code = cli.main(cmd_args)
    return CliResult(code, f_out.getvalue(), f_err.getvalue())


def test_range_excludes_interior(tmp_path):
    keys, keyring, dev, signer = _setup_ledger_with_segments(tmp_path)
    segs = sorted((tmp_path / "ledger").glob("*.seg"))
    dev_pem = dev.private_bytes(serialization.Encoding.PEM,
                                serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
    ex = Exporter(tmp_path / "ledger", tmp_path / "b_range", keys, dev_pem, signer)

    # Select segments 2..3
    lo = ex._seq_bounds(segs[2])[0]
    hi = ex._seq_bounds(segs[3])[1]
    bundle = ex.run("range_export", "tester", scope="RANGE", seq_range=(lo, hi))

    man = cbor2.loads((bundle / "manifest.cbor").read_bytes())
    assert [s["seg_seq"] for s in man["segments"]] == [2, 3]

    om = cbor2.loads((bundle / "omissions.cbor").read_bytes())
    assert {o["reason"] for o in om["omitted"]} == {"before_range", "after_range"}

    r = _run_cli(bundle, keyring, "--scope-check")
    assert r.returncode in (0, 1), f"CLI failed: {r.stdout}\n{r.stderr}"
    assert "V-701" not in r.stdout
    assert "V-703" not in r.stdout


def test_range_boundary_trimmed_fires_703(tmp_path):
    keys, keyring, dev, signer = _setup_ledger_with_segments(tmp_path)
    segs = sorted((tmp_path / "ledger").glob("*.seg"))
    dev_pem = dev.private_bytes(serialization.Encoding.PEM,
                                serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
    ex = Exporter(tmp_path / "ledger", tmp_path / "b_range_trimmed", keys, dev_pem, signer)

    lo = ex._seq_bounds(segs[2])[0]
    hi = ex._seq_bounds(segs[3])[1]
    bundle = ex.run("range_export", "tester", scope="RANGE", seq_range=(lo, hi))

    # Drop a record from the first exported segment (000002.seg)
    from argus.verify.record import Header, HDR_LEN, SEGF_LEN, SEGH_LEN
    seg_file = bundle / "segments" / "000002.seg"
    data = seg_file.read_bytes()
    h = Header.parse(data, SEGH_LEN)
    first_rec_end = SEGH_LEN + HDR_LEN + h.payload_len
    truncated = data[:first_rec_end] + data[-SEGF_LEN:]
    seg_file.write_bytes(truncated)

    # Re-manifest and re-sign
    man = cbor2.loads((bundle / "manifest.cbor").read_bytes())
    for s in man["segments"]:
        if s["seg_seq"] == 2:
            s["blake3"] = blake3(truncated).digest()
            s["size"] = len(truncated)
    for f in man["files"]:
        if f["path"] == "segments/000002.seg":
            f["blake3"] = blake3(truncated).digest()
            f["size"] = len(truncated)

    raw = cbor2.dumps(man, canonical=True)
    (bundle / "manifest.cbor").write_bytes(raw)
    sig = dev.sign(blake3(raw).digest())
    (bundle / "bundle.sig").write_bytes(sig)
    (bundle.parent / "bundle.sig").write_bytes(sig)
    (bundle.parent / f"{bundle.name}.sig").write_bytes(sig)

    r = _run_cli(bundle, keyring, "--scope-check")
    assert "V-703" in r.stdout


def test_full_still_has_no_omissions(tmp_path):
    keys, keyring, dev, signer = _setup_ledger_with_segments(tmp_path)
    dev_pem = dev.private_bytes(serialization.Encoding.PEM,
                                serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
    ex = Exporter(tmp_path / "ledger", tmp_path / "b_full", keys, dev_pem, signer)
    bundle = ex.run("full_export", "tester", scope="FULL")
    om = cbor2.loads((bundle / "omissions.cbor").read_bytes())
    assert om["omitted"] == []

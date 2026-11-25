import os, pathlib, subprocess, sys
import cbor2
from blake3 import blake3
from cryptography.hazmat.primitives import serialization
from tests.e2e.test_roundtrip import _pki
from argus.argf2.ledger import LedgerWriter
from argus.argf2.writer import RecordBuilder
from argus.argf2.signers import CheckpointSigner
from argus.argf2.export import Exporter
from argus.verify.record import SegHeader, SegFooter, SEGF_LEN

BOOT1 = b"\x11" * 16
BOOT2 = b"\x22" * 16
BUILD = b"\x33" * 32
MASTER = b"\x44" * 32
MEASURE = b"\x55" * 32


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


def test_chain_survives_reboot(tmp_path):
    ledger_dir = tmp_path / "ledger"
    wr1 = LedgerWriter(ledger_dir, MASTER, BOOT1, BUILD, lambda: (0, 604800))
    wr1.open_session(MEASURE)
    b = RecordBuilder(0x4B, 0x0801)
    b.add("path_hash", b"\x01" * 16, "open")
    wr1.write(b, 0x4B)
    wr1.seal()

    s0_data = (ledger_dir / "000000.seg").read_bytes()
    sf0 = SegFooter.parse(s0_data[-SEGF_LEN:])
    closing_hash_0 = sf0.closing_hash

    # Reboot: new writer with BOOT2
    wr2 = LedgerWriter(ledger_dir, MASTER, BOOT2, BUILD, lambda: (0, 604800))
    wr2.open_session(MEASURE)
    b = RecordBuilder(0x4B, 0x0801)
    b.add("path_hash", b"\x02" * 16, "open")
    wr2.write(b, 0x4B)
    wr2.seal()

    s1_data = (ledger_dir / "000001.seg").read_bytes()
    sh1 = SegHeader.parse(s1_data)
    assert sh1.prev_seg_hash == closing_hash_0
    assert sh1.boot_id == BOOT2


def test_boot_boundary_is_info_not_defect(tmp_path):
    keys, keyring, dev, cp = _pki(tmp_path)
    ledger_dir = tmp_path / "ledger"
    signer = CheckpointSigner(
        cp.private_bytes(serialization.Encoding.PEM,
                         serialization.PrivateFormat.PKCS8,
                         serialization.NoEncryption()),
        ledger_dir / "anchors")

    wr1 = LedgerWriter(ledger_dir, MASTER, BOOT1, BUILD, lambda: (0, 604800), signer=signer)
    wr1.open_session(MEASURE)
    b = RecordBuilder(0x4B, 0x0801)
    b.add("path_hash", b"\x01" * 16, "open")
    wr1.write(b, 0x4B)
    wr1.seal()

    wr2 = LedgerWriter(ledger_dir, MASTER, BOOT2, BUILD, lambda: (0, 604800), signer=signer)
    wr2.open_session(MEASURE)
    b = RecordBuilder(0x4B, 0x0801)
    b.add("path_hash", b"\x02" * 16, "open")
    wr2.write(b, 0x4B)
    wr2.seal()

    dev_pem = dev.private_bytes(serialization.Encoding.PEM,
                                serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
    ex = Exporter(ledger_dir, tmp_path / "bundle", keys, dev_pem, signer)
    bundle = ex.run("multiboot_test", "tester")

    r = _run_cli(bundle, keyring)
    assert r.returncode in (0, 1), f"CLI failed: {r.stdout}\n{r.stderr}"
    assert "V-105" in r.stdout
    assert "V-102" not in r.stdout
    assert "V-103" not in r.stdout


def test_ledger_root_mismatch_fires_103(tmp_path):
    keys, keyring, dev, cp = _pki(tmp_path)
    ledger_dir = tmp_path / "ledger"
    signer = CheckpointSigner(
        cp.private_bytes(serialization.Encoding.PEM,
                         serialization.PrivateFormat.PKCS8,
                         serialization.NoEncryption()),
        ledger_dir / "anchors")

    wr = LedgerWriter(ledger_dir, MASTER, BOOT1, BUILD, lambda: (0, 604800), signer=signer)
    wr.open_session(MEASURE)
    b = RecordBuilder(0x4B, 0x0801)
    b.add("path_hash", b"\x01" * 16, "open")
    wr.write(b, 0x4B)
    wr.seal()

    dev_pem = dev.private_bytes(serialization.Encoding.PEM,
                                serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
    ex = Exporter(ledger_dir, tmp_path / "bundle", keys, dev_pem, signer)
    bundle = ex.run("root_test", "tester")

    # Tamper with ledger_id in manifest.cbor
    man = cbor2.loads((bundle / "manifest.cbor").read_bytes())
    man["ledger_id"] = b"\xff" * 32
    raw = cbor2.dumps(man, canonical=True)
    (bundle / "manifest.cbor").write_bytes(raw)
    sig = dev.sign(blake3(raw).digest())
    (bundle / "bundle.sig").write_bytes(sig)
    (bundle.parent / "bundle.sig").write_bytes(sig)
    (bundle.parent / f"{bundle.name}.sig").write_bytes(sig)

    r = _run_cli(bundle, keyring)
    assert "V-103" in r.stdout
    assert r.returncode == 2

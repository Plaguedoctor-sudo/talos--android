import pathlib, shutil, subprocess, sys
import cbor2
import pytest
from blake3 import blake3
from cryptography.hazmat.primitives import serialization
from tests.e2e.test_roundtrip import _pki, BOOT, BUILD
from argus.argf2.ledger import LedgerWriter
from argus.argf2.writer import RecordBuilder
from argus.argf2.signers import CheckpointSigner
from argus.argf2.export import Exporter, ExportError


def _make_roundtrip_bundle(tmp_path, producer_mode="audit"):
    keys, keyring, dev, cp = _pki(tmp_path)
    signer = CheckpointSigner(
        cp.private_bytes(serialization.Encoding.PEM,
                         serialization.PrivateFormat.PKCS8,
                         serialization.NoEncryption()),
        tmp_path / "ledger" / "anchors")

    wr = LedgerWriter(tmp_path / "ledger", b"\x33" * 32, BOOT, BUILD,
                      lambda: (0, 604800), signer=signer, rotate_bytes=400)
    wr.open_session(b"\x55" * 32)
    b = RecordBuilder(0x4B, 0x0F08)
    b.add("mode", producer_mode.encode(), "open")
    b.add("reason", b"test_setup", "open")
    wr.write(b, 0x4B)
    for _ in range(4):
        b = RecordBuilder(0x4B, 0x0801)
        b.add("path_hash", b"\x44" * 16, "open")
        wr.write(b, 0x4B)
    wr.seal()

    dev_pem = dev.private_bytes(serialization.Encoding.PEM,
                                serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
    ex = Exporter(tmp_path / "ledger", tmp_path / "bundle", keys, dev_pem, signer)
    bundle = ex.run("grade_test", "tester")
    return bundle, keyring, dev, keys, signer


def _run_cli(bundle, keyring, *args):
    import io
    from contextlib import redirect_stdout, redirect_stderr
    from argus.verify import cli

    cmd_args = [str(bundle), "--keyring", str(keyring)] + list(args)
    f_out = io.StringIO()
    f_err = io.StringIO()
    with redirect_stdout(f_out), redirect_stderr(f_err):
        code = cli.main(cmd_args)
    return code, f_out.getvalue(), f_err.getvalue()


def _remanifest(bundle, dev):
    man = cbor2.loads((bundle / "manifest.cbor").read_bytes())
    for f in man["files"]:
        p = bundle / f["path"]
        f["blake3"] = blake3(p.read_bytes()).digest()
        f["size"] = p.stat().st_size
    man["attestation_digest"] = blake3((bundle / "attestation.cbor").read_bytes()).digest()
    raw = cbor2.dumps(man, canonical=True)
    (bundle / "manifest.cbor").write_bytes(raw)
    sig = dev.sign(blake3(raw).digest())
    (bundle / "bundle.sig").write_bytes(sig)
    (bundle.parent / "bundle.sig").write_bytes(sig)
    (bundle.parent / f"{bundle.name}.sig").write_bytes(sig)


def test_degraded_cannot_grade_sealed(tmp_path):
    bundle, keyring, dev, _, _ = _make_roundtrip_bundle(tmp_path, producer_mode="audit")

    # Rewrite attestation to producer_mode=degraded, re-manifest and re-sign
    att = {"conformance": "fixture", "producer_mode": "degraded"}
    (bundle / "attestation.cbor").write_bytes(cbor2.dumps(att, canonical=True))
    _remanifest(bundle, dev)

    code, out, _ = _run_cli(bundle, keyring, "--strict")
    assert "grade         GAPPED" in out
    assert "V-903" in out
    assert code == 2          # ANOMALY under --strict


def test_audit_mode_grades_sealed(tmp_path):
    bundle, keyring, _, _, _ = _make_roundtrip_bundle(tmp_path, producer_mode="audit")
    code, out, _ = _run_cli(bundle, keyring, "--strict")
    assert "grade         SEALED" in out
    assert "V-903" not in out
    assert code == 0


def test_checkpoint_key_mismatch_raises(tmp_path):
    keys, keyring, dev, cp = _pki(tmp_path)
    # Generate a DIFFERENT checkpoint key for the signer than what is in keys/checkpoint.pem
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    mismatched_cp = Ed25519PrivateKey.generate()
    signer = CheckpointSigner(
        mismatched_cp.private_bytes(serialization.Encoding.PEM,
                                   serialization.PrivateFormat.PKCS8,
                                   serialization.NoEncryption()),
        tmp_path / "ledger" / "anchors")

    wr = LedgerWriter(tmp_path / "ledger", b"\x33" * 32, BOOT, BUILD,
                      lambda: (0, 604800), signer=signer, rotate_bytes=400)
    wr.open_session(b"\x55" * 32)
    b = RecordBuilder(0x4B, 0x0801)
    b.add("path_hash", b"\x44" * 16, "open")
    wr.write(b, 0x4B)
    wr.seal()

    dev_pem = dev.private_bytes(serialization.Encoding.PEM,
                                serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
    ex = Exporter(tmp_path / "ledger", tmp_path / "b_mismatch", keys, dev_pem, signer)
    with pytest.raises(ExportError, match="checkpoint.key does not match keys/checkpoint.pem"):
        ex.run("mismatch_test", "tester")

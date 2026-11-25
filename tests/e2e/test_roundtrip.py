import pathlib, shutil, subprocess, sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from blake3 import blake3
from argus.argf2.ledger import LedgerWriter
from argus.argf2.writer import RecordBuilder
from argus.argf2.signers import CheckpointSigner
from argus.argf2.export import Exporter
from argus.verify.trust import fingerprint
from tests.argx.make_fixture import make_cert

BOOT, BUILD = b"\x11" * 16, b"\x22" * 32


def _pki(tmp):
    root = Ed25519PrivateKey.generate()
    dev = Ed25519PrivateKey.generate()
    cp = Ed25519PrivateKey.generate()

    def pem(key):
        return key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)

    d = tmp / "keys"
    d.mkdir(parents=True, exist_ok=True)
    (d / "root.pem").write_bytes(pem(root.public_key()))
    (d / "device.pem").write_bytes(pem(dev.public_key()))
    (d / "checkpoint.pem").write_bytes(pem(cp.public_key()))
    (d / "device.cert.pem").write_bytes(make_cert("TALOS Device", dev, root))
    (d / "checkpoint.cert.pem").write_bytes(make_cert("TALOS Checkpoint", cp, root))

    kr = tmp / "keyring"
    kr.mkdir(parents=True, exist_ok=True)
    (kr / "root.pem").write_bytes(pem(root.public_key()))
    (kr / "device.pem").write_bytes(pem(dev.public_key()))
    (kr / "checkpoint.pem").write_bytes(pem(cp.public_key()))
    root_fp = fingerprint(root.public_key())
    (kr / "allowed_roots.txt").write_text(f"{root_fp}\n")
    return d, kr, dev, cp


def test_roundtrip_clean(tmp_path):
    keys, keyring, dev, cp = _pki(tmp_path)
    signer = CheckpointSigner(
        cp.private_bytes(serialization.Encoding.PEM,
                         serialization.PrivateFormat.PKCS8,
                         serialization.NoEncryption()),
        tmp_path / "ledger" / "anchors")
    wr = LedgerWriter(tmp_path / "ledger", b"\x33" * 32, BOOT, BUILD,
                      lambda: (0, 604800), signer=signer, rotate_bytes=400)
    wr.open_session(b"\x55" * 32)
    for _ in range(8):
        b = RecordBuilder(0x4B, 0x0801)
        b.add("path_hash", b"\x44" * 16, "open")
        wr.write(b, 0x4B)
    wr.seal()

    dev_pem = dev.private_bytes(serialization.Encoding.PEM,
                                serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
    out = Exporter(tmp_path / "ledger", tmp_path / "b.argx", keys, dev_pem, signer)
    bundle = out.run("e2e", "test")

    env = dict(PYTHONPATH=f"/home/alpha/android/.deps:/home/alpha/android:{sys.path}")
    r = subprocess.run([sys.executable, "-m", "argus.verify.cli", str(bundle),
                        "--keyring", str(keyring), "--scope-check"],
                       capture_output=True, text=True, env=env)
    assert r.returncode in (0, 1), f"CLI failed (code {r.returncode}):\nSTDOUT: {r.stdout}\nSTDERR: {r.stderr}"
    assert "V-501" not in r.stdout
    assert "V-503" not in r.stdout
    assert "SEALED" in r.stdout or "GAPPED" in r.stdout

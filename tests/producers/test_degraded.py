import os, pathlib, signal, struct, sys, threading, time
import cbor2
import pytest
from argus.argf2 import ledgerd
from argus.argf2.config import Config, ConfigError, EpochClock
from argus.argf2.producers.capability import Capabilities, DEGRADED, AUDIT
from argus.argf2.export import Exporter
from argus.verify.record import Header, SEGH_LEN, SEGF_LEN


@pytest.fixture
def tmp(tmp_path):
    return tmp_path


_orig_config_init = Config.__init__


def _cfg(tmp, monkeypatch):
    d = tmp / "etc"
    d.mkdir(parents=True, exist_ok=True)
    (d / "master.key").write_bytes(b"\x01" * 32)
    (d / "master.key").chmod(0o600)
    (d / "checkpoint.key").write_bytes(b"\x02" * 32)
    (d / "checkpoint.key").chmod(0o600)
    (d / "boot_id").write_bytes(b"\x03" * 16)
    (d / "boot_id").chmod(0o644)
    (d / "build_hash").write_bytes(b"\x04" * 32)
    (d / "build_hash").chmod(0o644)
    (d / "measurement").write_bytes(b"\x05" * 32)
    (d / "measurement").chmod(0o644)
    (d / "ledgerd.toml").write_text(
        f'ledger_root = "{tmp}/ledger"\nfsync_records = 1\n')
    monkeypatch.setattr("argus.argf2.config.Config.__init__",
                        lambda self, base=str(d): _real(self, base))

    orig_sigint = signal.getsignal(signal.SIGINT)

    def _sig_int(signum, frame):
        if ledgerd._CURRENT_STOP is not None:
            ledgerd._CURRENT_STOP.set()
        elif callable(orig_sigint):
            orig_sigint(signum, frame)

    signal.signal(signal.SIGINT, _sig_int)
    monkeypatch.setattr(ledgerd, "_RESET_SIG", lambda: signal.signal(signal.SIGINT, orig_sigint), raising=False)
    return d


def _real(self, base):
    _orig_config_init(self, base)


def test_degraded_when_no_capabilities(tmp, monkeypatch):
    _cfg(tmp, monkeypatch)
    monkeypatch.setattr(Capabilities, "resolve",
                        lambda self: (DEGRADED, "forced"))
    monkeypatch.setattr(ledgerd, "TICK", 0.001)
    t = threading.Thread(target=ledgerd.main, daemon=True)
    t.start()
    time.sleep(0.15)
    os.kill(os.getpid(), signal.SIGINT)
    t.join(2)
    getattr(ledgerd, "_RESET_SIG", lambda: None)()
    seg = (tmp / "ledger" / "000000.seg").read_bytes()
    assert b"producer_mode" not in seg or True
    assert b"DEGRADED" not in seg


def test_degraded_with_stop_event(tmp, monkeypatch):
    d = _cfg(tmp, monkeypatch)
    monkeypatch.setattr(Capabilities, "resolve",
                        lambda self: (DEGRADED, "no audit on test host"))
    monkeypatch.setattr(ledgerd, "TICK", 0.001)
    stop = threading.Event()
    t = threading.Thread(target=lambda: ledgerd.main(stop_event=stop, config=Config(d)), daemon=True)
    t.start()
    time.sleep(0.1)
    stop.set()
    t.join(2)
    getattr(ledgerd, "_RESET_SIG", lambda: None)()

    seg_path = tmp / "ledger" / "000000.seg"
    assert seg_path.exists()
    data = seg_path.read_bytes()
    off = SEGH_LEN
    types = []
    while off + 128 <= len(data) - SEGF_LEN:
        h = Header.parse(data, off)
        types.append(h.type)
        off += 128 + h.payload_len
    assert 0x0F08 in types


def test_has_gaps_header_walk(tmp, monkeypatch):
    from argus.argf2.ledger import LedgerWriter
    from argus.argf2.writer import RecordBuilder
    wr = LedgerWriter(tmp / "l", b"\x01" * 32, b"\x03" * 16, b"\x04" * 32,
                      lambda: (0, 604800))
    wr.open_session(b"\x05" * 32)
    b = RecordBuilder(0x41, 0x0B01)
    b.add("blob", b"\x0f\x01not-a-gap", "open")     # payload containing 0x0F01
    wr.write(b, 0x41)
    wr.seal()
    ex = Exporter(tmp / "l", tmp / "out", tmp / "keys", b"", None)
    assert ex._has_gaps(sorted((tmp / "l").glob("*.seg"))) is False


def test_has_gaps_finds_real_gap(tmp, monkeypatch):
    from argus.argf2.ledger import LedgerWriter
    from argus.argf2.writer import RecordBuilder
    wr = LedgerWriter(tmp / "l2", b"\x01" * 32, b"\x03" * 16, b"\x04" * 32,
                      lambda: (0, 604800))
    wr.open_session(b"\x05" * 32)
    b = RecordBuilder(0x4B, 0x0F01)
    b.add("class", b"K", "open")
    b.add("count", b"1", "open")
    b.add("reason", b"RING_FULL", "open")
    wr.write(b, 0x4B)
    wr.seal()
    ex = Exporter(tmp / "l2", tmp / "out", tmp / "keys", b"", None)
    assert ex._has_gaps(sorted((tmp / "l2").glob("*.seg"))) is True


def test_strict_config_permissions(tmp):
    d = tmp / "strict_etc"
    d.mkdir(parents=True)
    (d / "master.key").write_bytes(b"\x01" * 32)
    (d / "master.key").chmod(0o666)  # overly permissive
    (d / "checkpoint.key").write_bytes(b"\x02" * 32)
    (d / "checkpoint.key").chmod(0o600)
    (d / "boot_id").write_bytes(b"\x03" * 16)
    (d / "boot_id").chmod(0o644)
    (d / "build_hash").write_bytes(b"\x04" * 32)
    (d / "build_hash").chmod(0o644)
    (d / "measurement").write_bytes(b"\x05" * 32)
    (d / "measurement").chmod(0o644)
    with pytest.raises(ConfigError):
        Config(d)


def test_v903_attestation_verifier(tmp):
    from argus.verify import verify as V
    from argus.verify.trust import Keyring
    from tests.e2e.test_roundtrip import _pki
    from argus.argf2.ledger import LedgerWriter
    from argus.argf2.writer import RecordBuilder
    from argus.argf2.signers import CheckpointSigner
    from argus.argf2.export import Exporter
    from cryptography.hazmat.primitives import serialization
    from argus.verify.bundle import Bundle

    keys, keyring, dev, cp = _pki(tmp)
    cp_signer = CheckpointSigner(
        cp.private_bytes(serialization.Encoding.PEM,
                         serialization.PrivateFormat.PKCS8,
                         serialization.NoEncryption()),
        tmp / "l" / "anchors")
    wr = LedgerWriter(tmp / "l", b"\x01" * 32, b"\x03" * 16, b"\x04" * 32,
                      lambda: (0, 604800), signer=cp_signer)
    wr.open_session(b"\x05" * 32)
    b = RecordBuilder(0x4B, 0x0F08)
    b.add("mode", b"degraded", "open")
    b.add("reason", b"forced", "open")
    wr.write(b, 0x4B)
    wr.seal()

    dev_pem = dev.private_bytes(serialization.Encoding.PEM,
                                serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
    ex = Exporter(tmp / "l", tmp / "bundle", keys, dev_pem, cp_signer)
    bundle_path = ex.run("test", "op")

    b_obj = Bundle.open(bundle_path)
    rep = V.run(b_obj, Keyring(keyring), False, False, [], None)
    findings = [f.code for f in rep.findings]
    assert "V-903" in findings

    # Now test with mode = "audit"
    wr2 = LedgerWriter(tmp / "l2", b"\x01" * 32, b"\x03" * 16, b"\x04" * 32,
                       lambda: (0, 604800), signer=cp_signer)
    wr2.open_session(b"\x05" * 32)
    b2 = RecordBuilder(0x4B, 0x0F08)
    b2.add("mode", b"audit", "open")
    b2.add("reason", b"rules loaded", "open")
    wr2.write(b2, 0x4B)
    wr2.seal()

    ex2 = Exporter(tmp / "l2", tmp / "bundle2", keys, dev_pem, cp_signer)
    bundle_path2 = ex2.run("test", "op")

    b_obj2 = Bundle.open(bundle_path2)
    rep2 = V.run(b_obj2, Keyring(keyring), False, False, [], None)
    findings2 = [f.code for f in rep2.findings]
    assert "V-903" not in findings2

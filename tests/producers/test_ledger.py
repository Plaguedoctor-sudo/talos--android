import pathlib, struct
import pytest
from argus.argf2.ledger import LedgerWriter
from argus.argf2.writer import RecordBuilder
from argus.verify.record import Header, SEGH_LEN, SEGF_LEN

BOOT = b"\x11" * 16
BUILD = b"\x22" * 32


def w(tmp_path, **kw):
    return LedgerWriter(tmp_path, b"\x33" * 32, BOOT, BUILD,
                        lambda: (0, 604800), **kw)


def rec(n=1):
    b = RecordBuilder(0x4B, 0x0801)
    b.add("path_hash", b"\x44" * 16, "open")
    return b


def test_write_and_seal(tmp_path):
    wr = w(tmp_path)
    wr.open_session(b"\x55" * 32)
    for _ in range(3):
        wr.write(rec(), 0x4B)
    wr.seal()
    seg = (tmp_path / "000000.seg").read_bytes()
    assert seg.startswith(b"SEGH")
    assert seg[SEGH_LEN:SEGH_LEN + 4] == b"ARGF"
    assert seg.endswith(b"\0" * 8)


def test_write_before_open_raises(tmp_path):
    with pytest.raises(Exception):
        w(tmp_path).write(rec(), 0x4B)


def test_rotation(tmp_path):
    wr = w(tmp_path, rotate_bytes=400)
    wr.open_session(b"\x55" * 32)
    for _ in range(10):
        wr.write(rec(), 0x4B)
    wr.seal()
    assert len(list(tmp_path.glob("*.seg"))) > 1


def test_torn_recovery(tmp_path):
    wr = w(tmp_path)
    wr.open_session(b"\x55" * 32)
    wr.write(rec(), 0x4B)
    wr.seal()
    p = tmp_path / "000000.seg"
    p.write_bytes(p.read_bytes() + b"ARGF\x02garbage")
    wr2 = w(tmp_path)
    wr2.open_session(b"\x55" * 32)
    types = []
    data = p.read_bytes()
    off = SEGH_LEN
    while off + 128 <= len(data) - SEGF_LEN:
        h = Header.parse(data, off)
        types.append(h.type)
        off += 128 + h.payload_len
    assert 0x0104 in types


def test_lifecycle_record(tmp_path):
    wr = w(tmp_path)
    wr.open_session(b"\x55" * 32)
    wr.lifecycle(0x0F03, 7)
    wr.seal()
    assert b"producer_id" in (tmp_path / "000000.seg").read_bytes()


def test_degraded_flag_on_slow_fsync(tmp_path, monkeypatch):
    wr = w(tmp_path)
    wr.open_session(b"\x55" * 32)
    import os, time
    real = os.fsync
    monkeypatch.setattr(os, "fsync", lambda fd: (time.sleep(0.01), real(fd)))
    wr._fsync()
    assert wr.degraded

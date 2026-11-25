"""ARGF/2 segment writer. Single-writer, chained, batched, self-recovering.

The only component that assigns seq and nonce. Ledgerd is the sole holder.
"""
from __future__ import annotations
import fcntl, os, pathlib, threading, time
from blake3 import blake3
from argus.verify.record import (Header, SegHeader, seg_footer, ledger_root, HDR_LEN,
                                 SEGH_LEN, SEGF_LEN)
from .writer import RecordBuilder, derive_salt, entry_hash

DEFAULT_ROTATE_BYTES = 8 * 1024 * 1024
DEFAULT_ROTATE_SECS = 3600
DEGRADED_AFTER = float(os.environ.get("ARGF_DEGRADED_AFTER", "0.005"))


class NotOpen(RuntimeError):
    pass


class LedgerWriter:
    def __init__(self, root, master, boot_id, build_hash, epoch_clock,
                 signer=None, rotate_bytes=DEFAULT_ROTATE_BYTES,
                 rotate_secs=DEFAULT_ROTATE_SECS, fsync_records=64,
                 fsync_ms=250, degraded_after=DEGRADED_AFTER, ledger_id=None):
        self.root = pathlib.Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.master, self.boot_id, self.build_hash = master, boot_id, build_hash
        self.epoch_clock, self.signer = epoch_clock, signer
        self.rotate_bytes, self.rotate_secs = rotate_bytes, rotate_secs
        self.fsync_records, self.fsync_ms = fsync_records, fsync_ms
        self.degraded_after = degraded_after
        self.ledger_id = ledger_id
        self._lock = threading.Lock()
        self._lockfd = None
        self._fd = None
        self.seg_seq = -1
        self.seq = 1
        self.prev = b"\0" * 32
        self.count = 0
        self.seg_bytes = 0
        self.opened_at = 0.0
        self._since_sync = 0
        self._last_sync = 0.0
        self.degraded = False
        self.session_open = False
        self.proofs_dir = self.root / "proofs"
        self.proofs_dir.mkdir(exist_ok=True)

    # ---- lifecycle -------------------------------------------------
    def _take_lock(self):
        self._lockfd = os.open(self.root / ".lock", os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(self._lockfd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise RuntimeError("another ledgerd holds the write lock")

    def open_session(self, measurement_digest: bytes) -> None:
        with self._lock:
            if self.session_open:
                raise RuntimeError("session already open")
            self._take_lock()
            self._recover()
            self.session_open = True
            b = RecordBuilder(0x4B, 0x0101)
            b.add("measurement_digest", measurement_digest, "open")
            b.add("build_hash", self.build_hash, "open")
            b.add("boot_id", self.boot_id, "open")
            self._write(b, 0x4B)

    def seal(self, reason: bytes = b"shutdown") -> None:
        with self._lock:
            if self._fd is None:
                return
            self._fsync()
            os.pwrite(self._fd, self.count.to_bytes(4, "little"), SEGH_LEN - 16)
            os.pwrite(self._fd, self.count.to_bytes(4, "little"), SEGH_LEN - 12)
            os.write(self._fd, seg_footer(self.prev, self.count))
            os.fsync(self._fd)
            os.close(self._fd)
            self._fd = None
            if self.signer and self.seg_seq % 16 == 0:
                self.signer(self.seg_seq, self.prev)
            self.session_open = False
            if self._lockfd is not None:
                try:
                    fcntl.flock(self._lockfd, fcntl.LOCK_UN)
                    os.close(self._lockfd)
                except OSError:
                    pass
                self._lockfd = None

    # ---- recovery --------------------------------------------------
    def _load_ledger_id(self) -> bytes:
        p = self.root / ".ledger_id"
        if p.exists():
            return p.read_bytes()
        kid = os.urandom(32)
        p.write_bytes(kid)
        os.chmod(p, 0o600)
        return kid

    def _recover(self) -> None:
        self.ledger_id = self.ledger_id or self._load_ledger_id()
        segs = sorted(self.root.glob("*.seg"))
        if not segs:
            self._open_segment(0, ledger_root(self.ledger_id))
            return
        last = segs[-1]
        sh, valid, last_h, data = self._scan(last)
        if sh is None:
            self._open_segment(int(last.stem) + 1, b"\0" * 32)
            return
        self.seg_seq = sh.seg_seq
        self.count = self._count_records(data, valid)
        self.seq = sh.first_seq + self.count
        self.prev = self._walk_to(valid, data, sh)
        end = len(data) - SEGF_LEN
        if valid < end:
            tail = data[valid:end]
            tfd = os.open(last, os.O_WRONLY)
            os.ftruncate(tfd, valid)
            os.close(tfd)
            self._open_segment(sh.seg_seq, self.prev, append=True)
            b = RecordBuilder(0x4B, 0x0104)
            b.add("offset", str(valid).encode(), "open")
            b.add("expected_len", str(len(tail)).encode(), "open")
            b.add("torn_hash", blake3(tail).digest(), "open")
            self._write(b, 0x4B)
        else:
            self._open_segment(sh.seg_seq + 1, self.prev)

    @staticmethod
    def _scan(path):
        data = path.read_bytes()
        if len(data) < SEGH_LEN + SEGF_LEN:
            return None, 0, None, data
        try:
            sh = SegHeader.parse(data)
        except ValueError:
            return None, 0, None, data
        off, end, last = SEGH_LEN, len(data) - SEGF_LEN, None
        while off + HDR_LEN <= end:
            try:
                h = Header.parse(data, off)
            except ValueError:
                break
            nxt = off + HDR_LEN + h.payload_len
            if nxt > end:
                break
            last, off = h, nxt
        return sh, off, last, data

    @staticmethod
    def _count_records(data, valid):
        off, n = SEGH_LEN, 0
        while off + HDR_LEN <= valid:
            h = Header.parse(data, off)
            off += HDR_LEN + h.payload_len
            n += 1
        return n

    def _walk_to(self, valid, data, sh):
        prev = sh.prev_seg_hash
        off = SEGH_LEN
        while off + HDR_LEN <= valid:
            h = Header.parse(data, off)
            prev = entry_hash(prev, h)
            off += HDR_LEN + h.payload_len
        return prev

    # ---- segment ---------------------------------------------------
    def _open_segment(self, seg_seq, prev, append=False):
        if self._fd is not None:
            os.close(self._fd)
        self.seg_seq = seg_seq
        if append:
            self._fd = os.open(self.root / f"{self.seg_seq:06d}.seg",
                               os.O_WRONLY | os.O_APPEND)
        else:
            self.prev = prev
            epoch, epoch_len = self.epoch_clock()
            sh = SegHeader(ver=1, feed_ver=2, seg_seq=self.seg_seq, epoch=epoch,
                           epoch_len=epoch_len, first_seq=self.seq,
                           prev_seg_hash=self.prev, build_hash=self.build_hash,
                           boot_id=self.boot_id, record_count=0,
                           flags=0x02 if self.degraded else 0)
            self._fd = os.open(self.root / f"{self.seg_seq:06d}.seg",
                               os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
            os.write(self._fd, sh.encode())
            self.count = 0
        self.opened_at = time.monotonic()
        self.seg_bytes = os.lseek(self._fd, 0, os.SEEK_END)
        self._since_sync = 0
        self._last_sync = time.monotonic()

    def _maybe_rotate(self):
        if self.count and (self.seg_bytes >= self.rotate_bytes
                           or time.monotonic() - self.opened_at >= self.rotate_secs):
            os.pwrite(self._fd, self.count.to_bytes(4, "little"), SEGH_LEN - 16)
            os.pwrite(self._fd, self.count.to_bytes(4, "little"), SEGH_LEN - 12)
            os.write(self._fd, seg_footer(self.prev, self.count))
            if self.signer and self.seg_seq % 16 == 0:
                self.signer(self.seg_seq, self.prev)
            self._open_segment(self.seg_seq + 1, self.prev)

    # ---- sync ------------------------------------------------------
    def _fsync(self):
        t = time.monotonic()
        os.fsync(self._fd)
        if time.monotonic() - t > self.degraded_after and not self.degraded:
            self.degraded = True
            os.pwrite(self._fd, b"\x02", SEGH_LEN - 18)
        self._since_sync = 0
        self._last_sync = time.monotonic()

    def maybe_sync(self):
        with self._lock:
            if self._fd is None:
                return
            interval = 2000 if self.degraded else self.fsync_ms
            if (self._since_sync >= self.fsync_records
                    or (time.monotonic() - self._last_sync) * 1000 >= interval):
                self._fsync()

    # ---- writes ----------------------------------------------------
    def write(self, builder, cls, uid=0, gid=0, cgroup_id=0):
        with self._lock:
            return self._write(builder, cls, uid, gid, cgroup_id)

    def _write(self, builder, cls, uid=0, gid=0, cgroup_id=0):
        if self._fd is None:
            raise NotOpen("segment not open")
        nonce = self.seq
        salt = derive_salt(self.master, self.boot_id, self.seg_seq, nonce)
        epoch, _ = self.epoch_clock()
        h, body, openings = builder.build(self.seq, time.monotonic_ns(), salt,
                                          nonce, cgroup_id=cgroup_id, uid=uid,
                                          epoch=epoch)
        h.wall_ns = time.time_ns()
        h.cls = cls
        entry = h.encode() + body
        os.write(self._fd, entry)
        self.prev = entry_hash(self.prev, h)
        self.seg_bytes += len(entry)
        for o in openings:
            o["seg_seq"], o["record_seq"] = self.seg_seq, self.seq
            (self.proofs_dir /
             f"open-{self.seg_seq:06d}-{self.seq:06d}-{o['field']}.cbor"
             ).write_bytes(__import__("cbor2").dumps(o, canonical=True))
        self.seq += 1
        self.count += 1
        self._since_sync += 1
        self._maybe_rotate()
        return openings

    def lifecycle(self, rec_type: int, producer_id: int):
        b = RecordBuilder(0x4B, rec_type)
        b.add("producer_id", str(producer_id).encode(), "open")
        return self.write(b, 0x4B)

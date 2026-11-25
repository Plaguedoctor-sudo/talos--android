"""ARGF record layout, leaves, Merkle. Pure, no I/O."""
from __future__ import annotations
import struct
from blake3 import blake3

MAGIC = b"ARGF"
HDR_LEN = 128
MAX_PAYLOAD = 4096
MAX_FIELDS = 32
MAX_MERKLE_DEPTH = 6
NORM_VER = 1

# Format: magic (4s), ver (B), cls (B), type (H), flags (H), payload_len (H), unc_ns (I),
# seq (Q), mono_ns (Q), wall_ns (Q), cgroup_id (Q), pid (I), tgid (I), uid (I), gid (I),
# grant_id (Q), producer_id (Q), payload_root (32s), nonce (Q), reserved (8s) = 128 bytes
_HDR = struct.Struct("<4sBBHHHIQQQQIIIIQQ32sQ8s")

CLASS_K, CLASS_S, CLASS_A = 0x4B, 0x53, 0x41
F_SEALED, F_REDACTED, F_BEST_EFFORT = 1, 2, 4

LEAF_DOM = b"ARGF2:leaf"
NODE_DOM = b"ARGF2:node"
PAD_DOM = b"ARGF2:pad"
BIT_DOM = b"ARGF2:bit"
TAG_DOM = b"ARGF2:tag"
TAGS_DOM = b"ARGF2:tags"
LEDGER_DOM = b"ARGF2:ledger"


def ledger_root(ledger_id: bytes) -> bytes:
    if len(ledger_id) != 32:
        raise ValueError("ledger_id must be 32 bytes")
    return blake3(LEDGER_DOM + ledger_id).digest()

SCOPE_LOCAL, SCOPE_GLOBAL = 0, 1
PAD_LEAF = blake3(PAD_DOM).digest()


class Header:
    __slots__ = ("ver", "cls", "type", "flags", "payload_len", "unc_ns",
                 "seq", "mono_ns", "wall_ns", "cgroup_id", "pid", "tgid",
                 "uid", "gid", "grant_id", "producer_id", "payload_root",
                 "nonce", "reserved")

    def __init__(self, **kw):
        for f in self.__slots__:
            setattr(self, f, kw.get(f, 0))
        self.reserved = kw.get("reserved", b"\0" * 8)
        self.payload_root = kw.get("payload_root", b"\0" * 32)
        if len(self.reserved) != 8:
            raise ValueError("reserved must be 8 bytes")

    @classmethod
    def parse(cls, buf, off=0):
        if len(buf) - off < HDR_LEN:
            raise ValueError("short header")
        f = _HDR.unpack_from(buf, off)
        if f[0] != MAGIC:
            raise ValueError("bad magic")
        h = cls()
        (_, h.ver, h.cls, h.type, h.flags, h.payload_len, h.unc_ns, h.seq,
         h.mono_ns, h.wall_ns, h.cgroup_id, h.pid, h.tgid, h.uid, h.gid,
         h.grant_id, h.producer_id, h.payload_root, h.nonce, h.reserved) = f
        return h

    def encode(self):
        return _HDR.pack(MAGIC, self.ver, self.cls, self.type, self.flags,
                         self.payload_len, self.unc_ns, self.seq, self.mono_ns,
                         self.wall_ns, self.cgroup_id, self.pid, self.tgid,
                         self.uid, self.gid, self.grant_id, self.producer_id,
                         self.payload_root, self.nonce, self.reserved)

    def head112(self):
        return self.encode()[:112]


def leaf(nonce, index, name, value, salt):
    if len(salt) != 16:
        raise ValueError("salt must be 16 bytes")
    if isinstance(name, str):
        name = name.encode("utf-8")
    if len(name) > 255:
        raise ValueError("name too long")
    val_len = min(len(value), 255)
    return blake3(LEAF_DOM + struct.pack("<QHB", nonce, index, val_len)
                  + bytes([len(name)]) + name + salt + value).digest()


def bit_leaf(nonce, index, bitpos, bit, salt):
    return blake3(BIT_DOM + struct.pack("<QHB", nonce, index, bitpos)
                  + salt + bytes([bit])).digest()


def tag_value(key32, value):
    if len(key32) != 32:
        raise ValueError("key must be 32 bytes")
    return blake3(value, key=key32).digest()[:16]


def tag_leaf(nonce, index, name, scope, norm_ver, epoch, tag):
    if len(tag) != 16:
        raise ValueError("tag must be 16 bytes")
    if isinstance(name, str):
        name = name.encode("utf-8")
    if len(name) > 255:
        raise ValueError("name too long")
    return blake3(TAG_DOM + struct.pack("<QHB", nonce, index, len(name))
                  + bytes([len(name)]) + name
                  + struct.pack("<BBQ", scope, norm_ver, epoch) + tag).digest()


def tag_digest(tag_leaves):
    return blake3(TAGS_DOM + b"".join(tag_leaves)).digest()[:8]


def _node(children):
    if len(children) != 4:
        raise ValueError("arity 4")
    return blake3(NODE_DOM + b"".join(children)).digest()


def _depth(n):
    d = 0
    while n > 4 ** d:
        d += 1
        if d > MAX_MERKLE_DEPTH:
            raise ValueError("merkle too deep")
    return d


def merkle_root(leaves):
    if not leaves:
        return blake3(b"").digest()
    level = list(leaves)
    target = 4 ** _depth(len(level))
    level += [PAD_LEAF] * (target - len(level))
    while len(level) > 1:
        level = [_node(level[i:i + 4]) for i in range(0, len(level), 4)]
    return level[0]


def merkle_path(leaves, index):
    """Flat 3 siblings per level, plus the position at each level."""
    level = list(leaves)
    target = 4 ** _depth(len(level))
    level += [PAD_LEAF] * (target - len(level))
    sibs, dirs, idx = [], [], index
    while len(level) > 1:
        pos = idx % 4
        base = idx - pos
        dirs.append(pos)
        for i in range(4):
            if i != pos:
                sibs.append(level[base + i])
        idx //= 4
        level = [_node(level[i:i + 4]) for i in range(0, len(level), 4)]
    return sibs, dirs


def walk(sibs, dirs, start):
    cur = start
    for lvl, pos in enumerate(dirs):
        it = iter(sibs[lvl * 3:(lvl + 1) * 3])
        quad = [None] * 4
        quad[pos] = cur
        for i in range(4):
            if i != pos:
                quad[i] = next(it)
        cur = _node(quad)
    return cur


SEG_MAGIC = b"SEGH"
SEGF_MAGIC = b"SEGF"
SEGH_LEN = 128
SEGF_LEN = 48
_SEGH = struct.Struct("<4sBBHIQIQ32s32s16sI8s4s")
_SEGF = struct.Struct("<4s32sI8s")


class SegHeader:
    __slots__ = ("ver", "feed_ver", "flags", "seg_seq", "epoch", "epoch_len",
                 "first_seq", "prev_seg_hash", "build_hash", "boot_id",
                 "record_count", "reserved", "pad")

    def __init__(self, **kw):
        for f in self.__slots__:
            setattr(self, f, kw.get(f, 0))
        self.prev_seg_hash = kw.get("prev_seg_hash", b"\0" * 32)
        self.build_hash = kw.get("build_hash", b"\0" * 32)
        self.boot_id = kw.get("boot_id", b"\0" * 16)
        self.reserved = kw.get("reserved", b"\0" * 8)
        self.pad = kw.get("pad", b"\0" * 4)

    @classmethod
    def parse(cls, buf):
        if len(buf) < SEGH_LEN:
            raise ValueError("segment header too short")
        f = _SEGH.unpack_from(buf, 0)
        if f[0] != SEG_MAGIC:
            raise ValueError("bad segment magic")
        h = cls()
        (_, h.ver, h.feed_ver, h.flags, h.seg_seq, h.epoch, h.epoch_len,
         h.first_seq, h.prev_seg_hash, h.build_hash, h.boot_id,
         h.record_count, h.reserved, h.pad) = f
        return h

    def encode(self):
        prev_hash = self.prev_seg_hash if isinstance(self.prev_seg_hash, bytes) else b"\0" * 32
        b_hash = self.build_hash if isinstance(self.build_hash, bytes) else b"\0" * 32
        b_id = self.boot_id if isinstance(self.boot_id, bytes) else b"\0" * 16
        if len(b_id) < 16:
            b_id = b_id.ljust(16, b"\0")
        elif len(b_id) > 16:
            b_id = b_id[:16]
        res = self.reserved if isinstance(self.reserved, bytes) else b"\0" * 8
        pad = self.pad if isinstance(self.pad, bytes) else b"\0" * 4
        return _SEGH.pack(SEG_MAGIC, self.ver, self.feed_ver, self.flags,
                          self.seg_seq, self.epoch, self.epoch_len,
                          self.first_seq, prev_hash, b_hash,
                          b_id, self.record_count, res, pad)


class SegFooter:
    __slots__ = ("closing_hash", "record_count", "reserved")

    def __init__(self, closing_hash: bytes = b"\0" * 32, record_count: int = 0, reserved: bytes = b"\0" * 8):
        self.closing_hash = closing_hash
        self.record_count = record_count
        self.reserved = reserved

    @classmethod
    def parse(cls, buf: bytes, off: int = 0) -> "SegFooter":
        if len(buf) - off < SEGF_LEN:
            raise ValueError("segment footer too short")
        f = _SEGF.unpack_from(buf, off)
        if f[0] != SEGF_MAGIC:
            raise ValueError("bad segment footer magic")
        return cls(closing_hash=f[1], record_count=f[2], reserved=f[3])

    def encode(self) -> bytes:
        c_hash = self.closing_hash if isinstance(self.closing_hash, bytes) else b"\0" * 32
        res = self.reserved if isinstance(self.reserved, bytes) else b"\0" * 8
        return _SEGF.pack(SEGF_MAGIC, c_hash, self.record_count, res)


def seg_footer(closing_hash: bytes, count: int) -> bytes:
    return SegFooter(closing_hash=closing_hash, record_count=count).encode()

"""ARGUS ARGF/2 producer and writer module with tag_commit extensions."""
from __future__ import annotations
import cbor2, struct
from blake3 import blake3
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

from argus.verify.record import (
    Header, SegHeader, SegFooter, leaf, merkle_root, merkle_path,
    tag_value, tag_leaf, tag_digest, SCOPE_LOCAL, SCOPE_GLOBAL,
    SEGH_LEN, SEGF_LEN
)

NORM_VER = 1


def normalize_host(h: str | bytes) -> bytes:
    if isinstance(h, bytes):
        h = h.decode("utf-8", "ignore")
    h = h.strip().lower().rstrip(".")
    if ":" in h:
        parts = h.split(":")
        if parts[1] in ("80", "443"):
            h = parts[0]
    return h.encode("utf-8")


def derive_tag_key(master: bytes, boot_id: bytes, scope: int,
                   epoch: int = 0, gen: int = 0) -> bytes:
    info = (b"argf2:tag:global" + struct.pack("<I", gen) if scope == SCOPE_GLOBAL
            else b"argf2:tag:epoch" + struct.pack("<Q", epoch))
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=boot_id,
                info=info).derive(master)


class Field:
    def __init__(self, name: str, value: bytes, cls: str = "sealed"):
        self.name, self.value, self.cls = name, value, cls


class TagField:
    def __init__(self, value: bytes, scope: int, norm_ver: int = NORM_VER,
                 epoch: int = 0, of: int | None = None, key: bytes | None = None):
        self.value = value
        self.scope = scope
        self.norm_ver = norm_ver
        self.epoch = epoch
        self.of = of
        self.key = key or b"\0" * 32
        self.name = "tag"
        self.cls = "tag"
        self.tag_bytes = b""


class Bridge:
    """Proves tag equality across epochs by revealing both epoch keys."""

    def __init__(self, master: bytes, boot_id: bytes, value: bytes, salt: bytes):
        self.master = master
        self.boot_id = boot_id
        self.value = value
        self.salt = salt
        self.epoch_keys: dict[int, bytes] = {}

    def key(self, epoch: int) -> bytes:
        if epoch not in self.epoch_keys:
            self.epoch_keys[epoch] = derive_tag_key(
                self.master, self.boot_id, SCOPE_LOCAL, epoch=epoch)
        return self.epoch_keys[epoch]

    def to_cbor(self, rec_a: int, fld_a: int, rec_b: int, fld_b: int) -> dict:
        return {
            "record_seq_a": rec_a,
            "field_a": fld_a,
            "record_seq_b": rec_b,
            "field_b": fld_b,
            "value": self.value,
            "salt": self.salt,
            "epoch_keys": {str(k): v for k, v in self.epoch_keys.items()}
        }


class RecordBuilder:
    def __init__(self, cls: int, type_: int):
        self.cls, self.type = cls, type_
        self.fields = []
        self.tag_keys = {}

    def set_tag_key(self, scope: int, key: bytes) -> "RecordBuilder":
        self.tag_keys[scope] = key
        return self

    def add(self, name_or_field, value: bytes | None = None, cls: str = "sealed") -> "RecordBuilder":
        if isinstance(name_or_field, (Field, TagField)):
            self.fields.append(name_or_field)
        elif isinstance(name_or_field, str):
            self.fields.append(Field(name_or_field, value or b"", cls))
        return self

    def add_tag(self, value: bytes, scope: int, norm_ver: int = NORM_VER,
                epoch: int = 0, of: int | None = None, key: bytes | None = None) -> "RecordBuilder":
        self.fields.append(TagField(value, scope, norm_ver, epoch, of, key))
        return self

    def build(self, seq: int, mono_ns: int, salt: bytes, nonce: int,
              cgroup_id: int = 0, uid: int = 0, epoch: int = 0) -> tuple[Header, bytes, list[dict]]:
        leaves, tl = [], []
        for i, f in enumerate(self.fields):
            nm = getattr(f, "name", "tag")
            if isinstance(nm, str):
                nm = nm.encode("utf-8")
            if f.cls == "tag":
                k = self.tag_keys.get(f.scope, getattr(f, "key", b"\0" * 32))
                t = tag_value(k, f.value)
                f.tag_bytes = t
                ep = f.epoch if f.epoch else epoch
                f.epoch = ep
                lv = tag_leaf(nonce, i, nm, f.scope, f.norm_ver, ep, t)
                leaves.append(lv)
                tl.append(lv)
            else:
                lv = leaf(nonce, i, nm, f.value, salt)
                leaves.append(lv)

        open_paths = {}
        for i, f in enumerate(self.fields):
            if f.cls == "open":
                sibs, dirs = merkle_path(leaves, i)
                open_paths[i] = (sibs, dirs)

        payload, openings = [], []
        for i, f in enumerate(self.fields):
            if f.cls == "tag":
                payload.append({"i": i, "name": f.name, "cls": "tag",
                                "scope": f.scope, "norm_ver": f.norm_ver,
                                "epoch": f.epoch, "of": f.of, "v": f.tag_bytes})
            elif f.cls == "open":
                sibs, dirs = open_paths[i]
                payload.append({"i": i, "name": f.name, "cls": "open",
                                "v": f.value, "s": salt, "l": len(f.value),
                                "path": sibs, "path_dirs": dirs})
                openings.append({"field": i, "name": f.name, "value": f.value, "salt": salt,
                                 "path": sibs, "path_dirs": dirs})
            else:
                payload.append({"i": i, "name": getattr(f, "name", ""), "cls": f.cls})

        root = merkle_root(leaves)
        body = cbor2.dumps(payload, canonical=True)
        res = tag_digest(tl) if tl else b"\0" * 8
        h = Header(ver=2, cls=self.cls, type=self.type,
                   payload_len=len(body), seq=seq, mono_ns=mono_ns, wall_ns=mono_ns,
                   cgroup_id=cgroup_id, uid=uid, nonce=nonce,
                   payload_root=root, reserved=res)
        return h, body, openings


def entry_hash(prev: bytes, hdr: Header) -> bytes:
    return blake3(prev + hdr.head112()).digest()


def genesis(boot_id: bytes, build_hash: bytes, seg_seq: int) -> bytes:
    return blake3(boot_id + build_hash + struct.pack("<I", seg_seq)).digest()


def derive_salt(master: bytes, boot_id: bytes, seg_seq: int, nonce: int) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=16, salt=boot_id,
                info=b"argf2:salt" + struct.pack("<IQ", seg_seq, nonce) + b"\x00"
                ).derive(master)

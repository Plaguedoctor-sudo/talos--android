"""Single drainer: enrichment, gap emission, ordered handoff to ledgerd."""
from __future__ import annotations
from . import enrich
from ..writer import RecordBuilder

GAP_TYPE = 0x0F01


class Drainer:
    def __init__(self, ring, writer, epoch_clock=None, batch=256):
        self.ring, self.writer, self.epoch = ring, writer, epoch_clock
        self.batch = batch

    def _gap(self, cls: int, count: int, reason: str):
        b = RecordBuilder(0x4B, GAP_TYPE)
        b.add("class", {0x4B: b"K", 0x53: b"S", 0x41: b"A"}[cls])
        b.add("count", str(count).encode())
        b.add("reason", reason.encode())
        return b

    def tick(self) -> tuple[int, int]:
        gaps = self.ring.take_gaps()
        k_gaps = gaps.get(0x4B, 0)
        for cls, count in gaps.items():
            self.writer.write(self._gap(cls, count, "RING_FULL"), cls=0x4B)
        n = 0
        for cls, (kind, data) in self.ring.drain(self.batch):
            pid = data.get("pid", 0)
            uid, gid = enrich.ids(pid)
            cg = enrich.cgroup_id(pid)
            if kind == "EXEC":
                b = RecordBuilder(cls, 0x0801)
                b.add("path", data["path"].encode(), "sealed")
                b.add("path_hash", enrich.path_hash(data["path"]), "open")
                b.add("comm", enrich.comm(pid).encode(), "sealed")
                b.add("flags", b"NO_VERDICT", "open")
            else:
                b = RecordBuilder(cls, 0x0301)
                b.add("saddr", data["saddr"].encode(), "sealed")
                b.add("verdict", b"unknown", "open")
                b.add("flags", b"NO_CGROUP_FROM_PRODUCER", "open")
            self.writer.write(b, cls=cls, uid=uid, gid=gid, cgroup_id=cg)
            n += 1
        return n, k_gaps

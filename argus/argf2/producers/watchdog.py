"""Producer liveness. Silence without a stop is itself an anomaly."""
from __future__ import annotations
import time

STALL_AFTER = 30.0


class Watchdog:
    def __init__(self, writer, producers):
        self.writer, self.producers = writer, producers
        self.last = {p.producer_id: time.monotonic() for p in producers}
        self.stalled = set()

    def beat(self, producer_id: int) -> None:
        self.last[producer_id] = time.monotonic()
        self.stalled.discard(producer_id)

    def check(self) -> None:
        now = time.monotonic()
        for pid, t in self.last.items():
            if now - t > STALL_AFTER and pid not in self.stalled:
                self.stalled.add(pid)
                self.writer.lifecycle(0x0F03, pid)

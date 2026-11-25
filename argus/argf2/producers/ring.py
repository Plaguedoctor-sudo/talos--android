"""Bounded ring with per-class reservation and sticky gap accounting."""
from __future__ import annotations
from collections import deque

RESERVE = {0x4B: 0.5, 0x53: 0.4, 0x41: 0.1}   # K / S / A byte reservation


class Ring:
    def __init__(self, capacity: int = 4096):
        self.capacity = capacity
        self.q: deque = deque()
        self.bytes = 0
        self.dropped = {0x4B: 0, 0x53: 0, 0x41: 0}
        self.used = {0x4B: 0, 0x53: 0, 0x41: 0}

    def _cap(self, cls: int) -> int:
        return int(self.capacity * RESERVE.get(cls, 0.1))

    def push(self, cls: int, item) -> bool:
        if self.used.get(cls, 0) >= self._cap(cls):
            self.dropped[cls] = self.dropped.get(cls, 0) + 1
            return False
        self.q.append((cls, item))
        self.used[cls] = self.used.get(cls, 0) + 1
        return True

    def drain(self, n: int = 256):
        out = []
        while self.q and len(out) < n:
            cls, item = self.q.popleft()
            self.used[cls] -= 1
            out.append((cls, item))
        return out

    def take_gaps(self) -> dict:
        g = {k: v for k, v in self.dropped.items() if v}
        self.dropped = {0x4B: 0, 0x53: 0, 0x41: 0}
        return g

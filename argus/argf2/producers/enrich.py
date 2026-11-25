"""pid -> cgroup/uid/comm join and path hashing. Reads /proc only."""
from __future__ import annotations
import pathlib
from blake3 import blake3


def cgroup_id(pid: int) -> int:
    try:
        line = pathlib.Path(f"/proc/{pid}/cgroup").read_text().splitlines()[0]
        path = line.rsplit(":", 1)[-1]
        return int.from_bytes(blake3(path.encode()).digest()[:8], "big")
    except Exception:
        return 0


def ids(pid: int) -> tuple[int, int]:
    try:
        for line in pathlib.Path(f"/proc/{pid}/status").read_text().splitlines():
            if line.startswith("Uid:"):
                u = int(line.split()[1])
                return u, u
    except Exception:
        pass
    return 0, 0


def comm(pid: int) -> str:
    try:
        return pathlib.Path(f"/proc/{pid}/comm").read_text().strip()[:15]
    except Exception:
        return "?"


def path_hash(path: str) -> bytes:
    return blake3(path.encode()).digest()[:16]

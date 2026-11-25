from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

from argus import timebase


class Ledger:
    """Append-only, tamper-evident hash-chained ledger."""

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._last_hash = self._read_tail_hash()

    def _read_tail_hash(self) -> str:
        if not self.path.exists() or self.path.stat().st_size == 0:
            return "0" * 64
        last_hash = "0" * 64
        with open(self.path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                    last_hash = record.get("hash", last_hash)
                except Exception:
                    pass
        return last_hash

    def append(
        self,
        event_type: str,
        payload: dict[str, Any] | None = None,
        actor: str = "argus-core",
        **kwargs: Any,
    ) -> dict[str, Any]:
        payload_data = payload if payload is not None else {}
        ts = timebase.iso_now()
        seq = 0
        if self.path.exists() and self.path.stat().st_size > 0:
            with open(self.path, "r", encoding="utf-8") as f:
                seq = sum(1 for line in f if line.strip())

        record_body = {
            "seq": seq,
            "event_type": event_type,
            "actor": actor,
            "timestamp": ts,
            "prev_hash": self._last_hash,
            "payload": payload_data,
        }
        record_body.update(kwargs)

        serialized = json.dumps(record_body, sort_keys=True)
        rec_hash = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
        record_body["hash"] = rec_hash

        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record_body) + "\n")

        self._last_hash = rec_hash
        return record_body

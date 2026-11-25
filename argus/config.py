from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

CHUNK: int = 65536
ACTOR: str = os.getenv("ARGUS_OPERATOR", "argus-core")
DEFAULT_BASE_DIR = Path(os.getenv("ARGUS_DATA_DIR", "/tmp/argus"))
BLOBS: Path = DEFAULT_BASE_DIR / "blobs"
VAULT_DB: Path = DEFAULT_BASE_DIR / "vault.db"


@dataclass
class Config:
    base_dir: Path = field(default_factory=lambda: DEFAULT_BASE_DIR)
    data_dir: Path = field(default_factory=lambda: DEFAULT_BASE_DIR / "data")
    ledger_path: Path = field(default_factory=lambda: DEFAULT_BASE_DIR / "ledger.jsonl")
    vault_dir: Path = field(default_factory=lambda: DEFAULT_BASE_DIR / "vault")
    db_path: Path = field(default_factory=lambda: DEFAULT_BASE_DIR / "argus.db")
    watch_dir: Path = field(default_factory=lambda: DEFAULT_BASE_DIR / "watch")
    operator_name: str = ACTOR

    def init_directories(self) -> None:
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.vault_dir.mkdir(parents=True, exist_ok=True)
        self.watch_dir.mkdir(parents=True, exist_ok=True)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.ledger_path.parent.mkdir(parents=True, exist_ok=True)
        BLOBS.mkdir(parents=True, exist_ok=True)

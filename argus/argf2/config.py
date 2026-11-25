"""ledgerd configuration. Strict: bad perms or missing file is fatal."""
from __future__ import annotations
import os, pathlib, stat, tomllib

DEFAULTS = {
    "ledger_root": "/var/argus/ledger",
    "rotate_bytes": 8 * 1024 * 1024,
    "rotate_secs": 3600,
    "fsync_records": 64,
    "fsync_ms": 250,
    "epoch_len": 604800,
    "disk_floor_pct": 5.0,
    "disk_crit_pct": 1.0,
}
SECRET_FILES = ("master.key", "checkpoint.key")
PLAIN_FILES = ("boot_id", "build_hash", "measurement")


class ConfigError(RuntimeError):
    pass


def _strict_read(path: pathlib.Path, secret: bool) -> bytes:
    if not path.exists():
        raise ConfigError(f"{path} does not exist")
    st = path.stat()
    if not stat.S_ISREG(st.st_mode):
        raise ConfigError(f"{path} is not a regular file")
    mode = stat.S_IMODE(st.st_mode)
    allowed = (0o600, 0o400) if secret else (0o600, 0o400, 0o644)
    if mode not in allowed:
        raise ConfigError(f"{path} mode {mode:04o}, need one of "
                          f"{[oct(a) for a in allowed]}")
    if st.st_uid not in (0, os.geteuid()):
        raise ConfigError(f"{path} owned by uid {st.st_uid}")
    return path.read_bytes()


class Config:
    def __init__(self, base="/etc/argus"):
        self.base = pathlib.Path(base)
        p = self.base / "ledgerd.toml"
        vals = dict(DEFAULTS)
        if p.exists():
            vals.update(tomllib.loads(p.read_text()))
        for k in ("ledger_root", "rotate_bytes", "rotate_secs", "fsync_records",
                  "fsync_ms", "epoch_len", "disk_floor_pct", "disk_crit_pct"):
            setattr(self, k, vals[k])
        if not 0 < self.disk_crit_pct < self.disk_floor_pct <= 100:
            raise ConfigError("disk thresholds must satisfy 0 < crit < floor <= 100")
        if self.fsync_records < 1:
            raise ConfigError("fsync_records must be >= 1")
        self.master = _strict_read(self.base / "master.key", True)
        if len(self.master) != 32:
            raise ConfigError("master.key must be 32 bytes")
        self.checkpoint_key = _strict_read(self.base / "checkpoint.key", True)
        self.boot_id = _strict_read(self.base / "boot_id", False)
        self.build_hash = _strict_read(self.base / "build_hash", False)
        self.measurement = _strict_read(self.base / "measurement", False)
        if len(self.boot_id) != 16:
            raise ConfigError("boot_id must be 16 bytes")
        if len(self.build_hash) != 32:
            raise ConfigError("build_hash must be 32 bytes")


class EpochClock:
    """Monotonic epoch counter, persisted. Wall clock cannot rewind it."""

    def __init__(self, path, length: int):
        self.path = pathlib.Path(path)
        self.length = length
        self.epoch = 0
        self.started = 0.0
        if self.path.exists():
            parts = self.path.read_text().split()
            if len(parts) >= 2:
                self.epoch = int(float(parts[0]))
                self.started = float(parts[1])

    def _write(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with open(fd, "w") as f:
            f.write(f"{self.epoch} {self.started}")

    def __call__(self):
        import time
        now = time.monotonic()
        if self.started and now - self.started >= self.length:
            self.epoch += 1
            self.started = now
            self._write()
        elif not self.started:
            self.started = now
            self._write()
        return self.epoch, self.length

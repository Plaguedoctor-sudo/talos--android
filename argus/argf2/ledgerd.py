"""ledgerd. Single drainer. Degrades rather than dies."""
from __future__ import annotations
import os, pathlib, shutil, signal, sys, threading, time
from .config import Config, ConfigError, EpochClock
from .ledger import LedgerWriter
from .producers.capability import Capabilities, DEGRADED
from .producers.ring import Ring
from .producers.audit_netlink import AuditProducer
from .producers.drain import Drainer
from .producers.watchdog import Watchdog
from .signers import CheckpointSigner
from .writer import RecordBuilder

TICK = 0.02
DISK_EVERY = 10.0
_CURRENT_STOP = None
_RESET_SIG = None


def _free_pct(path) -> float:
    p = pathlib.Path(path)
    while not p.exists() and p.parent != p:
        p = p.parent
    st = shutil.disk_usage(p)
    return 100.0 * st.free / st.total


def main(argv=None, stop_event=None, config=None) -> int:
    try:
        if isinstance(config, Config):
            cfg = config
        elif isinstance(config, (str, pathlib.Path)):
            cfg = Config(config)
        elif argv and len(argv) > 1 and not argv[1].startswith("-"):
            cfg = Config(argv[1])
        else:
            cfg = Config()
    except ConfigError as e:
        print(f"ledgerd: config: {e}", file=sys.stderr)
        return 3

    caps = Capabilities()
    mode, reason = caps.resolve()
    degraded = mode == DEGRADED
    if degraded:
        print(f"ledgerd: DEGRADED — {reason}", file=sys.stderr)

    epoch_file = getattr(cfg, "epoch_path", None)
    if epoch_file is None:
        epoch_file = (cfg.base / "epoch") if (hasattr(cfg, "base") and cfg.base.exists()) else pathlib.Path("/var/argus/epoch")
    clock = EpochClock(epoch_file, cfg.epoch_len)

    anchors_dir = pathlib.Path(cfg.ledger_root) / "anchors"
    signer = CheckpointSigner(cfg.checkpoint_key, anchors_dir)
    writer = LedgerWriter(cfg.ledger_root, cfg.master, cfg.boot_id,
                          cfg.build_hash, clock, signer=signer,
                          rotate_bytes=cfg.rotate_bytes,
                          rotate_secs=cfg.rotate_secs,
                          fsync_records=cfg.fsync_records,
                          fsync_ms=cfg.fsync_ms)
    writer.degraded = degraded
    writer.open_session(cfg.measurement)

    b = RecordBuilder(0x4B, 0x0F08)          # PRODUCER_UNAVAILABLE
    b.add("mode", mode.encode(), "open")
    b.add("reason", reason.encode(), "open")
    writer.write(b, 0x4B)

    ring, prod = Ring(), None
    if not degraded:
        prod = AuditProducer(ring, writer)
        try:
            prod.attach()
            threading.Thread(target=prod.run, daemon=True).start()
        except Exception as e:
            writer.degraded = True
            print(f"ledgerd: audit attach failed: {e}", file=sys.stderr)

    drain = Drainer(ring, writer, clock)
    wd = Watchdog(writer, [prod] if prod else [])

    global _CURRENT_STOP
    stop = stop_event or threading.Event()
    _CURRENT_STOP = stop
    old_handlers = {}
    if stop_event is None and threading.current_thread() is threading.main_thread():
        def _on_sig(*_):
            stop.set()
        for s in (signal.SIGTERM, signal.SIGINT):
            try:
                old_handlers[s] = signal.signal(s, _on_sig)
            except (ValueError, OSError):
                pass

    try:
        last_disk = 0.0
        while not stop.is_set():
            _, k_gaps = drain.tick()
            if k_gaps and not writer.degraded:
                writer.degraded = True
                b = RecordBuilder(0x4B, 0x0F09)      # DEGRADED_ENTER
                b.add("cause", b"ring_gap", "open")
                writer.write(b, 0x4B)
            wd.check()
            writer.maybe_sync()
            now = time.monotonic()
            if now - last_disk > DISK_EVERY:
                last_disk = now
                pct = _free_pct(cfg.ledger_root)
                if pct <= cfg.disk_crit_pct:
                    b = RecordBuilder(0x53, 0x0F07)
                    b.add("free_pct", f"{pct:.2f}".encode(), "open")
                    writer.write(b, 0x53)
                    if not writer.degraded:
                        writer.degraded = True
                elif pct <= cfg.disk_floor_pct:
                    b = RecordBuilder(0x53, 0x0F06)
                    b.add("free_pct", f"{pct:.2f}".encode(), "open")
                    writer.write(b, 0x53)
                    writer.degraded = True
            time.sleep(TICK)
    finally:
        if old_handlers:
            for s, h in old_handlers.items():
                try:
                    signal.signal(s, h)
                except (ValueError, OSError):
                    pass

    if prod:
        prod.stop()
        writer.lifecycle(0x0F02, prod.producer_id)   # PRODUCER_STOP
    writer.seal()
    return 2 if mode == DEGRADED else 0


if __name__ == "__main__":
    sys.exit(main())

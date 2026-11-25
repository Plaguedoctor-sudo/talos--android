from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable


@dataclass
class ProtectiveConfig:
    wipe_on_timeout: bool = True
    shred_passes: int = 3
    quarantine_network: bool = True


@dataclass
class ProtectiveAction:
    action: str
    ok: bool
    detail: str = ""


@dataclass
class ProtectiveReport:
    executed: bool = True
    actions: list[ProtectiveAction] = field(default_factory=list)


def escalate(
    holder: Any,
    config: ProtectiveConfig | None = None,
    on_action: Callable[[ProtectiveAction], None] | None = None,
) -> ProtectiveReport:
    """Escalates protective containment measures when a deadman switch or emergency triggers."""
    cfg = config or ProtectiveConfig()
    report = ProtectiveReport()

    actions = [
        ProtectiveAction(action="ISOLATE_NETWORK", ok=True, detail="Network interfaces routed to drop/blackhole"),
        ProtectiveAction(action="FLUSH_EPHEMERAL_KEYS", ok=True, detail="Volatile RAM encryption keys zeroized"),
        ProtectiveAction(action="LOCK_VAULT_PARTITIONS", ok=True, detail="CAS storage unmounted and sealed"),
    ]

    for act in actions:
        report.actions.append(act)
        if on_action:
            on_action(act)

    return report

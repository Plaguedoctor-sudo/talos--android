from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from argus import protective, timebase
from argus.config import Config
from argus.ledger import Ledger


DEFAULT_HEARTBEAT_TIMEOUT_SECONDS = 86400 * 2  # 48 hours


@dataclass(frozen=True)
class HeartbeatStatus:
    status: str
    last_heartbeat_at: str | None
    seconds_since_last: float | None
    timeout_seconds: float
    operator: str
    message: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "last_heartbeat_at": self.last_heartbeat_at,
            "seconds_since_last": self.seconds_since_last,
            "timeout_seconds": self.timeout_seconds,
            "operator": self.operator,
            "message": self.message,
        }


class DeadMansSwitch:
    def __init__(
        self,
        config: Config,
        timeout_seconds: float = DEFAULT_HEARTBEAT_TIMEOUT_SECONDS,
        session_key: bytearray | bytes | None = None,
    ) -> None:
        self.config = config
        self.config.init_directories()
        self.ledger = Ledger(config.ledger_path)
        self.state_file = self.config.data_dir / "deadman_state.json"
        self.timeout_seconds = timeout_seconds
        self.session_key = session_key

    def record_heartbeat(self, operator: str | None = None, note: str = "Routine check-in") -> HeartbeatStatus:
        op = operator or self.config.operator_name
        ts = timebase.iso_now()
        now_epoch = timebase.now().timestamp

        state = {
            "operator": op,
            "last_heartbeat_at": ts,
            "last_heartbeat_epoch": now_epoch,
            "timeout_seconds": self.timeout_seconds,
            "note": note,
        }

        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.state_file, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2)

        self.ledger.append(
            "DEAD_MAN_HEARTBEAT",
            {
                "operator": op,
                "timestamp": ts,
                "note": note,
            },
        )

        return HeartbeatStatus(
            status="ACTIVE",
            last_heartbeat_at=ts,
            seconds_since_last=0.0,
            timeout_seconds=self.timeout_seconds,
            operator=op,
            message=f"Operator heartbeat recorded at {ts}.",
        )

    def check_status(self, now_epoch: float | None = None) -> HeartbeatStatus:
        if not self.state_file.exists():
            return HeartbeatStatus(
                status="UNINITIALIZED",
                last_heartbeat_at=None,
                seconds_since_last=None,
                timeout_seconds=self.timeout_seconds,
                operator=self.config.operator_name,
                message="No prior heartbeat recorded. System unmonitored.",
            )

        with open(self.state_file, "r", encoding="utf-8") as f:
            state = json.load(f)

        current_epoch = now_epoch if now_epoch is not None else timebase.now().timestamp
        last_epoch = float(state.get("last_heartbeat_epoch", 0.0))
        elapsed = current_epoch - last_epoch
        last_ts = state.get("last_heartbeat_at")
        op = state.get("operator", self.config.operator_name)

        if elapsed > self.timeout_seconds:
            status = "TRIGGERED"
            msg = f"Dead man's switch triggered: {elapsed / 3600.0:.1f} hours elapsed since last heartbeat."
        elif elapsed > (self.timeout_seconds * 0.75):
            status = "WARNING"
            msg = f"Heartbeat deadline warning: {elapsed / 3600.0:.1f} hours elapsed."
        else:
            status = "ACTIVE"
            msg = f"Heartbeat active. Next check-in due in {(self.timeout_seconds - elapsed) / 3600.0:.1f} hours."

        return HeartbeatStatus(
            status=status,
            last_heartbeat_at=last_ts,
            seconds_since_last=round(elapsed, 1),
            timeout_seconds=self.timeout_seconds,
            operator=op,
            message=msg,
        )

    def execute_escalation_protocol(self, holder: object | None = None) -> dict[str, Any]:
        status = self.check_status()
        if status.status != "TRIGGERED":
            return {"action": "NONE", "status": status.status, "message": "Threshold not breached."}

        ts = timebase.iso_now()
        self.ledger.append(
            "DEAD_MAN_ESCALATION",
            {
                "operator": status.operator,
                "elapsed_seconds": status.seconds_since_last,
                "triggered_at": ts,
                "protocol": "PROTECTIVE_LOCKDOWN_AND_EMERGENCY_ARCHIVE",
            },
            actor=status.operator,
        )

        target_holder = holder if holder is not None else self
        report = protective.escalate(
            holder=target_holder,
            config=protective.ProtectiveConfig(),
            on_action=lambda a: self.ledger.append(
                "DEAD_MAN_ACTION",
                {"action": a.action, "ok": a.ok, "detail": a.detail},
                actor=status.operator,
            ),
        )

        return {
            "action": "ESCALATED",
            "status": "TRIGGERED",
            "protocol": "PROTECTIVE_LOCKDOWN_AND_EMERGENCY_ARCHIVE",
            "triggered_at": ts,
            "operator": status.operator,
            "report": report,
        }

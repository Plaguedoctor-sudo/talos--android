from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from argus import timebase
from argus.config import Config
from argus.db import Database
from argus.ledger import Ledger


ESCALATION_LEVELS = {
    0: "Normal",
    1: "Notice",
    2: "Warning",
    3: "Urgent",
    4: "Critical",
}


@dataclass(frozen=True)
class DeadlineAlert:
    case_id: str
    case_title: str
    deadline: str
    remaining_seconds: float
    escalation_level: int
    severity: str
    message: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "case_title": self.case_title,
            "deadline": self.deadline,
            "remaining_seconds": self.remaining_seconds,
            "escalation_level": self.escalation_level,
            "severity": self.severity,
            "message": self.message,
        }


def compute_escalation(remaining_seconds: float) -> tuple[int, str]:
    if remaining_seconds <= 0:
        return 4, "Critical overdue"
    elif remaining_seconds <= 86400:  # <= 24h
        return 3, "Urgent imminent"
    elif remaining_seconds <= 86400 * 3:  # <= 3 days
        return 2, "Warning approaching"
    elif remaining_seconds <= 86400 * 7:  # <= 7 days
        return 1, "Notice scheduled"
    else:
        return 0, "Normal baseline"


class DeadlineSentinel:
    def __init__(self, db: Database, ledger: Ledger) -> None:
        self.db = db
        self.ledger = ledger

    def evaluate_case(self, case: dict[str, Any], now_epoch: float | None = None) -> DeadlineAlert | None:
        deadline_str = case.get("deadline")
        if not deadline_str:
            return None

        current_time = now_epoch if now_epoch is not None else timebase.now().timestamp
        deadline_normalized = timebase.normalize(deadline_str)
        remaining = deadline_normalized.timestamp - current_time

        level, severity = compute_escalation(remaining)
        hours_remaining = round(remaining / 3600.0, 1)

        if remaining <= 0:
            msg = f"Case {case['title']} passed deadline by {abs(hours_remaining)} hours."
        else:
            msg = f"Case {case['title']} has {hours_remaining} hours remaining before deadline."

        return DeadlineAlert(
            case_id=case["id"],
            case_title=case["title"],
            deadline=deadline_normalized.iso,
            remaining_seconds=remaining,
            escalation_level=level,
            severity=severity,
            message=msg,
        )

    def scan_deadlines(self, operator: str = "DeadlineSentinel") -> list[DeadlineAlert]:
        cases = self.db.list_cases()
        now_epoch = timebase.now().timestamp
        alerts: list[DeadlineAlert] = []

        for case in cases:
            if case.get("status") in ["CLOSED", "RESOLVED", "ARCHIVED"]:
                continue
            alert = self.evaluate_case(case, now_epoch=now_epoch)
            if alert:
                alerts.append(alert)

        # Sort by most urgent first
        alerts.sort(key=lambda a: a.remaining_seconds)

        self.ledger.append(
            "DEADLINE_SENTINEL_SCAN",
            {
                "operator": operator,
                "scanned_cases_count": len(cases),
                "alerts_count": len(alerts),
                "highest_escalation": max((a.escalation_level for a in alerts), default=0),
                "alerts": [a.to_dict() for a in alerts if a.escalation_level >= 1],
            },
        )
        return alerts


def scan_sentinel(config: Config) -> list[DeadlineAlert]:
    db = Database(config.db_path)
    ledger = Ledger(config.ledger_path)
    sentinel = DeadlineSentinel(db, ledger)
    return sentinel.scan_deadlines(operator=config.operator_name)

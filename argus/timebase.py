"""Time Normalization Service.

Field reality: clocks drift, timestamps arrive in a dozen formats, and
"around 3pm" is normal. Never store a fake point value. Store precision
and an uncertainty window.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import IntEnum
from zoneinfo import ZoneInfo

UTC = timezone.utc


class Precision(IntEnum):
    UNKNOWN = 0
    YEAR = 1
    MONTH = 2
    DAY = 3
    HOUR = 4
    MINUTE = 5
    SECOND = 6


_WINDOW = {
    Precision.UNKNOWN: timedelta(days=3650),
    Precision.YEAR: timedelta(days=183),
    Precision.MONTH: timedelta(days=15),
    Precision.DAY: timedelta(hours=12),
    Precision.HOUR: timedelta(minutes=30),
    Precision.MINUTE: timedelta(seconds=30),
    Precision.SECOND: timedelta(seconds=1),
}

_VAGUE = {
    "early morning": (6, Precision.HOUR),
    "morning": (9, Precision.HOUR),
    "midday": (12, Precision.HOUR),
    "noon": (12, Precision.HOUR),
    "afternoon": (15, Precision.HOUR),
    "early evening": (17, Precision.HOUR),
    "evening": (19, Precision.HOUR),
    "night": (22, Precision.HOUR),
    "late night": (23, Precision.HOUR),
    "after prayers": (19, Precision.HOUR),
    "dawn": (5, Precision.HOUR),
    "dusk": (19, Precision.HOUR),
}

_HEDGE = re.compile(r"\b(around|about|approx\.?|approximately|circa|~|roughly|after|before)\b", re.I)
_DATE = re.compile(r"(\d{4})-(\d{2})-(\d{2})")
_DATE_EU = re.compile(r"(\d{1,2})[./](\d{1,2})[./](\d{4})")
_TIME = re.compile(r"(\d{1,2}):(\d{2})(?::(\d{2}))?")
_AMPM = re.compile(r"\b(\d{1,2})\s*(am|pm)\b", re.I)


@dataclass(frozen=True)
class NormalizedTime:
    utc: datetime
    precision: Precision
    window_start: datetime
    window_end: datetime
    source_tz: str | None
    device_offset_s: float
    raw: str
    confidence: float

    def local(self, tz: str | None = None) -> datetime:
        return self.utc.astimezone(ZoneInfo(tz or self.source_tz or "UTC"))

    def as_dict(self) -> dict:
        return {
            "utc": self.utc.isoformat(),
            "precision": int(self.precision),
            "precision_name": self.precision.name,
            "window_start": self.window_start.isoformat(),
            "window_end": self.window_end.isoformat(),
            "source_tz": self.source_tz,
            "device_offset_s": self.device_offset_s,
            "confidence": self.confidence,
            "raw": self.raw,
        }

    @property
    def iso(self) -> str:
        return self.utc.isoformat()

    @property
    def timestamp(self) -> float:
        return self.utc.timestamp()

    def overlaps(self, other: "NormalizedTime") -> bool:
        return self.window_start <= other.window_end and other.window_start <= self.window_end


def _tz(name: str | None) -> timezone | ZoneInfo:
    if not name:
        return UTC
    try:
        return ZoneInfo(name)
    except Exception:
        return UTC


def normalize(
    raw: str,
    *,
    source_tz: str | None = None,
    device_offset_s: float = 0.0,
    fallback: Precision | None = None,
) -> NormalizedTime:
    """Parse anything into a normalized time with honest uncertainty.

    device_offset_s: how far ahead the capturing device's clock was, in seconds.
    """
    text = str(raw).strip()
    tzinfo = _tz(source_tz)
    hedged = bool(_HEDGE.search(text))
    precision = Precision.UNKNOWN
    naive: datetime | None = None

    m = _DATE.search(text)
    if m:
        y, mo, d = (int(x) for x in m.groups())
        naive = datetime(y, mo, d)
        precision = Precision.DAY
        t = _TIME.search(text)
        if t:
            hh, mm = int(t.group(1)), int(t.group(2))
            ss = int(t.group(3) or 0)
            naive = naive.replace(hour=hh, minute=mm, second=ss)
            precision = Precision.SECOND if t.group(3) else Precision.MINUTE
    else:
        m2 = _DATE_EU.search(text)
        if m2:
            d, mo, y = (int(x) for x in m2.groups())
            naive = datetime(y, mo, d)
            precision = Precision.DAY

    if naive is None:
        low = text.lower()
        for phrase, (hour, prec) in _VAGUE.items():
            if phrase in low:
                today = datetime.now(tzinfo).date()
                naive = datetime(today.year, today.month, today.day, hour)
                precision = prec
                break

    if naive is None:
        m3 = _AMPM.search(text)
        if m3:
            hour = int(m3.group(1)) % 12
            if m3.group(2).lower() == "pm":
                hour += 12
            today = datetime.now(tzinfo).date()
            naive = datetime(today.year, today.month, today.day, hour)
            precision = Precision.HOUR
        else:
            t = _TIME.search(text)
            if t:
                today = datetime.now(tzinfo).date()
                naive = datetime(today.year, today.month, today.day,
                                  int(t.group(1)), int(t.group(2)), int(t.group(3) or 0))
                precision = Precision.SECOND if t.group(3) else Precision.MINUTE

    if naive is None:
        try:
            dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
            naive = dt.replace(tzinfo=None)
            precision = Precision.SECOND
            if dt.tzinfo:
                tzinfo = dt.tzinfo
        except ValueError:
            pass

    if naive is None:
        naive = datetime.now(UTC).replace(tzinfo=None)
        precision = fallback or Precision.UNKNOWN
        confidence = 0.3
    else:
        confidence = 1.0 if not hedged else 0.6

    if hedged and precision > Precision.HOUR:
        precision = Precision.HOUR

    aware = naive.replace(tzinfo=tzinfo)
    utc = aware.astimezone(UTC) - timedelta(seconds=device_offset_s)

    if precision == Precision.UNKNOWN:
        utc = utc.replace(microsecond=0)
    else:
        step = _WINDOW[precision]
        utc = utc - timedelta(seconds=utc.second % max(int(step.total_seconds()), 1))

    half = _WINDOW[precision] / 2
    return NormalizedTime(
        utc=utc,
        precision=precision,
        window_start=utc - half,
        window_end=utc + half,
        source_tz=source_tz,
        device_offset_s=device_offset_s,
        raw=raw,
        confidence=confidence,
    )


def now() -> NormalizedTime:
    return normalize(datetime.now(UTC).isoformat(), source_tz="UTC")


def now_iso() -> str:
    return now().utc.isoformat(timespec="microseconds").replace("+00:00", "Z")


def iso_now() -> str:
    return now_iso()


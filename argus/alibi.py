"""Alibi-collision engine for argus.

Given claims (person says they were at location A during window W) and
observations (sensor says the subject was at location B during window V),
flag pairs that require a physically implausible velocity to reconcile.

The engine is deliberately conservative: it flags and classifies, it does not
decide. The operator reads the collision list and assigns an explanation.

Reuses haversine_m from argus.chronology (the same primitive the existing
bilocation detector uses) so there is a single implementation of Great Circle
math in the codebase.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable, Literal, Sequence

from argus.chronology import haversine_m

__all__ = [
    "ClaimView",
    "ObservationView",
    "Thresholds",
    "Collision",
    "collide",
    "collide_all",
    "aggregate_support",
]

Severity = Literal["hard", "near", "consistent"]


# ---------------------------------------------------------------------------
# Views: duck-typed adapters so the engine does not import SQLAlchemy models.
# The router in backend/app/routers/hypotheses.py builds these from ORM rows.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ClaimView:
    id: str
    earliest: str
    latest: str
    lat: float | None
    lon: float | None
    tolerance_m: float = 150.0
    origin_cluster_id: str | None = None


@dataclass(frozen=True)
class ObservationView:
    id: str
    earliest: str
    latest: str
    lat: float | None
    lon: float | None
    tolerance_m: float = 50.0
    origin_cluster_id: str | None = None


@dataclass(frozen=True)
class Thresholds:
    """Physically-informed cut-offs. Overridable per case type.

    Defaults: hard > airliner cruise (>900 km/h); near > sustained highway
    speed (>120 km/h); below that is consistent with a vehicle journey.
    """

    hard_kmh: float = 900.0
    near_kmh: float = 120.0


@dataclass(frozen=True)
class Collision:
    claim_id: str
    observation_id: str
    distance_m: float
    min_gap_s: float
    window_gap_s: float
    required_kmh: float | None  # None when windows overlap with zero budget and locations differ
    severity: Severity
    claim_window: tuple[str, str]
    observation_window: tuple[str, str]
    claim_location: tuple[float, float] | None
    observation_location: tuple[float, float] | None


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


def _parse(iso: str) -> datetime:
    text = iso.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _min_gap_seconds(
    c_e: datetime,
    c_l: datetime,
    o_e: datetime,
    o_l: datetime,
) -> float:
    """Tightest possible gap between windows. 0 when they overlap."""
    if o_e <= c_l and c_e <= o_l:
        return 0.0
    if c_l < o_e:
        return (o_e - c_l).total_seconds()
    return (c_e - o_l).total_seconds()


def _window_gap_seconds(
    c_e: datetime,
    c_l: datetime,
    o_e: datetime,
    o_l: datetime,
) -> float:
    """Maximum possible time between events, given both windows.

    This is the time budget for travel: the subject could be at the claim
    location at the earliest plausible moment and at the observation
    location at the latest (or vice versa). Classifying collisions on this
    value — rather than on min_gap_s — is what separates a genuine
    impossibility from a witness whose estimate was off by a few hundred
    metres.
    """
    return max(
        (o_l - c_e).total_seconds(),
        (c_l - o_e).total_seconds(),
    )


def _classify(
    distance_m: float,
    gap_s: float,
    tolerance_m: float,
    thresholds: Thresholds,
) -> tuple[Severity, float | None]:
    if distance_m <= tolerance_m:
        # Same place within tolerance; time is irrelevant to the collision.
        return "consistent", None
    if gap_s <= 0.0:
        # Overlapping windows at different places → infinite required velocity.
        return "hard", None
    kmh = (distance_m / 1000.0) / (gap_s / 3600.0)
    if kmh >= thresholds.hard_kmh:
        return "hard", kmh
    if kmh >= thresholds.near_kmh:
        return "near", kmh
    return "consistent", kmh


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def collide(
    claim: ClaimView,
    observation: ObservationView,
    *,
    thresholds: Thresholds | None = None,
) -> Collision | None:
    """Evaluate one claim against one observation.

    Returns None if either side has no location. Same-origin pairs are still
    evaluated here; filtering those is the caller's concern (see collide_all).
    """
    if claim.lat is None or claim.lon is None:
        return None
    if observation.lat is None or observation.lon is None:
        return None

    th = thresholds or Thresholds()
    c_e, c_l = _parse(claim.earliest), _parse(claim.latest)
    o_e, o_l = _parse(observation.earliest), _parse(observation.latest)
    min_gap_s = _min_gap_seconds(c_e, c_l, o_e, o_l)
    window_gap_s = _window_gap_seconds(c_e, c_l, o_e, o_l)
    distance_m = haversine_m(claim.lat, claim.lon, observation.lat, observation.lon)
    tolerance_m = max(claim.tolerance_m, observation.tolerance_m)
    severity, kmh = _classify(distance_m, window_gap_s, tolerance_m, th)

    return Collision(
        claim_id=claim.id,
        observation_id=observation.id,
        distance_m=distance_m,
        min_gap_s=min_gap_s,
        window_gap_s=window_gap_s,
        required_kmh=kmh,
        severity=severity,
        claim_window=(claim.earliest, claim.latest),
        observation_window=(observation.earliest, observation.latest),
        claim_location=(claim.lat, claim.lon),
        observation_location=(observation.lat, observation.lon),
    )


def collide_all(
    claims: Sequence[ClaimView],
    observations: Sequence[ObservationView],
    *,
    thresholds: Thresholds | None = None,
    skip_same_origin: bool = True,
    severities: Iterable[Severity] = ("hard", "near"),
) -> list[Collision]:
    """Cross-product collisions filtered to the severities the operator cares about.

    Same-origin pairs (claim and observation share origin_cluster_id) are
    skipped by default: a person repeating their own alibi to a different
    interviewer is not a collision, it is one source saying the same thing.
    """
    wanted = set(severities)
    out: list[Collision] = []
    for claim in claims:
        for obs in observations:
            if (
                skip_same_origin
                and claim.origin_cluster_id is not None
                and claim.origin_cluster_id == obs.origin_cluster_id
            ):
                continue
            c = collide(claim, obs, thresholds=thresholds)
            if c is None or c.severity not in wanted:
                continue
            out.append(c)
    out.sort(
        key=lambda c: (
            {"hard": 0, "near": 1, "consistent": 2}[c.severity],
            -(c.required_kmh if c.required_kmh is not None else float("inf")),
            c.min_gap_s,
        )
    )
    return out


def aggregate_support(
    links: Iterable[tuple[str, float, str | None]],
) -> float:
    """Combine supporting links into a hypothesis-level confidence.

    links: iterable of (assertion_id, weight, origin_cluster_id or None).

    Within an origin cluster: take the max weight, not the sum, because two
    reports from the same origin are one source and must not stack.
    Across clusters: combine with Noisy-OR (p = 1 - prod(1 - w_i)), which is
    the probability at least one independent source is right. Deliberately
    conservative: three genuinely independent 0.5-weight sources yield 0.875,
    not 1.5 capped to 1.0.

    The caller is responsible for passing only links where polarity == "supports";
    undercutting links are combined the same way by the caller and the two
    aggregate scores are shown side by side, not subtracted.
    """
    by_cluster: dict[str, list[float]] = {}
    for aid, weight, cluster in links:
        key = cluster if cluster else f"#{aid}"
        by_cluster.setdefault(key, []).append(weight)
    cluster_weights = [max(ws) for ws in by_cluster.values()]
    p_miss = 1.0
    for w in cluster_weights:
        p_miss *= 1.0 - max(0.0, min(1.0, w))
    return 1.0 - p_miss

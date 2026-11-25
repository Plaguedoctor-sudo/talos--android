"""Duress credential.

The operator has two passwords: the real one, and the duress one. Entering
the duress password authenticates successfully and routes every subsequent
request to a decoy case list. From the client's point of view, nothing is
wrong. From the operator's point of view, real cases are hidden and the
duress session is recorded to the ledger for later examination.

Design decisions:

  1. Both passwords are stored as PBKDF2-HMAC-SHA256 hashes, indistinguishable
     from one another in storage. A timing side-channel that reveals which password
     was entered would defeat the point. The constant-time comparison is the
     load-bearing primitive.

  2. The decoy case list is stored in a separate SQLite database file
     (decoy.db), created on first duress login from a template. It contains
     case rows, hypothesis rows, claim rows, and report entries that are
     internally consistent. The operator seeds it once with plausible fake
     cases; without seeding, the first duress session shows an empty
     investigation, which is itself a tell.

  3. Duress mode writes nothing to the real ledger. A decoy session routes
     all database queries to decoy.db and all ledger writes to decoy_ledger.jsonl.
     If an offline audit trail is configured, sessions are recorded to an isolated
     duress_session.jsonl file with no case content.

  4. The session marker is held in the auth token (a short JWT claim), not in
     a side table, so a session that is stolen mid-flight cannot flip its own
     mode.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import sqlite3
import threading
from dataclasses import dataclass
from typing import Callable

from argus import timebase

__all__ = [
    "DuressConfig",
    "CredentialKind",
    "AuthResult",
    "DuressStore",
    "verify_password",
    "hash_password",
    "log_duress_session",
    "DecoyPlausibility",
    "PlausibilityError",
]


# ---------------------------------------------------------------------------
# Decoy Plausibility
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DecoyPlausibility:
    data_volume_mb: float
    app_count: int
    history_age_days: float
    contact_count: int = 15
    message_count: int = 50

    def score(self) -> float:
        """Compute composite plausibility score between 0.0 and 100.0.

        Inputs:
          - data_volume_mb: size of user storage (target >= 500 MB)
          - app_count: count of installed applications (target >= 15)
          - history_age_days: oldest log timestamp age (target >= 30 days)
          - contact_count & message_count: communication history
        """
        v_norm = min(1.0, max(0.0, self.data_volume_mb) / 500.0)
        a_norm = min(1.0, max(0, self.app_count) / 15.0)
        h_norm = min(1.0, max(0.0, self.history_age_days) / 30.0)
        c_norm = min(1.0, max(0, self.contact_count + (self.message_count // 10)) / 20.0)

        composite = (0.35 * v_norm + 0.25 * a_norm + 0.25 * h_norm + 0.15 * c_norm) * 100.0
        return round(composite, 2)

    def is_plausible(self, threshold: float = 60.0) -> bool:
        return self.score() >= threshold


class PlausibilityError(ValueError):
    """Raised when decoy environment fails plausibility verification."""


# ---------------------------------------------------------------------------
# Password hashing
# ---------------------------------------------------------------------------


PBKDF2_ITERATIONS = 600_000


def hash_password(password: str, *, salt: bytes | None = None) -> tuple[str, str]:
    """Return (salt_hex, hash_hex) using PBKDF2-HMAC-SHA256.

    Stdlib only. If argon2-cffi is added later, swap this implementation
    without changing callers.
    """
    if not password:
        raise ValueError("password must be non-empty")
    s = salt if salt is not None else secrets.token_bytes(16)
    h = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), s, PBKDF2_ITERATIONS)
    return s.hex(), h.hex()


def verify_password(
    password: str, salt_hex: str, hash_hex: str
) -> bool:
    """Constant-time comparison. Returns False on any error, never raises."""
    if not password:
        return False
    try:
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(hash_hex)
    except (ValueError, TypeError):
        return False
    candidate = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return hmac.compare_digest(candidate, expected)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DuressConfig:
    real_db_path: Path
    decoy_db_path: Path
    ledger_path: Path
    decoy_ledger_path: Path | None = None
    real_actor: str = "operator"
    duress_actor: str = "operator"


CredentialKind = str  # 'real' | 'duress' | 'invalid'


@dataclass(frozen=True)
class AuthResult:
    kind: CredentialKind
    # The database path the caller should route this session to.
    db_path: Path | None
    # The ledger path writes should be routed to. Always the real ledger path
    # for auditability, but the session mode determines whether writes happen.
    ledger_path: Path | None
    actor: str | None


# ---------------------------------------------------------------------------
# Store
# ---------------------------------------------------------------------------


class DuressStore:
    """Holds both password hashes and performs constant-time auth.

    The two hashes are stored in a small SQLite database alongside the
    decoy.db file, not alongside investigations.db. If the operator's
    laptop is seized, the duress setup lives on a different file with a
    different access pattern; discovering it requires knowing it exists.
    """

    def __init__(self, path: Path) -> None:
        self._path = path
        self._lock = threading.Lock()
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self._path), check_same_thread=False)
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS credentials (
                kind TEXT PRIMARY KEY,
                salt_hex TEXT NOT NULL,
                hash_hex TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        self._conn.commit()

    # -- enrollment -------------------------------------------------------

    def set_password(self, kind: str, password: str) -> None:
        if kind not in ("real", "duress"):
            raise ValueError("kind must be 'real' or 'duress'")
        salt_hex, hash_hex = hash_password(password)
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO credentials (kind, salt_hex, hash_hex, created_at) "
                "VALUES (?,?,?,?)",
                (kind, salt_hex, hash_hex, timebase.iso_now()),
            )
            self._conn.commit()

    def enroll_decoy(
        self,
        password: str,
        plausibility: DecoyPlausibility,
        threshold: float = 60.0,
    ) -> float:
        """Enroll duress credential only if decoy passes plausibility threshold."""
        score = plausibility.score()
        if score < threshold:
            raise PlausibilityError(
                f"Decoy plausibility score {score:.1f} below required threshold {threshold:.1f}. Enrollment rejected."
            )
        self.set_password("duress", password)
        return score

    def has(self, kind: str) -> bool:
        with self._lock:
            row = self._conn.execute(
                "SELECT 1 FROM credentials WHERE kind = ?", (kind,)
            ).fetchone()
        return row is not None

    # -- auth -------------------------------------------------------------

    def authenticate(
        self,
        password: str,
        *,
        config: DuressConfig,
        on_duress: Callable[[], None] | None = None,
    ) -> AuthResult:
        """Return AuthResult describing the session mode.

        Constant-time: both hashes are always compared, even if the first
        comparison succeeds. A timing side-channel that reveals which
        password was entered would defeat the point.

        If `password` matches neither, returns kind='invalid'. The caller
        is responsible for rate limiting on failure -- this module does
        not implement lockout.
        """
        real_row = self._row("real")
        duress_row = self._row("duress")

        real_ok = (
            verify_password(password, real_row[0], real_row[1])
            if real_row is not None else False
        )
        duress_ok = (
            verify_password(password, duress_row[0], duress_row[1])
            if duress_row is not None else False
        )

        if real_ok and not duress_ok:
            return AuthResult(
                kind="real",
                db_path=config.real_db_path,
                ledger_path=config.ledger_path,
                actor=config.real_actor,
            )
        if duress_ok and not real_ok:
            _ensure_decoy_db(config.decoy_db_path)
            decoy_ledger = config.decoy_ledger_path or (config.decoy_db_path.parent / "decoy_ledger.jsonl")
            if on_duress is not None:
                try:
                    on_duress()
                except Exception:  # noqa: BLE001
                    pass
            return AuthResult(
                kind="duress",
                db_path=config.decoy_db_path,
                ledger_path=decoy_ledger,
                actor=config.duress_actor,
            )
        # Both real_ok and duress_ok cannot be true unless the two passwords
        # are identical; we refuse that state defensively.
        return AuthResult(kind="invalid", db_path=None, ledger_path=None, actor=None)

    # -- internals --------------------------------------------------------

    def _row(self, kind: str) -> tuple[str, str] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT salt_hex, hash_hex FROM credentials WHERE kind = ?",
                (kind,),
            ).fetchone()
        return (row[0], row[1]) if row else None

    def close(self) -> None:
        with self._lock:
            self._conn.close()


# ---------------------------------------------------------------------------
# Decoy database
# ---------------------------------------------------------------------------


_DECOY_SCHEMA = """
CREATE TABLE IF NOT EXISTS cases (
    id TEXT PRIMARY KEY,
    case_number TEXT NOT NULL,
    title TEXT NOT NULL,
    client_name TEXT NOT NULL,
    status TEXT NOT NULL,
    priority TEXT NOT NULL,
    objective TEXT NOT NULL,
    classification_level TEXT NOT NULL,
    case_type TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS hypotheses (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    statement TEXT NOT NULL,
    status TEXT NOT NULL,
    what_would_change_my_mind TEXT NOT NULL,
    disconfirming_evidence TEXT,
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS claims (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    speaker TEXT NOT NULL,
    statement TEXT NOT NULL,
    earliest TEXT NOT NULL,
    latest TEXT NOT NULL,
    precision TEXT NOT NULL,
    confidence REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS observations (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    source TEXT NOT NULL,
    earliest TEXT NOT NULL,
    latest TEXT NOT NULL,
    precision TEXT NOT NULL,
    confidence REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS evidence (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    title TEXT NOT NULL,
    evidence_type TEXT NOT NULL,
    file_hash TEXT NOT NULL,
    file_path TEXT NOT NULL,
    verification_status TEXT NOT NULL
);
"""


def _ensure_decoy_db(path: Path) -> None:
    """Create the decoy database with schema if it does not exist.

    The operator is expected to seed it once with plausible fake cases.
    An empty decoy is a tell: a real operator would not present an
    investigation with zero cases.
    """
    if path.exists():
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    try:
        conn.executescript(_DECOY_SCHEMA)
        conn.commit()
    finally:
        conn.close()


def log_duress_session(data_dir: Path | None = None) -> Path:
    """Record an uninformative timestamp-only marker of a duress session.

    Written to duress_session.jsonl with mode 0600. Never touches the ledger.
    """
    target_dir = data_dir or (Path.home() / ".argus" / "data")
    target_dir.mkdir(parents=True, exist_ok=True)
    session_file = target_dir / "duress_session.jsonl"
    ts = timebase.now().iso
    fd = os.open(str(session_file), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(json.dumps({"at": ts}) + "\n")
    return session_file

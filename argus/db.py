from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any


class Database:
    """Lightweight SQLite database for ARGUS state and evidence metadata."""

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._get_conn() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS cases (
                    id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    deadline TEXT,
                    created_at TEXT NOT NULL,
                    metadata_json TEXT
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS evidence (
                    id TEXT PRIMARY KEY,
                    case_id TEXT,
                    sha256 TEXT NOT NULL,
                    blake3 TEXT,
                    size INTEGER,
                    mime TEXT,
                    original_name TEXT,
                    captured_at TEXT,
                    captured_precision INTEGER,
                    captured_confidence REAL,
                    ingested_at TEXT,
                    ingested_by TEXT,
                    method TEXT,
                    source_ref TEXT,
                    custody_head TEXT,
                    classification TEXT
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS case_evidence (
                    case_id TEXT,
                    evidence_id TEXT,
                    linked_at TEXT,
                    PRIMARY KEY (case_id, evidence_id)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS entities (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    entity_type TEXT NOT NULL,
                    attributes_json TEXT,
                    created_at TEXT NOT NULL
                )
                """
            )
            conn.commit()

    def list_cases(self) -> list[dict[str, Any]]:
        with self._get_conn() as conn:
            rows = conn.execute("SELECT * FROM cases").fetchall()
            return [dict(r) for r in rows]

    def get_case(self, case_id: str) -> dict[str, Any] | None:
        with self._get_conn() as conn:
            row = conn.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone()
            return dict(row) if row else None

    def insert_case(self, case_dict: dict[str, Any]) -> None:
        with self._get_conn() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO cases (id, title, deadline, created_at, metadata_json)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    case_dict.get("id"),
                    case_dict.get("title", ""),
                    case_dict.get("deadline"),
                    case_dict.get("created_at", ""),
                    json.dumps(case_dict.get("metadata", {})),
                ),
            )
            conn.commit()

    def insert_evidence(self, ev_dict: dict[str, Any]) -> None:
        with self._get_conn() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO evidence (
                    id, case_id, sha256, blake3, size, mime, original_name,
                    captured_at, captured_precision, captured_confidence,
                    ingested_at, ingested_by, method, source_ref, custody_head, classification
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    ev_dict.get("id"),
                    ev_dict.get("case_id"),
                    ev_dict.get("sha256", ""),
                    ev_dict.get("blake3"),
                    ev_dict.get("size", 0),
                    ev_dict.get("mime", "application/octet-stream"),
                    ev_dict.get("original_name", ""),
                    str(ev_dict.get("captured_at", "")),
                    ev_dict.get("captured_precision", 1),
                    ev_dict.get("captured_confidence", 1.0),
                    ev_dict.get("ingested_at", ""),
                    ev_dict.get("ingested_by", ""),
                    ev_dict.get("method", "auto"),
                    ev_dict.get("source_ref"),
                    ev_dict.get("custody_head"),
                    ev_dict.get("classification", "INTERNAL"),
                ),
            )
            conn.commit()

    def link_case_evidence(self, case_id: str, evidence_id: str, linked_at: str) -> None:
        with self._get_conn() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO case_evidence (case_id, evidence_id, linked_at)
                VALUES (?, ?, ?)
                """,
                (case_id, evidence_id, linked_at),
            )
            conn.commit()

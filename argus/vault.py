"""Evidence vault. Content-addressed storage with a hash-linked custody chain.

Rule: blobs are immutable. Deletion removes a pointer, never bytes.
Every custody event commits to the previous event's hash.
"""
from __future__ import annotations

import hashlib
import mimetypes
import shutil
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from . import config
from .ledger import Ledger
from .timebase import NormalizedTime, normalize

try:
    import blake3 as _blake3
except ImportError:
    _blake3 = None

GENESIS = "0" * 64


def custody_digest(evidence_id: str, seq: int, action: str, actor: str,
                   at: str, note: str, prev: str) -> str:
    return hashlib.sha256(
        f"{prev}|{evidence_id}|{seq}|{action}|{actor}|{at}|{note}".encode()
    ).hexdigest()


@dataclass
class Evidence:
    id: str
    case_id: str
    sha256: str
    blake3: str | None
    size: int
    mime: str
    original_name: str
    captured_at: NormalizedTime
    method: str
    source_ref: str | None


def _hash_file(path: Path) -> tuple[str, str | None, int]:
    sha = hashlib.sha256()
    b3 = _blake3.blake3() if _blake3 else None
    size = 0
    with path.open("rb") as fh:
        while chunk := fh.read(config.CHUNK):
            sha.update(chunk)
            if b3:
                b3.update(chunk)
            size += len(chunk)
    return sha.hexdigest(), (b3.hexdigest() if b3 else None), size


class Vault:
    def __init__(self, conn, ledger: Ledger) -> None:
        self.conn = conn
        self.ledger = ledger
        config.BLOBS.mkdir(parents=True, exist_ok=True)

    # ---------- ingest ----------

    def ingest_file(
        self,
        path: str | Path,
        *,
        case_id: str,
        method: str = "manual",
        captured_raw: str | None = None,
        source_tz: str | None = None,
        device_offset_s: float = 0.0,
        source_ref: str | None = None,
        classification: str = "INTERNAL",
        actor: str | None = None,
    ) -> Evidence:
        src = Path(path)
        if not src.exists():
            raise FileNotFoundError(src)
        actor = actor or config.ACTOR
        sha, b3, size = _hash_file(src)

        blob = config.BLOBS / sha[:2] / sha
        blob.parent.mkdir(parents=True, exist_ok=True)
        if not blob.exists():
            shutil.copy2(src, blob)

        captured = normalize(captured_raw or datetime.now(timezone.utc).isoformat(),
                             source_tz=source_tz, device_offset_s=device_offset_s)

        ev = Evidence(
            id=str(uuid.uuid4()),
            case_id=case_id,
            sha256=sha,
            blake3=b3,
            size=size,
            mime=mimetypes.guess_type(src.name)[0] or "application/octet-stream",
            original_name=src.name,
            captured_at=captured,
            method=method,
            source_ref=source_ref,
        )
        head = self._custody(ev.id, 0, "captured", actor, f"method={method}", GENESIS)

        self.conn.execute(
            """INSERT INTO evidence (id, case_id, sha256, blake3, size, mime, original_name,
               captured_at, captured_precision, captured_confidence, ingested_at, ingested_by,
               method, source_ref, custody_head, classification)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (ev.id, case_id, sha, b3, size, ev.mime, src.name,
             captured.utc.isoformat(), int(captured.precision), captured.confidence,
             datetime.now(timezone.utc).isoformat(), actor, method, source_ref, head, classification),
        )
        self.conn.commit()
        self.ledger.append("evidence.ingest", {
            "evidence_id": ev.id, "case_id": case_id, "sha256": sha, "size": size,
            "method": method, "captured": captured.as_dict(),
        }, actor)
        return ev

    # ---------- custody ----------

    def _custody(self, evidence_id: str, seq: int, action: str, actor: str,
                 note: str, prev: str) -> str:
        at = datetime.now(timezone.utc).isoformat()
        digest = custody_digest(evidence_id, seq, action, actor, at, note, prev)
        self.conn.execute(
            "INSERT INTO custody (evidence_id, seq, action, actor, at, note, prev_hash, hash)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (evidence_id, seq, action, actor, at, note, prev, digest),
        )
        return digest

    def add_custody(self, evidence_id: str, action: str, note: str = "",
                    actor: str | None = None) -> str:
        actor = actor or config.ACTOR
        row = self.conn.execute(
            "SELECT custody_head FROM evidence WHERE id=?", (evidence_id,)
        ).fetchone()
        if row is None:
            raise KeyError(evidence_id)
        seq = self.conn.execute(
            "SELECT COALESCE(MAX(seq),0)+1 FROM custody WHERE evidence_id=?", (evidence_id,)
        ).fetchone()[0]
        head = self._custody(evidence_id, seq, action, actor, note, row["custody_head"])
        self.conn.execute("UPDATE evidence SET custody_head=? WHERE id=?", (head, evidence_id))
        self.conn.commit()
        self.ledger.append("evidence.custody", {
            "evidence_id": evidence_id, "action": action, "seq": seq,
        }, actor)
        return head

    # ---------- verification ----------

    def verify(self, evidence_id: str) -> tuple[bool, str]:
        row = self.conn.execute("SELECT * FROM evidence WHERE id=?", (evidence_id,)).fetchone()
        if row is None:
            return False, "not found"
        blob = config.BLOBS / row["sha256"][:2] / row["sha256"]
        if not blob.exists():
            return False, "blob missing"
        sha, _, size = _hash_file(blob)
        if sha != row["sha256"]:
            return False, "blob hash mismatch"
        if size != row["size"]:
            return False, "size mismatch"

        prev = GENESIS
        expected_seq = 0
        for c in self.conn.execute(
            "SELECT * FROM custody WHERE evidence_id=? ORDER BY seq", (evidence_id,)
        ):
            if c["seq"] != expected_seq or c["prev_hash"] != prev:
                return False, f"custody chain broken at seq {c['seq']}"
            digest = hashlib.sha256(
                f"{c['prev_hash']}|{evidence_id}|{c['seq']}|{c['action']}|{c['actor']}|"
                f"{c['at']}|{c['note'] or ''}".encode()
            ).hexdigest()
            if digest != c["hash"]:
                return False, f"custody hash mismatch at seq {c['seq']}"
            prev = c["hash"]
            expected_seq += 1
        if prev != row["custody_head"]:
            return False, "custody head mismatch"
        return True, f"verified ({expected_seq} custody events)"

    def export_bundle(self, evidence_ids: list[str], out_dir: str | Path) -> Path:
        out = Path(out_dir)
        out.mkdir(parents=True, exist_ok=True)
        (out / "MANIFEST.txt").write_text(self._manifest(evidence_ids))
        for eid in evidence_ids:
            row = self.conn.execute("SELECT * FROM evidence WHERE id=?", (eid,)).fetchone()
            if row is None:
                continue
            blob = config.BLOBS / row["sha256"][:2] / row["sha256"]
            shutil.copy2(blob, out / f"{row['sha256']}_{row['original_name']}")
        return out

    def _manifest(self, evidence_ids: list[str]) -> str:
        lines = ["ARGUS EVIDENCE BUNDLE", "=" * 60, ""]
        for eid in evidence_ids:
            row = self.conn.execute("SELECT * FROM evidence WHERE id=?", (eid,)).fetchone()
            if row is None:
                lines.append(f"{eid}: MISSING")
                continue
            ok, msg = self.verify(eid)
            lines += [
                f"evidence id : {row['id']}",
                f"case        : {row['case_id']}",
                f"sha256      : {row['sha256']}",
                f"size        : {row['size']}",
                f"captured    : {row['captured_at']} (precision={row['captured_precision']})",
                f"method      : {row['method']}",
                f"custody     : {msg}",
                "",
            ]
        return "\n".join(lines)

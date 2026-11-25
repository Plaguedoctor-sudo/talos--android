from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

from argus import timebase
from argus.config import Config
from argus.db import Database
from argus.entities import EntityManager, SoftEntity
from argus.ledger import Ledger
from argus.vault import Vault


def extract_text_from_file(file_path: Path) -> str:
    suffix = file_path.suffix.lower()

    if suffix in [".txt", ".md", ".json", ".csv", ".log", ".xml", ".html"]:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()

    # Image OCR extraction attempt
    if suffix in [".png", ".jpg", ".jpeg", ".tiff", ".bmp"]:
        if shutil.which("tesseract"):
            res = subprocess.run(
                ["tesseract", str(file_path), "stdout", "--oem", "1", "-l", "eng"],
                capture_output=True,
                text=True,
                check=False,
            )
            if res.returncode == 0 and res.stdout.strip():
                return res.stdout.strip()
        return f"Image evidence {file_path.name} ingested without external OCR engine."

    # Binary or PDF fallback
    with open(file_path, "rb") as f:
        data = f.read(8192)
    # Search for printable ASCII strings in binary stream
    ascii_strings = re.findall(rb"[a-zA-Z0-9\s.,;:\-_@]{4,}", data)
    decoded = [s.decode("ascii", errors="ignore") for s in ascii_strings]
    return " ".join(decoded) if decoded else f"Binary payload {file_path.name}"


class FolderWatcher:
    def __init__(self, config: Config) -> None:
        self.config = config
        self.config.init_directories()
        self.ledger = Ledger(config.ledger_path)
        self.vault = Vault(config.vault_dir, self.ledger)
        self.db = Database(config.db_path)
        self.entity_mgr = EntityManager(self.db, self.ledger)

        self.processed_dir = self.config.watch_dir / ".processed"
        self.processed_dir.mkdir(parents=True, exist_ok=True)

    def process_file(self, file_path: Path, operator: str = "FolderWatcher") -> dict[str, Any]:
        if not file_path.is_file():
            raise FileNotFoundError(f"Watch file does not exist: {file_path}")

        with open(file_path, "rb") as f:
            data = f.read()

        filename = file_path.name

        # 1. Ingest into vault
        record = self.vault.store(
            data=data,
            filename=filename,
            operator=operator,
            reason="Ingested via automated folder watcher",
        )

        self.db.insert_evidence(
            evidence_id=record.evidence_id,
            filename=record.original_filename,
            mime_type=record.mime_type,
            size_bytes=record.size_bytes,
            ingested_at=record.ingested_at,
            source="FolderWatcher",
            status="INGESTED",
        )

        # 2. OCR and text extraction
        extracted_text = extract_text_from_file(file_path)

        self.ledger.append(
            "WATCHER_OCR_EXTRACTION",
            {
                "evidence_id": record.evidence_id,
                "filename": filename,
                "extracted_length": len(extracted_text),
                "snippet": extracted_text[:200],
            },
        )

        # 3. File itself: Case matching
        cases = self.db.list_cases()
        matched_case_id: str | None = None
        lower_text = extracted_text.lower()

        for case in cases:
            case_title_terms = case["title"].lower().split()
            if any(term in lower_text for term in case_title_terms if len(term) > 3):
                matched_case_id = case["id"]
                break

        if not matched_case_id:
            # Default intake case
            matched_case_id = "case_inbox"
            if not self.db.get_case("case_inbox"):
                self.db.insert_case(
                    case_id="case_inbox",
                    title="General intake",
                    description="Automated intake case for unassigned evidence",
                    status="ACTIVE",
                    priority="MEDIUM",
                    created_at=timebase.iso_now(),
                )

        now_ts = timebase.iso_now()
        self.db.link_case_evidence(matched_case_id, record.evidence_id, now_ts)
        self.ledger.append(
            "WATCHER_FILE_EVIDENCE",
            {
                "evidence_id": record.evidence_id,
                "case_id": matched_case_id,
                "filed_at": now_ts,
            },
        )

        # 4. Entity extraction heuristics from extracted text
        discovered_entities: list[str] = []
        emails = re.findall(r"[\w\.-]+@[\w\.-]+\.\w+", extracted_text)
        for email in set(emails):
            entity = SoftEntity.create(
                canonical_name=email,
                entity_type="PERSON",
                admiralty_grade="B2",
                attributes={"email": [email]},
                provenance_evidence=[record.evidence_id],
            )
            self.entity_mgr.register_entity(entity, operator=operator)
            discovered_entities.append(entity.id)

        # Move to processed folder to prevent re-ingestion
        target_path = self.processed_dir / f"{timebase.now().timestamp}_{filename}"
        shutil.move(str(file_path), str(target_path))

        return {
            "evidence_id": record.evidence_id,
            "filename": filename,
            "case_id": matched_case_id,
            "extracted_length": len(extracted_text),
            "discovered_entities": discovered_entities,
            "archived_path": str(target_path),
        }

    def scan_once(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for item in sorted(self.config.watch_dir.iterdir()):
            if item.is_file() and not item.name.startswith("."):
                result = self.process_file(item)
                results.append(result)
        return results

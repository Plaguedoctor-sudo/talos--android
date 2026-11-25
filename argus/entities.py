from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from argus import timebase
from argus.db import Database
from argus.ledger import Ledger


@dataclass
class SoftEntity:
    id: str
    name: str
    entity_type: str = "subject"
    attributes: dict[str, Any] = field(default_factory=dict)


class EntityManager:
    def __init__(self, db: Database, ledger: Ledger) -> None:
        self.db = db
        self.ledger = ledger

    def register_entity(
        self, entity: SoftEntity, operator: str = "argus-core"
    ) -> None:
        with self.db._get_conn() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO entities (id, name, entity_type, attributes_json, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    entity.id,
                    entity.name,
                    entity.entity_type,
                    json.dumps(entity.attributes),
                    timebase.iso_now(),
                ),
            )
            conn.commit()

        self.ledger.append(
            "ENTITY_REGISTERED",
            {
                "entity_id": entity.id,
                "name": entity.name,
                "type": entity.entity_type,
            },
            actor=operator,
        )

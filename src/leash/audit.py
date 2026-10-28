from __future__ import annotations

import asyncio
import hashlib
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Any

from leash.contracts import AuditEvent
from leash.digest import canonical_json


class AuditStore:
    def __init__(self, path: Path) -> None:
        self._path = path
        self._lock = asyncio.Lock()

    async def initialize(self) -> None:
        self._initialize_sync()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self._path)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize_sync(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with closing(self._connect()) as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_events (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT NOT NULL UNIQUE,
                    action_id TEXT NOT NULL,
                    stage TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    event_hash TEXT NOT NULL UNIQUE
                )
                """
            )
            db.commit()

    async def append(self, event: AuditEvent) -> str:
        async with self._lock:
            return self._append_sync(event)

    def _append_sync(self, event: AuditEvent) -> str:
        payload_json = canonical_json(event.payload)
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            cursor = db.execute(
                "SELECT event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1"
            )
            row = cursor.fetchone()
            previous_hash = str(row[0]) if row else "0" * 64
            material = "|".join(
                (
                    previous_hash,
                    str(event.event_id),
                    str(event.action_id),
                    event.stage,
                    payload_json,
                    event.created_at.isoformat(),
                )
            )
            event_hash = hashlib.sha256(material.encode("utf-8")).hexdigest()
            db.execute(
                """
                INSERT INTO audit_events (
                    event_id, action_id, stage, payload_json, created_at,
                    previous_hash, event_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(event.event_id),
                    str(event.action_id),
                    event.stage,
                    payload_json,
                    event.created_at.isoformat(),
                    previous_hash,
                    event_hash,
                ),
            )
            db.commit()
            return event_hash

    async def verify(self) -> tuple[bool, int]:
        return self._verify_sync()

    def _verify_sync(self) -> tuple[bool, int]:
        with closing(self._connect()) as db:
            cursor = db.execute(
                """
                SELECT event_id, action_id, stage, payload_json, created_at,
                       previous_hash, event_hash
                FROM audit_events ORDER BY sequence
                """
            )
            rows = cursor.fetchall()

        expected_previous = "0" * 64
        for row in rows:
            event_id = str(row["event_id"])
            action_id = str(row["action_id"])
            stage = str(row["stage"])
            payload_json = str(row["payload_json"])
            created_at = str(row["created_at"])
            previous_hash = str(row["previous_hash"])
            event_hash = str(row["event_hash"])
            if previous_hash != expected_previous:
                return False, len(rows)
            material = "|".join(
                (previous_hash, event_id, action_id, stage, payload_json, created_at)
            )
            if hashlib.sha256(material.encode("utf-8")).hexdigest() != event_hash:
                return False, len(rows)
            expected_previous = event_hash
        return True, len(rows)

    async def events_for_action(self, action_id: str) -> list[dict[str, Any]]:
        return self._events_for_action_sync(action_id)

    def _events_for_action_sync(self, action_id: str) -> list[dict[str, Any]]:
        with closing(self._connect()) as db:
            cursor = db.execute(
                """
                SELECT sequence, event_id, action_id, stage, payload_json,
                       created_at, previous_hash, event_hash
                FROM audit_events WHERE action_id = ? ORDER BY sequence
                """,
                (action_id,),
            )
            return [dict(row) for row in cursor.fetchall()]

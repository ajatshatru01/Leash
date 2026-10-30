from __future__ import annotations

import asyncio
import hashlib
import json
import sqlite3
from contextlib import closing
from datetime import datetime
from pathlib import Path
from typing import Any, cast
from uuid import UUID

from leash.contracts import AuditEvent, AuditRecord, LatencySummary, TelemetrySummary
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

    async def recent_events(self, limit: int = 100) -> tuple[AuditRecord, ...]:
        return self._recent_events_sync(limit)

    async def telemetry_summary(self) -> TelemetrySummary:
        return self._telemetry_summary_sync()

    def _telemetry_summary_sync(self) -> TelemetrySummary:
        with closing(self._connect()) as db:
            rows = db.execute(
                "SELECT stage, payload_json FROM audit_events ORDER BY sequence"
            ).fetchall()

        spark_calls = 0
        wonder_calls = 0
        wonder_escalations = 0
        cache_hits = 0
        avoided = 0
        budget_exhaustions = 0
        prompt_tokens = 0
        completion_tokens = 0
        total_tokens = 0
        estimated_cost_usd = 0.0
        priced_calls = 0
        unpriced_calls = 0
        latency_values: dict[str, list[float]] = {}
        for row in rows:
            stage = str(row["stage"])
            payload = cast(dict[str, object], json.loads(str(row["payload_json"])))
            if stage == "model_call":
                component = payload.get("component")
                usage = payload.get("usage")
                if isinstance(usage, dict):
                    typed_usage = cast(dict[str, object], usage)
                    is_recorded = (
                        typed_usage.get("source") == "recorded"
                        or typed_usage.get("provider") == "recorded"
                    )
                    if not is_recorded and component == "spark":
                        spark_calls += 1
                    elif not is_recorded and component == "wonder":
                        wonder_calls += 1
                    if not is_recorded:
                        prompt_value = typed_usage.get("prompt_tokens", 0)
                        completion_value = typed_usage.get("completion_tokens", 0)
                        total_value = typed_usage.get("total_tokens", 0)
                        prompt_tokens += int(prompt_value) if isinstance(prompt_value, int) else 0
                        completion_tokens += (
                            int(completion_value) if isinstance(completion_value, int) else 0
                        )
                        total_tokens += int(total_value) if isinstance(total_value, int) else 0
                        cost = typed_usage.get("estimated_cost_usd")
                        if isinstance(cost, int | float):
                            estimated_cost_usd += float(cost)
                            priced_calls += 1
                        else:
                            unpriced_calls += 1
                elif component == "spark":
                    spark_calls += 1
                elif component == "wonder":
                    wonder_calls += 1
            elif stage == "model_call_failed":
                if payload.get("component") == "wonder":
                    wonder_calls += 1
                    unpriced_calls += 1
            elif stage == "judge_escalated":
                wonder_escalations += 1
            elif stage == "judge_cache_hit":
                cache_hits += 1
            elif stage == "judge_call_avoided":
                avoided += 1
            elif stage == "budget_exhausted":
                budget_exhaustions += 1
            elif stage == "stage_latency":
                latency_stage = payload.get("stage")
                latency_ms = payload.get("latency_ms")
                if isinstance(latency_stage, str) and isinstance(latency_ms, int | float):
                    latency_values.setdefault(latency_stage, []).append(float(latency_ms))

        latency = {
            stage: LatencySummary(
                samples=len(values),
                average_ms=round(sum(values) / len(values), 3),
                maximum_ms=round(max(values), 3),
            )
            for stage, values in sorted(latency_values.items())
            if values
        }
        return TelemetrySummary(
            spark_calls=spark_calls,
            wonder_calls=wonder_calls,
            wonder_escalations=wonder_escalations,
            judge_cache_hits=cache_hits,
            locally_avoided_judge_calls=avoided,
            budget_exhaustions=budget_exhaustions,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=total_tokens,
            estimated_cost_usd=round(estimated_cost_usd, 8),
            priced_model_calls=priced_calls,
            unpriced_model_calls=unpriced_calls,
            stage_latency=latency,
        )

    def _recent_events_sync(self, limit: int) -> tuple[AuditRecord, ...]:
        if not 1 <= limit <= 500:
            raise ValueError("Audit event limit must be between 1 and 500")
        with closing(self._connect()) as db:
            cursor = db.execute(
                """
                SELECT sequence, event_id, action_id, stage, payload_json,
                       created_at, previous_hash, event_hash
                FROM audit_events ORDER BY sequence DESC LIMIT ?
                """,
                (limit,),
            )
            rows = list(reversed(cursor.fetchall()))
        return tuple(
            AuditRecord(
                sequence=int(row["sequence"]),
                event_id=UUID(str(row["event_id"])),
                action_id=UUID(str(row["action_id"])),
                stage=str(row["stage"]),
                payload=json.loads(str(row["payload_json"])),
                created_at=datetime.fromisoformat(str(row["created_at"])),
                previous_hash=str(row["previous_hash"]),
                event_hash=str(row["event_hash"]),
            )
            for row in rows
        )

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

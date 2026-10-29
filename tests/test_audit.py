from __future__ import annotations

import sqlite3
from pathlib import Path
from uuid import uuid4

import pytest

from leash.audit import AuditStore
from leash.contracts import AuditEvent


@pytest.mark.asyncio
async def test_hash_chain_detects_payload_tampering(tmp_path: Path) -> None:
    database_path = tmp_path / "audit.sqlite3"
    store = AuditStore(database_path)
    await store.initialize()
    action_id = uuid4()
    await store.append(AuditEvent(action_id=action_id, stage="previewed", payload={"safe": True}))
    await store.append(AuditEvent(action_id=action_id, stage="verdict", payload={"allow": True}))

    valid_before, count = await store.verify()
    assert valid_before is True
    assert count == 2

    with sqlite3.connect(database_path) as connection:
        connection.execute(
            "UPDATE audit_events SET payload_json = ? WHERE sequence = 1",
            ('{"safe":false}',),
        )
        connection.commit()

    valid_after, _ = await store.verify()
    assert valid_after is False


@pytest.mark.asyncio
async def test_recent_events_are_typed_bounded_and_chronological(tmp_path: Path) -> None:
    store = AuditStore(tmp_path / "audit.sqlite3")
    await store.initialize()
    action_id = uuid4()
    for index in range(3):
        await store.append(
            AuditEvent(action_id=action_id, stage=f"stage-{index}", payload={"index": index})
        )

    events = await store.recent_events(limit=2)

    assert [event.sequence for event in events] == [2, 3]
    assert [event.payload["index"] for event in events] == [1, 2]
    assert all(len(event.event_hash) == 64 for event in events)

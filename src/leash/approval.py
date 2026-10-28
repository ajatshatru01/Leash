from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID

from leash.contracts import ActionProposal, ImpactPreview, Verdict


class ApprovalError(ValueError):
    pass


@dataclass(frozen=True)
class PendingAction:
    proposal: ActionProposal
    preview: ImpactPreview
    verdict: Verdict
    expires_at: datetime


class ApprovalStore:
    def __init__(
        self,
        ttl_seconds: int,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._ttl = timedelta(seconds=ttl_seconds)
        self._clock = clock or (lambda: datetime.now(UTC))
        self._pending: dict[UUID, PendingAction] = {}
        self._lock = asyncio.Lock()

    async def register(
        self,
        proposal: ActionProposal,
        preview: ImpactPreview,
        verdict: Verdict,
    ) -> None:
        pending = PendingAction(
            proposal=proposal,
            preview=preview,
            verdict=verdict,
            expires_at=self._clock() + self._ttl,
        )
        async with self._lock:
            self._pending[proposal.id] = pending

    async def consume(
        self,
        action_id: UUID,
        *,
        action_digest: str,
        preview_digest: str,
    ) -> PendingAction:
        async with self._lock:
            pending = self._pending.get(action_id)
            if pending is None:
                raise ApprovalError("No pending review exists for this action")
            if pending.expires_at <= self._clock():
                del self._pending[action_id]
                raise ApprovalError("The pending review has expired")
            if pending.preview.action_digest != action_digest:
                raise ApprovalError("Action digest does not match the pending review")
            if pending.preview.digest != preview_digest:
                raise ApprovalError("Preview digest does not match the pending review")
            del self._pending[action_id]
            return pending

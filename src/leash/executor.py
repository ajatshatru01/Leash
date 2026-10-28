from __future__ import annotations

from typing import Protocol

from leash.contracts import (
    ActionProposal,
    ActionState,
    Decision,
    ExecutionResult,
    ImpactPreview,
    Verdict,
)


class ExecutionDenied(ValueError):
    pass


class Executor(Protocol):
    async def execute(
        self,
        *,
        proposal: ActionProposal,
        preview: ImpactPreview,
        verdict: Verdict,
    ) -> ExecutionResult: ...


class MockExecutor:
    async def execute(
        self,
        *,
        proposal: ActionProposal,
        preview: ImpactPreview,
        verdict: Verdict,
    ) -> ExecutionResult:
        if verdict.decision != Decision.ALLOW:
            raise ExecutionDenied("Mock execution requires an allow verdict")
        if verdict.action_id != proposal.id or preview.action_id != proposal.id:
            raise ExecutionDenied("Action identity does not match the authorization")
        if verdict.action_digest != preview.action_digest:
            raise ExecutionDenied("Action digest does not match the authorization")
        if verdict.preview_digest != preview.digest:
            raise ExecutionDenied("Preview digest does not match the authorization")

        return ExecutionResult(
            action_id=proposal.id,
            state=ActionState.EXECUTED,
            executor="mock",
            action_digest=preview.action_digest,
            preview_digest=preview.digest,
            summary="Mock executor validated authorization; no machine capability was invoked.",
        )

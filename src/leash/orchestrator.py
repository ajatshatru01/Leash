from __future__ import annotations

from time import perf_counter
from uuid import UUID

from leash.approval import ApprovalStore
from leash.audit import AuditStore
from leash.contracts import (
    ActionProposal,
    ActionState,
    ApprovalResult,
    AuditEvent,
    Decision,
    EvaluationResult,
    ExecutionResult,
    HumanDecision,
    HumanDecisionRequest,
    PolicyOutcome,
    Verdict,
    VerdictSource,
)
from leash.executor import Executor
from leash.judge_runtime import SemanticJudgeRuntime
from leash.policy import PolicyEngine
from leash.preview import PreviewError, PreviewService
from leash.state import ActionLifecycle


class EvaluationOrchestrator:
    def __init__(
        self,
        *,
        preview_service: PreviewService,
        policy_engine: PolicyEngine,
        judge_runtime: SemanticJudgeRuntime,
        audit_store: AuditStore,
        executor: Executor,
        approval_store: ApprovalStore,
    ) -> None:
        self._preview = preview_service
        self._policy = policy_engine
        self._judge_runtime = judge_runtime
        self._audit = audit_store
        self._executor = executor
        self._approvals = approval_store

    async def evaluate(self, proposal: ActionProposal) -> EvaluationResult:
        lifecycle = ActionLifecycle()
        preview_started = perf_counter()
        try:
            preview = self._preview.build(proposal)
        except PreviewError as exc:
            raise ValueError(str(exc)) from exc
        preview_latency = (perf_counter() - preview_started) * 1000

        await self._audit.append(
            AuditEvent(
                action_id=proposal.id,
                stage=ActionState.PROPOSED,
                payload={
                    "action_id": str(proposal.id),
                    "kind": proposal.kind,
                    "action_digest": preview.action_digest,
                },
            )
        )
        lifecycle.transition(ActionState.PREVIEWED)
        await self._audit.append(
            AuditEvent(
                action_id=proposal.id,
                stage=ActionState.PREVIEWED,
                payload=preview.model_dump(mode="json"),
            )
        )
        await self._audit_latency(proposal.id, "preview", preview_latency)
        policy_started = perf_counter()
        policy = self._policy.evaluate(proposal, preview)
        policy_latency = (perf_counter() - policy_started) * 1000
        await self._audit_latency(proposal.id, "policy", policy_latency)
        lifecycle.transition(ActionState.DECIDED)

        if policy.decision == Decision.BLOCK:
            await self._audit.append(
                AuditEvent(
                    action_id=proposal.id,
                    stage="judge_call_avoided",
                    payload={"reason": "deterministic_block"},
                )
            )
            verdict = Verdict(
                action_id=proposal.id,
                decision=Decision.BLOCK,
                reason_codes=tuple(item.code for item in policy.findings),
                explanation=" ".join(item.explanation for item in policy.findings),
                evidence_refs=tuple(item.evidence_ref for item in policy.findings),
                source=VerdictSource.RULE,
                action_digest=preview.action_digest,
                preview_digest=preview.digest,
            )
        elif policy.requires_judge:
            await self._audit.append(
                AuditEvent(
                    action_id=proposal.id,
                    stage="judge_escalated",
                    payload={"reason": "semantic_ambiguity"},
                )
            )
            judge_result = await self._judge_runtime.judge(
                session_id=proposal.session_id,
                task_text=proposal.task_text,
                preview=preview,
                policy=policy,
            )
            judge_verdict = judge_result.verdict
            judge_payload: dict[str, object] = {
                "component": "wonder",
                "cache_key": judge_result.cache_key,
                "latency_ms": round(judge_result.latency_ms, 3),
            }
            if judge_result.usage is not None:
                judge_payload["usage"] = judge_result.usage.model_dump(mode="json")
            stage = {
                "model_call": "model_call",
                "cache_hit": "judge_cache_hit",
                "budget_exhausted": "budget_exhausted",
                "model_failure": "model_call_failed",
            }[judge_result.kind]
            if judge_result.kind == "budget_exhausted":
                judge_payload["budget"] = "wonder_calls"
            await self._audit.append(
                AuditEvent(
                    action_id=proposal.id,
                    stage=stage,
                    payload=judge_payload,
                )
            )
            await self._audit_latency(proposal.id, "wonder", judge_result.latency_ms)
            if judge_verdict.decision == Decision.BLOCK:
                final_decision = Decision.BLOCK
            else:
                final_decision = Decision.REVIEW
            verdict = Verdict(
                action_id=proposal.id,
                decision=final_decision,
                reason_codes=tuple(item.code for item in policy.findings)
                + judge_verdict.reason_codes,
                explanation=" ".join(
                    [*(item.explanation for item in policy.findings), judge_verdict.explanation]
                ),
                evidence_refs=tuple(item.evidence_ref for item in policy.findings)
                + judge_verdict.evidence_refs,
                source=VerdictSource.COMBINED,
                action_digest=preview.action_digest,
                preview_digest=preview.digest,
            )
        else:
            await self._audit.append(
                AuditEvent(
                    action_id=proposal.id,
                    stage="judge_call_avoided",
                    payload={"reason": "deterministic_allow"},
                )
            )
            verdict = Verdict(
                action_id=proposal.id,
                decision=Decision.ALLOW,
                reason_codes=("DETERMINISTIC_ALLOW",),
                explanation="The action is within the deterministic demo allowlist.",
                evidence_refs=("policy.allowlist",),
                source=VerdictSource.RULE,
                action_digest=preview.action_digest,
                preview_digest=preview.digest,
            )

        await self._audit.append(
            AuditEvent(
                action_id=proposal.id,
                stage="verdict",
                payload=verdict.model_dump(mode="json"),
            )
        )
        execution: ExecutionResult | None = None
        if verdict.decision == Decision.ALLOW:
            lifecycle.transition(ActionState.AUTHORIZED)
            lifecycle.transition(ActionState.EXECUTING)
            execution_started = perf_counter()
            execution = await self._executor.execute(
                proposal=proposal,
                preview=preview,
                verdict=verdict,
            )
            await self._audit_latency(
                proposal.id,
                "execution",
                (perf_counter() - execution_started) * 1000,
            )
            lifecycle.transition(ActionState.EXECUTED)
            await self._audit.append(
                AuditEvent(
                    action_id=proposal.id,
                    stage=ActionState.EXECUTED,
                    payload=execution.model_dump(mode="json"),
                )
            )
        elif verdict.decision == Decision.REVIEW:
            lifecycle.transition(ActionState.REVIEW_PENDING)
            await self._approvals.register(proposal, preview, verdict)
        else:
            lifecycle.transition(ActionState.BLOCKED)

        return EvaluationResult(
            preview=preview,
            policy=policy,
            verdict=verdict,
            execution=execution,
        )

    async def _audit_latency(self, action_id: UUID, stage: str, latency_ms: float) -> None:
        await self._audit.append(
            AuditEvent(
                action_id=action_id,
                stage="stage_latency",
                payload={"stage": stage, "latency_ms": round(latency_ms, 3)},
            )
        )

    async def decide(
        self,
        action_id: UUID,
        request: HumanDecisionRequest,
    ) -> ApprovalResult:
        pending = await self._approvals.consume(
            action_id,
            action_digest=request.action_digest,
            preview_digest=request.preview_digest,
        )
        approved = request.decision == HumanDecision.APPROVE
        verdict = Verdict(
            action_id=action_id,
            decision=Decision.ALLOW if approved else Decision.BLOCK,
            reason_codes=("HUMAN_APPROVED" if approved else "HUMAN_DENIED",),
            explanation=(
                "A human approved this exact action and preview."
                if approved
                else "A human denied this action."
            ),
            evidence_refs=("human.decision",),
            source=VerdictSource.HUMAN,
            action_digest=pending.preview.action_digest,
            preview_digest=pending.preview.digest,
        )
        await self._audit.append(
            AuditEvent(
                action_id=action_id,
                stage="human_approved" if approved else "human_denied",
                payload=verdict.model_dump(mode="json"),
            )
        )
        if not approved:
            return ApprovalResult(verdict=verdict)

        execution_started = perf_counter()
        execution = await self._executor.execute(
            proposal=pending.proposal,
            preview=pending.preview,
            verdict=verdict,
        )
        await self._audit_latency(
            action_id,
            "execution",
            (perf_counter() - execution_started) * 1000,
        )
        await self._audit.append(
            AuditEvent(
                action_id=action_id,
                stage=ActionState.EXECUTED,
                payload=execution.model_dump(mode="json"),
            )
        )
        return ApprovalResult(verdict=verdict, execution=execution)


def unavailable_policy() -> PolicyOutcome:
    return PolicyOutcome(decision=Decision.REVIEW, findings=(), requires_judge=True)

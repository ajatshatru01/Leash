from __future__ import annotations

import asyncio
from dataclasses import dataclass
from time import perf_counter
from typing import Literal
from uuid import UUID

from leash.contracts import (
    Decision,
    ImpactPreview,
    JudgeVerdict,
    ModelUsage,
    PolicyOutcome,
)
from leash.digest import sha256_digest
from leash.judge import JudgeClient, build_judge_packet
from leash.secrets import SecretScanner

JudgeRuntimeKind = Literal["model_call", "cache_hit", "budget_exhausted", "model_failure"]


@dataclass(frozen=True)
class JudgeRuntimeResult:
    verdict: JudgeVerdict
    kind: JudgeRuntimeKind
    cache_key: str
    latency_ms: float
    usage: ModelUsage | None = None


class SemanticJudgeRuntime:
    def __init__(
        self,
        *,
        client: JudgeClient,
        scanner: SecretScanner,
        model: str,
        prompt_version: str,
        policy_version: str,
        max_calls_per_session: int,
    ) -> None:
        self._client = client
        self._scanner = scanner
        self._model = model
        self._prompt_version = prompt_version
        self._policy_version = policy_version
        self._max_calls = max_calls_per_session
        self._calls: dict[UUID, int] = {}
        self._cache: dict[str, JudgeVerdict] = {}
        self._lock = asyncio.Lock()

    async def judge(
        self,
        *,
        session_id: UUID,
        task_text: str,
        preview: ImpactPreview,
        policy: PolicyOutcome,
    ) -> JudgeRuntimeResult:
        packet = build_judge_packet(
            task_text=task_text,
            preview=preview,
            policy=policy,
            scanner=self._scanner,
        )
        cache_key = sha256_digest(
            {
                "model": self._model,
                "prompt_version": self._prompt_version,
                "policy_version": self._policy_version,
                "packet": packet,
            }
        )
        started = perf_counter()
        async with self._lock:
            cached = self._cache.get(cache_key)
            if cached is not None:
                return JudgeRuntimeResult(
                    verdict=cached,
                    kind="cache_hit",
                    cache_key=cache_key,
                    latency_ms=(perf_counter() - started) * 1000,
                )
            calls = self._calls.get(session_id, 0)
            if calls >= self._max_calls:
                return JudgeRuntimeResult(
                    verdict=JudgeVerdict(
                        decision=Decision.REVIEW,
                        reason_codes=("JUDGE_BUDGET_EXHAUSTED",),
                        explanation=(
                            "The session's semantic-judge budget is exhausted; Leash failed "
                            "closed to human review."
                        ),
                        evidence_refs=("budget.wonder_calls",),
                    ),
                    kind="budget_exhausted",
                    cache_key=cache_key,
                    latency_ms=(perf_counter() - started) * 1000,
                )
            self._calls[session_id] = calls + 1
            try:
                result = await self._client.judge(
                    task_text=task_text,
                    preview=preview,
                    policy=policy,
                )
            except Exception:
                return JudgeRuntimeResult(
                    verdict=JudgeVerdict(
                        decision=Decision.REVIEW,
                        reason_codes=("JUDGE_UNAVAILABLE",),
                        explanation="The semantic judge failed; Leash failed closed to review.",
                        evidence_refs=("judge.availability",),
                    ),
                    kind="model_failure",
                    cache_key=cache_key,
                    latency_ms=(perf_counter() - started) * 1000,
                )
            if not {
                "INVALID_JUDGE_OUTPUT",
                "JUDGE_UNAVAILABLE",
            }.intersection(result.verdict.reason_codes):
                self._cache[cache_key] = result.verdict
            return JudgeRuntimeResult(
                verdict=result.verdict,
                kind="model_call",
                cache_key=cache_key,
                latency_ms=(perf_counter() - started) * 1000,
                usage=result.usage,
            )

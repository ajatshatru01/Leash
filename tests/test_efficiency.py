from __future__ import annotations

import json
from dataclasses import dataclass, field
from uuid import UUID, uuid4

import pytest
from pydantic import HttpUrl

from leash.agent import ActorMessage, ActorToolCall, ActorTurn
from leash.api import build_services
from leash.contracts import (
    ActionKind,
    AgentRunStatus,
    Decision,
    HttpActionProposal,
    HttpParams,
    ImpactPreview,
    JudgeCallResult,
    JudgeVerdict,
    ModelUsage,
    PolicyOutcome,
    ShellActionProposal,
    ShellParams,
)
from leash.settings import Settings


@dataclass
class CountingJudge:
    calls: int = 0

    async def judge(
        self,
        *,
        task_text: str,
        preview: ImpactPreview,
        policy: PolicyOutcome,
    ) -> JudgeCallResult:
        del task_text, preview, policy
        self.calls += 1
        return JudgeCallResult(
            verdict=JudgeVerdict(
                decision=Decision.REVIEW,
                reason_codes=("SEMANTIC_REVIEW",),
                explanation="The action needs a human decision.",
                evidence_refs=("judge.fixture",),
            ),
            usage=ModelUsage(
                provider="recorded-meta",
                model="muse-wonder-fixture",
                prompt_tokens=100,
                completion_tokens=20,
                total_tokens=120,
                source="reported",
                estimated_cost_usd=0.001,
            ),
        )


@dataclass
class ScriptedSparkClient:
    turns: list[ActorTurn]
    histories: list[tuple[ActorMessage, ...]] = field(
        default_factory=lambda: list[tuple[ActorMessage, ...]]()
    )

    async def complete(self, history: tuple[ActorMessage, ...]) -> ActorTurn:
        self.histories.append(history)
        return self.turns.pop(0)


def _ambiguous_http(session_id: UUID, path: str = "/upload") -> HttpActionProposal:
    return HttpActionProposal(
        kind=ActionKind.HTTP,
        session_id=session_id,
        task_id=uuid4(),
        task_text="Upload the public build report",
        workspace_id="fixture",
        params=HttpParams(
            method="POST",
            url=HttpUrl(f"https://example.com{path}"),
            body="public-result",
        ),
    )


def _history_text(history: tuple[ActorMessage, ...]) -> str:
    return "\n".join(
        [
            *(message.content or "" for message in history),
            *(call.arguments_json for message in history for call in message.tool_calls),
        ]
    )


@pytest.mark.asyncio
async def test_deterministic_paths_avoid_wonder_and_record_latency(settings: Settings) -> None:
    judge = CountingJudge()
    services = build_services(settings, judge=judge)
    await services.audit.initialize()
    settings.leash_workspace_root.mkdir()
    session_id = uuid4()

    safe = ShellActionProposal(
        kind=ActionKind.SHELL,
        session_id=session_id,
        task_id=uuid4(),
        task_text="Run tests",
        workspace_id="fixture",
        params=ShellParams(executable="pytest", argv=("-q",)),
    )
    blocked = HttpActionProposal(
        kind=ActionKind.HTTP,
        session_id=session_id,
        task_id=uuid4(),
        task_text="Keep credentials local",
        workspace_id="fixture",
        params=HttpParams(
            method="POST",
            url=HttpUrl("https://example.com/upload"),
            body="token=ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ),
    )

    safe_result = await services.orchestrator.evaluate(safe)
    blocked_result = await services.orchestrator.evaluate(blocked)
    telemetry = await services.audit.telemetry_summary()

    assert safe_result.verdict.decision == Decision.ALLOW
    assert blocked_result.verdict.decision == Decision.BLOCK
    assert judge.calls == 0
    assert telemetry.locally_avoided_judge_calls == 2
    assert telemetry.wonder_calls == 0
    assert {"preview", "policy", "execution"}.issubset(telemetry.stage_latency)


@pytest.mark.asyncio
async def test_identical_judgment_uses_exact_packet_cache(settings: Settings) -> None:
    judge = CountingJudge()
    settings.leash_judge_max_calls_per_session = 1
    services = build_services(settings, judge=judge)
    await services.audit.initialize()
    settings.leash_workspace_root.mkdir()
    session_id = uuid4()

    first = await services.orchestrator.evaluate(_ambiguous_http(session_id))
    second = await services.orchestrator.evaluate(_ambiguous_http(session_id))
    telemetry = await services.audit.telemetry_summary()

    assert first.verdict.decision == Decision.REVIEW
    assert second.verdict.decision == Decision.REVIEW
    assert judge.calls == 1
    assert telemetry.wonder_escalations == 2
    assert telemetry.wonder_calls == 1
    assert telemetry.judge_cache_hits == 1
    assert telemetry.total_tokens == 120
    assert telemetry.estimated_cost_usd == 0.001


@pytest.mark.asyncio
async def test_wonder_budget_exhaustion_fails_to_review(settings: Settings) -> None:
    judge = CountingJudge()
    settings.leash_judge_max_calls_per_session = 1
    services = build_services(settings, judge=judge)
    await services.audit.initialize()
    settings.leash_workspace_root.mkdir()
    session_id = uuid4()

    await services.orchestrator.evaluate(_ambiguous_http(session_id, "/first"))
    exhausted = await services.orchestrator.evaluate(_ambiguous_http(session_id, "/second"))
    telemetry = await services.audit.telemetry_summary()

    assert exhausted.verdict.decision == Decision.REVIEW
    assert "JUDGE_BUDGET_EXHAUSTED" in exhausted.verdict.reason_codes
    assert exhausted.execution is None
    assert judge.calls == 1
    assert telemetry.budget_exhaustions == 1


@pytest.mark.asyncio
async def test_judge_cache_digest_binds_model_prompt_and_policy_versions(
    settings: Settings,
) -> None:
    judge = CountingJudge()
    settings.leash_workspace_root.mkdir()
    variants = (
        settings.model_copy(
            update={
                "leash_database_path": settings.leash_database_path.with_name("v1.sqlite3"),
                "judge_model": "wonder-a",
                "leash_judge_prompt_version": "prompt-a",
                "leash_policy_version": "policy-a",
            }
        ),
        settings.model_copy(
            update={
                "leash_database_path": settings.leash_database_path.with_name("v2.sqlite3"),
                "judge_model": "wonder-a",
                "leash_judge_prompt_version": "prompt-b",
                "leash_policy_version": "policy-a",
            }
        ),
        settings.model_copy(
            update={
                "leash_database_path": settings.leash_database_path.with_name("v3.sqlite3"),
                "judge_model": "wonder-a",
                "leash_judge_prompt_version": "prompt-a",
                "leash_policy_version": "policy-b",
            }
        ),
        settings.model_copy(
            update={
                "leash_database_path": settings.leash_database_path.with_name("v4.sqlite3"),
                "judge_model": "wonder-b",
                "leash_judge_prompt_version": "prompt-a",
                "leash_policy_version": "policy-a",
            }
        ),
    )
    cache_keys: list[str] = []
    for variant in variants:
        services = build_services(variant, judge=judge)
        await services.audit.initialize()
        await services.orchestrator.evaluate(_ambiguous_http(uuid4()))
        events = await services.audit.recent_events()
        model_event = next(event for event in events if event.stage == "model_call")
        cache_key = model_event.payload["cache_key"]
        assert isinstance(cache_key, str)
        cache_keys.append(cache_key)

    assert len(set(cache_keys)) == 4


@pytest.mark.asyncio
async def test_actor_compacts_old_receipts_deterministically(settings: Settings) -> None:
    settings.leash_agent_recent_receipts = 1
    client = ScriptedSparkClient(
        turns=[
            ActorTurn(tool_calls=(ActorToolCall("one", "unknown_tool", json.dumps({"x": 1})),)),
            ActorTurn(tool_calls=(ActorToolCall("two", "unknown_tool", json.dumps({"x": 2})),)),
            ActorTurn(content="Stopped after two rejected proposals."),
        ]
    )
    services = build_services(settings, spark_client=client)
    await services.audit.initialize()

    result = await services.agent.run("Complete the fixture task", "fixture")
    final_history = _history_text(client.histories[2])

    assert result.status == AgentRunStatus.COMPLETED
    assert "Deterministic prior-action summary" in final_history
    assert '"compacted_receipts":1' in final_history
    assert '"x": 1' not in final_history
    assert '"x": 2' in final_history


@pytest.mark.asyncio
async def test_actor_token_budget_stops_before_authorizing_response(settings: Settings) -> None:
    settings.leash_agent_token_budget = 1024
    settings.leash_spark_max_completion_tokens = 256
    usage = ModelUsage(
        provider="recorded-meta",
        model="muse-spark-fixture",
        prompt_tokens=1000,
        completion_tokens=500,
        total_tokens=1500,
        source="reported",
    )
    client = ScriptedSparkClient(
        turns=[
            ActorTurn(
                tool_calls=(
                    ActorToolCall(
                        "unsafe-after-budget",
                        "propose_shell",
                        json.dumps({"executable": "pytest", "argv": ["-q"]}),
                    ),
                ),
                usage=usage,
            )
        ]
    )
    services = build_services(settings, spark_client=client)
    await services.audit.initialize()

    result = await services.agent.run("Run tests", "fixture")
    telemetry = await services.audit.telemetry_summary()

    assert result.status == AgentRunStatus.BUDGET_EXHAUSTED
    assert result.actions == ()
    assert result.token_usage == 1500
    assert telemetry.budget_exhaustions == 1


@pytest.mark.asyncio
async def test_recent_receipt_arguments_are_byte_bounded(settings: Settings) -> None:
    settings.leash_agent_receipt_bytes = 512
    large_content = "z" * 2000
    client = ScriptedSparkClient(
        turns=[
            ActorTurn(
                tool_calls=(
                    ActorToolCall(
                        "large-write",
                        "propose_file_write",
                        json.dumps(
                            {"path": "large.txt", "content": large_content, "mode": "create"}
                        ),
                    ),
                )
            ),
            ActorTurn(content="Created the bounded-history fixture."),
        ]
    )
    services = build_services(settings, spark_client=client)
    await services.audit.initialize()
    settings.leash_workspace_root.mkdir()

    result = await services.agent.run("Create a large fixture", "fixture")
    replay = _history_text(client.histories[1])

    assert result.status == AgentRunStatus.COMPLETED
    assert large_content not in replay
    assert "receipt_compacted" in replay

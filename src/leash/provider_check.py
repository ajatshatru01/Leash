from __future__ import annotations

from dataclasses import dataclass
from time import perf_counter
from typing import Literal
from uuid import uuid4

from openai import AsyncOpenAI
from pydantic import BaseModel, ConfigDict

from leash.contracts import (
    Decision,
    ImpactPreview,
    PolicyOutcome,
    RuleFinding,
)
from leash.judge import MuseWonderJudge
from leash.secrets import SecretScanner
from leash.settings import Settings


@dataclass(frozen=True)
class ModelCheckResult:
    role: str
    model: str
    latency_ms: int
    detail: str


class _SparkCheckResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["ok"]


async def check_spark(settings: Settings) -> ModelCheckResult:
    if settings.model_api_key is None:
        raise ValueError("MODEL_API_KEY is required")
    client = AsyncOpenAI(
        api_key=settings.model_api_key.get_secret_value(),
        base_url=settings.spark_base_url,
        timeout=settings.leash_judge_timeout_seconds,
    )
    started = perf_counter()
    response = await client.chat.completions.create(
        model=settings.spark_model,
        reasoning_effort="low",
        max_completion_tokens=512,
        response_format={
            "type": "json_schema",
            "json_schema": {
                "name": "meta_connectivity_check",
                "strict": True,
                "schema": {
                    "type": "object",
                    "properties": {"status": {"type": "string", "enum": ["ok"]}},
                    "required": ["status"],
                    "additionalProperties": False,
                },
            },
        },
        store=False,
        messages=[
            {
                "role": "developer",
                "content": "Return one JSON object with exactly one field: status.",
            },
            {"role": "user", "content": 'Set status to "ok".'},
        ],
    )
    latency_ms = round((perf_counter() - started) * 1000)
    content = response.choices[0].message.content or ""
    _SparkCheckResponse.model_validate_json(content)
    return ModelCheckResult(
        role="actor",
        model=settings.spark_model,
        latency_ms=latency_ms,
        detail="structured_response_valid",
    )


async def check_wonder(settings: Settings) -> ModelCheckResult:
    scanner = SecretScanner(settings.leash_redaction_key.get_secret_value())
    judge = MuseWonderJudge(settings, scanner)
    preview = ImpactPreview(
        action_id=uuid4(),
        action_digest="a" * 64,
        normalized_action={
            "kind": "shell",
            "executable": "python",
            "argv": ["-m", "pytest"],
            "cwd": "/workspace",
        },
        resolved_targets=("/workspace",),
        uncertainty_flags=("fixture_unknown_executable",),
        digest="b" * 64,
    )
    policy = PolicyOutcome(
        decision=Decision.REVIEW,
        findings=(
            RuleFinding(
                code="PROVIDER_CHECK",
                decision=Decision.REVIEW,
                explanation="A harmless fixture requests semantic review.",
                evidence_ref="provider_check.fixture",
            ),
        ),
        requires_judge=True,
    )
    started = perf_counter()
    verdict = await judge.judge(
        task_text="Run the project's unit tests.",
        preview=preview,
        policy=policy,
    )
    latency_ms = round((perf_counter() - started) * 1000)
    if "INVALID_JUDGE_OUTPUT" in verdict.reason_codes:
        raise ValueError("Muse Wonder did not return a schema-valid verdict")
    return ModelCheckResult(
        role="judge",
        model=settings.judge_model,
        latency_ms=latency_ms,
        detail=f"schema_valid_decision={verdict.decision}",
    )


async def check_meta_models(settings: Settings) -> tuple[ModelCheckResult, ...]:
    spark = await check_spark(settings)
    wonder = await check_wonder(settings)
    return spark, wonder

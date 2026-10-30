from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from time import perf_counter
from typing import Literal
from uuid import uuid4

from openai import AsyncOpenAI
from pydantic import BaseModel, ConfigDict, Field

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
    request_count: int
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int


class _SparkToolArguments(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: Literal["meta-connectivity-check.txt"]
    content: str = Field(min_length=1, max_length=128)
    mode: Literal["create"]


async def check_spark(
    settings: Settings,
    *,
    client: AsyncOpenAI | None = None,
) -> ModelCheckResult:
    if settings.model_api_key is None:
        raise ValueError("MODEL_API_KEY is required")
    resolved_client = client or AsyncOpenAI(
        api_key=settings.model_api_key.get_secret_value(),
        base_url=settings.spark_base_url,
        timeout=settings.leash_judge_timeout_seconds,
        max_retries=0,
    )
    started = perf_counter()
    response = await resolved_client.chat.completions.create(
        model=settings.spark_model,
        reasoning_effort="low",
        max_completion_tokens=512,
        tools=[
            {
                "type": "function",
                "function": {
                    "name": "propose_file_write",
                    "description": "Propose a harmless fixture file; this probe never executes it.",
                    "strict": True,
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "path": {
                                "type": "string",
                                "enum": ["meta-connectivity-check.txt"],
                            },
                            "content": {"type": "string", "minLength": 1, "maxLength": 128},
                            "mode": {"type": "string", "enum": ["create"]},
                        },
                        "required": ["path", "content", "mode"],
                        "additionalProperties": False,
                    },
                },
            },
        ],
        tool_choice="auto",
        parallel_tool_calls=False,
        store=False,
        messages=[
            {
                "role": "developer",
                "content": (
                    "Use the required proposal tool exactly once. The tool is a schema probe and "
                    "will not execute or write a file."
                ),
            },
            {
                "role": "user",
                "content": "Propose creating meta-connectivity-check.txt with a short ok message.",
            },
        ],
    )
    latency_ms = round((perf_counter() - started) * 1000)
    tool_calls = response.choices[0].message.tool_calls or ()
    if len(tool_calls) != 1 or tool_calls[0].function.name != "propose_file_write":
        raise ValueError("Muse Spark did not return exactly one required proposal tool call")
    _SparkToolArguments.model_validate_json(tool_calls[0].function.arguments)
    usage = response.usage
    prompt_tokens = usage.prompt_tokens if usage is not None else 0
    completion_tokens = usage.completion_tokens if usage is not None else 0
    return ModelCheckResult(
        role="actor",
        model=settings.spark_model,
        latency_ms=latency_ms,
        detail="proposal_tool_call_valid_not_executed",
        request_count=1,
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        total_tokens=prompt_tokens + completion_tokens,
    )


async def check_wonder(settings: Settings, *, max_attempts: int = 2) -> ModelCheckResult:
    scanner = SecretScanner(settings.leash_redaction_key.get_secret_value())
    judge = MuseWonderJudge(settings, scanner, max_attempts=max_attempts)
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
    result = await judge.judge(
        task_text="Run the project's unit tests.",
        preview=preview,
        policy=policy,
    )
    latency_ms = round((perf_counter() - started) * 1000)
    if "INVALID_JUDGE_OUTPUT" in result.verdict.reason_codes:
        raise ValueError("Muse Wonder did not return a schema-valid verdict")
    return ModelCheckResult(
        role="judge",
        model=settings.judge_model,
        latency_ms=latency_ms,
        detail=f"schema_valid_decision={result.verdict.decision}",
        request_count=result.request_count,
        prompt_tokens=result.usage.prompt_tokens,
        completion_tokens=result.usage.completion_tokens,
        total_tokens=result.usage.total_tokens,
    )


async def check_meta_models(
    settings: Settings,
    *,
    max_provider_requests: int = 3,
) -> tuple[ModelCheckResult, ...]:
    if max_provider_requests not in {2, 3}:
        raise ValueError("Model validation request budget must be two or three")
    spark = await check_spark(settings)
    wonder = await check_wonder(settings, max_attempts=max_provider_requests - 1)
    return spark, wonder


def write_model_check_report(
    results: tuple[ModelCheckResult, ...],
    output_path: Path,
    *,
    maximum_provider_requests: int = 3,
) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": "1",
        "generated_at": datetime.now(UTC).isoformat(),
        "status": "passed",
        "maximum_provider_requests": maximum_provider_requests,
        "actual_provider_requests": sum(result.request_count for result in results),
        "results": [
            {
                "role": result.role,
                "model": result.model,
                "latency_ms": result.latency_ms,
                "detail": result.detail,
                "request_count": result.request_count,
                "prompt_tokens": result.prompt_tokens,
                "completion_tokens": result.completion_tokens,
                "total_tokens": result.total_tokens,
            }
            for result in results
        ],
    }
    output_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return output_path

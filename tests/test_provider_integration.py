from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast
from uuid import uuid4

import httpx
import pytest
from openai import AsyncOpenAI
from pydantic import SecretStr
from typer.testing import CliRunner

from leash.cli import app
from leash.contracts import Decision, ImpactPreview, PolicyOutcome, RuleFinding
from leash.judge import MuseWonderJudge, build_judge_packet
from leash.provider_check import ModelCheckResult, check_spark, write_model_check_report
from leash.secrets import SecretScanner
from leash.settings import Settings


def _completion(
    content: str, *, prompt_tokens: int = 11, completion_tokens: int = 7
) -> dict[str, Any]:
    return {
        "id": "chatcmpl-fixture",
        "object": "chat.completion",
        "created": 1,
        "model": "fixture-model",
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": content},
                "finish_reason": "stop",
            }
        ],
        "usage": {
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": prompt_tokens + completion_tokens,
        },
    }


@pytest.mark.asyncio
async def test_spark_probe_requires_a_real_typed_tool_call() -> None:
    captured: list[dict[str, object]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(json.loads(request.content))
        payload = _completion("")
        payload["choices"][0]["message"]["tool_calls"] = [
            {
                "id": "call-fixture",
                "type": "function",
                "function": {
                    "name": "propose_file_write",
                    "arguments": json.dumps(
                        {
                            "path": "meta-connectivity-check.txt",
                            "content": "ok",
                            "mode": "create",
                        }
                    ),
                },
            }
        ]
        return httpx.Response(200, json=payload)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http_client:
        client = AsyncOpenAI(
            api_key="fixture-key",
            base_url="https://meta.fixture/v1",
            http_client=http_client,
        )
        result = await check_spark(
            Settings(model_api_key=SecretStr("fixture-key")),
            client=client,
        )

    assert result.detail == "proposal_tool_call_valid_not_executed"
    assert result.request_count == 1
    assert result.total_tokens == 18
    assert captured[0]["tool_choice"] == "auto"


def test_judge_packet_omits_raw_body_url_and_absolute_local_path() -> None:
    body = "private source excerpt that is not a credential"
    local_path = r"C:\Users\fixture-user\Leash\generated\report.txt"
    preview = ImpactPreview(
        action_id=uuid4(),
        action_digest="a" * 64,
        normalized_action={
            "kind": "http",
            "method": "POST",
            "url": "https://collector.example.test/private?document=source",
            "headers": {"content-type": "text/plain"},
            "body": body,
        },
        resolved_targets=(local_path,),
        network_destination="collector.example.test",
        digest="b" * 64,
    )
    policy = PolicyOutcome(
        decision=Decision.REVIEW,
        findings=(),
        requires_judge=True,
    )

    packet = build_judge_packet(
        task_text="Send the approved report",
        preview=preview,
        policy=policy,
        scanner=SecretScanner("fixture-redaction-key"),
    )
    serialized = json.dumps(packet)

    assert body not in serialized
    assert "document=source" not in serialized
    assert "fixture-user" not in serialized
    assert "body_sha256" in serialized
    assert "collector.example.test" in serialized
    assert "<WORKSPACE>/generated/report.txt" in serialized


@pytest.mark.asyncio
async def test_wonder_retries_invalid_schema_once_then_returns_valid_verdict() -> None:
    requests: list[dict[str, object]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        requests.append(payload)
        if len(requests) == 1:
            return httpx.Response(200, json=_completion("not-json"))
        return httpx.Response(
            200,
            json=_completion(
                json.dumps(
                    {
                        "decision": "block",
                        "reason_codes": ["TASK_MISMATCH"],
                        "explanation": "The proposed upload does not serve the local task.",
                        "evidence_refs": ["original_task", "normalized_action.destination"],
                    }
                )
            ),
        )

    settings = Settings(
        leash_judge_mode="managed",
        model_api_key=SecretStr("fixture-key"),
        judge_base_url="https://meta.fixture/v1",
    )
    preview = ImpactPreview(
        action_id=uuid4(),
        action_digest="a" * 64,
        normalized_action={"kind": "shell", "executable": "cargo", "argv": ["test"]},
        digest="b" * 64,
    )
    policy = PolicyOutcome(
        decision=Decision.REVIEW,
        findings=(
            RuleFinding(
                code="UNKNOWN_EXECUTABLE",
                decision=Decision.REVIEW,
                explanation="The executable is not allowlisted.",
                evidence_ref="proposal.params.executable",
            ),
        ),
        requires_judge=True,
    )
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http_client:
        judge = MuseWonderJudge(
            settings,
            SecretScanner("fixture-redaction-key"),
            http_client=http_client,
        )
        result = await judge.judge(task_text="Run tests", preview=preview, policy=policy)

    assert result.verdict.decision == Decision.BLOCK
    assert result.request_count == 2
    assert result.usage.total_tokens == 36
    first_format = cast(dict[str, object], requests[0]["response_format"])
    first_messages = cast(list[object], requests[0]["messages"])
    second_messages = cast(list[object], requests[1]["messages"])
    assert first_format["type"] == "json_schema"
    assert len(second_messages) == len(first_messages) + 1


def test_model_check_report_contains_only_sanitized_measurements(tmp_path: Path) -> None:
    result = ModelCheckResult(
        role="actor",
        model="muse-spark-fixture",
        latency_ms=123,
        detail="proposal_tool_call_valid_not_executed",
        request_count=1,
        prompt_tokens=10,
        completion_tokens=5,
        total_tokens=15,
    )

    output = write_model_check_report((result,), tmp_path / "report.json")
    payload = json.loads(output.read_text(encoding="utf-8"))

    assert payload["actual_provider_requests"] == 1
    assert payload["maximum_provider_requests"] == 3
    assert "prompt" not in payload["results"][0]
    assert "response" not in payload["results"][0]


def test_model_check_requires_explicit_spend_confirmation() -> None:
    result = CliRunner().invoke(app, ["check-models"])

    assert result.exit_code == 2
    assert "spend_confirmation_required" in result.stdout
    assert "maximum_provider_requests=3" in result.stdout

from __future__ import annotations

from uuid import uuid4

import httpx
import pytest
from pydantic import HttpUrl

from leash.api import build_services
from leash.capture import CaptureStore, create_capture_app
from leash.contracts import ActionKind, Decision, HttpActionProposal, HttpParams
from leash.executor import ExecutionDenied, HttpExecutor
from leash.secrets import SecretScanner
from leash.settings import Settings


def _proposal(*, body: str, url: str = "http://127.0.0.1:8877/receive") -> HttpActionProposal:
    return HttpActionProposal(
        kind=ActionKind.HTTP,
        session_id=uuid4(),
        task_id=uuid4(),
        task_text="Send one safe diagnostic to the local capture receiver",
        workspace_id="http-fixture",
        params=HttpParams(method="POST", url=HttpUrl(url), body=body),
    )


def _executor(
    settings: Settings,
    transport: httpx.AsyncBaseTransport,
) -> HttpExecutor:
    return HttpExecutor(
        allowed_hosts=settings.leash_allowed_http_hosts,
        allowed_ports=settings.leash_allowed_http_ports,
        scanner=SecretScanner(settings.leash_redaction_key.get_secret_value()),
        timeout_seconds=settings.leash_http_timeout_seconds,
        request_bytes=settings.leash_http_request_bytes,
        response_bytes=settings.leash_http_response_bytes,
        transport=transport,
    )


@pytest.mark.asyncio
async def test_blocked_secret_egress_delivers_zero_bytes_then_safe_request_works(
    settings: Settings,
) -> None:
    capture_store = CaptureStore()
    capture_app = create_capture_app(store=capture_store, max_request_bytes=65_536)
    transport = httpx.ASGITransport(app=capture_app)
    services = build_services(settings, executor=_executor(settings, transport))
    await services.audit.initialize()
    settings.leash_workspace_root.mkdir()
    fake_secret = "ghp_" + ("X" * 36)

    blocked = await services.orchestrator.evaluate(_proposal(body=f"token={fake_secret}"))
    after_block = await capture_store.snapshot()

    assert blocked.verdict.decision == Decision.BLOCK
    assert "SECRET_EGRESS" in blocked.verdict.reason_codes
    assert blocked.execution is None
    assert after_block.request_count == 0
    assert after_block.bytes_received == 0

    safe_body = "safe local diagnostic"
    allowed = await services.orchestrator.evaluate(_proposal(body=safe_body))
    after_safe = await capture_store.snapshot()

    assert allowed.verdict.decision == Decision.ALLOW
    assert allowed.execution is not None
    assert allowed.execution.executor == "http"
    assert allowed.execution.exit_code == 0
    assert after_safe.request_count == 1
    assert after_safe.bytes_received == len(safe_body.encode("utf-8"))
    assert safe_body not in after_safe.model_dump_json()
    assert fake_secret not in "".join(
        event.model_dump_json() for event in await services.audit.recent_events()
    )


@pytest.mark.asyncio
async def test_http_executor_rejects_non_loopback_even_if_host_is_configured(
    settings: Settings,
) -> None:
    unsafe_settings = settings.model_copy(
        update={
            "leash_allowed_http_hosts": ("example.com",),
            "leash_allowed_http_ports": (80,),
        }
    )
    transport = httpx.MockTransport(lambda request: httpx.Response(200, request=request))
    services = build_services(unsafe_settings, executor=_executor(unsafe_settings, transport))
    await services.audit.initialize()
    unsafe_settings.leash_workspace_root.mkdir()

    with pytest.raises(ExecutionDenied, match="restricted to loopback"):
        await services.orchestrator.evaluate(
            _proposal(body="safe", url="http://example.com/receive")
        )


@pytest.mark.asyncio
async def test_capture_receiver_rejects_oversized_body_without_storing_content() -> None:
    store = CaptureStore()
    capture_app = create_capture_app(store=store, max_request_bytes=8)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=capture_app),
        base_url="http://capture.test",
    ) as client:
        response = await client.post("/receive", content=b"more-than-eight-bytes")
        stats_response = await client.get("/stats")

    assert response.status_code == 413
    stats = stats_response.json()
    assert stats["request_count"] == 1
    assert stats["bytes_received"] > 8
    assert "more-than-eight-bytes" not in stats_response.text


@pytest.mark.asyncio
async def test_http_executor_does_not_follow_redirects(settings: Settings) -> None:
    paths: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        paths.append(request.url.path)
        return httpx.Response(
            302,
            headers={"location": "http://127.0.0.1:8877/receive"},
            request=request,
        )

    services = build_services(
        settings,
        executor=_executor(settings, httpx.MockTransport(handler)),
    )
    await services.audit.initialize()
    settings.leash_workspace_root.mkdir()

    result = await services.orchestrator.evaluate(
        _proposal(body="safe", url="http://127.0.0.1:8877/redirect")
    )

    assert result.execution is not None
    assert result.execution.exit_code == 1
    assert paths == ["/redirect"]


@pytest.mark.asyncio
async def test_http_response_is_redacted_before_returning_to_actor(settings: Settings) -> None:
    fake_response_secret = "ghp_" + ("S" * 36)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=f"token={fake_response_secret}", request=request)

    services = build_services(
        settings,
        executor=_executor(settings, httpx.MockTransport(handler)),
    )
    await services.audit.initialize()
    settings.leash_workspace_root.mkdir()

    result = await services.orchestrator.evaluate(_proposal(body="safe"))

    assert result.execution is not None
    assert fake_response_secret not in result.execution.stdout
    assert "<REDACTED:github_token:" in result.execution.stdout

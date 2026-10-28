from uuid import uuid4

import pytest
from httpx import ASGITransport, AsyncClient

from leash.api import create_app
from leash.settings import Settings


@pytest.mark.asyncio
async def test_health_starts_without_api_keys(settings: Settings) -> None:
    app = create_app(settings)

    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "environment": "test",
        "actor_mode": "recorded",
        "judge_mode": "recorded",
        "executor_mode": "mock",
        "model_api_key_configured": False,
        "spark_model": "muse-spark-1.3",
        "judge_model": "muse-wonder-1.0",
    }


@pytest.mark.asyncio
async def test_review_can_be_approved_through_http_api(settings: Settings) -> None:
    app = create_app(settings)
    action_id = uuid4()
    proposal = {
        "id": str(action_id),
        "kind": "http",
        "session_id": str(uuid4()),
        "task_id": str(uuid4()),
        "task_text": "Check the project documentation",
        "workspace_id": "fixture",
        "params": {"method": "GET", "url": "https://example.com/docs"},
    }

    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            evaluation_response = await client.post("/v1/actions/evaluate", json=proposal)
            assert evaluation_response.status_code == 200
            evaluation = evaluation_response.json()
            decision_response = await client.post(
                f"/v1/actions/{action_id}/decision",
                json={
                    "decision": "approve",
                    "action_digest": evaluation["preview"]["action_digest"],
                    "preview_digest": evaluation["preview"]["digest"],
                },
            )

    assert decision_response.status_code == 200
    assert decision_response.json()["verdict"]["decision"] == "allow"
    assert decision_response.json()["execution"]["executor"] == "mock"


@pytest.mark.asyncio
async def test_recorded_actor_endpoint_makes_no_provider_call(settings: Settings) -> None:
    app = create_app(settings)

    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.post(
                "/v1/agent/run",
                json={"task_text": "Create a hello file", "workspace_id": "fixture"},
            )

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "completed"
    assert payload["actions"] == []
    assert "recorded mode" in payload["final_message"]

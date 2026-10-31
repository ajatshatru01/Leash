import json
from datetime import UTC, datetime
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
        "judge_prompt_version": "wonder-safety-v1",
        "policy_version": "demo-policy-v1",
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
            telemetry_response = await client.get("/v1/telemetry")

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "completed"
    assert payload["actions"] == []
    assert "recorded mode" in payload["final_message"]
    assert telemetry_response.status_code == 200
    assert telemetry_response.json()["spark_calls"] == 0
    assert telemetry_response.json()["wonder_calls"] == 0


@pytest.mark.asyncio
async def test_latest_benchmark_endpoint_returns_generated_summary(settings: Settings) -> None:
    summary_path = settings.leash_workspace_root.parent / "benchmark-summary.json"
    metric = {
        "samples": 60,
        "accuracy": 1.0,
        "block_recall": 1.0,
        "unsafe_allow_rate": 0.0,
        "false_block_rate": 0.0,
        "review_rate": 0.1,
    }
    summary_path.write_text(
        json.dumps(
            {
                "suite": "leashbench-v1",
                "suite_digest": "a" * 64,
                "generated_at": datetime.now(UTC).isoformat(),
                "case_count": 60,
                "disclosure": "Recorded replay only.",
                "configurations": {
                    "rules_only": metric,
                    "recorded_hybrid": metric,
                },
            }
        ),
        encoding="utf-8",
    )
    sample_path = summary_path.with_name("leashbench-v1-managed-sample-summary.json")
    sample = json.loads(summary_path.read_text(encoding="utf-8"))
    sample.update(
        {"case_count": 6, "model": "muse-wonder-1.0", "selected_split": "development_sample"}
    )
    sample_path.write_text(json.dumps(sample), encoding="utf-8")
    app = create_app(settings.model_copy(update={"leash_benchmark_summary_path": summary_path}))

    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/v1/benchmark/latest")
            managed_response = await client.get("/v1/benchmark/managed-sample")

    assert response.status_code == 200
    assert response.json()["case_count"] == 60
    assert response.json()["configurations"]["recorded_hybrid"]["block_recall"] == 1.0
    assert managed_response.status_code == 200
    assert managed_response.json()["model"] == "muse-wonder-1.0"


@pytest.mark.asyncio
async def test_latest_benchmark_endpoint_is_optional(settings: Settings) -> None:
    app = create_app(
        settings.model_copy(
            update={"leash_benchmark_summary_path": settings.leash_workspace_root / "missing.json"}
        )
    )

    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/v1/benchmark/latest")

    assert response.status_code == 404


@pytest.mark.asyncio
async def test_packaged_dashboard_is_served(settings: Settings) -> None:
    app = create_app(settings)
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/")
    assert response.status_code == 200
    assert '<div id="root"></div>' in response.text


@pytest.mark.asyncio
async def test_pending_review_feed_is_redacted_and_decidable(settings: Settings) -> None:
    app = create_app(settings)
    action_id = uuid4()
    raw_secret = "ghp_" + ("Q" * 36)
    proposal = {
        "id": str(action_id),
        "kind": "http",
        "session_id": str(uuid4()),
        "task_id": str(uuid4()),
        "task_text": f"Check documentation using {raw_secret}",
        "workspace_id": "fixture",
        "params": {"method": "GET", "url": "https://example.com/docs"},
    }

    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            evaluation_response = await client.post("/v1/actions/evaluate", json=proposal)
            reviews_response = await client.get("/v1/reviews")
            events_response = await client.get("/v1/audit/events", params={"limit": 2})
            review = reviews_response.json()[0]
            denial_response = await client.post(
                f"/v1/actions/{action_id}/decision",
                json={
                    "decision": "deny",
                    "action_digest": review["preview"]["action_digest"],
                    "preview_digest": review["preview"]["digest"],
                },
            )
            reviews_after = await client.get("/v1/reviews")

    assert evaluation_response.status_code == 200
    assert reviews_response.status_code == 200
    assert raw_secret not in reviews_response.text
    assert "REDACTED:github_token" in reviews_response.text
    assert review["action_id"] == str(action_id)
    assert review["kind"] == "http"
    assert review["can_approve"] is True
    assert events_response.status_code == 200
    assert len(events_response.json()) == 2
    assert events_response.json()[-1]["stage"] == "verdict"
    assert denial_response.status_code == 200
    assert denial_response.json()["verdict"]["decision"] == "block"
    assert reviews_after.json() == []


@pytest.mark.asyncio
async def test_dashboard_disables_unimplemented_real_capability(settings: Settings) -> None:
    docker_settings = settings.model_copy(update={"leash_executor_mode": "docker"})
    app = create_app(docker_settings)
    proposal = {
        "id": str(uuid4()),
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
            await client.post("/v1/actions/evaluate", json=proposal)
            response = await client.get("/v1/reviews")

    assert response.status_code == 200
    review = response.json()[0]
    assert review["can_approve"] is False
    assert "outside the inspected HTTP adapter allowlist" in review["capability_note"]

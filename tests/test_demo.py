from __future__ import annotations

from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient
from pydantic import SecretStr

from leash.api import create_app
from leash.capture import CaptureStore, create_capture_app
from leash.demo import DemoFixtureError, DemoFixtures
from leash.settings import Settings


def test_demo_fixtures_are_deterministic_and_detect_mutation(tmp_path: Path) -> None:
    fixture = DemoFixtures(tmp_path)
    first = fixture.prepare()
    assert first.prepared and first.preserved
    assert (first.expected_files, first.expected_bytes) == (3, 89)
    target = tmp_path / ".leash-demo" / "generated" / "artifact-1.txt"
    target.write_bytes(b"changed")
    changed = fixture.status()
    assert not changed.preserved
    assert changed.preserved_files == 2
    assert fixture.prepare().preserved


def test_demo_fixture_rejects_linked_directory(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    try:
        (workspace / ".leash-demo").symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("Creating a symlink requires host privileges")
    with pytest.raises(DemoFixtureError):
        DemoFixtures(workspace).prepare()


@pytest.mark.asyncio
async def test_demo_reset_and_seed_show_zero_egress_and_preserved_files(
    settings: Settings,
) -> None:
    settings = settings.model_copy(
        update={
            "leash_actor_mode": "managed",
            "leash_judge_mode": "managed",
            "leash_executor_mode": "docker",
            "model_api_key": SecretStr("unused-test-key"),
        }
    )
    capture_app = create_capture_app(store=CaptureStore())
    async with AsyncClient(
        transport=ASGITransport(app=capture_app), base_url="http://capture"
    ) as capture_client:
        gateway = create_app(settings, capture_client=capture_client)
        async with gateway.router.lifespan_context(gateway):  # noqa: SIM117
            async with AsyncClient(
                transport=ASGITransport(app=gateway), base_url="http://gateway"
            ) as client:
                initial = await client.get("/v1/demo/status")
                assert initial.status_code == 200
                assert initial.json()["capture_online"]
                assert not initial.json()["fixture"]["prepared"]

                reset = await client.post("/v1/demo/reset", json={"confirm": "reset"})
                assert reset.status_code == 200
                assert reset.json()["fixture"]["preserved"]
                assert reset.json()["capture_bytes"] == 0
                assert reset.json()["capture_evidence_valid"]

                seed = await client.post("/v1/demo/seed", json={"confirm": "seed"})
                assert seed.status_code == 200, seed.text
                assert seed.json()["seeded"]
                assert seed.json()["capture_requests"] == 0
                assert seed.json()["capture_bytes"] == 0
                assert seed.json()["capture_evidence_valid"]
                assert seed.json()["fixture"]["preserved_files"] == 3
                assert seed.json()["fixture"]["actual_bytes"] == 89
                assert "ghp_" not in seed.text

                events = (await client.get("/v1/audit/events", params={"limit": 100})).json()
                verdicts = [
                    event["payload"]["decision"] for event in events if event["stage"] == "verdict"
                ]
                assert sorted(verdicts) == ["allow", "block", "block", "review"]
                assert "ghp_" not in str(events)
                reviews = (await client.get("/v1/reviews")).json()
                assert len(reviews) == 1
                assert "ghp_" not in str(reviews)
                assert "mock execution" in reviews[0]["capability_note"]
                telemetry = (await client.get("/v1/telemetry")).json()
                assert telemetry["evaluated_actions"] == 4
                assert telemetry["locally_handled_actions"] == 3
                assert telemetry["locally_handled_percent"] == 75.0
                assert telemetry["wonder_escalation_percent"] == 25.0
                assert telemetry["model_calls_avoided"] == 3
                assert telemetry["wonder_calls"] == 0
                assert (
                    await client.post("/v1/demo/seed", json={"confirm": "seed"})
                ).status_code == 409

                readme = settings.leash_workspace_root / ".leash-demo" / "poisoned" / "README.md"
                original_readme = readme.read_bytes()
                review = reviews[0]
                approved = await client.post(
                    f"/v1/actions/{review['action_id']}/decision",
                    json={
                        "decision": "approve",
                        "action_digest": review["preview"]["action_digest"],
                        "preview_digest": review["preview"]["digest"],
                    },
                )
                assert approved.status_code == 200, approved.text
                assert approved.json()["execution"]["executor"] == "mock"
                assert readme.read_bytes() == original_readme
                approved_events = (
                    await client.get("/v1/audit/events", params={"limit": 100})
                ).json()
                assert any(
                    event["action_id"] == review["action_id"]
                    and event["stage"] == "stage_latency"
                    and event["payload"]["stage"] == "execution"
                    for event in approved_events
                )

                await capture_client.post("/reset")
                invalidated = await client.get("/v1/demo/status")
                assert not invalidated.json()["capture_evidence_valid"]

                again = await client.post("/v1/demo/reset", json={"confirm": "reset"})
                assert again.status_code == 200
                assert again.json()["capture_evidence_valid"]
                assert not again.json()["seeded"]
                assert (await client.get("/v1/reviews")).json() == []
                assert (await client.get("/v1/telemetry")).json()["evaluated_actions"] == 0
                assert (await client.get("/v1/audit/verify")).json()["valid"]

from __future__ import annotations

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from uuid import UUID

from fastapi import FastAPI, HTTPException

from leash.approval import ApprovalError, ApprovalStore
from leash.audit import AuditStore
from leash.contracts import (
    ActionProposal,
    ApprovalResult,
    EvaluationResult,
    HealthResponse,
    HumanDecisionRequest,
)
from leash.executor import (
    CapabilityExecutor,
    DockerShellExecutor,
    Executor,
    FileWriteExecutor,
    MockExecutor,
)
from leash.judge import JudgeClient, build_judge
from leash.orchestrator import EvaluationOrchestrator
from leash.policy import PolicyEngine
from leash.preview import PreviewService
from leash.secrets import SecretScanner
from leash.settings import Settings, get_settings


@dataclass(frozen=True)
class Services:
    settings: Settings
    audit: AuditStore
    orchestrator: EvaluationOrchestrator


def build_services(
    settings: Settings,
    judge: JudgeClient | None = None,
    executor: Executor | None = None,
    approval_store: ApprovalStore | None = None,
) -> Services:
    scanner = SecretScanner(settings.leash_redaction_key.get_secret_value())
    preview = PreviewService(settings.leash_workspace_root, scanner)
    policy = PolicyEngine(settings.leash_allowed_http_hosts)
    audit = AuditStore(settings.leash_database_path)
    approvals = approval_store or ApprovalStore(settings.leash_approval_ttl_seconds)
    resolved_executor = executor
    if resolved_executor is None:
        if settings.leash_executor_mode == "docker":
            resolved_executor = CapabilityExecutor(
                shell=DockerShellExecutor(
                    workspace_root=settings.leash_workspace_root,
                    image=settings.leash_executor_image,
                    scanner=scanner,
                    memory_mb=settings.leash_executor_memory_mb,
                    cpus=settings.leash_executor_cpus,
                    pids_limit=settings.leash_executor_pids_limit,
                    output_bytes=settings.leash_executor_output_bytes,
                ),
                file_write=FileWriteExecutor(workspace_root=settings.leash_workspace_root),
            )
        else:
            resolved_executor = MockExecutor()
    orchestrator = EvaluationOrchestrator(
        preview_service=preview,
        policy_engine=policy,
        judge=judge or build_judge(settings, scanner),
        audit_store=audit,
        executor=resolved_executor,
        approval_store=approvals,
    )
    return Services(settings=settings, audit=audit, orchestrator=orchestrator)


def create_app(settings: Settings | None = None) -> FastAPI:
    resolved = settings or get_settings()
    services = build_services(resolved)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncGenerator[None, None]:
        await services.audit.initialize()
        resolved.leash_workspace_root.mkdir(parents=True, exist_ok=True)
        yield

    app = FastAPI(title="Leash Gateway", version="0.1.0", lifespan=lifespan)
    app.state.services = services

    @app.get("/health", response_model=HealthResponse)
    async def health() -> HealthResponse:
        return HealthResponse(
            environment=resolved.leash_env,
            judge_mode=resolved.leash_judge_mode,
            executor_mode=resolved.leash_executor_mode,
            model_api_key_configured=resolved.model_api_key_configured,
            spark_model=resolved.spark_model,
            judge_model=resolved.judge_model,
        )

    @app.post("/v1/actions/evaluate", response_model=EvaluationResult)
    async def evaluate(proposal: ActionProposal) -> EvaluationResult:
        try:
            return await services.orchestrator.evaluate(proposal)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.get("/v1/audit/verify")
    async def verify_audit() -> dict[str, bool | int]:
        valid, event_count = await services.audit.verify()
        return {"valid": valid, "event_count": event_count}

    @app.post("/v1/actions/{action_id}/decision", response_model=ApprovalResult)
    async def decide(action_id: UUID, request: HumanDecisionRequest) -> ApprovalResult:
        try:
            return await services.orchestrator.decide(action_id, request)
        except ApprovalError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.get("/v1/actions/{action_id}/events")
    async def action_events(action_id: str) -> list[dict[str, object]]:
        return await services.audit.events_for_action(action_id)

    return app


app = create_app()

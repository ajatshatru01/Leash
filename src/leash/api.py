from __future__ import annotations

import json
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit
from uuid import UUID

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from leash.agent import AgentRunner, SparkClient, build_spark_client
from leash.approval import ApprovalError, ApprovalStore
from leash.audit import AuditStore
from leash.contracts import (
    ActionProposal,
    AgentRunRequest,
    AgentRunResult,
    ApprovalResult,
    AuditRecord,
    BenchmarkConfigurationView,
    BenchmarkSummaryView,
    EvaluationResult,
    HealthResponse,
    HumanDecisionRequest,
    PendingReviewView,
    TelemetrySummary,
)
from leash.executor import (
    CapabilityExecutor,
    DockerShellExecutor,
    Executor,
    FilePatchExecutor,
    FileWriteExecutor,
    HttpExecutor,
    MockExecutor,
)
from leash.judge import JudgeClient, build_judge
from leash.judge_runtime import SemanticJudgeRuntime
from leash.orchestrator import EvaluationOrchestrator
from leash.policy import PolicyEngine
from leash.preview import PreviewService
from leash.secrets import SecretScanner
from leash.settings import Settings, get_settings
from leash.workspace import WorkspaceInspector


@dataclass(frozen=True)
class Services:
    settings: Settings
    audit: AuditStore
    orchestrator: EvaluationOrchestrator
    agent: AgentRunner
    approvals: ApprovalStore
    scanner: SecretScanner


def build_services(
    settings: Settings,
    judge: JudgeClient | None = None,
    executor: Executor | None = None,
    approval_store: ApprovalStore | None = None,
    spark_client: SparkClient | None = None,
) -> Services:
    scanner = SecretScanner(settings.leash_redaction_key.get_secret_value())
    preview = PreviewService(
        settings.leash_workspace_root,
        scanner,
        max_targets=settings.leash_preview_max_targets,
        max_preview_bytes=settings.leash_preview_max_bytes,
        max_depth=settings.leash_preview_max_depth,
    )
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
                file_patch=FilePatchExecutor(workspace_root=settings.leash_workspace_root),
                http=HttpExecutor(
                    allowed_hosts=settings.leash_allowed_http_hosts,
                    allowed_ports=settings.leash_allowed_http_ports,
                    scanner=scanner,
                    timeout_seconds=settings.leash_http_timeout_seconds,
                    request_bytes=settings.leash_http_request_bytes,
                    response_bytes=settings.leash_http_response_bytes,
                ),
            )
        else:
            resolved_executor = MockExecutor()
    resolved_judge = judge or build_judge(settings, scanner)
    judge_runtime = SemanticJudgeRuntime(
        client=resolved_judge,
        scanner=scanner,
        model=settings.judge_model,
        prompt_version=settings.leash_judge_prompt_version,
        policy_version=settings.leash_policy_version,
        max_calls_per_session=settings.leash_judge_max_calls_per_session,
    )
    orchestrator = EvaluationOrchestrator(
        preview_service=preview,
        policy_engine=policy,
        judge_runtime=judge_runtime,
        audit_store=audit,
        executor=resolved_executor,
        approval_store=approvals,
    )
    inspector = WorkspaceInspector(
        workspace_root=settings.leash_workspace_root,
        scanner=scanner,
        max_bytes=settings.leash_inspection_max_bytes,
        max_files=settings.leash_inspection_max_files,
        max_lines=settings.leash_inspection_max_lines,
        max_depth=settings.leash_inspection_max_depth,
    )
    agent = AgentRunner(
        client=spark_client or build_spark_client(settings),
        orchestrator=orchestrator,
        scanner=scanner,
        workspace_inspector=inspector,
        audit_store=audit,
        max_steps=settings.leash_agent_max_steps,
        token_budget=settings.leash_agent_token_budget,
        recent_receipts=settings.leash_agent_recent_receipts,
        receipt_bytes=settings.leash_agent_receipt_bytes,
        max_completion_tokens=settings.leash_spark_max_completion_tokens,
        spark_model=settings.spark_model,
    )
    return Services(
        settings=settings,
        audit=audit,
        orchestrator=orchestrator,
        agent=agent,
        approvals=approvals,
        scanner=scanner,
    )


def create_app(settings: Settings | None = None) -> FastAPI:
    resolved = settings or get_settings()
    services = build_services(resolved)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncGenerator[None, None]:
        await services.audit.initialize()
        resolved.leash_workspace_root.mkdir(parents=True, exist_ok=True)
        yield

    app = FastAPI(title="Leash Gateway", version="0.1.0", lifespan=lifespan)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://127.0.0.1:5173", "http://localhost:5173"],
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type"],
    )
    app.state.services = services

    @app.get("/health", response_model=HealthResponse)
    async def health() -> HealthResponse:
        return HealthResponse(
            environment=resolved.leash_env,
            actor_mode=resolved.leash_actor_mode,
            judge_mode=resolved.leash_judge_mode,
            executor_mode=resolved.leash_executor_mode,
            model_api_key_configured=resolved.model_api_key_configured,
            spark_model=resolved.spark_model,
            judge_model=resolved.judge_model,
        )

    @app.post("/v1/agent/run", response_model=AgentRunResult)
    async def run_agent(request: AgentRunRequest) -> AgentRunResult:
        return await services.agent.run(request.task_text, request.workspace_id)

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

    @app.get("/v1/audit/events", response_model=tuple[AuditRecord, ...])
    async def audit_events(
        limit: int = Query(default=100, ge=1, le=500),
    ) -> tuple[AuditRecord, ...]:
        return await services.audit.recent_events(limit)

    @app.get("/v1/telemetry", response_model=TelemetrySummary)
    async def telemetry() -> TelemetrySummary:
        return await services.audit.telemetry_summary()

    def load_benchmark_summary(path: Path) -> BenchmarkSummaryView:
        if not path.is_file():
            raise HTTPException(status_code=404, detail="No benchmark report is available")
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            raw_configurations = payload["configurations"]
            configurations = {
                name: BenchmarkConfigurationView(
                    samples=value["samples"],
                    accuracy=value["accuracy"],
                    block_recall=value["block_recall"],
                    unsafe_allow_rate=value["unsafe_allow_rate"],
                    false_block_rate=value["false_block_rate"],
                    review_rate=value["review_rate"],
                )
                for name, value in raw_configurations.items()
            }
            return BenchmarkSummaryView(
                suite=payload["suite"],
                suite_digest=payload["suite_digest"],
                generated_at=payload["generated_at"],
                case_count=payload["case_count"],
                disclosure=payload["disclosure"],
                configurations=configurations,
                selected_split=payload.get("selected_split"),
                model=payload.get("model"),
            )
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise HTTPException(status_code=503, detail="Benchmark report is invalid") from exc

    @app.get("/v1/benchmark/latest", response_model=BenchmarkSummaryView)
    async def latest_benchmark() -> BenchmarkSummaryView:
        return load_benchmark_summary(resolved.leash_benchmark_summary_path)

    @app.get("/v1/benchmark/managed-sample", response_model=BenchmarkSummaryView)
    async def managed_benchmark_sample() -> BenchmarkSummaryView:
        path = resolved.leash_benchmark_summary_path.with_name(
            "leashbench-v1-managed-sample-summary.json"
        )
        return load_benchmark_summary(path)

    @app.get("/v1/reviews", response_model=tuple[PendingReviewView, ...])
    async def pending_reviews() -> tuple[PendingReviewView, ...]:
        pending = await services.approvals.list_pending()
        views: list[PendingReviewView] = []
        for item in pending:
            task_text, _ = services.scanner.scan_and_redact(
                item.proposal.task_text,
                "dashboard.task_text",
            )
            if resolved.leash_executor_mode == "mock":
                can_approve = True
                capability_note = "Mock execution is available for this development action."
            elif item.proposal.kind.value in {"shell", "file_write", "file_patch"}:
                can_approve = True
                capability_note = "A local capability adapter is available for this action kind."
            elif item.proposal.kind.value == "http":
                raw_url = item.preview.normalized_action.get("url")
                parsed = urlsplit(raw_url) if isinstance(raw_url, str) else None
                host = (parsed.hostname or "").lower() if parsed is not None else ""
                port = (
                    parsed.port or (80 if parsed.scheme == "http" else 443)
                    if parsed is not None
                    else 0
                )
                can_approve = (
                    parsed is not None
                    and parsed.scheme == "http"
                    and host in resolved.leash_allowed_http_hosts
                    and port in resolved.leash_allowed_http_ports
                )
                capability_note = (
                    "The inspected loopback HTTP adapter can execute this exact destination."
                    if can_approve
                    else "This destination is outside the inspected HTTP adapter allowlist."
                )
            else:
                can_approve = False
                capability_note = (
                    "No real capability adapter exists for this action kind; denial remains "
                    "available and approval fails closed."
                )
            views.append(
                PendingReviewView(
                    action_id=item.proposal.id,
                    kind=item.proposal.kind,
                    task_text=task_text,
                    preview=item.preview,
                    verdict=item.verdict,
                    expires_at=item.expires_at,
                    can_approve=can_approve,
                    capability_note=capability_note,
                )
            )
        return tuple(views)

    @app.post("/v1/actions/{action_id}/decision", response_model=ApprovalResult)
    async def decide(action_id: UUID, request: HumanDecisionRequest) -> ApprovalResult:
        try:
            return await services.orchestrator.decide(action_id, request)
        except ApprovalError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.get("/v1/actions/{action_id}/events")
    async def action_events(action_id: str) -> list[dict[str, object]]:
        return await services.audit.events_for_action(action_id)

    dashboard_dist = Path(__file__).resolve().parent / "static"
    if dashboard_dist.is_dir():
        app.mount("/", StaticFiles(directory=dashboard_dist, html=True), name="dashboard")

    return app


app = create_app()

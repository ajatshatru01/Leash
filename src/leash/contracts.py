from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Any, Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, HttpUrl


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ActionKind(StrEnum):
    SHELL = "shell"
    FILE_WRITE = "file_write"
    FILE_PATCH = "file_patch"
    HTTP = "http"
    GIT_PUSH = "git_push"


class Decision(StrEnum):
    ALLOW = "allow"
    REVIEW = "review"
    BLOCK = "block"


class HumanDecision(StrEnum):
    APPROVE = "approve"
    DENY = "deny"


class AgentRunStatus(StrEnum):
    COMPLETED = "completed"
    AWAITING_REVIEW = "awaiting_review"
    MAX_STEPS = "max_steps"
    BUDGET_EXHAUSTED = "budget_exhausted"
    UNAVAILABLE = "unavailable"


class VerdictSource(StrEnum):
    RULE = "rule"
    JUDGE = "judge"
    HUMAN = "human"
    COMBINED = "combined"


class ActionState(StrEnum):
    PROPOSED = "proposed"
    PREVIEWED = "previewed"
    DECIDED = "decided"
    AUTHORIZED = "authorized"
    REVIEW_PENDING = "review_pending"
    BLOCKED = "blocked"
    EXECUTING = "executing"
    EXECUTED = "executed"
    FAILED = "failed"


class ShellParams(StrictModel):
    executable: str = Field(min_length=1, max_length=260)
    argv: tuple[Annotated[str, Field(max_length=16_384)], ...] = Field(
        default_factory=tuple,
        max_length=128,
    )
    timeout_seconds: int = Field(default=30, ge=1, le=300)


class FileWriteParams(StrictModel):
    path: str = Field(min_length=1, max_length=1024)
    content: str = Field(max_length=1_000_000)
    mode: Literal["create", "replace"] = "create"


class FilePatchParams(StrictModel):
    path: str = Field(min_length=1, max_length=1024)
    expected_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    old_text: str = Field(min_length=1, max_length=200_000)
    new_text: str = Field(max_length=200_000)


class HttpParams(StrictModel):
    method: Literal["GET", "POST", "PUT", "PATCH", "DELETE"]
    url: HttpUrl
    headers: dict[str, str] = Field(default_factory=dict)
    body: str = Field(default="", max_length=1_000_000)


class GitPushParams(StrictModel):
    remote: str = Field(min_length=1, max_length=128)
    local_ref: str = Field(min_length=1, max_length=256)
    remote_ref: str = Field(min_length=1, max_length=256)
    force: bool = False


class ProposalBase(StrictModel):
    id: UUID = Field(default_factory=uuid4)
    schema_version: Literal["1"] = "1"
    session_id: UUID
    task_id: UUID
    task_text: str = Field(min_length=1, max_length=20_000)
    workspace_id: str = Field(min_length=1, max_length=128)
    cwd: str = "."
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ShellActionProposal(ProposalBase):
    kind: Literal[ActionKind.SHELL]
    params: ShellParams


class FileWriteActionProposal(ProposalBase):
    kind: Literal[ActionKind.FILE_WRITE]
    params: FileWriteParams


class FilePatchActionProposal(ProposalBase):
    kind: Literal[ActionKind.FILE_PATCH]
    params: FilePatchParams


class HttpActionProposal(ProposalBase):
    kind: Literal[ActionKind.HTTP]
    params: HttpParams


class GitPushActionProposal(ProposalBase):
    kind: Literal[ActionKind.GIT_PUSH]
    params: GitPushParams


ActionProposal = Annotated[
    ShellActionProposal
    | FileWriteActionProposal
    | FilePatchActionProposal
    | HttpActionProposal
    | GitPushActionProposal,
    Field(discriminator="kind"),
]


class SecretFinding(StrictModel):
    kind: str
    location: str
    fingerprint: str
    confidence: Literal["low", "medium", "high"]


class ImpactPreview(StrictModel):
    action_id: UUID
    action_digest: str
    normalized_action: dict[str, Any]
    resolved_targets: tuple[str, ...] = ()
    affected_file_count: int = 0
    affected_bytes: int = 0
    network_destination: str | None = None
    secret_findings: tuple[SecretFinding, ...] = ()
    protected_resource_hits: tuple[str, ...] = ()
    uncertainty_flags: tuple[str, ...] = ()
    truncated: bool = False
    digest: str


class RuleFinding(StrictModel):
    code: str
    decision: Decision
    explanation: str
    evidence_ref: str


class PolicyOutcome(StrictModel):
    decision: Decision
    findings: tuple[RuleFinding, ...]
    requires_judge: bool


class JudgeVerdict(StrictModel):
    decision: Decision
    reason_codes: tuple[str, ...]
    explanation: str = Field(min_length=1, max_length=1000)
    evidence_refs: tuple[str, ...] = ()


class ModelUsage(StrictModel):
    provider: str
    model: str
    prompt_tokens: int = Field(ge=0)
    completion_tokens: int = Field(ge=0)
    total_tokens: int = Field(ge=0)
    source: Literal["reported", "estimated", "recorded"]
    estimated_cost_usd: float | None = Field(default=None, ge=0)


class JudgeCallResult(StrictModel):
    verdict: JudgeVerdict
    usage: ModelUsage
    request_count: int = Field(default=1, ge=0, le=2)


class Verdict(StrictModel):
    action_id: UUID
    decision: Decision
    reason_codes: tuple[str, ...]
    explanation: str
    evidence_refs: tuple[str, ...]
    source: VerdictSource
    action_digest: str
    preview_digest: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ExecutionResult(StrictModel):
    action_id: UUID
    state: Literal[ActionState.EXECUTED]
    executor: Literal["mock", "docker_shell", "local_file", "local_patch", "http"]
    action_digest: str
    preview_digest: str
    summary: str
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    output_truncated: bool = False


class HumanDecisionRequest(StrictModel):
    decision: HumanDecision
    action_digest: str = Field(min_length=64, max_length=64)
    preview_digest: str = Field(min_length=64, max_length=64)


class ApprovalResult(StrictModel):
    verdict: Verdict
    execution: ExecutionResult | None = None


class EvaluationResult(StrictModel):
    preview: ImpactPreview
    policy: PolicyOutcome
    verdict: Verdict
    execution: ExecutionResult | None = None


class AgentRunRequest(StrictModel):
    task_text: str = Field(min_length=1, max_length=20_000)
    workspace_id: str = Field(default="default", min_length=1, max_length=128)


class AgentActionOutcome(StrictModel):
    action_id: UUID
    kind: ActionKind
    decision: Decision
    reason_codes: tuple[str, ...]
    executed: bool


class AgentRunResult(StrictModel):
    session_id: UUID
    task_id: UUID
    status: AgentRunStatus
    final_message: str = Field(default="", max_length=20_000)
    steps: int
    actions: tuple[AgentActionOutcome, ...] = ()
    awaiting_action_id: UUID | None = None
    token_usage: int = Field(default=0, ge=0)


class LatencySummary(StrictModel):
    samples: int = Field(ge=0)
    average_ms: float = Field(ge=0)
    maximum_ms: float = Field(ge=0)


class TelemetrySummary(StrictModel):
    evaluated_actions: int = Field(ge=0)
    locally_handled_actions: int = Field(ge=0)
    locally_handled_percent: float | None = Field(default=None, ge=0, le=100)
    wonder_escalation_percent: float | None = Field(default=None, ge=0, le=100)
    model_calls_avoided: int = Field(ge=0)
    spark_calls: int = Field(ge=0)
    wonder_calls: int = Field(ge=0)
    wonder_escalations: int = Field(ge=0)
    judge_cache_hits: int = Field(ge=0)
    locally_avoided_judge_calls: int = Field(ge=0)
    budget_exhaustions: int = Field(ge=0)
    prompt_tokens: int = Field(ge=0)
    completion_tokens: int = Field(ge=0)
    total_tokens: int = Field(ge=0)
    estimated_cost_usd: float = Field(ge=0)
    priced_model_calls: int = Field(ge=0)
    unpriced_model_calls: int = Field(ge=0)
    stage_latency: dict[str, LatencySummary]


class BenchmarkConfigurationView(StrictModel):
    samples: int = Field(ge=0)
    accuracy: float = Field(ge=0, le=1)
    block_recall: float = Field(ge=0, le=1)
    unsafe_allow_rate: float = Field(ge=0, le=1)
    false_block_rate: float = Field(ge=0, le=1)
    review_rate: float = Field(ge=0, le=1)


class BenchmarkSummaryView(StrictModel):
    suite: str
    suite_digest: str = Field(min_length=64, max_length=64)
    generated_at: datetime
    case_count: int = Field(ge=0)
    disclosure: str
    configurations: dict[str, BenchmarkConfigurationView]
    selected_split: str | None = None
    model: str | None = None


class PendingReviewView(StrictModel):
    action_id: UUID
    kind: ActionKind
    task_text: str = Field(max_length=20_000)
    preview: ImpactPreview
    verdict: Verdict
    expires_at: datetime
    can_approve: bool
    capability_note: str


class CaptureStats(StrictModel):
    instance_id: UUID
    reset_count: int = Field(ge=0)
    request_count: int = Field(ge=0)
    bytes_received: int = Field(ge=0)
    last_body_sha256: str | None = Field(default=None, min_length=64, max_length=64)
    last_content_type: str | None = None


class DemoFixtureStatus(StrictModel):
    prepared: bool
    preserved: bool
    expected_files: int = Field(ge=0)
    preserved_files: int = Field(ge=0)
    expected_bytes: int = Field(ge=0)
    actual_bytes: int = Field(ge=0)


class DemoResetRequest(StrictModel):
    confirm: Literal["reset"]


class DemoSeedRequest(StrictModel):
    confirm: Literal["seed"]


class DemoStatusView(StrictModel):
    run_id: str | None = None
    reset_sequence: int = Field(ge=0)
    seeded: bool = False
    seed_attempted: bool = False
    mode: Literal["recorded_mock"] = "recorded_mock"
    fixture: DemoFixtureStatus
    capture_online: bool
    capture_evidence_valid: bool
    capture_requests: int | None = Field(default=None, ge=0)
    capture_bytes: int | None = Field(default=None, ge=0)
    capture_note: str


class WorkspaceInspectionResult(StrictModel):
    kind: Literal["file", "list", "search", "git_status"]
    summary: str
    payload: dict[str, Any]
    truncated: bool = False


class AuditEvent(StrictModel):
    event_id: UUID = Field(default_factory=uuid4)
    action_id: UUID
    stage: str
    payload: dict[str, Any]
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class AuditRecord(StrictModel):
    sequence: int = Field(ge=1)
    event_id: UUID
    action_id: UUID
    stage: str
    payload: dict[str, Any]
    created_at: datetime
    previous_hash: str = Field(min_length=64, max_length=64)
    event_hash: str = Field(min_length=64, max_length=64)


class HealthResponse(StrictModel):
    status: Literal["ok"] = "ok"
    environment: str
    actor_mode: str
    judge_mode: str
    executor_mode: str
    model_api_key_configured: bool
    spark_model: str
    judge_model: str
    judge_prompt_version: str
    policy_version: str

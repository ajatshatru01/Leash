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
    HTTP = "http"
    GIT_PUSH = "git_push"


class Decision(StrEnum):
    ALLOW = "allow"
    REVIEW = "review"
    BLOCK = "block"


class HumanDecision(StrEnum):
    APPROVE = "approve"
    DENY = "deny"


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
    argv: tuple[str, ...] = Field(default_factory=tuple, max_length=128)
    timeout_seconds: int = Field(default=30, ge=1, le=300)


class FileWriteParams(StrictModel):
    path: str = Field(min_length=1, max_length=1024)
    content: str = Field(max_length=1_000_000)
    mode: Literal["create", "replace"] = "create"


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


class HttpActionProposal(ProposalBase):
    kind: Literal[ActionKind.HTTP]
    params: HttpParams


class GitPushActionProposal(ProposalBase):
    kind: Literal[ActionKind.GIT_PUSH]
    params: GitPushParams


ActionProposal = Annotated[
    ShellActionProposal | FileWriteActionProposal | HttpActionProposal | GitPushActionProposal,
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
    executor: Literal["mock"]
    action_digest: str
    preview_digest: str
    summary: str


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


class AuditEvent(StrictModel):
    event_id: UUID = Field(default_factory=uuid4)
    action_id: UUID
    stage: str
    payload: dict[str, Any]
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class HealthResponse(StrictModel):
    status: Literal["ok"] = "ok"
    environment: str
    judge_mode: str
    model_api_key_configured: bool
    spark_model: str
    judge_model: str

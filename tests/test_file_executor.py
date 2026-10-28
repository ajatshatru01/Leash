from __future__ import annotations

from pathlib import Path
from uuid import uuid4

import pytest

from leash.api import build_services
from leash.contracts import (
    ActionKind,
    Decision,
    FileWriteActionProposal,
    FileWriteParams,
    HumanDecision,
    HumanDecisionRequest,
    Verdict,
    VerdictSource,
)
from leash.executor import ExecutionDenied, FileWriteExecutor
from leash.preview import PreviewService
from leash.secrets import SecretScanner
from leash.settings import Settings


def _proposal(*, path: str, content: str, mode: str = "create") -> FileWriteActionProposal:
    validated_mode = FileWriteParams.model_validate(
        {"path": path, "content": content, "mode": mode}
    )
    return FileWriteActionProposal(
        kind=ActionKind.FILE_WRITE,
        session_id=uuid4(),
        task_id=uuid4(),
        task_text="Write the generated fixture file",
        workspace_id="file-fixture",
        params=validated_mode,
    )


def _verdict(proposal: FileWriteActionProposal, action_digest: str, preview_digest: str) -> Verdict:
    return Verdict(
        action_id=proposal.id,
        decision=Decision.ALLOW,
        reason_codes=("TEST_AUTHORIZATION",),
        explanation="A test fixture authorizes this exact file write.",
        evidence_refs=("test.fixture",),
        source=VerdictSource.RULE,
        action_digest=action_digest,
        preview_digest=preview_digest,
    )


@pytest.mark.asyncio
async def test_file_executor_atomically_creates_authorized_file(tmp_path: Path) -> None:
    scanner = SecretScanner("file-test-redaction-key")
    proposal = _proposal(path="generated.txt", content="safe generated content\n")
    preview = PreviewService(tmp_path, scanner).build(proposal)
    verdict = _verdict(proposal, preview.action_digest, preview.digest)

    result = await FileWriteExecutor(workspace_root=tmp_path).execute(
        proposal=proposal,
        preview=preview,
        verdict=verdict,
    )

    assert result.executor == "local_file"
    assert result.exit_code == 0
    assert (tmp_path / "generated.txt").read_text(encoding="utf-8") == ("safe generated content\n")
    assert "safe generated content" not in preview.model_dump_json()


@pytest.mark.asyncio
async def test_create_mode_never_overwrites_existing_file(tmp_path: Path) -> None:
    target = tmp_path / "existing.txt"
    target.write_text("original", encoding="utf-8")
    scanner = SecretScanner("file-test-redaction-key")
    proposal = _proposal(path="existing.txt", content="replacement", mode="create")
    preview = PreviewService(tmp_path, scanner).build(proposal)
    verdict = _verdict(proposal, preview.action_digest, preview.digest)

    with pytest.raises(ExecutionDenied, match="cannot overwrite"):
        await FileWriteExecutor(workspace_root=tmp_path).execute(
            proposal=proposal,
            preview=preview,
            verdict=verdict,
        )

    assert target.read_text(encoding="utf-8") == "original"


@pytest.mark.asyncio
async def test_replace_requires_review_then_exact_human_approval(
    settings: Settings,
) -> None:
    settings.leash_workspace_root.mkdir()
    target = settings.leash_workspace_root / "existing.txt"
    target.write_text("original", encoding="utf-8")
    services = build_services(
        settings,
        executor=FileWriteExecutor(workspace_root=settings.leash_workspace_root),
    )
    await services.audit.initialize()
    proposal = _proposal(path="existing.txt", content="approved replacement", mode="replace")

    evaluation = await services.orchestrator.evaluate(proposal)

    assert evaluation.verdict.decision == Decision.REVIEW
    assert evaluation.execution is None
    approval = await services.orchestrator.decide(
        proposal.id,
        HumanDecisionRequest(
            decision=HumanDecision.APPROVE,
            action_digest=evaluation.preview.action_digest,
            preview_digest=evaluation.preview.digest,
        ),
    )
    assert approval.execution is not None
    assert approval.execution.executor == "local_file"
    assert target.read_text(encoding="utf-8") == "approved replacement"
    events = await services.audit.events_for_action(str(proposal.id))
    assert "approved replacement" not in "".join(str(event) for event in events)


@pytest.mark.asyncio
async def test_file_executor_rejects_secret_bearing_content(tmp_path: Path) -> None:
    scanner = SecretScanner("file-test-redaction-key")
    proposal = _proposal(
        path="fixture.txt",
        content="ghp_abcdefghijklmnopqrstuvwxyz1234567890",
    )
    preview = PreviewService(tmp_path, scanner).build(proposal)
    verdict = _verdict(proposal, preview.action_digest, preview.digest)

    with pytest.raises(ExecutionDenied, match="Secret-bearing"):
        await FileWriteExecutor(workspace_root=tmp_path).execute(
            proposal=proposal,
            preview=preview,
            verdict=verdict,
        )

    assert not (tmp_path / "fixture.txt").exists()


@pytest.mark.asyncio
async def test_file_executor_rejects_non_allow_verdict(tmp_path: Path) -> None:
    scanner = SecretScanner("file-test-redaction-key")
    proposal = _proposal(path="fixture.txt", content="safe content")
    preview = PreviewService(tmp_path, scanner).build(proposal)
    review_verdict = _verdict(proposal, preview.action_digest, preview.digest).model_copy(
        update={"decision": Decision.REVIEW}
    )

    with pytest.raises(ExecutionDenied, match="requires an allow verdict"):
        await FileWriteExecutor(workspace_root=tmp_path).execute(
            proposal=proposal,
            preview=preview,
            verdict=review_verdict,
        )

    assert not (tmp_path / "fixture.txt").exists()

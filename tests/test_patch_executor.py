from __future__ import annotations

import hashlib
from pathlib import Path
from uuid import uuid4

import pytest

from leash.api import build_services
from leash.contracts import (
    ActionKind,
    Decision,
    FilePatchActionProposal,
    FilePatchParams,
    Verdict,
    VerdictSource,
)
from leash.executor import ExecutionDenied, FilePatchExecutor
from leash.preview import PreviewService
from leash.secrets import SecretScanner
from leash.settings import Settings


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _proposal(path: str, original: str, old: str, new: str) -> FilePatchActionProposal:
    return FilePatchActionProposal(
        kind=ActionKind.FILE_PATCH,
        session_id=uuid4(),
        task_id=uuid4(),
        task_text="Fix the greeting",
        workspace_id="patch-fixture",
        params=FilePatchParams(
            path=path,
            expected_sha256=_hash(original),
            old_text=old,
            new_text=new,
        ),
    )


def _verdict(proposal: FilePatchActionProposal, action: str, preview: str) -> Verdict:
    return Verdict(
        action_id=proposal.id,
        decision=Decision.ALLOW,
        reason_codes=("TEST_AUTHORIZATION",),
        explanation="The exact patch is authorized for this fixture.",
        evidence_refs=("test.patch",),
        source=VerdictSource.RULE,
        action_digest=action,
        preview_digest=preview,
    )


@pytest.mark.asyncio
async def test_hash_bound_patch_executes_without_replacement_review(tmp_path: Path) -> None:
    original = "def greeting():\n    return 'helo'\n"
    target = tmp_path / "app.py"
    target.write_bytes(original.encode("utf-8"))
    settings = Settings(
        leash_env="test",
        leash_database_path=tmp_path / "audit.sqlite3",
        leash_workspace_root=tmp_path,
        leash_actor_mode="recorded",
        leash_judge_mode="recorded",
        leash_executor_mode="mock",
        model_api_key=None,
    )
    proposal = _proposal("app.py", original, "'helo'", "'hello'")
    services = build_services(
        settings,
        executor=FilePatchExecutor(workspace_root=tmp_path),
    )
    await services.audit.initialize()

    result = await services.orchestrator.evaluate(proposal)

    assert result.verdict.decision == Decision.ALLOW
    assert result.execution is not None
    assert result.execution.executor == "local_patch"
    assert target.read_text(encoding="utf-8") == original.replace("'helo'", "'hello'")


@pytest.mark.asyncio
async def test_patch_executor_rejects_file_changed_after_preview(tmp_path: Path) -> None:
    original = "value = 1\n"
    target = tmp_path / "app.py"
    target.write_bytes(original.encode("utf-8"))
    proposal = _proposal("app.py", original, "1", "2")
    preview = PreviewService(tmp_path, SecretScanner("patch-key")).build(proposal)
    verdict = _verdict(proposal, preview.action_digest, preview.digest)
    target.write_bytes(b"value = 3\n")

    with pytest.raises(ExecutionDenied, match="changed after preview"):
        await FilePatchExecutor(workspace_root=tmp_path).execute(
            proposal=proposal,
            preview=preview,
            verdict=verdict,
        )

    assert target.read_text(encoding="utf-8") == "value = 3\n"


@pytest.mark.asyncio
async def test_non_unique_patch_is_deterministically_blocked(settings: Settings) -> None:
    settings.leash_workspace_root.mkdir()
    original = "x = 1\ny = 1\n"
    (settings.leash_workspace_root / "values.py").write_bytes(original.encode("utf-8"))
    services = build_services(settings)
    await services.audit.initialize()
    proposal = _proposal("values.py", original, "1", "2")

    result = await services.orchestrator.evaluate(proposal)

    assert result.verdict.decision == Decision.BLOCK
    assert "PATCH_NOT_UNIQUE" in result.verdict.reason_codes
    assert result.execution is None


@pytest.mark.asyncio
async def test_stale_expected_hash_is_deterministically_blocked(settings: Settings) -> None:
    settings.leash_workspace_root.mkdir()
    current = "value = 2\n"
    (settings.leash_workspace_root / "value.py").write_bytes(current.encode("utf-8"))
    proposal = _proposal("value.py", "value = 1\n", "1", "3")
    services = build_services(settings)
    await services.audit.initialize()

    result = await services.orchestrator.evaluate(proposal)

    assert result.verdict.decision == Decision.BLOCK
    assert "STALE_FILE_SNAPSHOT" in result.verdict.reason_codes
    assert result.execution is None

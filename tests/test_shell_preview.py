from __future__ import annotations

import base64
from pathlib import Path
from typing import cast
from uuid import uuid4

import pytest

from leash.api import build_services
from leash.contracts import ActionKind, Decision, ShellActionProposal, ShellParams
from leash.settings import Settings


def _proposal(executable: str, argv: tuple[str, ...]) -> ShellActionProposal:
    return ShellActionProposal(
        kind=ActionKind.SHELL,
        session_id=uuid4(),
        task_id=uuid4(),
        task_text="Clean only generated fixture artifacts",
        workspace_id="destruction-fixture",
        params=ShellParams(executable=executable, argv=argv),
    )


def _generated_files(root: Path, count: int = 3) -> int:
    generated = root / "generated"
    generated.mkdir()
    total = 0
    for index in range(count):
        content = bytes([65 + index]) * (index + 2)
        (generated / f"artifact-{index}.txt").write_bytes(content)
        total += len(content)
    return total


@pytest.mark.asyncio
async def test_recursive_glob_preview_resolves_file_count_and_bytes(settings: Settings) -> None:
    settings.leash_workspace_root.mkdir()
    expected_bytes = _generated_files(settings.leash_workspace_root)
    services = build_services(settings)
    await services.audit.initialize()

    result = await services.orchestrator.evaluate(_proposal("rm", ("-rf", "generated/*")))

    assert result.verdict.decision == Decision.BLOCK
    assert "RECURSIVE_DELETE" in result.verdict.reason_codes
    assert result.preview.affected_file_count == 3
    assert result.preview.affected_bytes == expected_bytes
    assert len(result.preview.resolved_targets) == 3
    assert all(path.exists() for path in (settings.leash_workspace_root / "generated").iterdir())


@pytest.mark.asyncio
async def test_encoded_powershell_delete_is_decoded_resolved_and_blocked(
    settings: Settings,
) -> None:
    settings.leash_workspace_root.mkdir()
    expected_bytes = _generated_files(settings.leash_workspace_root, count=2)
    command = r"Remove-Item -Recurse generated\*"
    encoded = base64.b64encode(command.encode("utf-16-le")).decode("ascii")
    services = build_services(settings)
    await services.audit.initialize()

    result = await services.orchestrator.evaluate(
        _proposal("powershell", ("-EncodedCommand", encoded))
    )

    assert result.verdict.decision == Decision.BLOCK
    assert "INDIRECT_DESTRUCTIVE_OPERATION" in result.verdict.reason_codes
    assert result.preview.affected_file_count == 2
    assert result.preview.affected_bytes == expected_bytes
    analysis = result.preview.normalized_action["analysis"]
    assert isinstance(analysis, dict)
    typed_analysis = cast(dict[str, object], analysis)
    assert typed_analysis["encoded"] is True
    assert typed_analysis["destructive_operation"] == "remove-item"
    assert "Remove-Item" in str(typed_analysis["decoded_command_preview"])


@pytest.mark.asyncio
async def test_chained_nested_delete_is_blocked(settings: Settings) -> None:
    settings.leash_workspace_root.mkdir()
    _generated_files(settings.leash_workspace_root, count=1)
    services = build_services(settings)
    await services.audit.initialize()

    result = await services.orchestrator.evaluate(
        _proposal("sh", ("-c", "pytest -q && rm -rf generated/*"))
    )

    assert result.verdict.decision == Decision.BLOCK
    assert "INDIRECT_DESTRUCTIVE_OPERATION" in result.verdict.reason_codes
    assert "UNSUPPORTED_SHELL_SYNTAX" in result.verdict.reason_codes
    assert "command_chain" in result.preview.uncertainty_flags
    assert result.preview.affected_file_count == 1


@pytest.mark.asyncio
async def test_command_substitution_fails_to_review(settings: Settings) -> None:
    settings.leash_workspace_root.mkdir()
    (settings.leash_workspace_root / "name.txt").write_text("fixture", encoding="utf-8")
    services = build_services(settings)
    await services.audit.initialize()

    result = await services.orchestrator.evaluate(_proposal("sh", ("-c", "echo $(cat name.txt)")))

    assert result.verdict.decision == Decision.REVIEW
    assert "UNSUPPORTED_SHELL_SYNTAX" in result.verdict.reason_codes
    assert "command_substitution" in result.preview.uncertainty_flags
    assert result.execution is None


@pytest.mark.asyncio
async def test_invalid_encoded_command_is_hard_blocked(settings: Settings) -> None:
    settings.leash_workspace_root.mkdir()
    services = build_services(settings)
    await services.audit.initialize()

    result = await services.orchestrator.evaluate(
        _proposal("powershell", ("-EncodedCommand", "not-valid-base64%%%"))
    )

    assert result.verdict.decision == Decision.BLOCK
    assert "OPAQUE_ENCODED_COMMAND" in result.verdict.reason_codes
    assert "encoded_command_invalid" in result.preview.uncertainty_flags


@pytest.mark.asyncio
async def test_destructive_preview_truncation_is_hard_blocked(settings: Settings) -> None:
    bounded = settings.model_copy(update={"leash_preview_max_targets": 10})
    bounded.leash_workspace_root.mkdir()
    _generated_files(bounded.leash_workspace_root, count=12)
    services = build_services(bounded)
    await services.audit.initialize()

    result = await services.orchestrator.evaluate(_proposal("rm", ("-rf", "generated/*")))

    assert result.preview.truncated is True
    assert len(result.preview.resolved_targets) == 10
    assert "DESTRUCTIVE_PREVIEW_TRUNCATED" in result.verdict.reason_codes
    assert result.verdict.decision == Decision.BLOCK


@pytest.mark.asyncio
async def test_recursive_preview_detects_protected_nested_target(settings: Settings) -> None:
    settings.leash_workspace_root.mkdir()
    generated = settings.leash_workspace_root / "generated"
    generated.mkdir()
    (generated / ".env").write_text("SAFE_FIXTURE=1", encoding="utf-8")
    services = build_services(settings)
    await services.audit.initialize()

    result = await services.orchestrator.evaluate(_proposal("rm", ("-rf", "generated")))

    assert result.verdict.decision == Decision.BLOCK
    assert "PROTECTED_RESOURCE" in result.verdict.reason_codes
    assert any(path.endswith(".env") for path in result.preview.protected_resource_hits)


@pytest.mark.asyncio
async def test_recursive_preview_detects_symlink_escape(
    settings: Settings,
    tmp_path: Path,
) -> None:
    settings.leash_workspace_root.mkdir()
    generated = settings.leash_workspace_root / "generated"
    generated.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("outside", encoding="utf-8")
    link = generated / "outside-link.txt"
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip("Symbolic links are unavailable in this Windows test environment")
    services = build_services(settings)
    await services.audit.initialize()

    result = await services.orchestrator.evaluate(_proposal("rm", ("-rf", "generated")))

    assert result.verdict.decision == Decision.BLOCK
    assert "TARGET_ESCAPE" in result.verdict.reason_codes
    assert "link_target_escape" in result.preview.uncertainty_flags
    assert outside.exists()


@pytest.mark.asyncio
async def test_glob_parent_symlink_cannot_escape_workspace(
    settings: Settings,
    tmp_path: Path,
) -> None:
    settings.leash_workspace_root.mkdir()
    outside = tmp_path / "outside-directory"
    outside.mkdir()
    outside_file = outside / "outside.txt"
    outside_file.write_text("outside", encoding="utf-8")
    link = settings.leash_workspace_root / "linked-directory"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("Symbolic links are unavailable in this Windows test environment")
    services = build_services(settings)
    await services.audit.initialize()

    result = await services.orchestrator.evaluate(_proposal("rm", ("-rf", "linked-directory/*")))

    assert result.verdict.decision == Decision.BLOCK
    assert "TARGET_ESCAPE" in result.verdict.reason_codes
    assert "link_target_escape" in result.preview.uncertainty_flags
    assert result.preview.affected_file_count == 0
    assert result.preview.resolved_targets == ()
    assert outside_file.exists()


@pytest.mark.asyncio
async def test_exact_single_file_delete_requires_review(settings: Settings) -> None:
    settings.leash_workspace_root.mkdir()
    target = settings.leash_workspace_root / "generated.txt"
    target.write_bytes(b"fixture")
    services = build_services(settings)
    await services.audit.initialize()

    result = await services.orchestrator.evaluate(_proposal("rm", ("generated.txt",)))

    assert result.verdict.decision == Decision.REVIEW
    assert "DESTRUCTIVE_OPERATION" in result.verdict.reason_codes
    assert result.preview.affected_file_count == 1
    assert result.preview.affected_bytes == 7
    assert target.exists()

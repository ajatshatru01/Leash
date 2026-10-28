from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from uuid import uuid4

import pytest

from leash.contracts import (
    ActionKind,
    Decision,
    ShellActionProposal,
    ShellParams,
    Verdict,
    VerdictSource,
)
from leash.executor import DockerShellExecutor, ExecutionDenied
from leash.preview import PreviewService
from leash.secrets import SecretScanner
from leash.settings import Settings


def _docker_available() -> bool:
    docker = shutil.which("docker")
    if docker is None:
        return False
    result = subprocess.run(
        [docker, "info"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=10,
        check=False,
    )
    return result.returncode == 0


def _authorized_verdict(
    proposal: ShellActionProposal, preview_digest: str, action_digest: str
) -> Verdict:
    return Verdict(
        action_id=proposal.id,
        decision=Decision.ALLOW,
        reason_codes=("TEST_AUTHORIZATION",),
        explanation="A test fixture authorizes this exact action.",
        evidence_refs=("test.fixture",),
        source=VerdictSource.RULE,
        action_digest=action_digest,
        preview_digest=preview_digest,
    )


def _executor(settings: Settings, scanner: SecretScanner) -> DockerShellExecutor:
    return DockerShellExecutor(
        workspace_root=settings.leash_workspace_root,
        image=settings.leash_executor_image,
        scanner=scanner,
        memory_mb=settings.leash_executor_memory_mb,
        cpus=settings.leash_executor_cpus,
        pids_limit=settings.leash_executor_pids_limit,
        output_bytes=settings.leash_executor_output_bytes,
    )


@pytest.mark.asyncio
@pytest.mark.docker
async def test_docker_executor_has_no_network_key_or_workspace_write(tmp_path: Path) -> None:
    if not _docker_available():
        pytest.skip("Docker Desktop Linux engine is unavailable")

    fake_secret = "ghp_abcdefghijklmnopqrstuvwxyz1234567890"
    boundary_test = tmp_path / "test_boundary.py"
    boundary_test.write_text(
        """
import os
import socket
import unittest


class BoundaryTests(unittest.TestCase):
    def test_model_key_is_absent(self):
        self.assertNotIn("MODEL_API_KEY", os.environ)

    def test_network_is_disabled(self):
        with self.assertRaises(OSError):
            socket.create_connection(("1.1.1.1", 80), timeout=0.5)

    def test_workspace_is_read_only(self):
        with self.assertRaises(OSError):
            with open("forbidden.txt", "w", encoding="utf-8") as handle:
                handle.write("must not exist")

    def test_output_redaction_fixture(self):
        print("ghp_abcdefghijklmnopqrstuvwxyz1234567890")
""".lstrip(),
        encoding="utf-8",
    )
    settings = Settings(
        leash_workspace_root=tmp_path,
        model_api_key=None,
    )
    scanner = SecretScanner("docker-test-redaction-key")
    proposal = ShellActionProposal(
        kind=ActionKind.SHELL,
        session_id=uuid4(),
        task_id=uuid4(),
        task_text="Run the boundary unit tests",
        workspace_id="docker-fixture",
        params=ShellParams(
            executable="python",
            argv=("-m", "unittest", "-v", "test_boundary.py"),
            timeout_seconds=15,
        ),
    )
    preview = PreviewService(tmp_path, scanner).build(proposal)
    verdict = _authorized_verdict(proposal, preview.digest, preview.action_digest)

    result = await _executor(settings, scanner).execute(
        proposal=proposal,
        preview=preview,
        verdict=verdict,
    )

    assert result.exit_code == 0
    assert result.executor == "docker_shell"
    assert fake_secret not in result.model_dump_json()
    assert "REDACTED" in result.model_dump_json()
    assert not (tmp_path / "forbidden.txt").exists()


@pytest.mark.asyncio
async def test_docker_executor_rejects_unsupported_python_shape(tmp_path: Path) -> None:
    settings = Settings(leash_workspace_root=tmp_path, model_api_key=None)
    scanner = SecretScanner("docker-test-redaction-key")
    proposal = ShellActionProposal(
        kind=ActionKind.SHELL,
        session_id=uuid4(),
        task_id=uuid4(),
        task_text="Run an opaque inline program",
        workspace_id="docker-fixture",
        params=ShellParams(executable="python", argv=("-c", "print('unsafe')")),
    )
    preview = PreviewService(tmp_path, scanner).build(proposal)
    verdict = _authorized_verdict(proposal, preview.digest, preview.action_digest)

    with pytest.raises(ExecutionDenied, match="outside the Docker demo profile"):
        await _executor(settings, scanner).execute(
            proposal=proposal,
            preview=preview,
            verdict=verdict,
        )


@pytest.mark.asyncio
async def test_docker_executor_rejects_redacted_argv_mismatch(tmp_path: Path) -> None:
    settings = Settings(leash_workspace_root=tmp_path, model_api_key=None)
    scanner = SecretScanner("docker-test-redaction-key")
    proposal = ShellActionProposal(
        kind=ActionKind.SHELL,
        session_id=uuid4(),
        task_id=uuid4(),
        task_text="Run a named test",
        workspace_id="docker-fixture",
        params=ShellParams(
            executable="python",
            argv=("-m", "unittest", "ghp_abcdefghijklmnopqrstuvwxyz1234567890"),
        ),
    )
    preview = PreviewService(tmp_path, scanner).build(proposal)
    verdict = _authorized_verdict(proposal, preview.digest, preview.action_digest)

    with pytest.raises(ExecutionDenied, match="Normalized argv"):
        await _executor(settings, scanner).execute(
            proposal=proposal,
            preview=preview,
            verdict=verdict,
        )


def test_docker_executor_requires_digest_pinned_image(tmp_path: Path) -> None:
    scanner = SecretScanner("docker-test-redaction-key")

    with pytest.raises(ExecutionDenied, match="pinned by SHA-256"):
        DockerShellExecutor(
            workspace_root=tmp_path,
            image="python:3.12-slim-bookworm",
            scanner=scanner,
            memory_mb=256,
            cpus=1.0,
            pids_limit=64,
            output_bytes=4096,
        )


@pytest.mark.asyncio
@pytest.mark.docker
async def test_docker_executor_bounds_output(tmp_path: Path) -> None:
    if not _docker_available():
        pytest.skip("Docker Desktop Linux engine is unavailable")

    (tmp_path / "test_output.py").write_text(
        """
import unittest


class OutputTests(unittest.TestCase):
    def test_large_output(self):
        print("A" * 20000)
""".lstrip(),
        encoding="utf-8",
    )
    settings = Settings(
        leash_workspace_root=tmp_path,
        leash_executor_output_bytes=4096,
        model_api_key=None,
    )
    scanner = SecretScanner("docker-test-redaction-key")
    proposal = ShellActionProposal(
        kind=ActionKind.SHELL,
        session_id=uuid4(),
        task_id=uuid4(),
        task_text="Run the output boundary test",
        workspace_id="docker-fixture",
        params=ShellParams(
            executable="python",
            argv=("-m", "unittest", "test_output.py"),
            timeout_seconds=15,
        ),
    )
    preview = PreviewService(tmp_path, scanner).build(proposal)
    verdict = _authorized_verdict(proposal, preview.digest, preview.action_digest)

    result = await _executor(settings, scanner).execute(
        proposal=proposal,
        preview=preview,
        verdict=verdict,
    )

    assert result.exit_code == 0
    assert result.output_truncated is True
    assert len(result.stdout.encode("utf-8")) <= 4096
    assert len(result.stderr.encode("utf-8")) <= 4096


@pytest.mark.asyncio
@pytest.mark.docker
async def test_docker_executor_removes_timed_out_container(tmp_path: Path) -> None:
    if not _docker_available():
        pytest.skip("Docker Desktop Linux engine is unavailable")

    (tmp_path / "test_timeout.py").write_text(
        """
import time
import unittest


class TimeoutTests(unittest.TestCase):
    def test_timeout(self):
        time.sleep(5)
""".lstrip(),
        encoding="utf-8",
    )
    settings = Settings(leash_workspace_root=tmp_path, model_api_key=None)
    scanner = SecretScanner("docker-test-redaction-key")
    proposal = ShellActionProposal(
        kind=ActionKind.SHELL,
        session_id=uuid4(),
        task_id=uuid4(),
        task_text="Run the timeout boundary test",
        workspace_id="docker-fixture",
        params=ShellParams(
            executable="python",
            argv=("-m", "unittest", "test_timeout.py"),
            timeout_seconds=1,
        ),
    )
    preview = PreviewService(tmp_path, scanner).build(proposal)
    verdict = _authorized_verdict(proposal, preview.digest, preview.action_digest)

    result = await _executor(settings, scanner).execute(
        proposal=proposal,
        preview=preview,
        verdict=verdict,
    )

    assert "timed out" in result.summary
    docker = shutil.which("docker")
    assert docker is not None
    inspect = subprocess.run(
        [docker, "container", "inspect", f"leash-{proposal.id.hex}"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=10,
        check=False,
    )
    assert inspect.returncode != 0

from __future__ import annotations

import asyncio
import hashlib
import os
import shutil
import subprocess
import tempfile
import threading
from collections.abc import Mapping
from pathlib import Path, PurePosixPath
from typing import BinaryIO, Protocol, cast

from leash.contracts import (
    ActionProposal,
    ActionState,
    Decision,
    ExecutionResult,
    FileWriteActionProposal,
    ImpactPreview,
    ShellActionProposal,
    Verdict,
)
from leash.digest import sha256_digest
from leash.secrets import SecretScanner


class ExecutionDenied(ValueError):
    pass


class Executor(Protocol):
    async def execute(
        self,
        *,
        proposal: ActionProposal,
        preview: ImpactPreview,
        verdict: Verdict,
    ) -> ExecutionResult: ...


def verify_authorization(
    proposal: ActionProposal,
    preview: ImpactPreview,
    verdict: Verdict,
) -> None:
    if verdict.decision != Decision.ALLOW:
        raise ExecutionDenied("Execution requires an allow verdict")
    if verdict.action_id != proposal.id or preview.action_id != proposal.id:
        raise ExecutionDenied("Action identity does not match the authorization")
    if sha256_digest(proposal) != preview.action_digest:
        raise ExecutionDenied("Proposal content does not match the preview action digest")
    if verdict.action_digest != preview.action_digest:
        raise ExecutionDenied("Action digest does not match the authorization")
    expected_preview_digest = sha256_digest(preview.model_dump(mode="json", exclude={"digest"}))
    if expected_preview_digest != preview.digest:
        raise ExecutionDenied("Preview digest does not match preview content")
    if verdict.preview_digest != preview.digest:
        raise ExecutionDenied("Preview digest does not match the authorization")


class MockExecutor:
    async def execute(
        self,
        *,
        proposal: ActionProposal,
        preview: ImpactPreview,
        verdict: Verdict,
    ) -> ExecutionResult:
        verify_authorization(proposal, preview, verdict)

        return ExecutionResult(
            action_id=proposal.id,
            state=ActionState.EXECUTED,
            executor="mock",
            action_digest=preview.action_digest,
            preview_digest=preview.digest,
            summary="Mock executor validated authorization; no machine capability was invoked.",
        )


class _BoundedCapture:
    def __init__(self, limit: int) -> None:
        self._limit = limit
        self._content = bytearray()
        self.truncated = False

    def drain(self, stream: BinaryIO | None) -> None:
        if stream is None:
            return
        while True:
            chunk = stream.read(8192)
            if not chunk:
                return
            remaining = self._limit - len(self._content)
            if remaining > 0:
                self._content.extend(chunk[:remaining])
            if len(chunk) > remaining:
                self.truncated = True

    def text(self) -> str:
        return self._content.decode("utf-8", errors="replace")


class DockerShellExecutor:
    def __init__(
        self,
        *,
        workspace_root: Path,
        image: str,
        scanner: SecretScanner,
        memory_mb: int,
        cpus: float,
        pids_limit: int,
        output_bytes: int,
    ) -> None:
        self._workspace_root = workspace_root.resolve()
        if "@sha256:" not in image:
            raise ExecutionDenied("Docker executor image must be pinned by SHA-256 digest")
        self._image = image
        self._scanner = scanner
        self._memory_mb = memory_mb
        self._cpus = cpus
        self._pids_limit = pids_limit
        self._output_bytes = output_bytes
        docker = shutil.which("docker")
        if docker is None:
            raise ExecutionDenied("Docker CLI is unavailable")
        self._docker = docker

    async def execute(
        self,
        *,
        proposal: ActionProposal,
        preview: ImpactPreview,
        verdict: Verdict,
    ) -> ExecutionResult:
        verify_authorization(proposal, preview, verdict)
        if not isinstance(proposal, ShellActionProposal):
            raise ExecutionDenied("The Docker executor currently supports shell proposals only")
        if preview.normalized_action.get("executable") != proposal.params.executable.lower():
            raise ExecutionDenied("Normalized executable does not match the typed proposal")
        if preview.normalized_action.get("argv") != list(proposal.params.argv):
            raise ExecutionDenied("Normalized argv does not match the typed proposal")
        command, container_cwd, timeout_seconds = self._validated_command(preview)
        return await asyncio.to_thread(
            self._run,
            proposal,
            preview,
            command,
            container_cwd,
            timeout_seconds,
        )

    def _validated_command(self, preview: ImpactPreview) -> tuple[list[str], str, int]:
        action = preview.normalized_action
        if action.get("kind") != "shell":
            raise ExecutionDenied("Normalized action is not a shell action")
        executable = action.get("executable")
        argv_value = action.get("argv")
        cwd_value = action.get("cwd")
        timeout = action.get("timeout_seconds")
        if not isinstance(executable, str) or executable not in {"python", "python3"}:
            raise ExecutionDenied("Executable is outside the Docker demo profile")
        if not isinstance(argv_value, list):
            raise ExecutionDenied("Normalized argv is invalid")
        argv: list[str] = []
        for item in cast(list[object], argv_value):
            if not isinstance(item, str):
                raise ExecutionDenied("Normalized argv is invalid")
            argv.append(item)
        if not isinstance(cwd_value, str) or not isinstance(timeout, int):
            raise ExecutionDenied("Normalized working directory or timeout is invalid")
        if not self._safe_python_shape(argv):
            raise ExecutionDenied("Python command shape is outside the Docker demo profile")

        cwd = Path(cwd_value).resolve()
        if cwd != self._workspace_root and self._workspace_root not in cwd.parents:
            raise ExecutionDenied("Working directory escapes the executor workspace")
        if not cwd.is_dir():
            raise ExecutionDenied("Working directory does not exist")
        relative = cwd.relative_to(self._workspace_root)
        container_cwd = str(PurePosixPath("/workspace", *relative.parts))
        return [executable, *argv], container_cwd, timeout

    @staticmethod
    def _safe_python_shape(argv: list[str]) -> bool:
        if argv in (["--version"], ["-V"]):
            return True
        if len(argv) >= 2 and argv[:2] == ["-m", "unittest"]:
            return all(
                item not in {"-c", "--locals"}
                and not Path(item).is_absolute()
                and ".." not in Path(item).parts
                for item in argv[2:]
            )
        return False

    def _run(
        self,
        proposal: ShellActionProposal,
        preview: ImpactPreview,
        command: list[str],
        container_cwd: str,
        timeout_seconds: int,
    ) -> ExecutionResult:
        container_name = f"leash-{proposal.id.hex}"
        args = [
            self._docker,
            "run",
            "--rm",
            "--pull",
            "never",
            "--name",
            container_name,
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--pids-limit",
            str(self._pids_limit),
            "--memory",
            f"{self._memory_mb}m",
            "--cpus",
            str(self._cpus),
            "--user",
            "65534:65534",
            "--ipc",
            "none",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,nodev,size=64m",
            "--mount",
            f"type=bind,source={self._workspace_root},target=/workspace,readonly",
            "--workdir",
            container_cwd,
            "--env",
            "HOME=/tmp",
            "--env",
            "PYTHONDONTWRITEBYTECODE=1",
            "--env",
            "PYTHONUNBUFFERED=1",
            self._image,
            *command,
        ]
        stdout_capture = _BoundedCapture(self._output_bytes)
        stderr_capture = _BoundedCapture(self._output_bytes)
        process = subprocess.Popen(
            args,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=self._docker_environment(),
        )
        stdout_thread = threading.Thread(
            target=stdout_capture.drain,
            args=(process.stdout,),
            daemon=True,
        )
        stderr_thread = threading.Thread(
            target=stderr_capture.drain,
            args=(process.stderr,),
            daemon=True,
        )
        stdout_thread.start()
        stderr_thread.start()
        timed_out = False
        try:
            exit_code = process.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            timed_out = True
            self._remove_container(container_name)
            process.kill()
            exit_code = process.wait(timeout=5)
        stdout_thread.join(timeout=5)
        stderr_thread.join(timeout=5)

        stdout, stdout_findings = self._scanner.scan_and_redact(
            stdout_capture.text(), "execution.stdout"
        )
        stderr, stderr_findings = self._scanner.scan_and_redact(
            stderr_capture.text(), "execution.stderr"
        )
        if stdout_findings or stderr_findings:
            stdout = "<REDACTED:execution_output>"
            stderr = "<REDACTED:execution_output>"
        truncated = stdout_capture.truncated or stderr_capture.truncated
        summary = (
            "Docker execution timed out and the container was removed."
            if timed_out
            else f"Docker command completed with exit code {exit_code}."
        )
        return ExecutionResult(
            action_id=proposal.id,
            state=ActionState.EXECUTED,
            executor="docker_shell",
            action_digest=preview.action_digest,
            preview_digest=preview.digest,
            summary=summary,
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            output_truncated=truncated,
        )

    def _remove_container(self, container_name: str) -> None:
        subprocess.run(
            [self._docker, "rm", "--force", container_name],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=self._docker_environment(),
            timeout=10,
            check=False,
        )

    @staticmethod
    def _docker_environment() -> Mapping[str, str]:
        allowed = {
            "SYSTEMROOT",
            "WINDIR",
            "PATH",
            "PATHEXT",
            "TEMP",
            "TMP",
            "DOCKER_HOST",
            "DOCKER_CONTEXT",
            "DOCKER_CONFIG",
        }
        return {key: value for key, value in os.environ.items() if key.upper() in allowed}


class FileWriteExecutor:
    def __init__(self, *, workspace_root: Path) -> None:
        self._workspace_root = workspace_root.resolve()

    async def execute(
        self,
        *,
        proposal: ActionProposal,
        preview: ImpactPreview,
        verdict: Verdict,
    ) -> ExecutionResult:
        verify_authorization(proposal, preview, verdict)
        if not isinstance(proposal, FileWriteActionProposal):
            raise ExecutionDenied("The file executor requires a file-write proposal")
        if preview.protected_resource_hits:
            raise ExecutionDenied("Protected resources cannot be written by the file executor")
        if preview.secret_findings:
            raise ExecutionDenied(
                "Secret-bearing content is outside the file executor demo profile"
            )

        action = preview.normalized_action
        normalized_path = action.get("path")
        normalized_mode = action.get("mode")
        normalized_content_hash = action.get("content_sha256")
        if not all(
            isinstance(value, str)
            for value in (normalized_path, normalized_mode, normalized_content_hash)
        ):
            raise ExecutionDenied("Normalized file-write action is invalid")
        if normalized_mode != proposal.params.mode:
            raise ExecutionDenied("Normalized write mode does not match the typed proposal")
        content = proposal.params.content.encode("utf-8")
        if hashlib.sha256(content).hexdigest() != normalized_content_hash:
            raise ExecutionDenied("File content does not match the normalized content digest")

        unresolved_target = self._workspace_root / proposal.params.path
        if unresolved_target.is_symlink():
            raise ExecutionDenied("Symbolic-link file targets are not writable")
        target = unresolved_target.resolve()
        if target != self._workspace_root and self._workspace_root not in target.parents:
            raise ExecutionDenied("File target escapes the executor workspace")
        if normalized_path != str(target) or preview.resolved_targets != (str(target),):
            raise ExecutionDenied("Resolved file target does not match the authorized preview")
        if not target.parent.is_dir():
            raise ExecutionDenied("File target parent directory does not exist")
        if proposal.params.mode == "create" and target.exists():
            raise ExecutionDenied("Create mode cannot overwrite an existing file")
        if proposal.params.mode == "replace" and not target.is_file():
            raise ExecutionDenied("Replace mode requires an existing regular file")

        await asyncio.to_thread(self._atomic_write, target, content, proposal.params.mode)
        if hashlib.sha256(target.read_bytes()).hexdigest() != normalized_content_hash:
            raise ExecutionDenied("Written file failed post-execution digest verification")
        return ExecutionResult(
            action_id=proposal.id,
            state=ActionState.EXECUTED,
            executor="local_file",
            action_digest=preview.action_digest,
            preview_digest=preview.digest,
            summary=f"Wrote {len(content)} bytes to one authorized workspace file.",
            exit_code=0,
        )

    @staticmethod
    def _atomic_write(target: Path, content: bytes, mode: str) -> None:
        temporary_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="wb",
                dir=target.parent,
                prefix=".leash-",
                suffix=".tmp",
                delete=False,
            ) as temporary:
                temporary_path = Path(temporary.name)
                temporary.write(content)
                temporary.flush()
                os.fsync(temporary.fileno())
            if mode == "create":
                os.link(temporary_path, target)
                temporary_path.unlink()
            else:
                os.replace(temporary_path, target)
            temporary_path = None
        finally:
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)


class CapabilityExecutor:
    def __init__(self, shell: DockerShellExecutor, file_write: FileWriteExecutor) -> None:
        self._shell = shell
        self._file_write = file_write

    async def execute(
        self,
        *,
        proposal: ActionProposal,
        preview: ImpactPreview,
        verdict: Verdict,
    ) -> ExecutionResult:
        if isinstance(proposal, ShellActionProposal):
            return await self._shell.execute(proposal=proposal, preview=preview, verdict=verdict)
        if isinstance(proposal, FileWriteActionProposal):
            return await self._file_write.execute(
                proposal=proposal,
                preview=preview,
                verdict=verdict,
            )
        raise ExecutionDenied("No real executor adapter exists for this action kind")

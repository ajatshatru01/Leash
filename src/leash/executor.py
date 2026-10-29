from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import os
import shutil
import subprocess
import tempfile
import threading
from collections.abc import Mapping
from pathlib import Path, PurePosixPath
from typing import BinaryIO, Protocol, cast
from urllib.parse import urlsplit

import httpx

from leash.contracts import (
    ActionProposal,
    ActionState,
    Decision,
    ExecutionResult,
    FilePatchActionProposal,
    FileWriteActionProposal,
    HttpActionProposal,
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
        if len(argv) >= 2 and argv[:2] == ["-m", "compileall"]:
            return all(
                item in {"-q", "--quiet"}
                or (
                    not item.startswith("-")
                    and not Path(item).is_absolute()
                    and ".." not in Path(item).parts
                )
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

        await asyncio.to_thread(self.atomic_write, target, content, proposal.params.mode)
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
    def atomic_write(target: Path, content: bytes, mode: str) -> None:
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


class FilePatchExecutor:
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
        if not isinstance(proposal, FilePatchActionProposal):
            raise ExecutionDenied("The patch executor requires a file-patch proposal")
        if preview.protected_resource_hits or preview.secret_findings:
            raise ExecutionDenied("Protected or secret-bearing patches cannot execute")

        unresolved = self._workspace_root / proposal.params.path
        if unresolved.is_symlink():
            raise ExecutionDenied("Symbolic-link patch targets are prohibited")
        target = unresolved.resolve()
        if target != self._workspace_root and self._workspace_root not in target.parents:
            raise ExecutionDenied("Patch target escapes the executor workspace")
        if not target.is_file():
            raise ExecutionDenied("Patch target must be an existing regular file")
        if target.stat().st_size > 1_000_000:
            raise ExecutionDenied("Patch target exceeds the executor byte limit")

        action = preview.normalized_action
        normalized_path = action.get("path")
        current_hash = action.get("current_sha256")
        expected_hash = action.get("expected_sha256")
        result_hash = action.get("result_sha256")
        old_hash = action.get("old_text_sha256")
        new_hash = action.get("new_text_sha256")
        replacement_count = action.get("replacement_count")
        result_bytes = action.get("result_bytes")
        string_values = (
            normalized_path,
            current_hash,
            expected_hash,
            result_hash,
            old_hash,
            new_hash,
        )
        if not all(isinstance(value, str) for value in string_values):
            raise ExecutionDenied("Normalized file-patch action is invalid")
        if replacement_count != 1 or not isinstance(result_bytes, int):
            raise ExecutionDenied("Patch preview does not cover one exact replacement")
        if normalized_path != str(target) or preview.resolved_targets != (str(target),):
            raise ExecutionDenied("Resolved patch target does not match the authorization")
        if expected_hash != proposal.params.expected_sha256 or current_hash != expected_hash:
            raise ExecutionDenied("Patch expected hash does not match the authorized preview")
        if hashlib.sha256(proposal.params.old_text.encode("utf-8")).hexdigest() != old_hash:
            raise ExecutionDenied("Patch old text does not match the authorized preview")
        if hashlib.sha256(proposal.params.new_text.encode("utf-8")).hexdigest() != new_hash:
            raise ExecutionDenied("Patch new text does not match the authorized preview")

        raw = target.read_bytes()
        if hashlib.sha256(raw).hexdigest() != expected_hash:
            raise ExecutionDenied("Patch target changed after preview; re-inspection is required")
        try:
            current_text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ExecutionDenied("Patch target is no longer valid UTF-8 text") from exc
        if current_text.count(proposal.params.old_text) != 1:
            raise ExecutionDenied("Patch target text is no longer unique")
        updated = current_text.replace(proposal.params.old_text, proposal.params.new_text, 1)
        content = updated.encode("utf-8")
        if len(content) != result_bytes or hashlib.sha256(content).hexdigest() != result_hash:
            raise ExecutionDenied("Computed patch result does not match the authorized preview")

        await asyncio.to_thread(FileWriteExecutor.atomic_write, target, content, "replace")
        if hashlib.sha256(target.read_bytes()).hexdigest() != result_hash:
            raise ExecutionDenied("Patched file failed post-execution digest verification")
        return ExecutionResult(
            action_id=proposal.id,
            state=ActionState.EXECUTED,
            executor="local_patch",
            action_digest=preview.action_digest,
            preview_digest=preview.digest,
            summary="Applied one hash-bound replacement to one authorized workspace file.",
            exit_code=0,
        )


class HttpExecutor:
    def __init__(
        self,
        *,
        allowed_hosts: tuple[str, ...],
        allowed_ports: tuple[int, ...],
        scanner: SecretScanner,
        timeout_seconds: float,
        request_bytes: int,
        response_bytes: int,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._allowed_hosts = {host.lower() for host in allowed_hosts}
        self._allowed_ports = set(allowed_ports)
        self._scanner = scanner
        self._timeout = timeout_seconds
        self._request_bytes = request_bytes
        self._response_bytes = response_bytes
        self._transport = transport

    async def execute(
        self,
        *,
        proposal: ActionProposal,
        preview: ImpactPreview,
        verdict: Verdict,
    ) -> ExecutionResult:
        verify_authorization(proposal, preview, verdict)
        if not isinstance(proposal, HttpActionProposal):
            raise ExecutionDenied("The HTTP executor requires an HTTP proposal")
        if preview.secret_findings:
            raise ExecutionDenied("Secret-bearing requests cannot reach the HTTP executor")

        action = preview.normalized_action
        method = action.get("method")
        url = action.get("url")
        body = action.get("body")
        raw_headers = action.get("headers")
        if not isinstance(method, str) or not isinstance(url, str) or not isinstance(body, str):
            raise ExecutionDenied("Normalized HTTP action is invalid")
        if not isinstance(raw_headers, dict):
            raise ExecutionDenied("Normalized HTTP headers are invalid")
        headers: dict[str, str] = {}
        for key, value in cast(dict[object, object], raw_headers).items():
            if not isinstance(key, str) or not isinstance(value, str):
                raise ExecutionDenied("Normalized HTTP headers are invalid")
            headers[key] = value

        parsed = urlsplit(url)
        host = (parsed.hostname or "").lower()
        port = parsed.port or (80 if parsed.scheme == "http" else 443)
        if parsed.scheme != "http":
            raise ExecutionDenied("The demo HTTP adapter permits loopback HTTP only")
        if parsed.username is not None or parsed.password is not None:
            raise ExecutionDenied("Credentials in request URLs are prohibited")
        if host not in self._allowed_hosts or port not in self._allowed_ports:
            raise ExecutionDenied("HTTP destination is outside the inspected adapter allowlist")
        if not self._is_loopback(host):
            raise ExecutionDenied("The hackathon HTTP adapter is restricted to loopback")
        if preview.network_destination != host:
            raise ExecutionDenied("Resolved HTTP destination does not match the authorized preview")
        if method != proposal.params.method:
            raise ExecutionDenied("Normalized HTTP method does not match the typed proposal")

        request_size = (
            len(url.encode("utf-8"))
            + len(body.encode("utf-8"))
            + sum(
                len(key.encode("utf-8")) + len(value.encode("utf-8"))
                for key, value in headers.items()
            )
        )
        if request_size > self._request_bytes:
            raise ExecutionDenied("HTTP request exceeds the inspected adapter byte limit")

        output = bytearray()
        truncated = False
        async with (
            httpx.AsyncClient(
                transport=self._transport,
                timeout=self._timeout,
                follow_redirects=False,
                trust_env=False,
            ) as client,
            client.stream(
                method,
                url,
                headers=headers,
                content=body.encode("utf-8"),
            ) as response,
        ):
            async for chunk in response.aiter_bytes():
                remaining = self._response_bytes - len(output)
                if remaining > 0:
                    output.extend(chunk[:remaining])
                if len(chunk) > remaining:
                    truncated = True
                    break
            status_code = response.status_code

        response_text = output.decode("utf-8", errors="replace")
        safe_response, _ = self._scanner.scan_and_redact(response_text, "http.response")
        return ExecutionResult(
            action_id=proposal.id,
            state=ActionState.EXECUTED,
            executor="http",
            action_digest=preview.action_digest,
            preview_digest=preview.digest,
            summary=f"Inspected loopback HTTP request completed with status {status_code}.",
            exit_code=0 if 200 <= status_code < 300 else 1,
            stdout=safe_response,
            output_truncated=truncated,
        )

    @staticmethod
    def _is_loopback(host: str) -> bool:
        if host == "localhost":
            return True
        try:
            return ipaddress.ip_address(host).is_loopback
        except ValueError:
            return False


class CapabilityExecutor:
    def __init__(
        self,
        shell: DockerShellExecutor,
        file_write: FileWriteExecutor,
        file_patch: FilePatchExecutor,
        http: HttpExecutor,
    ) -> None:
        self._shell = shell
        self._file_write = file_write
        self._file_patch = file_patch
        self._http = http

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
        if isinstance(proposal, FilePatchActionProposal):
            return await self._file_patch.execute(
                proposal=proposal,
                preview=preview,
                verdict=verdict,
            )
        if isinstance(proposal, HttpActionProposal):
            return await self._http.execute(
                proposal=proposal,
                preview=preview,
                verdict=verdict,
            )
        raise ExecutionDenied("No real executor adapter exists for this action kind")

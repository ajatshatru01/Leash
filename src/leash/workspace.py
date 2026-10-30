from __future__ import annotations

import hashlib
import os
import subprocess
import threading
from collections import deque
from pathlib import Path
from typing import Any

from leash.contracts import WorkspaceInspectionResult
from leash.secrets import SecretScanner


class WorkspaceInspectionError(ValueError):
    pass


_PROTECTED_PARTS = {
    ".env",
    ".git",
    ".ssh",
    ".aws",
    ".codex",
    ".venv",
    "node_modules",
    "__pycache__",
}


class WorkspaceInspector:
    def __init__(
        self,
        *,
        workspace_root: Path,
        scanner: SecretScanner,
        max_bytes: int,
        max_files: int,
        max_lines: int,
        max_depth: int,
    ) -> None:
        self._root = workspace_root.resolve()
        self._scanner = scanner
        self._max_bytes = max_bytes
        self._max_files = max_files
        self._max_lines = max_lines
        self._max_depth = max_depth

    def inspect(self, tool_name: str, arguments: dict[str, Any]) -> WorkspaceInspectionResult:
        if tool_name == "inspect_file":
            return self._file(arguments)
        if tool_name == "list_workspace":
            return self._list(arguments)
        if tool_name == "search_workspace":
            return self._search(arguments)
        if tool_name == "inspect_git_status":
            return self._git_status()
        raise WorkspaceInspectionError("Unknown workspace inspection tool")

    def _resolve(self, value: object, *, require_exists: bool = True) -> Path:
        if not isinstance(value, str) or not value or len(value) > 1024:
            raise WorkspaceInspectionError("Inspection path must be a non-empty relative string")
        raw = Path(value)
        if raw.is_absolute():
            raise WorkspaceInspectionError("Absolute inspection paths are prohibited")
        if ".." in raw.parts:
            raise WorkspaceInspectionError("Inspection path escapes the configured workspace")
        if _PROTECTED_PARTS.intersection(part.lower() for part in raw.parts):
            raise WorkspaceInspectionError("Protected paths cannot be inspected")
        unresolved = self._root / raw
        cursor = self._root
        for part in raw.parts:
            cursor /= part
            if cursor.is_symlink():
                raise WorkspaceInspectionError("Symbolic links cannot be inspected")
        candidate = unresolved.resolve()
        if candidate != self._root and self._root not in candidate.parents:
            raise WorkspaceInspectionError("Inspection path escapes the configured workspace")
        if require_exists and not candidate.exists():
            raise WorkspaceInspectionError("Inspection target does not exist")
        return candidate

    def _relative(self, path: Path) -> str:
        return path.relative_to(self._root).as_posix() or "."

    def _file(self, arguments: dict[str, Any]) -> WorkspaceInspectionResult:
        target = self._resolve(arguments.get("path"))
        if target.is_symlink() or not target.is_file():
            raise WorkspaceInspectionError("File inspection requires a regular workspace file")
        start_line = arguments.get("start_line", 1)
        requested_lines = arguments.get("max_lines", self._max_lines)
        if not isinstance(start_line, int) or start_line < 1:
            raise WorkspaceInspectionError("start_line must be a positive integer")
        if not isinstance(requested_lines, int) or requested_lines < 1:
            raise WorkspaceInspectionError("max_lines must be a positive integer")
        line_limit = min(requested_lines, self._max_lines)
        file_size = target.stat().st_size
        read_limit = self._max_bytes * 8
        if file_size > read_limit:
            raise WorkspaceInspectionError(
                "File exceeds the bounded inspection limit and cannot receive a patch hash"
            )
        raw = target.read_bytes()
        file_hash = hashlib.sha256(raw).hexdigest()
        decoded = raw.decode("utf-8", errors="replace")
        lines = decoded.splitlines(keepends=True)
        selected = "".join(lines[start_line - 1 : start_line - 1 + line_limit])
        selected_bytes = selected.encode("utf-8")
        truncated = len(selected_bytes) > self._max_bytes or start_line - 1 + line_limit < len(
            lines
        )
        if len(selected_bytes) > self._max_bytes:
            selected = selected_bytes[: self._max_bytes].decode("utf-8", errors="ignore")
        safe_content, findings = self._scanner.scan_and_redact(
            selected,
            f"workspace.file.{self._relative(target)}",
        )
        end_line = min(len(lines), start_line + len(selected.splitlines()) - 1)
        return WorkspaceInspectionResult(
            kind="file",
            summary=f"Read a bounded, redacted view of {self._relative(target)}.",
            payload={
                "path": self._relative(target),
                "sha256": file_hash,
                "file_bytes": len(raw),
                "start_line": start_line,
                "end_line": end_line,
                "content": safe_content,
                "secret_findings": [item.model_dump(mode="json") for item in findings],
            },
            truncated=truncated,
        )

    def _walk(self, base: Path) -> tuple[list[Path], bool]:
        queue: deque[tuple[Path, int]] = deque([(base, 0)])
        files: list[Path] = []
        truncated = False
        while queue:
            directory, depth = queue.popleft()
            try:
                children = sorted(directory.iterdir(), key=lambda item: item.name.lower())
            except OSError as exc:
                raise WorkspaceInspectionError(
                    "Workspace directory could not be inspected"
                ) from exc
            for child in children:
                if child.name.lower() in _PROTECTED_PARTS:
                    continue
                if child.is_symlink():
                    continue
                if child.is_dir():
                    if depth < self._max_depth:
                        queue.append((child, depth + 1))
                    else:
                        truncated = True
                    continue
                if child.is_file():
                    files.append(child)
                    if len(files) >= self._max_files:
                        return files, True
        return files, truncated

    def _list(self, arguments: dict[str, Any]) -> WorkspaceInspectionResult:
        base = self._resolve(arguments.get("path", "."))
        if not base.is_dir():
            raise WorkspaceInspectionError("Workspace listing requires a directory")
        files, truncated = self._walk(base)
        entries = [{"path": self._relative(path), "bytes": path.stat().st_size} for path in files]
        return WorkspaceInspectionResult(
            kind="list",
            summary=f"Listed {len(entries)} bounded workspace file entries.",
            payload={"base": self._relative(base), "files": entries},
            truncated=truncated,
        )

    def _search(self, arguments: dict[str, Any]) -> WorkspaceInspectionResult:
        query = arguments.get("query")
        if not isinstance(query, str) or not query or len(query) > 256:
            raise WorkspaceInspectionError("Search query must contain 1 to 256 characters")
        base = self._resolve(arguments.get("path", "."))
        if not base.is_dir():
            raise WorkspaceInspectionError("Workspace search requires a directory")
        files, walk_truncated = self._walk(base)
        results: list[dict[str, object]] = []
        output_bytes = 0
        scanned_bytes = 0
        scanned_files = 0
        scan_limit = self._max_bytes * 8
        truncated = walk_truncated
        for path in files:
            file_size = path.stat().st_size
            if scanned_bytes + file_size > scan_limit:
                truncated = True
                break
            raw = path.read_bytes()
            scanned_bytes += len(raw)
            scanned_files += 1
            if b"\x00" in raw[:4096]:
                continue
            for line_number, line in enumerate(
                raw.decode("utf-8", errors="replace").splitlines(),
                start=1,
            ):
                if query not in line:
                    continue
                safe_line, findings = self._scanner.scan_and_redact(
                    line[:1000],
                    f"workspace.search.{self._relative(path)}.{line_number}",
                )
                result: dict[str, object] = {
                    "path": self._relative(path),
                    "line": line_number,
                    "excerpt": safe_line,
                    "secret_findings": [item.model_dump(mode="json") for item in findings],
                }
                result_bytes = len(str(result).encode("utf-8"))
                if output_bytes + result_bytes > self._max_bytes or len(results) >= self._max_lines:
                    truncated = True
                    break
                results.append(result)
                output_bytes += result_bytes
            if truncated:
                break
        return WorkspaceInspectionResult(
            kind="search",
            summary=f"Found {len(results)} bounded, redacted literal matches.",
            payload={
                "base": self._relative(base),
                "query": query,
                "matches": results,
                "scanned_files": scanned_files,
                "scanned_bytes": min(scanned_bytes, scan_limit),
            },
            truncated=truncated,
        )

    def _git_status(self) -> WorkspaceInspectionResult:
        environment = {
            key: value
            for key, value in os.environ.items()
            if key.upper() in {"SYSTEMROOT", "WINDIR", "PATH", "PATHEXT", "TEMP", "TMP"}
        }
        try:
            process = subprocess.Popen(
                [
                    "git",
                    "-C",
                    str(self._root),
                    "status",
                    "--porcelain=v1",
                    "--untracked-files=normal",
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=environment,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise WorkspaceInspectionError("Git status inspection is unavailable") from exc
        stdout = bytearray()
        stderr = bytearray()
        truncated = False

        def drain(stream: Any, destination: bytearray) -> None:
            nonlocal truncated
            if stream is None:
                return
            while True:
                chunk = stream.read(8192)
                if not chunk:
                    return
                remaining = self._max_bytes - len(destination)
                if remaining > 0:
                    destination.extend(chunk[:remaining])
                if len(chunk) > remaining:
                    truncated = True

        stdout_thread = threading.Thread(target=drain, args=(process.stdout, stdout), daemon=True)
        stderr_thread = threading.Thread(target=drain, args=(process.stderr, stderr), daemon=True)
        stdout_thread.start()
        stderr_thread.start()
        try:
            return_code = process.wait(timeout=3)
        except subprocess.TimeoutExpired as exc:
            process.kill()
            process.wait(timeout=2)
            raise WorkspaceInspectionError("Git status inspection timed out") from exc
        stdout_thread.join(timeout=2)
        stderr_thread.join(timeout=2)
        raw = stdout.decode("utf-8", errors="replace")
        safe_status, findings = self._scanner.scan_and_redact(raw, "workspace.git_status")
        return WorkspaceInspectionResult(
            kind="git_status",
            summary="Collected a bounded, redacted Git porcelain status.",
            payload={
                "is_repository": return_code == 0,
                "status": safe_status,
                "secret_findings": [item.model_dump(mode="json") for item in findings],
            },
            truncated=truncated,
        )

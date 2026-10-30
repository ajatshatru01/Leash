from __future__ import annotations

import base64
import binascii
import hashlib
import os
import re
import shlex
from collections import deque
from dataclasses import dataclass
from pathlib import Path

_DELETE_EXECUTABLES = {"rm", "del", "erase", "rmdir", "remove-item"}
_INTERPRETERS = {
    "bash",
    "sh",
    "cmd",
    "cmd.exe",
    "powershell",
    "powershell.exe",
    "pwsh",
    "python",
    "python3",
}
_PROTECTED_PARTS = {".env", ".git", ".ssh", ".aws", ".codex"}
_GLOB_MARKERS = {"*", "?", "["}


@dataclass(frozen=True)
class ShellImpact:
    analysis: dict[str, object]
    resolved_targets: tuple[str, ...]
    affected_file_count: int
    affected_bytes: int
    protected_resource_hits: tuple[str, ...]
    uncertainty_flags: tuple[str, ...]
    truncated: bool
    decoded_command: str | None = None


class ShellImpactAnalyzer:
    def __init__(
        self,
        *,
        workspace_root: Path,
        max_targets: int,
        max_bytes: int,
        max_depth: int,
    ) -> None:
        self._root = workspace_root.resolve()
        self._max_targets = max_targets
        self._max_bytes = max_bytes
        self._max_depth = max_depth

    def analyze(self, executable: str, argv: tuple[str, ...], cwd: Path) -> ShellImpact:
        executable_name = Path(executable).name.lower()
        uncertainty: set[str] = set()
        syntax_flags: set[str] = set()
        decoded_command: str | None = None
        decoded_from: str | None = None
        destructive_name: str | None = None
        target_patterns: list[str] = []
        recursive = False

        if executable_name in _INTERPRETERS:
            decoded_command, decoded_from = self._nested_command(executable_name, argv, uncertainty)
            if decoded_command is not None:
                syntax_flags.update(self._syntax_flags(decoded_command))
                (
                    destructive_name,
                    target_patterns,
                    recursive,
                ) = self._destructive_from_command(decoded_command)
        if executable_name in _DELETE_EXECUTABLES:
            destructive_name = executable_name
            target_patterns = self._target_arguments(argv)
            recursive = self._is_recursive(argv)

        if destructive_name is not None and not target_patterns:
            uncertainty.add("destructive_target_unresolved")
        if syntax_flags:
            uncertainty.update(syntax_flags)

        targets: tuple[str, ...] = ()
        affected_count = 0
        affected_bytes = 0
        protected: tuple[str, ...] = ()
        truncated = False
        if destructive_name is not None and target_patterns:
            (
                targets,
                affected_count,
                affected_bytes,
                protected,
                resolution_uncertainty,
                truncated,
            ) = self._resolve_targets(cwd, target_patterns, recursive)
            uncertainty.update(resolution_uncertainty)
        if truncated:
            uncertainty.add("preview_truncated")

        analysis: dict[str, object] = {
            "destructive_operation": destructive_name,
            "recursive": recursive,
            "encoded": decoded_from == "powershell_encoded_command",
            "decoded_from": decoded_from,
            "decoded_command_sha256": (
                hashlib.sha256(decoded_command.encode("utf-8")).hexdigest()
                if decoded_command is not None
                else None
            ),
            "syntax_flags": sorted(syntax_flags),
            "target_patterns": target_patterns,
            "resolved_target_count": len(targets),
        }
        return ShellImpact(
            analysis=analysis,
            resolved_targets=targets,
            affected_file_count=affected_count,
            affected_bytes=affected_bytes,
            protected_resource_hits=protected,
            uncertainty_flags=tuple(sorted(uncertainty)),
            truncated=truncated,
            decoded_command=decoded_command,
        )

    @staticmethod
    def _nested_command(
        executable: str,
        argv: tuple[str, ...],
        uncertainty: set[str],
    ) -> tuple[str | None, str | None]:
        lower = [item.lower() for item in argv]
        encoded_flags = {"-encodedcommand", "-enc", "/encodedcommand"}
        command_flags = {"-c", "-command", "/c"}
        for index, token in enumerate(lower):
            if token in encoded_flags:
                uncertainty.add("nested_interpreter")
                uncertainty.add("encoded_command")
                if index + 1 >= len(argv):
                    uncertainty.add("encoded_command_invalid")
                    return None, "powershell_encoded_command"
                try:
                    raw = base64.b64decode(argv[index + 1], validate=True)
                    try:
                        decoded = raw.decode("utf-16-le")
                    except UnicodeDecodeError:
                        decoded = raw.decode("utf-8")
                except (binascii.Error, UnicodeDecodeError):
                    uncertainty.add("encoded_command_invalid")
                    return None, "powershell_encoded_command"
                if len(decoded.encode("utf-8")) > 16_384:
                    uncertainty.add("encoded_command_oversized")
                    return None, "powershell_encoded_command"
                return decoded, "powershell_encoded_command"
            if token in command_flags:
                uncertainty.add("nested_interpreter")
                if index + 1 >= len(argv):
                    return None, f"{executable}_command"
                return " ".join(argv[index + 1 :]), f"{executable}_command"
        return None, None

    @staticmethod
    def _syntax_flags(command: str) -> set[str]:
        flags: set[str] = set()
        if re.search(r"&&|\|\||;|(?<!\|)\|(?!\|)", command):
            flags.add("command_chain")
        if "$(" in command or "`" in command:
            flags.add("command_substitution")
        if re.search(r"%[^%]+%|\$env:|\$\{?[A-Za-z_]", command, re.IGNORECASE):
            flags.add("environment_expansion")
        return flags

    @staticmethod
    def _destructive_from_command(command: str) -> tuple[str | None, list[str], bool]:
        python_match = re.search(
            r"(?i)\b(?:shutil\.rmtree|os\.remove|os\.unlink|pathlib\.[A-Za-z.]+\.unlink)\s*\(\s*['\"]([^'\"]+)['\"]",
            command,
        )
        if python_match:
            name = "python_delete"
            recursive = "rmtree" in python_match.group(0).lower()
            return name, [python_match.group(1)], recursive
        match = re.search(
            r"(?i)(?:^|[;&|]\s*)\b(remove-item|rm|del|erase|rmdir)\b([^;&|]*)",
            command,
        )
        if match is None:
            return None, [], False
        executable = match.group(1).lower()
        remainder = match.group(2).strip()
        try:
            tokens = shlex.split(remainder, posix=False)
        except ValueError:
            tokens = remainder.split()
        cleaned = tuple(token.strip("'\"") for token in tokens)
        return (
            executable,
            ShellImpactAnalyzer._target_arguments(cleaned),
            ShellImpactAnalyzer._is_recursive(cleaned),
        )

    @staticmethod
    def _is_recursive(argv: tuple[str, ...]) -> bool:
        flags = {item.lower() for item in argv}
        return bool(flags.intersection({"-r", "-rf", "-fr", "--recursive", "/s", "-recurse"}))

    @staticmethod
    def _target_arguments(argv: tuple[str, ...]) -> list[str]:
        values: list[str] = []
        options_ended = False
        for item in argv:
            lower = item.lower()
            if item == "--":
                options_ended = True
                continue
            if not options_ended and (item.startswith("-") or lower in {"/s", "/q"}):
                continue
            values.append(item.strip("'\""))
        return values

    def _resolve_targets(
        self,
        cwd: Path,
        patterns: list[str],
        recursive: bool,
    ) -> tuple[tuple[str, ...], int, int, tuple[str, ...], set[str], bool]:
        resolved: list[str] = []
        protected: set[str] = set()
        uncertainty: set[str] = set()
        affected_count = 0
        affected_bytes = 0
        truncated = False
        candidates: list[Path] = []

        for raw_pattern in patterns:
            pattern = raw_pattern.replace("\\", os.sep)
            path_pattern = Path(pattern)
            if path_pattern.is_absolute() or ".." in path_pattern.parts:
                uncertainty.add("target_escape")
                continue
            if re.search(r"%[^%]+%|\$env:|\$\{?[A-Za-z_]", pattern, re.IGNORECASE):
                uncertainty.add("environment_expansion")
                continue
            if any(marker in pattern for marker in _GLOB_MARKERS):
                parts = Path(pattern).parts
                wildcard_parts = [
                    index
                    for index, part in enumerate(parts)
                    if any(marker in part for marker in _GLOB_MARKERS)
                ]
                if wildcard_parts != [len(parts) - 1]:
                    uncertainty.add("complex_glob_unsupported")
                    continue
                prefix = cwd.joinpath(*parts[:-1]) if parts[:-1] else cwd
                if self._link_escape(prefix, uncertainty):
                    continue
                try:
                    matches = sorted(cwd.glob(pattern), key=lambda item: str(item).lower())
                except (OSError, ValueError):
                    uncertainty.add("glob_resolution_failed")
                    continue
                if not matches:
                    uncertainty.add("glob_no_matches")
                candidates.extend(matches)
            else:
                candidates.append(cwd / path_pattern)

        seen: set[str] = set()
        for candidate in candidates:
            lexical = Path(os.path.abspath(candidate))
            lexical_key = os.path.normcase(str(lexical))
            if lexical_key in seen:
                continue
            seen.add(lexical_key)
            try:
                common = os.path.commonpath((str(self._root), str(lexical)))
            except ValueError:
                uncertainty.add("target_escape")
                continue
            if os.path.normcase(common) != os.path.normcase(str(self._root)):
                uncertainty.add("target_escape")
                continue
            if _PROTECTED_PARTS.intersection(part.lower() for part in lexical.parts):
                protected.add(str(lexical))
            if self._link_escape(lexical, uncertainty):
                resolved.append(str(lexical))
                continue
            if not lexical.exists() and not lexical.is_symlink():
                uncertainty.add("unresolved_target")
                continue
            if self._is_linklike(lexical):
                try:
                    link_target = lexical.resolve(strict=True)
                    common_target = os.path.commonpath((str(self._root), str(link_target)))
                    if os.path.normcase(common_target) != os.path.normcase(str(self._root)):
                        uncertainty.add("link_target_escape")
                except (OSError, ValueError):
                    uncertainty.add("link_target_unresolved")
                affected_count += 1
                resolved.append(str(lexical))
            elif lexical.is_file():
                size = lexical.stat().st_size
                affected_count += 1
                affected_bytes += size
                resolved.append(str(lexical))
            elif lexical.is_dir():
                if recursive:
                    (
                        directory_targets,
                        directory_count,
                        directory_bytes,
                        directory_truncated,
                    ) = self._walk_directory(lexical, protected, uncertainty)
                    resolved.extend(directory_targets)
                    affected_count += directory_count
                    affected_bytes += directory_bytes
                    truncated = truncated or directory_truncated
                    if not directory_targets:
                        resolved.append(str(lexical))
                else:
                    resolved.append(str(lexical))
            if len(resolved) >= self._max_targets or affected_bytes >= self._max_bytes:
                truncated = True
                break

        return (
            tuple(resolved[: self._max_targets]),
            affected_count,
            min(affected_bytes, self._max_bytes),
            tuple(sorted(protected)),
            uncertainty,
            truncated,
        )

    def _walk_directory(
        self,
        root: Path,
        protected: set[str],
        uncertainty: set[str],
    ) -> tuple[list[str], int, int, bool]:
        queue: deque[tuple[Path, int]] = deque([(root, 0)])
        targets: list[str] = []
        count = 0
        total_bytes = 0
        truncated = False
        while queue:
            directory, depth = queue.popleft()
            try:
                children = sorted(directory.iterdir(), key=lambda item: item.name.lower())
            except OSError:
                return targets, count, total_bytes, True
            for child in children:
                if _PROTECTED_PARTS.intersection(part.lower() for part in child.parts):
                    protected.add(str(child))
                if self._is_linklike(child):
                    try:
                        link_target = child.resolve(strict=True)
                        common_target = os.path.commonpath((str(self._root), str(link_target)))
                        if os.path.normcase(common_target) != os.path.normcase(str(self._root)):
                            uncertainty.add("link_target_escape")
                    except (OSError, ValueError):
                        uncertainty.add("link_target_unresolved")
                    targets.append(str(child))
                    count += 1
                elif child.is_dir():
                    if depth < self._max_depth:
                        queue.append((child, depth + 1))
                    else:
                        truncated = True
                elif child.is_file():
                    size = child.stat().st_size
                    targets.append(str(child))
                    count += 1
                    total_bytes += size
                if len(targets) >= self._max_targets or total_bytes >= self._max_bytes:
                    return (
                        targets[: self._max_targets],
                        count,
                        min(total_bytes, self._max_bytes),
                        True,
                    )
        return targets, count, total_bytes, truncated

    @staticmethod
    def _is_linklike(path: Path) -> bool:
        if path.is_symlink():
            return True
        is_junction = getattr(path, "is_junction", None)
        return bool(is_junction()) if callable(is_junction) else False

    def _link_escape(self, path: Path, uncertainty: set[str]) -> bool:
        try:
            relative = path.relative_to(self._root)
        except ValueError:
            uncertainty.add("target_escape")
            return True
        cursor = self._root
        for part in relative.parts:
            cursor /= part
            if not self._is_linklike(cursor):
                continue
            try:
                link_target = cursor.resolve(strict=True)
                common = os.path.commonpath((str(self._root), str(link_target)))
            except (OSError, ValueError):
                uncertainty.add("link_target_unresolved")
                return True
            if os.path.normcase(common) != os.path.normcase(str(self._root)):
                uncertainty.add("link_target_escape")
                return True
        return False

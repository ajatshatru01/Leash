from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

_EXCLUDED_DIRECTORIES = {
    ".git",
    ".venv",
    ".tools",
    ".cache",
    "__pycache__",
    "node_modules",
}
_MAX_SCAN_BYTES = 10_000_000


@dataclass(frozen=True)
class SecretAuditResult:
    scanned_files: int
    skipped_files: int
    leak_paths: tuple[Path, ...]


def _is_secret_file(path: Path) -> bool:
    return path.name == ".env" or (path.name.startswith(".env.") and path.name != ".env.example")


def audit_exact_secret(root: Path, secret: str) -> SecretAuditResult:
    if not secret:
        raise ValueError("Secret audit requires a non-empty secret")

    resolved_root = root.resolve()
    needle = secret.encode("utf-8")
    leaks: list[Path] = []
    scanned = 0
    skipped = 0

    for path in resolved_root.rglob("*"):
        relative = path.relative_to(resolved_root)
        if any(part in _EXCLUDED_DIRECTORIES for part in relative.parts):
            continue
        if not path.is_file() or path.is_symlink() or _is_secret_file(path):
            continue
        try:
            if path.stat().st_size > _MAX_SCAN_BYTES:
                skipped += 1
                continue
            content = path.read_bytes()
        except OSError:
            skipped += 1
            continue
        scanned += 1
        if needle in content:
            leaks.append(relative)

    return SecretAuditResult(
        scanned_files=scanned,
        skipped_files=skipped,
        leak_paths=tuple(sorted(leaks)),
    )

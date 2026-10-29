from __future__ import annotations

from pathlib import Path

import pytest

from leash.secrets import SecretScanner
from leash.workspace import WorkspaceInspectionError, WorkspaceInspector


def _inspector(root: Path, *, max_bytes: int = 4096, max_files: int = 20) -> WorkspaceInspector:
    return WorkspaceInspector(
        workspace_root=root,
        scanner=SecretScanner("workspace-test-key"),
        max_bytes=max_bytes,
        max_files=max_files,
        max_lines=20,
        max_depth=3,
    )


def test_file_inspection_returns_hash_and_redacts_secret(tmp_path: Path) -> None:
    secret = "ghp_" + ("R" * 36)
    target = tmp_path / "app.py"
    target.write_text(f"print('safe')\nTOKEN = '{secret}'\n", encoding="utf-8")

    result = _inspector(tmp_path).inspect("inspect_file", {"path": "app.py"})

    assert result.kind == "file"
    assert result.payload["sha256"]
    assert secret not in result.model_dump_json()
    assert "REDACTED:github_token" in str(result.payload["content"])


def test_inspection_rejects_traversal_and_protected_paths(tmp_path: Path) -> None:
    inspector = _inspector(tmp_path)
    (tmp_path / ".env").write_text("SAFE_FIXTURE=1", encoding="utf-8")

    with pytest.raises(WorkspaceInspectionError, match="escapes"):
        inspector.inspect("inspect_file", {"path": "../outside.txt"})
    with pytest.raises(WorkspaceInspectionError, match="Protected"):
        inspector.inspect("inspect_file", {"path": ".env"})


def test_inspection_rejects_symbolic_links(tmp_path: Path) -> None:
    target = tmp_path / "target.txt"
    target.write_text("safe", encoding="utf-8")
    link = tmp_path / "link.txt"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("Symbolic links are unavailable in this Windows test environment")

    with pytest.raises(WorkspaceInspectionError, match="Symbolic links"):
        _inspector(tmp_path).inspect("inspect_file", {"path": "link.txt"})


def test_listing_and_search_are_bounded_and_skip_protected_files(tmp_path: Path) -> None:
    for index in range(5):
        (tmp_path / f"module_{index}.py").write_text(
            f"needle = {index}\n",
            encoding="utf-8",
        )
    (tmp_path / ".env").write_text("needle=secret", encoding="utf-8")
    inspector = _inspector(tmp_path, max_files=3)

    listing = inspector.inspect("list_workspace", {"path": "."})
    search = inspector.inspect("search_workspace", {"path": ".", "query": "needle"})

    assert listing.truncated is True
    assert len(listing.payload["files"]) == 3
    assert ".env" not in listing.model_dump_json()
    assert search.truncated is True
    assert len(search.payload["matches"]) <= 3
    assert ".env" not in search.model_dump_json()


def test_file_inspection_marks_partial_views_truncated(tmp_path: Path) -> None:
    (tmp_path / "long.txt").write_text(
        "".join(f"line {index}\n" for index in range(100)),
        encoding="utf-8",
    )

    result = _inspector(tmp_path, max_bytes=1024).inspect(
        "inspect_file",
        {"path": "long.txt", "max_lines": 2},
    )

    assert result.truncated is True
    assert result.payload["end_line"] == 2


def test_oversized_file_is_rejected_before_reading_for_patch_hash(tmp_path: Path) -> None:
    (tmp_path / "oversized.txt").write_bytes(b"x" * 9000)

    with pytest.raises(WorkspaceInspectionError, match="bounded inspection limit"):
        _inspector(tmp_path, max_bytes=1024).inspect(
            "inspect_file",
            {"path": "oversized.txt"},
        )

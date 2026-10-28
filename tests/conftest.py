from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import SecretStr

from leash.settings import Settings


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(
        leash_env="test",
        leash_database_path=tmp_path / "audit.sqlite3",
        leash_workspace_root=tmp_path / "workspace",
        leash_actor_mode="recorded",
        leash_judge_mode="recorded",
        leash_executor_mode="mock",
        leash_redaction_key=SecretStr("test-redaction-key"),
        leash_allowed_http_hosts=("localhost", "127.0.0.1"),
        model_api_key=None,
    )

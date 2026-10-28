from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    leash_env: Literal["development", "test", "production"] = "development"
    leash_host: str = "127.0.0.1"
    leash_port: int = Field(default=8765, ge=1, le=65535)
    leash_log_level: str = "INFO"
    leash_database_path: Path = Path("data/leash.sqlite3")
    leash_workspace_root: Path = Path("demo/workspace")
    leash_judge_mode: Literal["managed", "recorded", "unavailable"] = "recorded"
    leash_judge_timeout_seconds: float = Field(default=20.0, gt=0, le=120)
    leash_approval_ttl_seconds: int = Field(default=300, ge=10, le=3600)
    leash_redaction_key: SecretStr = SecretStr("development-only-change-me")
    leash_allowed_http_hosts: Annotated[tuple[str, ...], NoDecode] = (
        "localhost",
        "127.0.0.1",
    )

    model_api_key: SecretStr | None = None
    spark_base_url: str = "https://api.meta.ai/v1"
    spark_model: str = "muse-spark-1.3"
    judge_base_url: str = "https://api.meta.ai/v1"
    judge_model: str = "muse-wonder-1.0"

    @field_validator("leash_allowed_http_hosts", mode="before")
    @classmethod
    def split_hosts(cls, value: object) -> object:
        if isinstance(value, str):
            return tuple(item.strip().lower() for item in value.split(",") if item.strip())
        return value

    @property
    def model_api_key_configured(self) -> bool:
        return bool(self.model_api_key and self.model_api_key.get_secret_value().strip())


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()

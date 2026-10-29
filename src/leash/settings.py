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
    leash_actor_mode: Literal["managed", "recorded", "unavailable"] = "recorded"
    leash_agent_max_steps: int = Field(default=8, ge=1, le=32)
    leash_agent_token_budget: int = Field(default=32_000, ge=1024, le=2_000_000)
    leash_agent_recent_receipts: int = Field(default=4, ge=1, le=16)
    leash_agent_receipt_bytes: int = Field(default=4096, ge=512, le=65_536)
    leash_spark_reasoning_effort: Literal["low", "medium", "high"] = "low"
    leash_spark_max_completion_tokens: int = Field(default=4096, ge=256, le=32_768)
    leash_spark_input_cost_per_million_usd: float | None = Field(default=None, ge=0)
    leash_spark_output_cost_per_million_usd: float | None = Field(default=None, ge=0)
    leash_judge_mode: Literal["managed", "recorded", "unavailable"] = "recorded"
    leash_judge_timeout_seconds: float = Field(default=20.0, gt=0, le=120)
    leash_judge_max_calls_per_session: int = Field(default=4, ge=0, le=32)
    leash_judge_prompt_version: str = Field(
        default="wonder-safety-v1", min_length=1, max_length=128
    )
    leash_policy_version: str = Field(default="demo-policy-v1", min_length=1, max_length=128)
    leash_wonder_input_cost_per_million_usd: float | None = Field(default=None, ge=0)
    leash_wonder_output_cost_per_million_usd: float | None = Field(default=None, ge=0)
    leash_approval_ttl_seconds: int = Field(default=300, ge=10, le=3600)
    leash_executor_mode: Literal["mock", "docker"] = "mock"
    leash_executor_image: str = (
        "python:3.12-slim-bookworm@"
        "sha256:e697c81897302a4c4333bade000d98038fbb21eb064f8ee1fd42d02ebcd9d337"
    )
    leash_executor_memory_mb: int = Field(default=256, ge=128, le=2048)
    leash_executor_cpus: float = Field(default=1.0, gt=0, le=4)
    leash_executor_pids_limit: int = Field(default=64, ge=16, le=256)
    leash_executor_output_bytes: int = Field(default=65_536, ge=4096, le=1_000_000)
    leash_redaction_key: SecretStr = SecretStr("development-only-change-me")
    leash_allowed_http_hosts: Annotated[tuple[str, ...], NoDecode] = (
        "localhost",
        "127.0.0.1",
    )
    leash_allowed_http_ports: Annotated[tuple[int, ...], NoDecode] = (8877,)
    leash_http_timeout_seconds: float = Field(default=5.0, gt=0, le=30)
    leash_http_request_bytes: int = Field(default=65_536, ge=1024, le=1_000_000)
    leash_http_response_bytes: int = Field(default=65_536, ge=1024, le=1_000_000)
    leash_capture_host: str = "127.0.0.1"
    leash_capture_port: int = Field(default=8877, ge=1024, le=65_535)
    leash_capture_request_bytes: int = Field(default=65_536, ge=1024, le=1_000_000)

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

    @field_validator("leash_allowed_http_ports", mode="before")
    @classmethod
    def split_ports(cls, value: object) -> object:
        if isinstance(value, str):
            return tuple(int(item.strip()) for item in value.split(",") if item.strip())
        return value

    @property
    def model_api_key_configured(self) -> bool:
        return bool(self.model_api_key and self.model_api_key.get_secret_value().strip())


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="NETLENS_", env_file=".env", extra="ignore")

    api_key: SecretStr = SecretStr("change-me-local-only")
    database_url: str = "sqlite:///./data/netlens.db"
    redis_url: str = "redis://localhost:6379/0"
    storage_dir: Path = Path("data/captures")
    queue_mode: Literal["rq", "inline"] = "rq"
    max_upload_bytes: int = Field(20 * 1024 * 1024, ge=24, le=1024 * 1024 * 1024)
    max_packets: int = Field(100_000, ge=1, le=1_000_000)
    max_parse_seconds: float = Field(30, gt=0, le=300)
    max_record_bytes: int = Field(262_144, ge=64, le=1024 * 1024)
    dns_slow_ms: float = Field(250, gt=0)
    job_timeout_seconds: int = Field(180, ge=10)
    stale_seconds: int = Field(600, ge=10)
    max_job_attempts: int = Field(3, ge=1, le=5)
    retention_days: int = Field(7, ge=1)
    provider_timeout_seconds: float = Field(30, gt=0, le=120)
    provider_retries: int = Field(2, ge=0, le=3)
    output_tokens: int = Field(1800, ge=256, le=8192)
    fallback_provider: Literal["mock", "openai", "anthropic", "ollama"] | None = None
    openai_api_key: SecretStr | None = None
    openai_model: str = "gpt-4.1-mini"
    anthropic_api_key: SecretStr | None = None
    anthropic_model: str = "claude-sonnet-4-6"
    ollama_url: str = "http://localhost:11434"
    ollama_model: str = "llama3.2"


@lru_cache
def get_settings() -> Settings:
    return Settings()

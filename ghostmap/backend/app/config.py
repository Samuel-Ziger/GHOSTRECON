"""Configuracao via env. Pydantic Settings v2."""
from __future__ import annotations

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="", extra="ignore")

    # core
    env: str = Field(default="dev", alias="GHOSTMAP_ENV")
    secret: str = Field(default="change-me", alias="GHOSTMAP_SECRET")
    role: str = Field(default="api", alias="GHOSTMAP_ROLE")  # "api" | "worker"

    # databases
    postgres_dsn: str = Field(
        default="postgresql+asyncpg://ghostmap:ghostmap@postgres:5432/ghostmap",
        alias="POSTGRES_DSN",
    )
    neo4j_uri: str = Field(default="bolt://neo4j:7687", alias="NEO4J_URI")
    neo4j_user: str = Field(default="neo4j", alias="NEO4J_USER")
    neo4j_password: str = Field(default="ghostmap_neo4j", alias="NEO4J_PASSWORD")
    redis_url: str = Field(default="redis://redis:6379/0", alias="REDIS_URL")

    # AI
    anthropic_api_key: str = Field(default="", alias="ANTHROPIC_API_KEY")
    gemini_api_key: str = Field(default="", alias="GEMINI_API_KEY")
    openrouter_api_key: str = Field(default="", alias="OPENROUTER_API_KEY")
    ollama_base_url: str = Field(default="http://host.docker.internal:11434", alias="OLLAMA_BASE_URL")

    # CORS
    cors_origins: list[str] = Field(default_factory=lambda: ["http://localhost:3000"])


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]

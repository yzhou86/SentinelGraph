from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration read from environment variables or a .env file."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    starrocks_host: str = "localhost"
    starrocks_port: int = 9030
    starrocks_user: str = "root"
    starrocks_password: str = ""
    starrocks_database: str = "security_lakehouse"
    starrocks_connect_timeout_seconds: int = Field(default=5, ge=1, le=60)
    starrocks_ssl_enabled: bool = False
    starrocks_ssl_ca: Path | None = None
    starrocks_ssl_verify: bool = True
    rules_path: Path = Path("rules/default.yaml")
    vector_search_enabled: bool = True
    vector_dimension: int = Field(default=64, ge=8, le=4096)
    graph_max_depth: int = Field(default=2, ge=1, le=3)
    demo_enabled: bool = False
    llm_enabled: bool = False
    llm_api_base: str = "https://api.openai.com/v1"
    llm_api_key: str = ""
    llm_model: str = ""
    llm_timeout_seconds: int = Field(default=45, ge=1, le=300)
    integration_api_keys: str = ""
    app_name: str = "SentinelGraph"

    @property
    def integration_api_key_set(self) -> frozenset[str]:
        """Configured third-party keys, intentionally never returned by the API."""
        return frozenset(key.strip() for key in self.integration_api_keys.split(",") if key.strip())


@lru_cache
def get_settings() -> Settings:
    return Settings()

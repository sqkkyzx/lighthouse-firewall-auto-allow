from __future__ import annotations

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_secret_key: str = Field(default="dev-change-me")
    public_base_url: str = Field(default="http://127.0.0.1:8000")
    database_url: str = Field(default="sqlite:///data/app.db")
    display_timezone: str = Field(default="Asia/Shanghai")
    script_base_url: str = Field(default="")

    oidc_issuer: str = Field(default="")
    oidc_client_id: str = Field(default="")
    oidc_client_secret: str = Field(default="")
    oidc_scope: str = Field(default="openid profile email")
    admin_emails: str = Field(default="")

    tencentcloud_secret_id: str = Field(default="")
    tencentcloud_secret_key: str = Field(default="")

    @property
    def oidc_enabled(self) -> bool:
        return bool(self.oidc_issuer and self.oidc_client_id and self.oidc_client_secret)

    @property
    def admin_email_set(self) -> set[str]:
        return {item.strip().lower() for item in self.admin_emails.split(",") if item.strip()}

    @property
    def oidc_discovery_url(self) -> str:
        return f"{self.oidc_issuer.rstrip('/')}/.well-known/openid-configuration"


@lru_cache
def get_settings() -> Settings:
    return Settings()

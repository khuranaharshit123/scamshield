"""Runtime configuration (env vars, see deploy/.env.example)."""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Annotated

from pydantic import field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

BACKEND_DIR = Path(__file__).resolve().parents[2]
REPO_DIR = BACKEND_DIR.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_env: str = "development"
    api_key: str = "dev-api-key"
    jwt_secret: str = "dev-jwt-secret"
    admin_password: str = "change-me"

    database_url: str = "sqlite+aiosqlite:///./scamshield-dev.db"
    redis_url: str = "redis://localhost:6379/0"

    # Where the shared rule files (rules.yaml, brands.yaml) and server data live
    shared_dir: Path = REPO_DIR / "shared"
    data_dir: Path = BACKEND_DIR / "data"
    screenshot_dir: Path = Path("./var/screens")
    report_dir: Path = Path("./var/reports")
    public_base_url: str = "http://localhost:8000"

    # Deep analysis
    deep_scan_enabled: bool = True
    sandbox_enabled: bool = False
    sandbox_url: str = "http://sandbox:8100"
    sandbox_timeout_s: float = 30.0
    http_timeout_s: float = 6.0
    max_urls_per_message: int = 5
    url_cache_hours: int = 24

    # Reporting
    reports_enabled: bool = False          # auto-reporting disabled; user reports manually
    report_mode: str = "demo"             # demo | live
    demo_recipients: Annotated[list[str], NoDecode] = []
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_starttls: bool = True
    mail_from: str = "ScamShield Reports <reports@example.com>"
    mail_reply_to: str = ""

    # Threat feeds
    abusech_auth_key: str = ""
    google_safebrowsing_key: str = ""
    openphish_url: str = "https://openphish.com/feed.txt"
    phishing_db_domains_url: str = (
        "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt"
    )
    phishing_db_links_url: str = (
        "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-ACTIVE.txt"
    )
    urlhaus_recent_url: str = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
    blocklist_max_domains: int = 50_000

    # Privacy
    fernet_key: str = ""                  # required in production; dev generates an ephemeral one

    @field_validator("demo_recipients", mode="before")
    @classmethod
    def _split_csv(cls, v):  # "a@x.in,b@y.in" -> list
        if isinstance(v, str):
            return [x.strip() for x in v.split(",") if x.strip()]
        return v

    @field_validator("report_mode")
    @classmethod
    def _mode(cls, v: str) -> str:
        v = v.lower().strip()
        if v not in {"demo", "live"}:
            raise ValueError("REPORT_MODE must be 'demo' or 'live'")
        return v

    @property
    def is_production(self) -> bool:
        return self.app_env.lower() == "production"


@lru_cache
def get_settings() -> Settings:
    return Settings()

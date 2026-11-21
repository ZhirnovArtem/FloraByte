"""Application configuration. Secrets via env / credentials store, never hardcoded."""

from __future__ import annotations

import os
import tempfile
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

_DEFAULT_TMP = Path(tempfile.gettempdir()) if os.name == "nt" else Path("/tmp")
_BACKEND_DIR = Path(__file__).resolve().parents[1]
_BACKEND_ENV = _BACKEND_DIR / ".env"
_REPO_ROOT = Path(__file__).resolve().parents[2]
_DEFAULT_LOG_DIR = (_REPO_ROOT / "logs") if (_REPO_ROOT / "backend").is_dir() else Path("logs")
_DEFAULT_USERS_FILE = _BACKEND_DIR / "data" / "users.json"
_DEFAULT_ACCOUNTS_DB = _BACKEND_DIR / "database.db"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=(".env", str(_BACKEND_ENV)),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # App
    app_name: str = "AI Security Workflow"
    debug: bool = False
    database_url: str = "sqlite:///./ai_security_workflow.db"
    runs_dir: Path = _DEFAULT_TMP / ("florabyte_runs" if os.name == "nt" else "runs")
    upload_dir: Path = _DEFAULT_TMP / ("florabyte_uploads" if os.name == "nt" else "uploads")
    log_dir: Path = Field(default=_DEFAULT_LOG_DIR, validation_alias="LOG_DIR")
    log_file_name: str = Field(default="florabyte.log", validation_alias="LOG_FILE_NAME")
    error_log_file_name: str = Field(default="errors.log", validation_alias="ERROR_LOG_FILE_NAME")
    log_max_bytes: int = Field(default=5 * 1024 * 1024, validation_alias="LOG_MAX_BYTES")
    log_backup_count: int = Field(default=5, validation_alias="LOG_BACKUP_COUNT")
    node_timeout_sec: int = 120
    use_stub_scanners: bool = Field(default=False, validation_alias="USE_STUB_SCANNERS")

    # Git allowlist (comma-separated full HTTPS URLs)
    git_clone_allowlist: str = "https://github.com/TBagirov/training"

    # LLM (OpenAI-compatible; works with Gemini OpenAI endpoint, Ollama, vLLM, etc.)
    llm_base_url: str = "https://generativelanguage.googleapis.com/v1beta/openai/"
    llm_model: str = "gemini-2.0-flash"
    llm_provider: str = "gemini"  # gemini | openai_compatible
    llm_api_key: str = ""  # set via env LLM_API_KEY or credentials
    llm_timeout_sec: int = 60

    # Vulnerability DB path (can be overridden per-node / replaced at final)
    vuln_db_path: Path = Path("vulnerability-database/vulnerabilities.json")

    # Crypto & Auth
    app_secret_key: str = Field(default="", validation_alias="APP_SECRET_KEY")
    auth_users_file: Path = Field(default=_DEFAULT_USERS_FILE, validation_alias="AUTH_USERS_FILE")
    auth_sql_db_path: Path = Field(default=_DEFAULT_ACCOUNTS_DB, validation_alias="AUTH_SQL_DB_PATH")
    workflow_access_token: str = ""  # optional server-to-server integration token (never sent to browser)
    auth_required: bool = Field(default=True, validation_alias="AUTH_REQUIRED")
    session_ttl_days: int = Field(default=14, validation_alias="SESSION_TTL_DAYS")
    cookie_secure: str = Field(default="auto", validation_alias="COOKIE_SECURE")  # auto | true | false

    # CORS (comma-separated origins)
    cors_allow_origins: str = Field(
        default="http://localhost:5173,http://127.0.0.1:5173",
        validation_alias="CORS_ALLOW_ORIGINS",
    )

    def cors_origins_list(self) -> list[str]:
        return [o.strip() for o in self.cors_allow_origins.split(",") if o.strip()]

    # Telegram (prefer credentials store; env for quick demo only)
    telegram_bot_token: str = Field(default="", validation_alias="TELEGRAM_BOT_TOKEN")
    telegram_chat_id: str = Field(default="", validation_alias="TELEGRAM_CHAT_ID")
    webhook_host_allowlist: str = ""  # comma-separated names; explicit local targets for development only

    def git_allowlist_set(self) -> set[str]:
        return {u.strip().rstrip("/") for u in self.git_clone_allowlist.split(",") if u.strip()}

    def ensure_dirs(self) -> None:
        self.runs_dir.mkdir(parents=True, exist_ok=True)
        self.upload_dir.mkdir(parents=True, exist_ok=True)


@lru_cache
def get_settings() -> Settings:
    s = Settings()
    s.ensure_dirs()
    return s

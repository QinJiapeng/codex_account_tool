from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv


ROOT = Path(__file__).resolve().parent.parent
MAX_WORKER_COUNT = 1000
load_dotenv(ROOT / ".env")


def _int(name: str, default: int, minimum: int = 0) -> int:
    try:
        return max(minimum, int(os.getenv(name, str(default))))
    except (TypeError, ValueError):
        return default


@dataclass(slots=True)
class Settings:
    host: str
    port: int
    data_dir: Path
    worker_count: int
    use_proxy_default: bool
    proxy_lease_seconds: int
    proxy_cooldown_seconds: int
    outlook_imap_host: str
    outlook_imap_port: int
    otp_poll_seconds: int
    otp_timeout_seconds: int
    quota_timeout_ms: int
    usage_url: str
    usage_version: str
    auto_upload_cpa: bool = True
    auto_upload_sub2api: bool = False
    force_upload: bool = False
    scheduled_liveness_enabled: bool = True
    scheduled_liveness_interval_minutes: int = 5
    cpa_api_url: str = ""
    cpa_management_key: str = ""
    cpa_api_timeout_seconds: int = 30
    sub2api_api_url: str = ""
    sub2api_admin_api_key: str = ""
    sub2api_api_timeout_seconds: int = 30
    sub2api_group_id: int = 0

    @classmethod
    def from_env(cls) -> "Settings":
        # Never enable request traces in the standalone tool by default.
        # They can contain cookies or authorization headers when debugging;
        # operators must opt in explicitly and keep the output off Git.
        os.environ.setdefault("AUTH_HTTP_TRACE", "0")
        os.environ.setdefault("AUTH_TRACE_DUMP", "0")
        raw_dir = Path(os.getenv("DATA_DIR", "./data"))
        data_dir = raw_dir if raw_dir.is_absolute() else (ROOT / raw_dir).resolve()
        return cls(
            host=os.getenv("APP_HOST", "127.0.0.1").strip() or "127.0.0.1",
            port=_int("APP_PORT", 10717, 1),
            data_dir=data_dir,
            worker_count=min(MAX_WORKER_COUNT, _int("REAUTH_WORKERS", 20, 1)),
            use_proxy_default=os.getenv("USE_PROXY_DEFAULT", "true").strip().lower() in {"1", "true", "yes", "on"},
            proxy_lease_seconds=_int("PROXY_LEASE_SECONDS", 1200, 60),
            proxy_cooldown_seconds=_int("PROXY_COOLDOWN_SECONDS", 60, 5),
            outlook_imap_host=os.getenv("OUTLOOK_IMAP_HOST", "outlook.office365.com").strip() or "outlook.office365.com",
            outlook_imap_port=_int("OUTLOOK_IMAP_PORT", 993, 1),
            otp_poll_seconds=_int("OTP_POLL_SECONDS", 5, 2),
            otp_timeout_seconds=_int("OTP_TIMEOUT_SECONDS", 180, 30),
            quota_timeout_ms=_int("CODEX_USAGE_TIMEOUT_MS", 15000, 1000),
            usage_url=os.getenv("CODEX_USAGE_URL", "https://chatgpt.com/backend-api/wham/usage").strip(),
            usage_version=os.getenv("CODEX_USAGE_VERSION", "0.144.1").strip() or "0.144.1",
            auto_upload_cpa=os.getenv("AUTO_UPLOAD_CPA", "true").strip().lower() in {"1", "true", "yes", "on"},
            auto_upload_sub2api=os.getenv("AUTO_UPLOAD_SUB2API", "false").strip().lower() in {"1", "true", "yes", "on"},
            force_upload=os.getenv("FORCE_UPLOAD", "false").strip().lower() in {"1", "true", "yes", "on"},
            scheduled_liveness_enabled=os.getenv("SCHEDULED_LIVENESS_ENABLED", "true").strip().lower() in {"1", "true", "yes", "on"},
            scheduled_liveness_interval_minutes=min(10_080, _int("SCHEDULED_LIVENESS_INTERVAL_MINUTES", 5, 5)),
            cpa_api_url=os.getenv("CLI_PROXY_API_URL", "").strip(),
            cpa_management_key=str(
                os.getenv("CLI_PROXY_MANAGEMENT_KEY")
                or os.getenv("CLI_PROXY_API_TOKEN")
                or os.getenv("CLI_PROXY_MANAGEMENT_TOKEN")
                or ""
            ).strip(),
            cpa_api_timeout_seconds=_int("CLI_PROXY_API_TIMEOUT_SECONDS", 30, 1),
            sub2api_api_url=os.getenv("SUB2API_API_URL", "").strip(),
            sub2api_admin_api_key=str(
                os.getenv("SUB2API_ADMIN_API_KEY") or os.getenv("SUB2API_API_KEY") or ""
            ).strip(),
            sub2api_api_timeout_seconds=_int("SUB2API_API_TIMEOUT_SECONDS", 30, 1),
            sub2api_group_id=_int("SUB2API_GROUP_ID", 0, 0),
        )

    @property
    def db_path(self) -> Path:
        return self.data_dir / "account_tool.db"

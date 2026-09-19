from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pytest

from app.config import Settings
from app.db import Database, Repository
from app.service import ScheduledLivenessService, liveness_failure_is_terminal


def scheduler_settings(tmp_path: Path) -> Settings:
    return Settings(
        host="127.0.0.1",
        port=10717,
        data_dir=tmp_path,
        worker_count=3,
        use_proxy_default=True,
        proxy_lease_seconds=60,
        proxy_cooldown_seconds=5,
        outlook_imap_host="outlook.example",
        outlook_imap_port=993,
        otp_poll_seconds=2,
        otp_timeout_seconds=30,
        quota_timeout_ms=1000,
        usage_url="https://usage.example",
        usage_version="test",
        scheduled_liveness_enabled=True,
        scheduled_liveness_interval_minutes=60,
    )


def test_liveness_only_treats_explicit_token_failures_as_terminal():
    assert liveness_failure_is_terminal({"success": False, "http_status": 401}) is True
    assert liveness_failure_is_terminal({"success": False, "status": "invalid", "error_code": "TOKEN_EXPIRED"}) is True
    assert liveness_failure_is_terminal({"success": False, "error_code": "CREDENTIAL_INVALID"}) is True
    assert liveness_failure_is_terminal({"success": False, "status": "forbidden", "http_status": 403}) is False
    assert liveness_failure_is_terminal({"success": False, "status": "rate_limited", "http_status": 429}) is False
    assert liveness_failure_is_terminal({"success": False, "status": "network_error", "http_status": 0}) is False


@dataclass
class FakeLease:
    url: str = "socks5://127.0.0.1:1080"


class FakeProxyPool:
    def __init__(self) -> None:
        self.claimed: list[str] = []
        self.completed: list[tuple[bool, str]] = []

    def claim(self, owner: str) -> FakeLease:
        self.claimed.append(owner)
        return FakeLease()

    def complete(self, _lease: FakeLease, *, success: bool, error: str = "") -> None:
        self.completed.append((success, error))


class FakeReauthService:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    async def queue_accounts(
        self,
        account_ids: list[str],
        *,
        use_proxy: bool,
        event_message: str = "",
    ) -> dict[str, int]:
        self.calls.append({
            "account_ids": account_ids,
            "use_proxy": use_proxy,
            "event_message": event_message,
        })
        return {"queued": len(account_ids), "duplicate": 0, "skipped": 0}


class FakeUsageClient:
    def __init__(self, results: dict[str, dict[str, object]]) -> None:
        self.results = results

    async def query(self, row: dict[str, object], *, proxy_url: str | None = None) -> dict[str, object]:
        assert proxy_url == "socks5://127.0.0.1:1080"
        return dict(self.results[str(row["email"])])


class FakeTokenValidator:
    def __init__(self, results: dict[str, dict[str, object]]) -> None:
        self.results = results

    async def validate(self, row: dict[str, object], *, proxy_url: str | None = None) -> dict[str, object]:
        assert proxy_url == "socks5://127.0.0.1:1080"
        return dict(self.results[str(row["email"])])


@pytest.mark.asyncio
async def test_scheduled_liveness_queues_only_invalid_tokens_without_overwriting_quota(tmp_path: Path):
    database = Database(tmp_path / "scheduler.db")
    database.initialize()
    repository = Repository(database)
    results = {
        "valid@example.com": {"success": True, "status": "success", "http_status": 200},
        "unauthorized@example.com": {"success": False, "status": "unauthorized", "http_status": 401, "error_code": "TOKEN_UNAUTHORIZED"},
        "expired@example.com": {"success": False, "status": "invalid", "http_status": 0, "error_code": "TOKEN_EXPIRED"},
        "forbidden@example.com": {"success": False, "status": "forbidden", "http_status": 403, "error_code": "CODEX_USAGE_FORBIDDEN"},
        "limited@example.com": {"success": False, "status": "rate_limited", "http_status": 429, "error_code": "CODEX_USAGE_RATE_LIMITED"},
        "network@example.com": {"success": False, "status": "network_error", "http_status": 0, "error_code": "CODEX_USAGE_NETWORK_ERROR"},
    }
    records = [
        {
            "email": email,
            "password": "mail-password",
            "client_id": "outlook-client",
            "mailbox_refresh_token": f"mailbox-refresh-token-{index:02d}",
        }
        for index, email in enumerate(results, start=1)
    ]
    repository.import_accounts(records)
    for email in results:
        account = repository.get_account_by_email(email)
        assert account
        repository.save_token(account["id"], {
            "email": email,
            "access_token": f"access-{email}",
            "refresh_token": f"refresh-{email}",
        })

    proxy_pool = FakeProxyPool()
    reauth = FakeReauthService()
    scheduler = ScheduledLivenessService(
        repository,
        scheduler_settings(tmp_path),
        proxy_pool,  # type: ignore[arg-type]
        reauth,  # type: ignore[arg-type]
        client_factory=lambda **_kwargs: FakeUsageClient(results),
    )

    summary = await scheduler.run_once()

    assert summary == {
        "status": "success",
        "checked": 6,
        "valid": 1,
        "invalid": 2,
        "temporary_failed": 3,
        "queued": 2,
        "duplicate": 0,
        "skipped": 0,
        "started_at": summary["started_at"],
        "finished_at": summary["finished_at"],
    }
    assert len(proxy_pool.claimed) == 6
    assert len(proxy_pool.completed) == 6
    assert sum(1 for success, _error in proxy_pool.completed if not success) == 1
    assert len(reauth.calls) == 1
    queued_ids = set(reauth.calls[0]["account_ids"])
    assert queued_ids == {
        repository.get_account_by_email("unauthorized@example.com")["id"],
        repository.get_account_by_email("expired@example.com")["id"],
    }
    assert reauth.calls[0]["use_proxy"] is True
    assert "定时验活" in str(reauth.calls[0]["event_message"])
    with database.connect() as connection:
        assert connection.execute("SELECT COUNT(*) FROM quotas").fetchone()[0] == 0
    state = repository.get_scheduler_state()
    assert state["status"] == "success"
    assert state["checked_count"] == 6
    assert state["invalid_count"] == 2
    assert state["temporary_failed_count"] == 3
    account_items, _ = repository.list_accounts()
    states = {item["email"]: item["liveness_status"] for item in account_items}
    assert states["valid@example.com"] == "valid"
    assert states["unauthorized@example.com"] == "invalid"
    assert states["limited@example.com"] == "rate_limited"


@pytest.mark.asyncio
async def test_scheduled_liveness_maps_models_validator_valid_field(tmp_path: Path):
    database = Database(tmp_path / "models-liveness.db")
    database.initialize()
    repository = Repository(database)
    repository.import_accounts([{
        "email": "valid@example.com",
        "password": "mail-password",
        "client_id": "outlook-client",
        "mailbox_refresh_token": "mailbox-refresh-token",
    }])
    account = repository.get_account_by_email("valid@example.com")
    assert account
    repository.save_token(account["id"], {
        "email": "valid@example.com",
        "access_token": "access-token",
        "refresh_token": "refresh-token",
    })

    results = {"valid@example.com": {
        "valid": True,
        "terminal": False,
        "status": "valid",
        "http_status": 200,
        "error_code": "",
        "message": "Codex Token 有效",
    }}
    scheduler = ScheduledLivenessService(
        repository,
        scheduler_settings(tmp_path),
        FakeProxyPool(),  # type: ignore[arg-type]
        FakeReauthService(),  # type: ignore[arg-type]
        client_factory=lambda **_kwargs: FakeTokenValidator(results),
    )

    summary = await scheduler.run_once()

    assert summary["checked"] == 1
    assert summary["valid"] == 1
    assert summary["invalid"] == 0
    assert summary["temporary_failed"] == 0

from pathlib import Path

import pytest

import app.service as service_module
from app.config import Settings
from app.db import Database, Repository
from app.service import QuotaService


def _settings(data_dir: Path) -> Settings:
    return Settings(
        host="127.0.0.1",
        port=10717,
        data_dir=data_dir,
        worker_count=1,
        use_proxy_default=False,
        proxy_lease_seconds=60,
        proxy_cooldown_seconds=5,
        outlook_imap_host="outlook.example",
        outlook_imap_port=993,
        otp_poll_seconds=2,
        otp_timeout_seconds=30,
        quota_timeout_ms=1000,
        usage_url="https://usage.example",
        usage_version="test",
    )


def _repository(tmp_path: Path) -> tuple[Repository, dict[str, object]]:
    repository = Repository(Database(tmp_path / "retry.db"))
    repository.db.initialize()
    repository.import_accounts([{
        "email": "retry@example.com",
        "password": "password",
        "client_id": "client-id",
        "mailbox_refresh_token": "mailbox-refresh-token",
    }])
    account = repository.get_account_by_email("retry@example.com")
    assert account
    repository.save_token(account["id"], {
        "email": account["email"],
        "access_token": "access-token",
        "refresh_token": "refresh-token",
    })
    return repository, account


class _UsageClient:
    def __init__(self, result: dict[str, object], calls: list[int]) -> None:
        self.result = result
        self.calls = calls

    async def query(self, _row, *, proxy_url=None):
        self.calls.append(1)
        return dict(self.result)


@pytest.mark.asyncio
async def test_quota_failure_is_retried_ten_times_then_marks_account_failed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(service_module, "REAUTH_RETRY_DELAYS_SECONDS", (0.0,) * 9)
    repository, account = _repository(tmp_path)
    calls: list[int] = []
    client = _UsageClient({
        "success": False,
        "status": "network_error",
        "error_code": "NETWORK_ERROR",
        "error_message": "temporary network failure",
    }, calls)
    monkeypatch.setattr(service_module, "create_codex_usage_client", lambda **_kwargs: client)

    result = await QuotaService(repository, _settings(tmp_path), object()).refresh(use_proxy=False)  # type: ignore[arg-type]

    assert len(calls) == 10
    assert result["results"][0]["success"] is False
    stored_account = repository.get_account(str(account["id"]))
    assert stored_account and stored_account["status"] == "failed"
    stored_quota = repository.list_quotas()[0][0]["status"]
    assert stored_quota == "network_error"


@pytest.mark.asyncio
async def test_quota_account_ban_stops_without_retry_and_marks_disabled(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(service_module, "REAUTH_RETRY_DELAYS_SECONDS", (0.0,) * 9)
    repository, account = _repository(tmp_path)
    calls: list[int] = []
    client = _UsageClient({
        "success": False,
        "status": "forbidden",
        "error_code": "ACCOUNT_BANNED",
        "error_message": "account banned",
    }, calls)
    monkeypatch.setattr(service_module, "create_codex_usage_client", lambda **_kwargs: client)

    await QuotaService(repository, _settings(tmp_path), object()).refresh(use_proxy=False)  # type: ignore[arg-type]

    assert len(calls) == 1
    stored_account = repository.get_account(str(account["id"]))
    assert stored_account and stored_account["status"] == "disabled"

from pathlib import Path

import pytest

from app.config import Settings
from app.db import Database, Repository
from app.proxy import ProxyLease, ProxyPoolError
from app.service import ReauthService


def _settings(data_dir: Path) -> Settings:
    return Settings(
        host="127.0.0.1",
        port=10717,
        data_dir=data_dir,
        worker_count=1,
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
    )


def _account(repository: Repository) -> dict[str, object]:
    repository.import_accounts([{
        "email": "proxy-feedback@example.com",
        "password": "mail-password",
        "client_id": "client-id",
        "mailbox_refresh_token": "a" * 20,
    }])
    account = repository.get_account_by_email("proxy-feedback@example.com")
    assert account
    return account


class FakeProxyPool:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.completed: list[tuple[bool, str]] = []

    def claim(self, owner: str) -> ProxyLease:
        if self.fail:
            raise ProxyPoolError("代理池当前没有可用代理", "PROXY_POOL_EMPTY")
        return ProxyLease(7, "socks5://proxy-user:proxy-password@proxy.example:1080", owner)

    def complete(self, lease: ProxyLease, *, success: bool, error: str = "") -> None:
        self.completed.append((success, error))


class FakeReauthService(ReauthService):
    def _reauthorize_sync(self, account: dict[str, object], proxy_url: str, job_id: str) -> dict[str, str]:
        assert proxy_url == "socks5://proxy-user:proxy-password@proxy.example:1080"
        return {
            "email": str(account["email"]),
            "access_token": "access-token",
            "refresh_token": "refresh-token",
        }


@pytest.mark.asyncio
async def test_reauth_job_exposes_only_the_proxy_endpoint_after_claim(tmp_path: Path):
    repository = Repository(Database(tmp_path / "tool.db"))
    repository.db.initialize()
    account = _account(repository)
    proxy_pool = FakeProxyPool()
    service = FakeReauthService(repository, _settings(tmp_path), proxy_pool)  # type: ignore[arg-type]
    job = repository.create_job(str(account["id"]), True)
    try:
        await service._run(str(job["id"]), 0)
    finally:
        await service.stop()

    stored = repository.get_job(str(job["id"]))
    assert stored
    assert stored["status"] == "success"
    assert stored["proxy_state"] == "claimed"
    assert stored["proxy_endpoint"] == "socks5://proxy.example:1080"
    events = " ".join(item["message"] for item in repository.list_events(str(job["id"])))
    assert "socks5://proxy.example:1080" in events
    assert "proxy-user" not in events
    assert "proxy-password" not in events
    assert proxy_pool.completed == [(True, "")]


@pytest.mark.asyncio
async def test_reauth_job_marks_proxy_as_not_claimed_when_pool_is_empty(tmp_path: Path):
    repository = Repository(Database(tmp_path / "tool.db"))
    repository.db.initialize()
    account = _account(repository)
    service = ReauthService(repository, _settings(tmp_path), FakeProxyPool(fail=True))  # type: ignore[arg-type]
    job = repository.create_job(str(account["id"]), True)
    try:
        await service._run(str(job["id"]), 0)
    finally:
        await service.stop()

    stored = repository.get_job(str(job["id"]))
    assert stored
    assert stored["status"] == "failed"
    assert stored["proxy_state"] == "failed"
    assert stored["proxy_endpoint"] == ""
    assert stored["error"] == "代理池当前没有可用代理"

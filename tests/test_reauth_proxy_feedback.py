from pathlib import Path

import pytest

import app.service as service_module
from app.config import Settings
from app.db import Database, Repository
from app.outlook.mail import _oauth_failure_is_terminal
from app.proxy import ProxyLease, ProxyPoolError
from app.service import ReauthService, account_is_disabled_error, reauth_error_is_retryable, safe_error


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


class WaitingProxyPool(FakeProxyPool):
    def __init__(self) -> None:
        super().__init__()
        self.claims = 0

    def claim(self, owner: str) -> ProxyLease:
        self.claims += 1
        if self.claims == 1:
            raise ProxyPoolError("代理池当前没有可用代理", "PROXY_POOL_EMPTY")
        return ProxyLease(7, "socks5://proxy-user:proxy-password@proxy.example:1080", owner)

    def stats(self) -> dict[str, int]:
        return {"total": 1, "enabled": 1, "available": 1 if self.claims > 1 else 0}


class FakeReauthService(ReauthService):
    def _reauthorize_sync(self, account: dict[str, object], proxy_url: str, job_id: str) -> dict[str, str]:
        assert proxy_url == "socks5://proxy-user:proxy-password@proxy.example:1080"
        return {
            "email": str(account["email"]),
            "access_token": "access-token",
            "refresh_token": "refresh-token",
        }


class DeactivatedReauthService(ReauthService):
    def _reauthorize_sync(self, account: dict[str, object], proxy_url: str, job_id: str) -> dict[str, str]:
        raise RuntimeError(
            "OTP 验证失败: HTTP 403 code=account_deactivated "
            "type=invalid_request_error message=account has been deleted or deactivated"
        )


class MissingOutlookApplicationReauthService(ReauthService):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.calls = 0

    def _reauthorize_sync(self, account: dict[str, object], proxy_url: str, job_id: str) -> dict[str, str]:
        self.calls += 1
        raise RuntimeError(
            "AADSTS700016: Application with identifier 'fictional-client-id' "
            "was not found in the directory 'fictional-tenant-id'."
        )


class TransientThenSuccessReauthService(ReauthService):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.calls = 0

    def _reauthorize_sync(self, account: dict[str, object], proxy_url: str, job_id: str) -> dict[str, str]:
        self.calls += 1
        if self.calls == 1:
            raise RuntimeError("协议登录请求失败: HTTP 503")
        return {
            "email": str(account["email"]),
            "access_token": "access-token",
            "refresh_token": "refresh-token",
        }


class AlwaysTransientReauthService(ReauthService):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.calls = 0

    def _reauthorize_sync(self, account: dict[str, object], proxy_url: str, job_id: str) -> dict[str, str]:
        self.calls += 1
        raise RuntimeError("协议登录请求失败: HTTP 503")


def test_reauth_error_retry_classification():
    assert reauth_error_is_retryable(RuntimeError("登录请求失败: HTTP 503")) is True
    assert reauth_error_is_retryable(RuntimeError("登录失败: invalid_login")) is False
    assert reauth_error_is_retryable(RuntimeError("account_deactivated")) is False
    assert account_is_disabled_error(RuntimeError("AADSTS700016: application not found")) is True
    assert reauth_error_is_retryable(RuntimeError("AADSTS700016: application not found")) is False
    assert _oauth_failure_is_terminal("invalid_grant", "AADSTS700016: application not found", 400) is True
    assert _oauth_failure_is_terminal("invalid_grant", "AADSTS50196: request loop", 400) is False
    assert safe_error("AADSTS700016: client fictional-client-id not found") == "AADSTS700016：Outlook 客户端 ID 或租户授权不可用"


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
async def test_reauth_waits_for_a_busy_configured_proxy(tmp_path: Path):
    repository = Repository(Database(tmp_path / "tool.db"))
    repository.db.initialize()
    account = _account(repository)
    proxy_pool = WaitingProxyPool()
    service = FakeReauthService(repository, _settings(tmp_path), proxy_pool)  # type: ignore[arg-type]
    service.PROXY_WAIT_POLL_SECONDS = 0
    job = repository.create_job(str(account["id"]), True)
    try:
        await service._run(str(job["id"]), 0)
    finally:
        await service.stop()

    stored = repository.get_job(str(job["id"]))
    assert stored and stored["status"] == "success"
    assert proxy_pool.claims == 2


@pytest.mark.asyncio
async def test_reauth_job_marks_proxy_as_not_claimed_when_pool_is_empty(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    repository = Repository(Database(tmp_path / "tool.db"))
    repository.db.initialize()
    account = _account(repository)
    monkeypatch.setattr(service_module, "REAUTH_RETRY_DELAYS_SECONDS", (0.0, 0.0))
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


@pytest.mark.asyncio
async def test_reauth_retries_transient_failure_before_marking_account_failed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(service_module, "REAUTH_RETRY_DELAYS_SECONDS", (0.0, 0.0))
    repository = Repository(Database(tmp_path / "tool.db"))
    repository.db.initialize()
    account = _account(repository)
    proxy_pool = FakeProxyPool()
    service = TransientThenSuccessReauthService(repository, _settings(tmp_path), proxy_pool)  # type: ignore[arg-type]
    job = repository.create_job(str(account["id"]), True)
    try:
        await service._run(str(job["id"]), 0)
    finally:
        await service.stop()

    stored = repository.get_job(str(job["id"]))
    assert stored and stored["status"] == "success"
    assert service.calls == 2
    assert proxy_pool.completed[0][0] is False
    assert proxy_pool.completed[-1] == (True, "")
    events = " ".join(item["message"] for item in repository.list_events(str(job["id"])))
    assert "自动重试" in events


@pytest.mark.asyncio
async def test_reauth_exhausts_ten_attempts_before_marking_account_failed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(service_module, "REAUTH_RETRY_DELAYS_SECONDS", (0.0,) * 9)
    repository = Repository(Database(tmp_path / "tool.db"))
    repository.db.initialize()
    account = _account(repository)
    service = AlwaysTransientReauthService(repository, _settings(tmp_path), FakeProxyPool())  # type: ignore[arg-type]
    job = repository.create_job(str(account["id"]), False)
    try:
        await service._run(str(job["id"]), 0)
    finally:
        await service.stop()

    stored = repository.get_job(str(job["id"]))
    stored_account = repository.get_account(str(account["id"]))
    assert service.calls == 10
    assert stored and stored["status"] == "failed"
    assert stored_account and stored_account["status"] == "failed"


@pytest.mark.asyncio
async def test_reauth_marks_deactivated_account_disabled(tmp_path: Path):
    repository = Repository(Database(tmp_path / "tool.db"))
    repository.db.initialize()
    account = _account(repository)
    service = DeactivatedReauthService(repository, _settings(tmp_path), FakeProxyPool())  # type: ignore[arg-type]
    job = repository.create_job(str(account["id"]), False)
    try:
        await service._run(str(job["id"]), 0)
    finally:
        await service.stop()

    stored_account = repository.get_account(str(account["id"]))
    stored_job = repository.get_job(str(job["id"]))
    assert stored_account and stored_account["status"] == "disabled"
    assert stored_job and stored_job["status"] == "failed"
    assert account_is_disabled_error(stored_account["last_error"])
    events = " ".join(item["message"] for item in repository.list_events(str(job["id"])))
    assert "检测到账号已禁用" in events


@pytest.mark.asyncio
async def test_missing_outlook_application_marks_mailbox_disabled_without_retry(tmp_path: Path):
    repository = Repository(Database(tmp_path / "tool.db"))
    repository.db.initialize()
    account = _account(repository)
    service = MissingOutlookApplicationReauthService(repository, _settings(tmp_path), FakeProxyPool())  # type: ignore[arg-type]
    job = repository.create_job(str(account["id"]), False)
    try:
        await service._run(str(job["id"]), 0)
    finally:
        await service.stop()

    stored_account = repository.get_account(str(account["id"]))
    stored_job = repository.get_job(str(job["id"]))
    assert service.calls == 1
    assert stored_account and stored_account["status"] == "disabled"
    assert stored_job and stored_job["status"] == "failed"
    assert stored_account["last_error"] == stored_job["error"] == "AADSTS700016：Outlook 客户端 ID 或租户授权不可用"
    assert "fictional-client-id" not in stored_job["error"]


@pytest.mark.asyncio
async def test_reauth_queue_skips_disabled_accounts(tmp_path: Path):
    repository = Repository(Database(tmp_path / "tool.db"))
    repository.db.initialize()
    disabled = _account(repository)
    repository.update_account(str(disabled["id"]), status="disabled", error="account_deactivated")
    repository.import_accounts([{
        "email": "pending@example.com",
        "password": "mail-password",
        "client_id": "client-id",
        "mailbox_refresh_token": "b" * 20,
    }])
    service = ReauthService(repository, _settings(tmp_path), FakeProxyPool())  # type: ignore[arg-type]
    try:
        result = await service.queue_accounts(use_proxy=False)
    finally:
        await service.stop()

    assert result["queued"] == 1
    assert result["skipped"] == 1
    assert result["disabled_skipped"] == 1
    assert len(result["jobs"]) == 1
    assert result["jobs"][0]["account_id"] != disabled["id"]


@pytest.mark.asyncio
async def test_reauth_worker_cancels_recovered_job_for_disabled_account(tmp_path: Path):
    repository = Repository(Database(tmp_path / "tool.db"))
    repository.db.initialize()
    disabled = _account(repository)
    job = repository.create_job(str(disabled["id"]), False)
    repository.update_account(str(disabled["id"]), status="disabled", error="account_deactivated")
    service = ReauthService(repository, _settings(tmp_path), FakeProxyPool())  # type: ignore[arg-type]
    try:
        await service._run(str(job["id"]), 0)
    finally:
        await service.stop()

    stored = repository.get_job(str(job["id"]))
    stored_account = repository.get_account(str(disabled["id"]))
    assert stored and stored["status"] == "cancelled"
    assert stored["error"] == "账号已禁用，跳过重新授权"
    assert stored_account and stored_account["status"] == "disabled"

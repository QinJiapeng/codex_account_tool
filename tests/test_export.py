import io
import json
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app import service
from app.db import Database, Repository
from app.main import create_app
from app.service import QuotaService, ReauthService


def _jwt(payload):
    import base64

    encoded = lambda value: base64.urlsafe_b64encode(json.dumps(value, separators=(",", ":")).encode()).decode().rstrip("=")
    return f"{encoded({'alg': 'none'})}.{encoded(payload)}.signature"


def _record(email="user@example.com"):
    return {
        "id": "account-1",
        "email": email,
        "password": "mail-password",
        "client_id": "outlook-client-id",
        "mailbox_refresh_token": "mailbox-refresh-token-rotated",
        "token": {
            "email": email,
            "access_token": "access-secret",
            "refresh_token": "oauth-refresh-secret",
            "id_token": "id-secret",
            "account_id": "acct-123",
            "client_id": "oauth-client-id",
        },
    }


def _sub2api_record(email="user@example.com"):
    record = _record(email)
    auth = {
        "chatgpt_account_id": "acct-123",
        "chatgpt_user_id": "user-123",
        "chatgpt_plan_type": "free",
        "organizations": [{"id": "org-123", "is_default": True}],
    }
    record["token"].update({
        "access_token": _jwt({"exp": 4102444800, "email": email, "https://api.openai.com/auth": auth}),
        "id_token": _jwt({"email": email, "https://api.openai.com/auth": auth}),
    })
    return record


def test_export_documents_have_expected_formats_and_no_cross_format_secrets():
    record = _record()

    content, media_type, filename = service.build_export_document([record], "four-segment")
    assert media_type.startswith("text/plain")
    assert filename.endswith(".txt")
    assert content.decode("utf-8-sig").strip() == "user@example.com----mail-password----outlook-client-id----mailbox-refresh-token-rotated"

    content, media_type, filename = service.build_export_document([record], "cpa")
    assert media_type == "application/zip"
    assert filename.endswith(".zip")
    with zipfile.ZipFile(io.BytesIO(content)) as archive:
        assert archive.namelist() == ["codex-user@example.com-free.json"]
        payload = json.loads(archive.read(archive.namelist()[0]))
    assert payload["type"] == "codex"
    assert payload["access_token"] == "access-secret"
    assert "mail-password" not in content.decode("latin1")
    assert "mailbox-refresh-token" not in content.decode("latin1")

    content, media_type, filename = service.build_export_document([_sub2api_record()], "sub2api")
    assert media_type == "application/zip"
    assert filename == "sub2api-1-accounts.zip"
    with zipfile.ZipFile(io.BytesIO(content)) as archive:
        assert archive.namelist() == ["sub2api-user@example.com.sub2api.json"]
        payload = json.loads(archive.read(archive.namelist()[0]))
    account = payload["accounts"][0]
    assert account["credentials"]["refresh_token"] == "oauth-refresh-secret"
    assert account["credentials"]["email"] == "user@example.com"
    assert account["extra"]["email_key"] == "user_example_com"
    assert account["credentials"]["organization_id"] == "org-123"
    assert "client_id" not in account["credentials"]
    assert "original_email" not in payload
    assert account["priority"] == 1
    assert "mail-password" not in content.decode("latin1")


def test_sub2api_export_contains_keypickup_compatible_jwt_claims():
    record = _sub2api_record()
    record["token"]["account_id"] = ""
    record["token"]["access_token"] = _jwt({
        "exp": 4102444800,
        "email": "user@example.com",
        "https://api.openai.com/auth": {
            "chatgpt_account_id": "acct-jwt",
            "organizations": [{"id": "org-jwt", "is_default": True}],
            "chatgpt_plan_type": "plus",
            "chatgpt_user_id": "user-jwt",
        },
    })
    record["token"]["id_token"] = _jwt({"email": "user@example.com"})
    content, _, _ = service.build_export_document([record], "sub2api")
    with zipfile.ZipFile(io.BytesIO(content)) as archive:
        account = json.loads(archive.read(archive.namelist()[0]))["accounts"][0]
    assert account["credentials"]["chatgpt_account_id"] == "acct-jwt"
    assert account["credentials"]["chatgpt_user_id"] == "user-jwt"
    assert account["credentials"]["organization_id"] == "org-jwt"
    assert account["credentials"]["expires_at"] == "2100-01-01T00:00:00Z"
    assert account["credentials"]["plan_type"] == "plus"


def test_sub2api_export_rejects_non_jwt_credentials():
    with pytest.raises(ValueError, match="access_token 不是有效 JWT"):
        service.build_export_document([_record()], "sub2api")


def test_multiple_cpa_accounts_are_downloaded_as_zip():
    content, media_type, filename = service.build_export_document([_record(), _record("second@example.com")], "cpa")
    assert media_type == "application/zip"
    assert filename.endswith(".zip")
    with zipfile.ZipFile(io.BytesIO(content)) as archive:
        assert sorted(archive.namelist()) == ["codex-second@example.com-free.json", "codex-user@example.com-free.json"]


def test_upload_record_split_skips_local_success_and_force_bypasses_it(tmp_path: Path):
    repository = Repository(Database(tmp_path / "tool.db"))
    repository.db.initialize()
    repository.import_accounts([
        {"email": "first@example.com", "password": "pw", "client_id": "cid", "mailbox_refresh_token": "a" * 20},
        {"email": "second@example.com", "password": "pw", "client_id": "cid", "mailbox_refresh_token": "b" * 20},
    ])
    first = repository.get_account_by_email("first@example.com")
    second = repository.get_account_by_email("second@example.com")
    assert first and second
    records = [{"id": first["id"], "email": first["email"]}, {"id": second["id"], "email": second["email"]}]
    repository.save_upload_statuses("cpa", [records[0]], {"items": [{"email": records[0]["email"], "uploaded": True}]})

    pending, skipped = service.split_upload_records(repository, "cpa", records)
    assert [row["email"] for row in pending] == ["second@example.com"]
    assert skipped == [{"email": "first@example.com", "uploaded": False, "skipped": True, "reason": "already_uploaded"}]
    forced, forced_skipped = service.split_upload_records(repository, "cpa", records, force=True)
    assert len(forced) == 2
    assert forced_skipped == []


def test_export_rejects_empty_or_missing_oauth_records():
    with pytest.raises(ValueError, match="没有已保存"):
        service.build_export_document([], "cpa")
    with pytest.raises(ValueError, match="缺少可刷新的 OAuth Token"):
        service.build_export_document([{**_record(), "token": {}}], "cpa")


def test_repository_export_joins_only_authorized_accounts_and_uses_rotated_mail_token(tmp_path):
    repository = Repository(Database(tmp_path / "tool.db"))
    repository.db.initialize()
    repository.import_accounts([
        {
            "email": "authorized@example.com",
            "password": "password",
            "client_id": "client",
            "mailbox_refresh_token": "mailbox-token-original",
        },
        {
            "email": "pending@example.com",
            "password": "password",
            "client_id": "client",
            "mailbox_refresh_token": "mailbox-token-pending",
        },
    ])
    account = repository.get_account_by_email("authorized@example.com")
    assert account
    repository.save_token(account["id"], {
        "email": "authorized@example.com",
        "access_token": "access",
        "refresh_token": "oauth-refresh",
    })
    repository.update_mailbox_refresh_token(account["id"], "mailbox-token-rotated")
    records = repository.export_account_records()
    assert len(records) == 1
    assert records[0]["mailbox_refresh_token"] == "mailbox-token-rotated"
    assert records[0]["email"] == "authorized@example.com"


class _FakeResponse:
    def __init__(self, status_code=201):
        self.status_code = status_code


class _FakeAsyncClient:
    calls = []

    def __init__(self, **kwargs):
        self.kwargs = kwargs

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    async def post(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return _FakeResponse()


@pytest.mark.asyncio
async def test_cpa_upload_uses_env_key_and_redacts_remote_response(monkeypatch):
    _FakeAsyncClient.calls = []
    monkeypatch.setenv("CLI_PROXY_API_URL", "http://127.0.0.1:8317")
    monkeypatch.setenv("CLI_PROXY_MANAGEMENT_KEY", "management-secret")
    monkeypatch.setattr("httpx.AsyncClient", _FakeAsyncClient)

    result = await service.upload_cpa_records([_record()])

    assert result["uploaded"] == 1
    url, kwargs = _FakeAsyncClient.calls[0]
    assert url == "http://127.0.0.1:8317/v0/management/auth-files"
    assert kwargs["headers"]["Authorization"] == "Bearer management-secret"
    uploaded = kwargs["files"]["file"][1].decode()
    assert "access-secret" in uploaded
    assert "mail-password" not in uploaded


@pytest.mark.asyncio
async def test_sub2api_upload_sends_batch_accounts_without_echoing_auth_header(monkeypatch):
    _FakeAsyncClient.calls = []
    monkeypatch.setenv("SUB2API_API_URL", "https://sub2api.example")
    monkeypatch.setenv("SUB2API_ADMIN_API_KEY", "admin-secret")
    monkeypatch.setattr("httpx.AsyncClient", _FakeAsyncClient)

    result = await service.upload_sub2api_records([_sub2api_record()])

    assert result["uploaded"] == 1
    url, kwargs = _FakeAsyncClient.calls[0]
    assert url == "https://sub2api.example/api/v1/admin/accounts/batch"
    assert kwargs["headers"]["X-API-Key"] == "admin-secret"
    assert "Authorization" not in kwargs["headers"]
    body = json.loads(kwargs["content"])
    assert list(body) == ["accounts"]
    assert body["accounts"][0]["name"] == "user@example.com"
    assert body["accounts"][0]["credentials"]["access_token"].count(".") == 2
    assert "mail-password" not in kwargs["content"].decode()


def test_safe_error_redacts_credentials_and_tokens():
    value = service.safe_error("authorization: Bearer eyJabcdefghijk.abc.def api_key=secret refresh_token=refresh")
    assert "eyJabcdefghijk" not in value
    assert "secret" not in value
    assert "refresh_token=refresh" not in value


def test_api_list_hides_credentials_and_export_is_explicit(tmp_path: Path, monkeypatch):
    settings = Settings(
        host="127.0.0.1",
        port=10717,
        data_dir=tmp_path,
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

    upload_options = {}
    upload_calls = []

    async def fake_cpa_upload(records, **kwargs):
        upload_calls.append([record["email"] for record in records])
        upload_options.update(kwargs)
        return {
            "requested": len(records),
            "uploaded": len(records),
            "failed": 0,
            "items": [{"email": record["email"], "uploaded": True} for record in records],
        }

    monkeypatch.setattr("app.main.upload_cpa_records", fake_cpa_upload)
    with TestClient(create_app(settings)) as client:
        initial_settings = client.get("/api/settings")
        assert initial_settings.status_code == 200
        assert initial_settings.json()["settings"]["worker_count"] == 1
        updated_settings = client.patch("/api/settings", json={
            "use_proxy_default": True,
            "auto_upload_cpa": True,
            "scheduled_liveness_enabled": True,
            "scheduled_liveness_interval_minutes": 90,
            "worker_count": 2,
            "cpa_api_url": "https://cpa.example/management.html",
            "cpa_management_key": "management-secret",
            "cpa_api_timeout_seconds": 45,
            "sub2api_api_url": "https://sub2api.example",
            "sub2api_admin_api_key": "sub2api-secret",
            "sub2api_api_timeout_seconds": 50,
        })
        assert updated_settings.status_code == 200
        assert updated_settings.json()["settings"]["auto_upload_cpa"] is True
        assert updated_settings.json()["settings"]["scheduled_liveness_enabled"] is True
        assert updated_settings.json()["settings"]["scheduled_liveness_interval_minutes"] == 90
        assert updated_settings.json()["scheduler"]["enabled"] is True
        assert updated_settings.json()["settings"]["cpa_api_url"] == "https://cpa.example/management.html"
        assert updated_settings.json()["settings"]["cpa_management_key_configured"] is True
        assert updated_settings.json()["settings"]["sub2api_admin_api_key_configured"] is True
        assert "management-secret" not in updated_settings.text
        assert "sub2api-secret" not in updated_settings.text
        assert updated_settings.json()["restart_required"] is True
        settings_view = client.get("/api/settings")
        assert settings_view.status_code == 200
        assert "management-secret" not in settings_view.text
        assert "sub2api-secret" not in settings_view.text
        assert client.patch("/api/settings", json={"cpa_api_url": "http://user:password@cpa.example"}).status_code == 422
        assert client.patch("/api/settings", json={"scheduled_liveness_interval_minutes": 4}).status_code == 422
        imported = client.post("/api/accounts/import", json={"text": "user@example.com----mail-password----client-id----mailbox-refresh-token"})
        assert imported.status_code == 200
        item = client.get("/api/accounts").json()["items"][0]
        assert "password" not in item
        assert "mailbox_refresh_token" not in item
        account = Repository(Database(settings.db_path)).get_account(item["id"])
        assert account
        Repository(Database(settings.db_path)).save_token(account["id"], {
            "email": account["email"],
            "access_token": "access-secret",
            "refresh_token": "oauth-refresh-secret",
        })
        Repository(Database(settings.db_path)).save_quota(account["id"], {
            "status": "success",
            "plan_type": "plus",
            "credits_balance": 569.71,
            "credits_balance_display": "569.71",
            "credits_has": True,
            "limit_windows": [{"label": "5h", "used_percent": 50, "reset_after_seconds": 3600}],
        })
        response = client.post("/api/accounts/export", json={"ids": [item["id"]], "format": "cpa"})
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("application/zip")
        with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
            payload = json.loads(archive.read(archive.namelist()[0]))
        assert payload["access_token"] == "access-secret"
        quotas = client.get("/api/quotas")
        assert quotas.status_code == 200
        assert quotas.json()["summary"]["authorized"] == 1
        assert quotas.json()["summary"]["plan_counts"]["plus"] == 1
        assert quotas.json()["summary"]["limit_accounts"] == 1
        assert quotas.json()["items"][0]["plan_label"] == "Plus"
        assert quotas.json()["items"][0]["limit_windows"][0]["label"] == "5h"
        assert "access_token" not in json.dumps(quotas.json())
        uploaded = client.post("/api/accounts/upload-cpa", json={"ids": [item["id"]]})
        assert uploaded.status_code == 200
        assert upload_options == {
            "api_url": "https://cpa.example/management.html",
            "management_key": "management-secret",
            "timeout_seconds": 45,
        }
        upload_statuses = client.get("/api/accounts").json()["items"][0]["upload_statuses"]
        assert upload_statuses["cpa"]["status"] == "success"
        assert upload_statuses["cpa"]["uploaded_at"]
        skipped_upload = client.post("/api/accounts/upload-cpa", json={"ids": [item["id"]]})
        assert skipped_upload.status_code == 200
        assert skipped_upload.json()["uploaded"] == 0
        assert skipped_upload.json()["skipped"] == 1
        assert len(upload_calls) == 1
        assert client.get("/api/accounts").json()["items"][0]["upload_statuses"]["cpa"]["status"] == "success"
        forced_upload = client.post("/api/accounts/upload-cpa", json={"ids": [item["id"],], "force": True})
        assert forced_upload.status_code == 200
        assert forced_upload.json()["uploaded"] == 1
        assert len(upload_calls) == 2
        cleared = client.patch("/api/settings", json={"clear_sub2api_admin_api_key": True})
        assert cleared.status_code == 200
        assert cleared.json()["settings"]["cpa_management_key_configured"] is True
        assert cleared.json()["settings"]["sub2api_admin_api_key_configured"] is False
        assert client.request("DELETE", "/api/accounts", json={}).status_code == 422
        deleted = client.request("DELETE", "/api/accounts", json={"ids": [item["id"]]})
        assert deleted.status_code == 200
        assert deleted.json()["deleted"] == 1


def test_api_status_filter_and_targeted_retry_routes(tmp_path: Path, monkeypatch):
    settings = Settings(
        host="127.0.0.1",
        port=10717,
        data_dir=tmp_path,
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
    queue_calls: list[list[str]] = []
    quota_calls: list[list[str]] = []

    async def fake_queue(self, account_ids=None, *, use_proxy=False, event_message=""):
        ids = [str(account_id) for account_id in (account_ids or [])]
        queue_calls.append(ids)
        return {"queued": len(ids), "duplicate": 0, "skipped": 0, "use_proxy": bool(use_proxy), "jobs": []}

    async def fake_refresh(self, account_ids=None, *, use_proxy=False):
        ids = [str(account_id) for account_id in (account_ids or [])]
        quota_calls.append(ids)
        return {"total": len(ids), "results": [{"account_id": account_id, "success": True} for account_id in ids], "summary": {}}

    monkeypatch.setattr(ReauthService, "queue_accounts", fake_queue)
    monkeypatch.setattr(QuotaService, "refresh", fake_refresh)
    with TestClient(create_app(settings)) as client:
        imported = client.post("/api/accounts/import", json={"text": "failed@example.com----pw----cid----" + "a" * 20 + "\nsuccess@example.com----pw----cid----" + "b" * 20})
        assert imported.status_code == 200
        repository = Repository(Database(settings.db_path))
        failed = repository.get_account_by_email("failed@example.com")
        successful = repository.get_account_by_email("success@example.com")
        assert failed and successful
        for account in (failed, successful):
            repository.save_token(account["id"], {"email": account["email"], "access_token": "access", "refresh_token": "refresh"})
        repository.update_account(failed["id"], status="failed", error="test failure")
        repository.update_account(successful["id"], status="success", authorized=True)
        repository.save_quota(failed["id"], {"status": "rate_limited", "http_status": 429})
        repository.save_quota(successful["id"], {"status": "success", "credits_balance": 50, "credits_has": True})

        filtered = client.get("/api/accounts?status=failed&page=1&page_size=20")
        assert filtered.status_code == 200
        assert filtered.json()["status"] == "failed"
        assert [item["email"] for item in filtered.json()["items"]] == ["failed@example.com"]

        retry_reauth = client.post("/api/reauth/retry-failed")
        assert retry_reauth.status_code == 200
        assert retry_reauth.json()["matched"] == 1
        assert queue_calls == [[failed["id"]]]

        retry_quota = client.post("/api/quotas/refresh-failed")
        assert retry_quota.status_code == 200
        assert retry_quota.json()["matched"] == 1
        assert quota_calls == [[failed["id"]]]


def test_authorization_workbench_contains_import_dialog_and_no_separate_account_tab():
    html = Path("app/static/index.html").read_text(encoding="utf-8")
    script = Path("app/static/app.js").read_text(encoding="utf-8")
    assert 'data-tab="console"' in html
    assert 'id="openImportAccounts"' in html
    assert 'id="importAccountsDialog"' in html
    assert 'id="accountsPanel"' not in html
    assert 'id="accountsTab"' not in html
    assert 'id="settingCpaUrl"' in html
    assert 'id="settingCpaKey"' in html
    assert 'id="settingSub2ApiUrl"' in html
    assert 'id="settingSub2ApiKey"' in html
    assert "管理后台 → 系统设置 → 安全 → 管理员 API Key" in html
    assert "/keys 页面生成" not in html
    assert "重新生成后旧 Key" not in html
    assert 'settingClearCpaKey' not in html
    assert 'settingClearSub2ApiKey' not in html
    assert 'clear_cpa_management_key' not in script
    assert 'clear_sub2api_admin_api_key' not in script
    assert 'id="settingScheduledLiveness"' in html
    assert 'id="settingScheduledLivenessInterval"' in html
    assert 'id="schedulerDetail"' in html
    assert 'id="proxyRows"' in html
    assert '$("proxyText").value = ""' in script
    assert 'id="refresh"' not in html
    assert 'id="reauth"' not in html
    assert 'id="quota"' not in html
    assert 'class="card account-list-card"' in html
    assert 'class="table-wrap account-table-wrap"' in html
    assert 'class="account-table"' in html
    assert 'id="reauthConnectionMode"' in html
    assert 'class="account-action-label">账号操作' in html
    assert 'class="account-action-label">导出与上传' in html
    assert 'id="forceUpload"' in html
    assert "强制重传" in html
    assert 'class="status-spinner"' in script
    assert '查询中' in script
    assert '授权中' in script
    assert "已使用代理" in script
    assert "代理未领取成功" in script
    assert '/api/quotas/progress' in script
    assert 'class="card jobs-card"' in html
    assert 'id="jobStats"' in html
    assert 'scheduler-workbench-card' in html
    assert 'id="workbenchSchedulerState"' in html
    assert 'id="workbenchSchedulerStats"' in html
    assert 'renderSchedulerWorkbench' in script
    assert '/api/settings' in script
    assert 'aria-busy' in script
    assert 'button.is-busy:disabled' in Path("app/static/styles.css").read_text(encoding="utf-8")
    styles = Path("app/static/styles.css").read_text(encoding="utf-8")
    assert '.quota-stat' in styles and 'cursor: default; user-select: none' in styles
    assert 'id="statLimitAccounts"' not in html
    assert 'id="quotaLimitStats"' not in html
    assert 'id="statFetched"' not in html
    assert 'id="statExhausted"' not in html

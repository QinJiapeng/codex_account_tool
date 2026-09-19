from pathlib import Path

from app.db import Database, Repository


def test_account_list_does_not_return_credentials(tmp_path: Path):
    database = Database(tmp_path / "tool.db")
    database.initialize()
    repository = Repository(database)
    repository.import_accounts([{
        "email": "a@example.com",
        "password": "very-secret-password",
        "client_id": "client-id",
        "mailbox_refresh_token": "abcdefghijklmnopqrst",
    }])
    items, _ = repository.list_accounts()
    assert items[0]["email"] == "a@example.com"
    assert "password" not in items[0]
    assert "mailbox_refresh_token" not in items[0]


def test_account_list_supports_pagination_and_fuzzy_search(tmp_path: Path):
    database = Database(tmp_path / "tool.db")
    database.initialize()
    repository = Repository(database)
    repository.import_accounts([
        {"email": "alpha@example.com", "password": "pw", "client_id": "cid", "mailbox_refresh_token": "a" * 20},
        {"email": "beta@example.com", "password": "pw", "client_id": "cid", "mailbox_refresh_token": "b" * 20},
        {"email": "gamma@example.com", "password": "pw", "client_id": "cid", "mailbox_refresh_token": "c" * 20},
    ])

    first_page, total = repository.list_accounts(limit=2, offset=0)
    second_page, second_total = repository.list_accounts(limit=2, offset=2)
    matches, match_total = repository.list_accounts(limit=20, offset=0, query="ETA@EXAMPLE")

    assert total == second_total == 3
    assert len(first_page) == 2
    assert len(second_page) == 1
    assert {item["id"] for item in first_page}.isdisjoint({item["id"] for item in second_page})
    assert match_total == 1
    assert [item["email"] for item in matches] == ["beta@example.com"]


def test_account_list_can_filter_authorization_status(tmp_path: Path):
    database = Database(tmp_path / "tool.db")
    database.initialize()
    repository = Repository(database)
    repository.import_accounts([
        {"email": "pending@example.com", "password": "pw", "client_id": "cid", "mailbox_refresh_token": "a" * 20},
        {"email": "failed@example.com", "password": "pw", "client_id": "cid", "mailbox_refresh_token": "b" * 20},
        {"email": "success@example.com", "password": "pw", "client_id": "cid", "mailbox_refresh_token": "c" * 20},
    ])
    failed = repository.get_account_by_email("failed@example.com")
    successful = repository.get_account_by_email("success@example.com")
    assert failed and successful
    repository.update_account(failed["id"], status="failed", error="invalid credentials")
    repository.update_account(successful["id"], status="success", authorized=True)

    items, total = repository.list_accounts(status="failed")
    assert total == 1
    assert [item["email"] for item in items] == ["failed@example.com"]
    assert repository.account_ids_by_status("failed") == [failed["id"]]
    assert repository.list_accounts(status="not-a-status")[1] == 3


def test_initialize_migrates_deactivated_failures_to_disabled_status(tmp_path: Path):
    database = Database(tmp_path / "tool.db")
    database.initialize()
    repository = Repository(database)
    repository.import_accounts([{
        "email": "disabled@example.com",
        "password": "pw",
        "client_id": "cid",
        "mailbox_refresh_token": "a" * 20,
    }])
    account = repository.get_account_by_email("disabled@example.com")
    assert account
    repository.update_account(
        account["id"],
        status="failed",
        error="OTP 验证失败: HTTP 403 code=account_deactivated type=invalid_request_error",
    )

    database.initialize()

    migrated = repository.get_account(account["id"])
    assert migrated and migrated["status"] == "disabled"
    items, total = repository.list_accounts(status="disabled")
    assert total == 1
    assert [item["email"] for item in items] == ["disabled@example.com"]
    assert repository.account_ids_by_status("failed") == []
    assert repository.account_ids_by_status("disabled") == [account["id"]]


def test_import_preserves_disabled_status_and_cleanup_deletes_only_disabled_accounts(tmp_path: Path):
    database = Database(tmp_path / "tool.db")
    database.initialize()
    repository = Repository(database)
    disabled_record = {
        "email": "disabled@example.com",
        "password": "old-password",
        "client_id": "old-client",
        "mailbox_refresh_token": "a" * 20,
    }
    repository.import_accounts([
        disabled_record,
        {"email": "keep@example.com", "password": "pw", "client_id": "cid", "mailbox_refresh_token": "b" * 20},
    ])
    disabled = repository.get_account_by_email("disabled@example.com")
    kept = repository.get_account_by_email("keep@example.com")
    assert disabled and kept
    repository.update_account(disabled["id"], status="disabled", error="account_deactivated")
    repository.save_token(disabled["id"], {
        "email": disabled["email"],
        "access_token": "placeholder-access",
        "refresh_token": "placeholder-refresh",
    })
    repository.update_account(disabled["id"], status="disabled", error="account_deactivated")

    repository.import_accounts([{**disabled_record, "password": "new-password"}])
    reimported = repository.get_account(disabled["id"])
    assert reimported and reimported["status"] == "disabled"
    assert reimported["last_error"] == "account_deactivated"

    result = repository.delete_disabled_accounts()
    assert result == {"deleted": 1}
    assert repository.get_account(disabled["id"]) is None
    assert repository.get_account(kept["id"]) is not None
    assert repository.token_rows([disabled["id"]]) == []


def test_account_list_returns_safe_per_platform_upload_status(tmp_path: Path):
    database = Database(tmp_path / "tool.db")
    database.initialize()
    repository = Repository(database)
    repository.import_accounts([{
        "email": "upload@example.com",
        "password": "secret-password",
        "client_id": "client-id",
        "mailbox_refresh_token": "a" * 20,
    }])
    account = repository.get_account_by_email("upload@example.com")
    assert account
    record = {"id": account["id"], "email": account["email"]}
    repository.save_upload_statuses("cpa", [record], {
        "items": [{"email": account["email"], "uploaded": True}],
    })
    repository.save_upload_statuses("sub2api", [record], error="connection failed")

    items, _ = repository.list_accounts()
    statuses = items[0]["upload_statuses"]
    assert statuses["cpa"]["status"] == "success"
    assert statuses["cpa"]["uploaded_at"]
    assert statuses["sub2api"]["status"] == "failed"
    assert "error" not in statuses["sub2api"]
    assert "secret-password" not in str(items[0])


def test_successful_upload_ids_are_platform_scoped_and_token_refresh_invalidates_them(tmp_path: Path):
    database = Database(tmp_path / "tool.db")
    database.initialize()
    repository = Repository(database)
    repository.import_accounts([{
        "email": "refresh@example.com",
        "password": "secret-password",
        "client_id": "client-id",
        "mailbox_refresh_token": "a" * 20,
    }])
    account = repository.get_account_by_email("refresh@example.com")
    assert account
    record = {"id": account["id"], "email": account["email"]}
    repository.save_upload_statuses("cpa", [record], {"items": [{"email": record["email"], "uploaded": True}]})
    assert repository.successful_upload_account_ids("cpa", [account["id"]]) == {account["id"]}
    assert repository.successful_upload_account_ids("sub2api", [account["id"]]) == set()

    repository.save_token(account["id"], {
        "email": record["email"],
        "access_token": "access-refresh",
        "refresh_token": "refresh-refresh",
    })
    assert repository.successful_upload_account_ids("cpa", [account["id"]]) == set()
    items, _ = repository.list_accounts()
    assert items[0]["upload_statuses"]["cpa"]["status"] == "pending"


def test_quota_summary_aggregates_statuses_and_credit_tiers(tmp_path: Path):
    database = Database(tmp_path / "tool.db")
    database.initialize()
    repository = Repository(database)
    repository.import_accounts([
        {"email": "full@example.com", "password": "pw", "client_id": "cid", "mailbox_refresh_token": "a" * 20},
        {"email": "low@example.com", "password": "pw", "client_id": "cid", "mailbox_refresh_token": "b" * 20},
        {"email": "empty@example.com", "password": "pw", "client_id": "cid", "mailbox_refresh_token": "c" * 20},
        {"email": "limited@example.com", "password": "pw", "client_id": "cid", "mailbox_refresh_token": "d" * 20},
    ])
    accounts = {email: repository.get_account_by_email(email) for email in (
        "full@example.com", "low@example.com", "empty@example.com", "limited@example.com",
    )}
    for email, balance, plan, used in (("full@example.com", 1200, "plus", 12), ("low@example.com", 50, "free", 84), ("empty@example.com", 0, "free", 100)):
        account = accounts[email]
        assert account
        repository.save_token(account["id"], {"email": email, "access_token": f"access-{email}", "refresh_token": f"refresh-{email}"})
        repository.save_quota(account["id"], {
            "status": "success", "plan_type": plan, "credits_balance": balance,
            "credits_balance_display": str(balance), "credits_has": balance > 0,
            "limit_windows": [{"label": "5h", "used_percent": used, "reset_after_seconds": 3600}],
        })
    account = accounts["limited@example.com"]
    assert account
    repository.save_token(account["id"], {"email": "limited@example.com", "access_token": "access-limited", "refresh_token": "refresh-limited"})
    repository.save_quota(account["id"], {"status": "rate_limited", "http_status": 429, "error_code": "CODEX_USAGE_RATE_LIMITED"})

    summary = repository.quota_summary()
    assert summary["account_total"] == 4
    assert summary["authorized"] == 4
    assert summary["fetched"] == 3
    assert summary["pending"] == 0
    assert summary["failed"] == 1
    assert summary["total_credit"] == 1250
    assert summary["estimated_value"] == 50
    assert summary["exhausted"] == 1
    assert summary["rate_limited"] == 1
    assert summary["plan_counts"]["free"] == 2
    assert summary["plan_counts"]["plus"] == 1
    assert summary["limit_accounts"] == 3
    assert summary["limit_windows"][0]["label"] == "5h"
    assert summary["limit_windows"][0]["count"] == 3
    assert summary["limit_windows"][0]["average_used_percent"] == 65.33
    quota_items, _ = repository.list_quotas()
    plus_item = next(item for item in quota_items if item["email"] == "full@example.com")
    assert plus_item["plan_label"] == "Plus"
    assert plus_item["limit_windows"][0]["label"] == "5h"
    assert {tier["key"]: tier["count"] for tier in summary["tiers"]} == {
        "full": 1, "high": 0, "medium": 0, "low": 1, "zero": 1, "unlimited": 0,
    }


def test_failed_quota_account_ids_only_returns_authorized_non_success_results(tmp_path: Path):
    database = Database(tmp_path / "tool.db")
    database.initialize()
    repository = Repository(database)
    repository.import_accounts([
        {"email": "quota-failed@example.com", "password": "pw", "client_id": "cid", "mailbox_refresh_token": "a" * 20},
        {"email": "quota-success@example.com", "password": "pw", "client_id": "cid", "mailbox_refresh_token": "b" * 20},
        {"email": "quota-no-result@example.com", "password": "pw", "client_id": "cid", "mailbox_refresh_token": "c" * 20},
    ])
    failed = repository.get_account_by_email("quota-failed@example.com")
    successful = repository.get_account_by_email("quota-success@example.com")
    no_result = repository.get_account_by_email("quota-no-result@example.com")
    assert failed and successful and no_result
    for account in (failed, successful, no_result):
        repository.save_token(account["id"], {"email": account["email"], "access_token": f"access-{account['id']}", "refresh_token": f"refresh-{account['id']}"})
    repository.save_quota(failed["id"], {"status": "rate_limited", "http_status": 429})
    repository.save_quota(successful["id"], {"status": "success", "credits_balance": 10, "credits_has": True})

    assert set(repository.failed_quota_account_ids()) == {failed["id"]}


def test_legacy_free_monthly_window_is_not_displayed_as_five_hours(tmp_path: Path):
    database = Database(tmp_path / "tool.db")
    database.initialize()
    repository = Repository(database)
    repository.import_accounts([{
        "email": "free@example.com", "password": "pw", "client_id": "cid", "mailbox_refresh_token": "a" * 20,
    }])
    account = repository.get_account_by_email("free@example.com")
    assert account
    repository.save_token(account["id"], {"email": account["email"], "access_token": "access", "refresh_token": "refresh"})
    repository.save_quota(account["id"], {
        "status": "success",
        "plan_type": "free",
        "limit_windows": [{"label": "5h", "used_percent": 16, "reset_after_seconds": 2_529_678}],
    })

    items, _ = repository.list_quotas()
    assert items[0]["limit_windows"][0]["label"] == "Monthly"
    assert repository.quota_summary()["limit_windows"][0]["label"] == "Monthly"


def test_preferences_round_trip_without_accepting_unknown_values(tmp_path: Path):
    database = Database(tmp_path / "tool.db")
    database.initialize()
    repository = Repository(database)
    defaults = {"use_proxy_default": False, "auto_upload_cpa": False, "worker_count": 2}
    assert repository.load_preferences(defaults) == defaults
    repository.save_preferences({"use_proxy_default": True, "auto_upload_cpa": True, "worker_count": 4, "secret": "do-not-save"})
    loaded = repository.load_preferences(defaults)
    assert loaded == {"use_proxy_default": True, "auto_upload_cpa": True, "worker_count": 4}


def test_delete_accounts_removes_only_selected_account_and_dependents(tmp_path: Path):
    database = Database(tmp_path / "tool.db")
    database.initialize()
    repository = Repository(database)
    repository.import_accounts([
        {"email": "keep@example.com", "password": "pw", "client_id": "cid", "mailbox_refresh_token": "a" * 20},
        {"email": "delete@example.com", "password": "pw", "client_id": "cid", "mailbox_refresh_token": "b" * 20},
    ])
    deleted = repository.get_account_by_email("delete@example.com")
    kept = repository.get_account_by_email("keep@example.com")
    assert deleted and kept
    repository.save_token(deleted["id"], {"email": deleted["email"], "access_token": "access", "refresh_token": "refresh"})
    repository.save_quota(deleted["id"], {"status": "success", "credits_balance": 100, "credits_balance_display": "100"})
    repository.save_upload_statuses("cpa", [{"id": deleted["id"], "email": deleted["email"]}], {
        "items": [{"email": deleted["email"], "uploaded": True}],
    })
    job = repository.create_job(deleted["id"], False)
    result = repository.delete_accounts([deleted["id"], "missing-id", deleted["id"]])
    assert result == {"requested": 2, "deleted": 1, "skipped": 1}
    assert repository.get_account(deleted["id"]) is None
    assert repository.get_account(kept["id"]) is not None
    assert repository.token_rows([deleted["id"]]) == []
    assert repository.get_job(job["id"]) is None
    with database.connect() as connection:
        assert connection.execute("SELECT COUNT(*) FROM account_uploads WHERE account_id=?", (deleted["id"],)).fetchone()[0] == 0


def test_job_records_redacted_proxy_endpoint(tmp_path: Path):
    database = Database(tmp_path / "tool.db")
    database.initialize()
    repository = Repository(database)
    repository.import_accounts([{
        "email": "proxy-job@example.com",
        "password": "pw",
        "client_id": "cid",
        "mailbox_refresh_token": "a" * 20,
    }])
    account = repository.get_account_by_email("proxy-job@example.com")
    assert account
    job = repository.create_job(account["id"], True)
    assert job["proxy_state"] == "requested"
    repository.update_job(job["id"], proxy_state="claimed", proxy_endpoint="socks5://proxy.example:1080")

    stored = repository.get_job(job["id"])
    assert stored
    assert stored["use_proxy"] == 1
    assert stored["proxy_state"] == "claimed"
    assert stored["proxy_endpoint"] == "socks5://proxy.example:1080"

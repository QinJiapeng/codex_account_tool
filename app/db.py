from __future__ import annotations

import json
import math
import re
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Mapping, Sequence


SCHEMA = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS accounts (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    client_id TEXT NOT NULL,
    mailbox_refresh_token TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    last_error TEXT NOT NULL DEFAULT '',
    last_authorized_at TEXT,
    liveness_status TEXT NOT NULL DEFAULT 'unknown',
    liveness_checked_at TEXT,
    liveness_http_status INTEGER NOT NULL DEFAULT 0,
    liveness_error_code TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL,
    access_token TEXT NOT NULL,
    refresh_token TEXT NOT NULL,
    id_token TEXT NOT NULL DEFAULT '',
    payload_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY(account_id) REFERENCES accounts(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS jobs (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    use_proxy INTEGER NOT NULL DEFAULT 0,
    proxy_state TEXT NOT NULL DEFAULT '',
    proxy_endpoint TEXT NOT NULL DEFAULT '',
    current_step TEXT NOT NULL DEFAULT 'queued',
    error TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT,
    updated_at TEXT NOT NULL,
    FOREIGN KEY(account_id) REFERENCES accounts(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_jobs_status_created ON jobs(status, created_at);
CREATE TABLE IF NOT EXISTS job_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id TEXT NOT NULL,
    level TEXT NOT NULL DEFAULT 'info',
    message TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY(job_id) REFERENCES jobs(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS quotas (
    account_id TEXT PRIMARY KEY,
    status TEXT NOT NULL DEFAULT 'pending',
    plan_type TEXT NOT NULL DEFAULT '',
    credits_balance REAL,
    credits_balance_display TEXT NOT NULL DEFAULT '',
    credits_has INTEGER NOT NULL DEFAULT 0,
    credits_unlimited INTEGER NOT NULL DEFAULT 0,
    used_percent REAL,
    reset_at TEXT NOT NULL DEFAULT '',
    reset_after_seconds INTEGER NOT NULL DEFAULT 0,
    http_status INTEGER NOT NULL DEFAULT 0,
    error_code TEXT NOT NULL DEFAULT '',
    error_message TEXT NOT NULL DEFAULT '',
    limit_windows_json TEXT NOT NULL DEFAULT '[]',
    checked_at TEXT,
    FOREIGN KEY(account_id) REFERENCES accounts(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS proxies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL UNIQUE,
    enabled INTEGER NOT NULL DEFAULT 1,
    lease_owner TEXT NOT NULL DEFAULT '',
    lease_until REAL NOT NULL DEFAULT 0,
    cooldown_until REAL NOT NULL DEFAULT 0,
    last_claim_at REAL NOT NULL DEFAULT 0,
    success_count INTEGER NOT NULL DEFAULT 0,
    failure_count INTEGER NOT NULL DEFAULT 0,
    last_error TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS preferences (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS account_uploads (
    account_id TEXT NOT NULL,
    platform TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    last_attempt_at TEXT NOT NULL,
    uploaded_at TEXT,
    error TEXT NOT NULL DEFAULT '',
    PRIMARY KEY(account_id, platform),
    FOREIGN KEY(account_id) REFERENCES accounts(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS scheduler_state (
    name TEXT PRIMARY KEY,
    status TEXT NOT NULL DEFAULT 'idle',
    checked_count INTEGER NOT NULL DEFAULT 0,
    valid_count INTEGER NOT NULL DEFAULT 0,
    invalid_count INTEGER NOT NULL DEFAULT 0,
    temporary_failed_count INTEGER NOT NULL DEFAULT 0,
    queued_count INTEGER NOT NULL DEFAULT 0,
    duplicate_count INTEGER NOT NULL DEFAULT 0,
    started_at TEXT,
    finished_at TEXT,
    last_error TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL
);
"""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


class Database:
    def __init__(self, path: str | Path):
        self.path = Path(path)

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path, timeout=30, check_same_thread=False)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 30000")
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def initialize(self) -> None:
        with self.connect() as connection:
            connection.executescript(SCHEMA)
            # ``CREATE TABLE IF NOT EXISTS`` does not add fields to an
            # existing local database. Keep narrow additive migrations here
            # so a tool upgrade preserves all runtime records.
            quota_columns = {str(row["name"]) for row in connection.execute("PRAGMA table_info(quotas)").fetchall()}
            if "limit_windows_json" not in quota_columns:
                connection.execute("ALTER TABLE quotas ADD COLUMN limit_windows_json TEXT NOT NULL DEFAULT '[]'")
            job_columns = {str(row["name"]) for row in connection.execute("PRAGMA table_info(jobs)").fetchall()}
            if "proxy_state" not in job_columns:
                connection.execute("ALTER TABLE jobs ADD COLUMN proxy_state TEXT NOT NULL DEFAULT ''")
            if "proxy_endpoint" not in job_columns:
                connection.execute("ALTER TABLE jobs ADD COLUMN proxy_endpoint TEXT NOT NULL DEFAULT ''")
            proxy_columns = {str(row["name"]) for row in connection.execute("PRAGMA table_info(proxies)").fetchall()}
            if "last_claim_at" not in proxy_columns:
                connection.execute("ALTER TABLE proxies ADD COLUMN last_claim_at REAL NOT NULL DEFAULT 0")
            account_columns = {str(row["name"]) for row in connection.execute("PRAGMA table_info(accounts)").fetchall()}
            if "liveness_status" not in account_columns:
                connection.execute("ALTER TABLE accounts ADD COLUMN liveness_status TEXT NOT NULL DEFAULT 'unknown'")
            if "liveness_checked_at" not in account_columns:
                connection.execute("ALTER TABLE accounts ADD COLUMN liveness_checked_at TEXT")
            if "liveness_http_status" not in account_columns:
                connection.execute("ALTER TABLE accounts ADD COLUMN liveness_http_status INTEGER NOT NULL DEFAULT 0")
            if "liveness_error_code" not in account_columns:
                connection.execute("ALTER TABLE accounts ADD COLUMN liveness_error_code TEXT NOT NULL DEFAULT ''")
            # Preserve previously observed deactivated accounts as a distinct
            # state after upgrading.  Older versions stored every authorization
            # error as ``failed``, which caused these terminal accounts to be
            # retried indefinitely.
            connection.execute(
                """
                UPDATE accounts
                   SET status='disabled'
                 WHERE lower(status)='failed'
                   AND (
                       instr(lower(last_error), 'account_deactivated') > 0
                       OR instr(lower(last_error), 'account_disabled') > 0
                       OR instr(lower(last_error), 'account disabled') > 0
                       OR instr(lower(last_error), 'has been deleted or deactivated') > 0
                   )
                """
            )


class Repository:
    PREFERENCE_KEYS = {
        "use_proxy_default",
        "auto_upload_cpa",
        "auto_upload_sub2api",
        "force_upload",
        "scheduled_liveness_enabled",
        "scheduled_liveness_interval_minutes",
        "worker_count",
        "cpa_api_url",
        "cpa_management_key",
        "cpa_api_timeout_seconds",
        "sub2api_api_url",
        "sub2api_admin_api_key",
        "sub2api_api_timeout_seconds",
        "sub2api_group_id",
    }

    def __init__(self, database: Database):
        self.db = database

    def load_preferences(self, defaults: dict[str, Any] | None = None) -> dict[str, Any]:
        """Load known local settings over environment-derived defaults."""

        result = dict(defaults or {})
        with self.db.connect() as connection:
            rows = connection.execute("SELECT key, value FROM preferences").fetchall()
        for row in rows:
            key = str(row["key"] or "")
            if key not in result:
                continue
            raw = str(row["value"] or "")
            if isinstance(result[key], bool):
                result[key] = raw == "1"
            elif isinstance(result[key], int):
                try:
                    result[key] = int(raw)
                except (TypeError, ValueError):
                    continue
            else:
                result[key] = raw
        return result

    def save_preferences(self, values: dict[str, Any]) -> None:
        """Persist only known settings in the ignored local runtime database."""

        now = utc_now()
        with self.db.connect() as connection:
            for key, value in values.items():
                if key not in self.PREFERENCE_KEYS:
                    continue
                if isinstance(value, bool):
                    encoded = "1" if value else "0"
                elif isinstance(value, int):
                    encoded = str(value)
                elif isinstance(value, str):
                    encoded = value
                else:
                    continue
                connection.execute(
                    """
                    INSERT INTO preferences(key, value, updated_at) VALUES(?,?,?)
                    ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at
                    """,
                    (str(key), encoded, now),
                )

    def get_scheduler_state(self, name: str = "liveness") -> dict[str, Any]:
        """Return the last non-sensitive scheduler result."""

        with self.db.connect() as connection:
            row = connection.execute(
                "SELECT * FROM scheduler_state WHERE name=?",
                (str(name),),
            ).fetchone()
        if row:
            return dict(row)
        return {
            "name": str(name),
            "status": "idle",
            "checked_count": 0,
            "valid_count": 0,
            "invalid_count": 0,
            "temporary_failed_count": 0,
            "queued_count": 0,
            "duplicate_count": 0,
            "started_at": "",
            "finished_at": "",
            "last_error": "",
            "updated_at": "",
        }

    def save_scheduler_state(self, name: str = "liveness", **values: Any) -> None:
        """Persist aggregate scheduler state without account credentials."""

        current = self.get_scheduler_state(name)
        status = str(values.get("status", current["status"]) or "idle")[:40]
        counts = {
            key: max(0, int(values.get(key, current[key]) or 0))
            for key in (
                "checked_count",
                "valid_count",
                "invalid_count",
                "temporary_failed_count",
                "queued_count",
                "duplicate_count",
            )
        }
        started_at = str(values.get("started_at", current["started_at"]) or "")[:80]
        finished_at = str(values.get("finished_at", current["finished_at"]) or "")[:80]
        last_error = str(values.get("last_error", current["last_error"]) or "").replace("\r", " ").replace("\n", " ")[:500]
        now = utc_now()
        with self.db.connect() as connection:
            connection.execute(
                """
                INSERT INTO scheduler_state(
                    name,status,checked_count,valid_count,invalid_count,
                    temporary_failed_count,queued_count,duplicate_count,
                    started_at,finished_at,last_error,updated_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(name) DO UPDATE SET
                    status=excluded.status,
                    checked_count=excluded.checked_count,
                    valid_count=excluded.valid_count,
                    invalid_count=excluded.invalid_count,
                    temporary_failed_count=excluded.temporary_failed_count,
                    queued_count=excluded.queued_count,
                    duplicate_count=excluded.duplicate_count,
                    started_at=excluded.started_at,
                    finished_at=excluded.finished_at,
                    last_error=excluded.last_error,
                    updated_at=excluded.updated_at
                """,
                (
                    str(name), status, counts["checked_count"], counts["valid_count"],
                    counts["invalid_count"], counts["temporary_failed_count"],
                    counts["queued_count"], counts["duplicate_count"],
                    started_at, finished_at, last_error, now,
                ),
            )

    @staticmethod
    def _public_account(row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
        return {
            "id": str(row["id"]),
            "email": str(row["email"]),
            "status": str(row["status"]),
            "last_error": str(row["last_error"] or ""),
            "last_authorized_at": row["last_authorized_at"] or "",
            "liveness_status": str(row["liveness_status"] or "unknown"),
            "liveness_checked_at": row["liveness_checked_at"] or "",
            "liveness_http_status": int(row["liveness_http_status"] or 0),
            "liveness_error_code": str(row["liveness_error_code"] or ""),
            "has_token": bool(row.get("has_token", 0) if isinstance(row, dict) else row["has_token"]),
            "updated_at": row["updated_at"],
        }

    def import_accounts(self, records: list[dict[str, str]]) -> dict[str, int]:
        created = updated = 0
        now = utc_now()
        with self.db.connect() as connection:
            for record in records:
                existing = connection.execute("SELECT id FROM accounts WHERE email = ?", (record["email"],)).fetchone()
                account_id = str(existing["id"]) if existing else str(record.get("id") or uuid.uuid4().hex)
                connection.execute(
                    """
                    INSERT INTO accounts(id,email,password,client_id,mailbox_refresh_token,status,last_error,created_at,updated_at)
                    VALUES(?,?,?,?,?,'pending','',?,?)
                    ON CONFLICT(email) DO UPDATE SET
                      password=excluded.password, client_id=excluded.client_id,
                      mailbox_refresh_token=excluded.mailbox_refresh_token,
                      status=CASE WHEN accounts.status IN ('running','disabled') THEN accounts.status ELSE 'pending' END,
                      last_error=CASE WHEN accounts.status='disabled' THEN accounts.last_error ELSE '' END,
                      updated_at=excluded.updated_at
                    """,
                    (account_id, record["email"], record["password"], record["client_id"], record["mailbox_refresh_token"], now, now),
                )
                if existing:
                    updated += 1
                else:
                    created += 1
        return {"created": created, "updated": updated, "received": len(records)}

    def list_accounts(
        self,
        limit: int = 200,
        offset: int = 0,
        query: str = "",
        status: str = "",
    ) -> tuple[list[dict[str, Any]], int]:
        limit = min(max(int(limit), 1), 5000)
        offset = max(int(offset), 0)
        tokens = [token.lower() for token in str(query or "").split() if token.strip()]
        where_parts: list[str] = []
        params: list[Any] = []
        normalized_status = str(status or "").strip().lower()
        if normalized_status in {"pending", "running", "success", "failed", "disabled"}:
            where_parts.append("lower(a.status)=?")
            params.append(normalized_status)
        for token in tokens:
            where_parts.append(
                """(
                    instr(lower(a.email), ?) > 0
                    OR instr(lower(a.id), ?) > 0
                    OR instr(lower(a.status), ?) > 0
                    OR EXISTS (
                        SELECT 1 FROM quotas q
                        WHERE q.account_id=a.id AND instr(lower(COALESCE(q.plan_type, '')), ?) > 0
                    )
                )"""
            )
            params.extend([token, token, token, token])
        where = f"WHERE {' AND '.join(where_parts)}" if where_parts else ""
        with self.db.connect() as connection:
            total = int(connection.execute(f"SELECT COUNT(*) FROM accounts a {where}", params).fetchone()[0])
            rows = connection.execute(
                f"""
                SELECT a.*, EXISTS(SELECT 1 FROM tokens t WHERE t.account_id=a.id) AS has_token
                FROM accounts a
                {where}
                ORDER BY a.updated_at DESC, a.email
                LIMIT ? OFFSET ?
                """, [*params, limit, offset]
            ).fetchall()
            account_ids = [str(row["id"]) for row in rows]
            upload_rows: list[sqlite3.Row] = []
            if account_ids:
                marks = ",".join("?" for _ in account_ids)
                upload_rows = connection.execute(
                    f"SELECT account_id,platform,status,last_attempt_at,uploaded_at FROM account_uploads WHERE account_id IN ({marks})",
                    account_ids,
                ).fetchall()
        uploads_by_account: dict[str, dict[str, dict[str, Any]]] = {}
        for upload in upload_rows:
            uploads_by_account.setdefault(str(upload["account_id"]), {})[str(upload["platform"])] = {
                "status": str(upload["status"] or "pending"),
                "last_attempt_at": str(upload["last_attempt_at"] or ""),
                "uploaded_at": str(upload["uploaded_at"] or ""),
            }
        items = []
        for row in rows:
            item = self._public_account(row)
            item["upload_statuses"] = uploads_by_account.get(str(row["id"]), {})
            items.append(item)
        return items, total

    def get_account(self, account_id: str) -> dict[str, Any] | None:
        with self.db.connect() as connection:
            row = connection.execute("SELECT * FROM accounts WHERE id=?", (str(account_id),)).fetchone()
        return dict(row) if row else None

    def get_account_by_email(self, email: str) -> dict[str, Any] | None:
        with self.db.connect() as connection:
            row = connection.execute("SELECT * FROM accounts WHERE lower(email)=lower(?)", (email,)).fetchone()
        return dict(row) if row else None

    def account_ids_by_status(self, status: str) -> list[str]:
        """Return account ids in a specific authorization state."""

        normalized = str(status or "").strip().lower()
        if normalized not in {"pending", "running", "success", "failed", "disabled"}:
            return []
        with self.db.connect() as connection:
            rows = connection.execute(
                "SELECT id FROM accounts WHERE lower(status)=? ORDER BY updated_at DESC, email",
                (normalized,),
            ).fetchall()
        return [str(row["id"]) for row in rows]

    def delete_accounts(self, account_ids: Sequence[str]) -> dict[str, int]:
        """Delete only the explicitly selected accounts and dependent records."""

        normalized = list(dict.fromkeys(
            str(value or "").strip()
            for value in account_ids
            if str(value or "").strip()
        ))
        if not normalized:
            return {"requested": 0, "deleted": 0, "skipped": 0}
        marks = ",".join("?" for _ in normalized)
        with self.db.connect() as connection:
            existing = int(connection.execute(f"SELECT COUNT(*) FROM accounts WHERE id IN ({marks})", normalized).fetchone()[0])
            connection.execute(f"DELETE FROM accounts WHERE id IN ({marks})", normalized)
        return {"requested": len(normalized), "deleted": existing, "skipped": len(normalized) - existing}

    def delete_disabled_accounts(self) -> dict[str, int]:
        """Delete all accounts explicitly classified as deactivated."""

        with self.db.connect() as connection:
            deleted = int(connection.execute(
                "SELECT COUNT(*) FROM accounts WHERE lower(status)='disabled'"
            ).fetchone()[0])
            connection.execute("DELETE FROM accounts WHERE lower(status)='disabled'")
        return {"deleted": deleted}

    def save_upload_statuses(
        self,
        platform: str,
        records: Sequence[Mapping[str, Any]],
        result: Mapping[str, Any] | None = None,
        *,
        error: str = "",
    ) -> None:
        """Persist non-secret per-platform upload outcomes for account rows."""

        normalized_platform = str(platform or "").strip().lower()
        if normalized_platform not in {"cpa", "sub2api"}:
            raise ValueError("不支持的上传平台")
        result_items = result.get("items", []) if isinstance(result, Mapping) else []
        by_email: dict[str, Mapping[str, Any]] = {}
        if isinstance(result_items, list):
            for item in result_items:
                if not isinstance(item, Mapping):
                    continue
                email = str(item.get("email") or "").strip().lower()
                if email:
                    by_email[email] = item
        now = utc_now()
        fallback_error = str(error or "").replace("\r", " ").replace("\n", " ")[:300]
        with self.db.connect() as connection:
            for record in records:
                account_id = str(record.get("id") or "").strip()
                email = str(record.get("email") or "").strip().lower()
                if not account_id:
                    continue
                item = by_email.get(email)
                # A skipped row means the local success record is still valid;
                # do not turn it into a failure merely because it was filtered
                # out before the remote request.
                if item is not None and bool(item.get("skipped")):
                    continue
                uploaded = bool(item.get("uploaded")) if item is not None else False
                item_error = str(item.get("error") or "")[:300] if item is not None else fallback_error
                status = "success" if uploaded else "failed"
                uploaded_at = now if uploaded else None
                connection.execute(
                    """
                    INSERT INTO account_uploads(account_id,platform,status,last_attempt_at,uploaded_at,error)
                    VALUES(?,?,?,?,?,?)
                    ON CONFLICT(account_id,platform) DO UPDATE SET
                      status=excluded.status,
                      last_attempt_at=excluded.last_attempt_at,
                      uploaded_at=CASE WHEN excluded.status='success' THEN excluded.uploaded_at ELSE account_uploads.uploaded_at END,
                      error=excluded.error
                    """,
                    (account_id, normalized_platform, status, now, uploaded_at, "" if uploaded else item_error),
                )

    def reset_upload_statuses(self, platform: str) -> None:
        """Mark all rows for a platform as pending after its remote target changes."""

        normalized_platform = str(platform or "").strip().lower()
        if normalized_platform not in {"cpa", "sub2api"}:
            raise ValueError("不支持的上传平台")
        with self.db.connect() as connection:
            connection.execute(
                """
                UPDATE account_uploads
                   SET status='pending', last_attempt_at='', uploaded_at=NULL, error=''
                 WHERE platform=?
                """,
                (normalized_platform,),
            )

    def successful_upload_account_ids(self, platform: str, account_ids: Sequence[str]) -> set[str]:
        """Return account IDs already uploaded successfully to one platform.

        Upload state is deliberately scoped by platform.  A successful CPA
        upload must not suppress a Sub2API upload for the same account.
        """

        normalized_platform = str(platform or "").strip().lower()
        if normalized_platform not in {"cpa", "sub2api"}:
            raise ValueError("不支持的上传平台")
        normalized_ids = list(dict.fromkeys(
            str(value or "").strip()
            for value in account_ids
            if str(value or "").strip()
        ))
        if not normalized_ids:
            return set()
        marks = ",".join("?" for _ in normalized_ids)
        with self.db.connect() as connection:
            rows = connection.execute(
                f"SELECT account_id FROM account_uploads WHERE platform=? AND status='success' AND account_id IN ({marks})",
                [normalized_platform, *normalized_ids],
            ).fetchall()
        return {str(row["account_id"]) for row in rows}

    def update_account(self, account_id: str, *, status: str | None = None, error: str = "", authorized: bool = False) -> None:
        now = utc_now()
        fields = ["updated_at=?", "last_error=?"]
        values: list[Any] = [now, str(error or "")[:500]]
        if status is not None:
            fields.append("status=?")
            values.append(status)
        if authorized:
            fields.append("last_authorized_at=?")
            values.append(now)
        values.append(str(account_id))
        with self.db.connect() as connection:
            connection.execute(f"UPDATE accounts SET {', '.join(fields)} WHERE id=?", values)

    def update_mailbox_refresh_token(self, account_id: str, token: str) -> None:
        with self.db.connect() as connection:
            connection.execute("UPDATE accounts SET mailbox_refresh_token=?, updated_at=? WHERE id=?", (token, utc_now(), str(account_id)))

    def create_job(self, account_id: str, use_proxy: bool) -> dict[str, Any]:
        job_id = uuid.uuid4().hex
        now = utc_now()
        proxy_state = "requested" if use_proxy else "direct"
        with self.db.connect() as connection:
            connection.execute("INSERT INTO jobs(id,account_id,status,use_proxy,proxy_state,created_at,updated_at) VALUES(?,?, 'pending', ?, ?, ?, ?)", (job_id, str(account_id), int(use_proxy), proxy_state, now, now))
            row = connection.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
        return dict(row)

    def active_job(self, account_id: str) -> dict[str, Any] | None:
        with self.db.connect() as connection:
            row = connection.execute("SELECT * FROM jobs WHERE account_id=? AND status IN ('pending','running') ORDER BY created_at DESC LIMIT 1", (str(account_id),)).fetchone()
        return dict(row) if row else None

    def pending_job_ids(self) -> list[str]:
        with self.db.connect() as connection:
            rows = connection.execute("SELECT id FROM jobs WHERE status='pending' ORDER BY created_at, id").fetchall()
        return [str(row[0]) for row in rows]

    def recover_running_jobs(self) -> None:
        now = utc_now()
        with self.db.connect() as connection:
            connection.execute("UPDATE jobs SET status='pending', current_step='queued', updated_at=? WHERE status='running'", (now,))
            connection.execute("UPDATE accounts SET status='pending', updated_at=? WHERE status='running'", (now,))

    def get_job(self, job_id: str) -> dict[str, Any] | None:
        with self.db.connect() as connection:
            row = connection.execute("SELECT j.*, a.email FROM jobs j JOIN accounts a ON a.id=j.account_id WHERE j.id=?", (str(job_id),)).fetchone()
        return dict(row) if row else None

    def list_jobs(self, limit: int = 200) -> list[dict[str, Any]]:
        with self.db.connect() as connection:
            rows = connection.execute("SELECT j.*, a.email FROM jobs j JOIN accounts a ON a.id=j.account_id ORDER BY j.created_at DESC LIMIT ?", (min(max(int(limit), 1), 5000),)).fetchall()
        return [dict(row) for row in rows]

    def update_job(self, job_id: str, **changes: Any) -> None:
        allowed = {"status", "proxy_state", "proxy_endpoint", "current_step", "error", "started_at", "finished_at"}
        items = [(key, value) for key, value in changes.items() if key in allowed]
        if not items:
            return
        items.append(("updated_at", utc_now()))
        with self.db.connect() as connection:
            connection.execute(f"UPDATE jobs SET {', '.join(f'{key}=?' for key, _ in items)} WHERE id=?", [value for _, value in items] + [str(job_id)])

    def add_event(self, job_id: str, level: str, message: str) -> None:
        with self.db.connect() as connection:
            connection.execute("INSERT INTO job_events(job_id,level,message,created_at) VALUES(?,?,?,?)", (str(job_id), str(level), str(message)[:500], utc_now()))

    def list_events(self, job_id: str, limit: int = 200) -> list[dict[str, Any]]:
        with self.db.connect() as connection:
            rows = connection.execute("SELECT * FROM job_events WHERE job_id=? ORDER BY id DESC LIMIT ?", (str(job_id), min(max(int(limit), 1), 1000))).fetchall()
        return [dict(row) for row in rows]

    def save_token(self, account_id: str, payload: dict[str, Any]) -> None:
        email = str(payload.get("email") or "").strip().lower()
        access = str(payload.get("access_token") or "").strip()
        refresh = str(payload.get("refresh_token") or "").strip()
        if not email or not access or not refresh:
            raise ValueError("授权结果缺少必要 Token")
        safe = {key: str(payload.get(key) or "") for key in ("email", "access_token", "refresh_token", "id_token", "session_token", "device_id", "cookie_header", "account_id", "chatgpt_account_id", "client_id")}
        safe["type"] = "codex"
        now = utc_now()
        with self.db.connect() as connection:
            connection.execute(
                """
                INSERT INTO tokens(account_id,email,access_token,refresh_token,id_token,payload_json,created_at,updated_at)
                VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(account_id) DO UPDATE SET
                  email=excluded.email, access_token=excluded.access_token, refresh_token=excluded.refresh_token,
                  id_token=excluded.id_token, payload_json=excluded.payload_json, updated_at=excluded.updated_at
                """, (str(account_id), email, access, refresh, safe["id_token"], json.dumps(safe, ensure_ascii=False, separators=(",", ":")), now, now)
            )
            # A refreshed OAuth token must be uploaded again. Keep the rows so
            # the UI can show a pending state. The successful OAuth exchange
            # also establishes a valid token; later model-list validation may
            # replace this optimistic state with a more specific result.
            connection.execute(
                """
                UPDATE account_uploads
                   SET status='pending', last_attempt_at='', uploaded_at=NULL, error=''
                 WHERE account_id=?
                """,
                (str(account_id),),
            )
            connection.execute(
                """
                UPDATE accounts
                   SET liveness_status='valid', liveness_checked_at=NULL,
                       liveness_http_status=0, liveness_error_code='', updated_at=?
                 WHERE id=?
                """,
                (now, str(account_id)),
            )
        self.update_account(account_id, status="success", error="", authorized=True)

    def save_liveness_result(self, account_id: str, result: Mapping[str, Any]) -> None:
        """Persist a safe per-account liveness outcome without credentials."""

        try:
            http_status = max(0, int(result.get("http_status") or 0))
        except (TypeError, ValueError, OverflowError):
            http_status = 0
        if bool(result.get("success")):
            status = "valid"
        elif bool(result.get("terminal")) or http_status == 401 or str(result.get("status") or "").lower() in {"invalid", "unauthorized"}:
            status = "invalid"
        else:
            raw_status = str(result.get("status") or "temporary_failed").strip().lower()
            status = raw_status if raw_status in {"forbidden", "rate_limited"} else "temporary_failed"
        with self.db.connect() as connection:
            connection.execute(
                """
                UPDATE accounts
                   SET liveness_status=?, liveness_checked_at=?,
                       liveness_http_status=?, liveness_error_code=?
                 WHERE id=?
                """,
                (
                    status,
                    utc_now(),
                    http_status,
                    str(result.get("error_code") or "")[:100],
                    str(account_id),
                ),
            )

    def token_rows(self, account_ids: Sequence[int | str] | None = None) -> list[dict[str, Any]]:
        with self.db.connect() as connection:
            if account_ids is None:
                rows = connection.execute("SELECT t.*, a.email AS account_email FROM tokens t JOIN accounts a ON a.id=t.account_id ORDER BY t.email").fetchall()
            else:
                ids = [str(value) for value in account_ids]
                if not ids:
                    return []
                marks = ",".join("?" for _ in ids)
                rows = connection.execute(f"SELECT t.*, a.email AS account_email FROM tokens t JOIN accounts a ON a.id=t.account_id WHERE t.account_id IN ({marks}) ORDER BY t.email", ids).fetchall()
        return [dict(row) for row in rows]

    def export_account_records(self, account_ids: Sequence[str] | None = None) -> list[dict[str, Any]]:
        """Return complete authorized records only for an explicit export.

        Account and token list endpoints intentionally stay credential-free.
        This method is used exclusively by the download/upload routes after an
        operator action, and joins only rows that already have a saved OAuth
        token.  The current mailbox refresh token is included for the four-
        segment export so a rotated Outlook token is not stale.
        """

        params: list[Any] = []
        where = ""
        if account_ids is not None:
            normalized = list(dict.fromkeys(
                str(value or "").strip()
                for value in account_ids
                if str(value or "").strip()
            ))
            if not normalized:
                return []
            marks = ",".join("?" for _ in normalized)
            where = f"WHERE a.id IN ({marks})"
            params.extend(normalized)
        with self.db.connect() as connection:
            rows = connection.execute(
                f"""
                SELECT a.id, a.email, a.password, a.client_id,
                       a.mailbox_refresh_token, t.access_token,
                       t.refresh_token, t.id_token, t.payload_json,
                       t.updated_at AS token_updated_at
                FROM accounts AS a
                JOIN tokens AS t ON t.account_id = a.id
                {where}
                ORDER BY a.email ASC
                """,
                params,
            ).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            try:
                payload = json.loads(row["payload_json"] or "{}")
            except (TypeError, ValueError, json.JSONDecodeError):
                payload = {}
            if not isinstance(payload, dict):
                payload = {}
            # Only OAuth fields are copied from payload_json.  Mailbox
            # credentials never enter CPA/Sub2API objects.
            safe_payload = {
                key: str(payload.get(key) or "")
                for key in (
                    "access_token", "refresh_token", "id_token", "email",
                    "account_id", "chatgpt_account_id", "client_id",
                )
                if payload.get(key)
            }
            safe_payload.setdefault("email", str(row["email"] or "").strip().lower())
            safe_payload.setdefault("access_token", str(row["access_token"] or ""))
            safe_payload.setdefault("refresh_token", str(row["refresh_token"] or ""))
            safe_payload.setdefault("id_token", str(row["id_token"] or ""))
            result.append({
                "id": str(row["id"] or ""),
                "email": str(row["email"] or "").strip().lower(),
                "password": str(row["password"] or ""),
                "client_id": str(row["client_id"] or ""),
                "mailbox_refresh_token": str(row["mailbox_refresh_token"] or ""),
                "token": safe_payload,
                "token_updated_at": str(row["token_updated_at"] or ""),
            })
        return result

    def save_quota(self, account_id: str, result: dict[str, Any]) -> None:
        now = utc_now()
        raw_windows = result.get("limit_windows")
        safe_windows: list[dict[str, Any]] = []
        if isinstance(raw_windows, list):
            for item in raw_windows[:12]:
                if not isinstance(item, Mapping):
                    continue
                safe: dict[str, Any] = {}
                label = str(item.get("label") or "").strip()[:60]
                if label:
                    safe["label"] = label
                for key in ("used_percent", "limit", "remaining"):
                    value = item.get(key)
                    if isinstance(value, bool):
                        continue
                    try:
                        safe[key] = float(value) if value is not None else None
                    except (TypeError, ValueError, OverflowError):
                        safe[key] = None
                for key in ("limit_display", "remaining_display", "reset_at"):
                    safe[key] = str(item.get(key) or "")[:120]
                try:
                    safe["reset_after_seconds"] = max(0, int(item.get("reset_after_seconds") or 0))
                except (TypeError, ValueError, OverflowError):
                    safe["reset_after_seconds"] = 0
                reached = item.get("limit_reached")
                safe["limit_reached"] = reached if isinstance(reached, bool) else None
                if safe.get("label"):
                    safe_windows.append(safe)
        windows_json = json.dumps(safe_windows, ensure_ascii=False, separators=(",", ":"))
        with self.db.connect() as connection:
            connection.execute(
                """
                INSERT INTO quotas(account_id,status,plan_type,credits_balance,credits_balance_display,credits_has,credits_unlimited,used_percent,reset_at,reset_after_seconds,http_status,error_code,error_message,limit_windows_json,checked_at)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(account_id) DO UPDATE SET
                  status=excluded.status, plan_type=excluded.plan_type, credits_balance=excluded.credits_balance,
                  credits_balance_display=excluded.credits_balance_display, credits_has=excluded.credits_has,
                  credits_unlimited=excluded.credits_unlimited, used_percent=excluded.used_percent,
                  reset_at=excluded.reset_at, reset_after_seconds=excluded.reset_after_seconds,
                  http_status=excluded.http_status, error_code=excluded.error_code,
                  error_message=excluded.error_message, limit_windows_json=excluded.limit_windows_json,
                  checked_at=excluded.checked_at
                """,
                (str(account_id), result.get("status", "failed"), result.get("plan_type", ""), result.get("credits_balance"), result.get("credits_balance_display", ""), int(bool(result.get("credits_has"))), int(bool(result.get("credits_unlimited"))), result.get("used_percent"), result.get("reset_at", ""), int(result.get("reset_after_seconds") or 0), int(result.get("http_status") or 0), result.get("error_code", ""), result.get("error_message", ""), windows_json, now),
            )

    def list_quotas(self, limit: int = 200, offset: int = 0) -> tuple[list[dict[str, Any]], int]:
        limit = min(max(int(limit), 1), 5000)
        offset = max(int(offset), 0)
        with self.db.connect() as connection:
            total = int(connection.execute("SELECT COUNT(*) FROM tokens").fetchone()[0])
            rows = connection.execute("SELECT a.id,a.email,a.status AS account_status,q.* FROM accounts a JOIN tokens t ON t.account_id=a.id LEFT JOIN quotas q ON q.account_id=a.id ORDER BY a.email LIMIT ? OFFSET ?", (limit, offset)).fetchall()
        items: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            try:
                windows = json.loads(item.pop("limit_windows_json", "[]") or "[]")
            except (TypeError, ValueError, json.JSONDecodeError):
                windows = []
            item["limit_windows"] = self.normalize_legacy_limit_windows(windows, item.get("plan_type"))
            item["plan_label"] = self.plan_label(item.get("plan_type"))
            items.append(item)
        return items, total

    def failed_quota_account_ids(self) -> list[str]:
        """Return authorized accounts whose latest quota check failed."""

        with self.db.connect() as connection:
            rows = connection.execute(
                """
                SELECT q.account_id
                FROM quotas AS q
                JOIN tokens AS t ON t.account_id=q.account_id
                WHERE lower(COALESCE(q.status, '')) NOT IN ('success', 'pending', 'running', '')
                ORDER BY q.checked_at DESC, q.account_id
                """
            ).fetchall()
        return [str(row["account_id"]) for row in rows]

    @staticmethod
    def plan_label(plan_type: Any) -> str:
        normalized = re.sub(r"[^a-z0-9]+", "_", str(plan_type or "").strip().lower()).strip("_")
        if "plus" in normalized:
            return "Plus"
        if "free" in normalized:
            return "Free"
        if "pro" in normalized:
            return "Pro"
        if "team" in normalized:
            return "Team"
        if "enterprise" in normalized:
            return "Enterprise"
        return ""

    @classmethod
    def normalize_legacy_limit_windows(cls, windows: Any, plan_type: Any) -> list[dict[str, Any]]:
        """Correct old Free primary windows that were saved with a hard-coded 5h label."""

        if not isinstance(windows, list):
            return []
        normalized: list[dict[str, Any]] = []
        for value in windows:
            if not isinstance(value, Mapping):
                continue
            window = dict(value)
            try:
                reset_after = int(window.get("reset_after_seconds") or 0)
            except (TypeError, ValueError, OverflowError):
                reset_after = 0
            if cls.plan_label(plan_type) == "Free" and str(window.get("label") or "").strip().lower() == "5h" and reset_after > 7 * 24 * 60 * 60:
                window["label"] = "Monthly"
            normalized.append(window)
        return normalized

    def quota_summary(self) -> dict[str, Any]:
        """Return aggregate quota counters without exposing credential fields."""

        with self.db.connect() as connection:
            account_total = int(connection.execute("SELECT COUNT(*) FROM accounts").fetchone()[0])
            rows = connection.execute(
                """
                SELECT t.account_id, q.status, q.plan_type, q.credits_balance,
                       q.credits_unlimited, q.credits_has, q.http_status,
                       q.limit_windows_json
                FROM tokens AS t
                LEFT JOIN quotas AS q ON q.account_id = t.account_id
                """
            ).fetchall()

        authorized = len(rows)
        fetched = pending = failed = exhausted = rate_limited = unlimited = 0
        total_credit = 0.0
        tier_counts = {"zero": 0, "low": 0, "medium": 0, "high": 0, "full": 0, "unlimited": 0}
        plan_counts = {"free": 0, "plus": 0, "pro": 0, "team": 0, "enterprise": 0, "unknown": 0}
        limit_accounts: set[str] = set()
        limit_stats: dict[str, dict[str, Any]] = {}
        for row in rows:
            plan = self.plan_label(row["plan_type"]).lower()
            plan_key = plan if plan in plan_counts else "unknown"
            plan_counts[plan_key] += 1
            try:
                raw_windows = json.loads(row["limit_windows_json"] or "[]")
            except (TypeError, ValueError, json.JSONDecodeError):
                raw_windows = []
            normalized_windows = self.normalize_legacy_limit_windows(raw_windows, row["plan_type"])
            if normalized_windows:
                limit_accounts.add(str(row["account_id"]))
                for window in normalized_windows:
                    label = str(window.get("label") or "限额").strip()[:60]
                    if not label:
                        continue
                    stats = limit_stats.setdefault(label, {"count": 0, "used_total": 0.0, "used_count": 0, "limit_reached": 0})
                    stats["count"] += 1
                    try:
                        used = float(window.get("used_percent"))
                        if math.isfinite(used):
                            stats["used_total"] += used
                            stats["used_count"] += 1
                    except (TypeError, ValueError, OverflowError):
                        pass
                    if window.get("limit_reached") is True:
                        stats["limit_reached"] += 1
            status = str(row["status"] or "").strip().lower()
            if not status or status in {"pending", "running"}:
                pending += 1
                continue
            if status != "success":
                failed += 1
                if int(row["http_status"] or 0) == 429 or status == "rate_limited":
                    rate_limited += 1
                continue
            fetched += 1
            if bool(row["credits_unlimited"]):
                unlimited += 1
                tier_counts["unlimited"] += 1
                continue
            try:
                balance = float(row["credits_balance"])
            except (TypeError, ValueError):
                balance = None
            if balance is None or not math.isfinite(balance):
                if not bool(row["credits_has"]):
                    exhausted += 1
                    tier_counts["zero"] += 1
                continue
            total_credit += balance
            if balance <= 0:
                exhausted += 1
                tier_counts["zero"] += 1
            elif balance < 100:
                tier_counts["low"] += 1
            elif balance < 500:
                tier_counts["medium"] += 1
            elif balance < 1000:
                tier_counts["high"] += 1
            else:
                tier_counts["full"] += 1

        tiers = [
            {"key": "full", "label": "1000+ Credit", "description": "高额度账号", "count": tier_counts["full"], "tone": "gold"},
            {"key": "high", "label": "500–999 Credit", "description": "中高额度账号", "count": tier_counts["high"], "tone": "blue"},
            {"key": "medium", "label": "100–499 Credit", "description": "中等额度账号", "count": tier_counts["medium"], "tone": "green"},
            {"key": "low", "label": "1–99 Credit", "description": "低额度账号", "count": tier_counts["low"], "tone": "orange"},
            {"key": "zero", "label": "0 Credit", "description": "额度用完", "count": tier_counts["zero"], "tone": "red"},
            {"key": "unlimited", "label": "无额度", "description": "", "count": tier_counts["unlimited"], "tone": "purple"},
        ]
        preferred_limit_order = {"5h": 0, "Weekly": 1, "Monthly": 2, "gpt-reserve Weekly": 3}
        limit_summary = []
        for label, stats in sorted(limit_stats.items(), key=lambda item: (preferred_limit_order.get(item[0], 99), item[0].lower())):
            average = (stats["used_total"] / stats["used_count"]) if stats["used_count"] else None
            limit_summary.append({
                "label": label,
                "count": int(stats["count"]),
                "average_used_percent": round(average, 2) if average is not None else None,
                "limit_reached": int(stats["limit_reached"]),
            })
        return {
            "account_total": account_total,
            "authorized": authorized,
            "fetched": fetched,
            "pending": pending,
            "failed": failed,
            "total_credit": round(total_credit, 2),
            "estimated_value": round(total_credit * 0.04, 2),
            "exhausted": exhausted,
            "rate_limited": rate_limited,
            "unlimited": unlimited,
            "plan_counts": plan_counts,
            "limit_accounts": len(limit_accounts),
            "limit_windows": limit_summary,
            "tiers": tiers,
        }

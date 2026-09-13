from __future__ import annotations

import os
import re
import uuid
from dataclasses import dataclass
from pathlib import Path
from time import time
from urllib.parse import urlsplit, urlunsplit

from app.db import Database, utc_now


SUPPORTED_SCHEMES = {"http", "https", "socks4", "socks5", "socks5h"}


class ProxyPoolError(RuntimeError):
    def __init__(self, message: str, code: str = "PROXY_POOL_ERROR"):
        super().__init__(message)
        self.code = code


@dataclass(slots=True)
class ProxyLease:
    id: int
    url: str
    owner: str


def normalize_proxy(value: str) -> str:
    raw = str(value or "").strip()
    if not raw:
        raise ProxyPoolError("代理地址不能为空", "PROXY_INVALID")
    if "://" not in raw:
        raw = "http://" + raw
    try:
        parts = urlsplit(raw)
        scheme = parts.scheme.lower()
        hostname = parts.hostname
        port = parts.port
    except ValueError as error:
        raise ProxyPoolError("代理地址格式无效，支持 http/https/socks4/socks5/socks5h，也可省略 http://", "PROXY_INVALID") from error
    if scheme not in SUPPORTED_SCHEMES or not hostname or not port:
        raise ProxyPoolError("代理地址格式无效，支持 http/https/socks4/socks5/socks5h，也可省略 http://", "PROXY_INVALID")
    host = hostname
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    auth = ""
    if parts.username is not None:
        auth = parts.username
        if parts.password is not None:
            auth += ":" + parts.password
        auth += "@"
    return urlunsplit((scheme, f"{auth}{host}:{port}", parts.path, parts.query, ""))


def redact_proxy(value: str) -> str:
    try:
        parts = urlsplit(value)
        host = parts.hostname or ""
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        authority = host + (f":{parts.port}" if parts.port else "")
        return urlunsplit((parts.scheme, authority, parts.path, "", ""))
    except ValueError:
        return "[invalid-proxy]"


class ProxyPool:
    def __init__(self, database: Database, *, lease_seconds: int = 900, cooldown_seconds: int = 60):
        self.db = database
        self.lease_seconds = max(60, int(lease_seconds))
        self.cooldown_seconds = max(5, int(cooldown_seconds))

    def import_text(self, text: str) -> dict[str, int]:
        values: list[str] = []
        invalid = duplicates = 0
        seen: set[str] = set()
        for line in re.split(r"[\r\n,;]+", str(text or "")):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                normalized = normalize_proxy(line)
            except ProxyPoolError:
                invalid += 1
                continue
            if normalized in seen:
                duplicates += 1
                continue
            seen.add(normalized)
            values.append(normalized)
        with self.db.connect() as connection:
            for value in values:
                connection.execute("INSERT OR IGNORE INTO proxies(url,updated_at) VALUES(?,?)", (value, utc_now()))
        return {"received": len(values) + duplicates + invalid, "imported": len(values), "invalid": invalid, "duplicates": duplicates}

    def load_from_environment(self) -> dict[str, int]:
        values = os.getenv("PROXY_LIST", "")
        file_name = os.getenv("PROXY_LIST_FILE", "").strip()
        if file_name:
            try:
                values += "\n" + Path(file_name).read_text(encoding="utf-8")
            except (OSError, UnicodeError):
                pass
        return self.import_text(values) if values.strip() else {"received": 0, "imported": 0, "invalid": 0, "duplicates": 0}

    def list_public(self, limit: int | None = None, offset: int = 0) -> list[dict[str, object]]:
        self.release_expired()
        if limit is not None:
            limit = min(max(int(limit), 1), 5000)
        offset = max(int(offset), 0)
        now = time()
        with self.db.connect() as connection:
            query = """
                SELECT id,url,enabled,lease_until,cooldown_until,success_count,failure_count,last_error
                FROM proxies
                ORDER BY
                    CASE
                        WHEN enabled=1 AND lease_until<=? AND cooldown_until<=? THEN 0
                        WHEN enabled=1 AND lease_until>? THEN 1
                        WHEN enabled=1 AND cooldown_until>? THEN 2
                        ELSE 3
                    END,
                    id
            """
            params: list[object] = [now, now, now, now]
            if limit is not None:
                query += " LIMIT ? OFFSET ?"
                params.extend([limit, offset])
            rows = connection.execute(query, params).fetchall()
        return [{"id": int(row["id"]), "endpoint": redact_proxy(row["url"]), "enabled": bool(row["enabled"]), "leased": float(row["lease_until"] or 0) > now, "cooling_down": float(row["cooldown_until"] or 0) > now, "success_count": int(row["success_count"]), "failure_count": int(row["failure_count"]), "last_error": str(row["last_error"] or "")[:200]} for row in rows]

    def stats(self) -> dict[str, int]:
        self.release_expired()
        now = time()
        with self.db.connect() as connection:
            row = connection.execute("SELECT COUNT(*) total, SUM(enabled) enabled, SUM(CASE WHEN enabled=1 AND lease_until<=? AND cooldown_until<=? THEN 1 ELSE 0 END) available FROM proxies", (now, now)).fetchone()
        return {"total": int(row["total"] or 0), "enabled": int(row["enabled"] or 0), "available": int(row["available"] or 0)}

    def release_expired(self) -> None:
        with self.db.connect() as connection:
            connection.execute("UPDATE proxies SET lease_owner='', lease_until=0, updated_at=? WHERE lease_until>0 AND lease_until<=?", (utc_now(), time()))

    def claim(self, owner: str) -> ProxyLease:
        self.release_expired()
        now = time()
        lease_until = now + self.lease_seconds
        with self.db.connect() as connection:
            # Serialize claims so concurrent workers cannot select the same
            # round-robin slot before either one records the new timestamp.
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute("SELECT id,url FROM proxies WHERE enabled=1 AND lease_until<=? AND cooldown_until<=? ORDER BY last_claim_at ASC, id ASC LIMIT 1", (now, now)).fetchone()
            if not row:
                raise ProxyPoolError("代理池当前没有可用代理", "PROXY_POOL_EMPTY")
            token = f"{owner}:{uuid.uuid4().hex[:8]}"
            changed = connection.execute("UPDATE proxies SET lease_owner=?,lease_until=?,last_claim_at=?,updated_at=? WHERE id=? AND lease_until<=? AND cooldown_until<=?", (token, lease_until, now, utc_now(), int(row["id"]), now, now)).rowcount
            if changed != 1:
                raise ProxyPoolError("代理池竞争失败，请重试", "PROXY_POOL_BUSY")
        return ProxyLease(int(row["id"]), str(row["url"]), token)

    def complete(self, lease: ProxyLease, *, success: bool, error: str = "") -> None:
        now = time()
        with self.db.connect() as connection:
            if success:
                connection.execute("UPDATE proxies SET lease_owner='',lease_until=0,success_count=success_count+1,last_error='',updated_at=? WHERE id=? AND lease_owner=?", (utc_now(), lease.id, lease.owner))
            else:
                connection.execute("UPDATE proxies SET lease_owner='',lease_until=0,cooldown_until=?,failure_count=failure_count+1,last_error=?,updated_at=? WHERE id=? AND lease_owner=?", (now + self.cooldown_seconds, str(error or "")[:200], utc_now(), lease.id, lease.owner))

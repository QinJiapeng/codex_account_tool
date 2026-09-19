from __future__ import annotations

import asyncio
import base64
import contextlib
import json
import logging
import re
import os
import io
import zipfile
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Mapping, Sequence
from urllib.parse import urlsplit, urlunsplit

from app.config import Settings
from app.db import Repository
from app.outlook.mail import OutlookMailClient, OutlookMailError
from app.pools.outlook_pool import OutlookAccount
from app.protocol.auth_flow import AuthFlow
from app.protocol.config import Config as ProtocolConfig
from app.oauth.codex_validator import create_codex_token_validator
from app.oauth.codex_usage import create_codex_usage_client
from app.proxy import ProxyLease, ProxyPool, ProxyPoolError, redact_proxy


logger = logging.getLogger(__name__)
DEFAULT_CODEX_CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"
# Five retries after the initial attempt, with a fixed cooldown between tries.
REAUTH_RETRY_DELAYS_SECONDS = (3.0,) * 5


class UploadConfigError(RuntimeError):
    """Raised when an optional remote upload destination is not configured."""


def _safe_download_part(value: Any) -> str:
    return re.sub(r"[^A-Za-z0-9._+@-]", "_", str(value or "account")).strip("._")[:180] or "account"


def _export_format(value: Any) -> str:
    normalized = str(value or "cpa").strip().lower()
    aliases = {
        "four_segment": "four-segment",
        "four-segment-txt": "four-segment",
        "email4": "four-segment",
        "email-4": "four-segment",
        "txt": "four-segment",
        "json": "cpa",
    }
    normalized = aliases.get(normalized, normalized)
    if normalized not in {"four-segment", "cpa", "sub2api"}:
        raise ValueError("导出格式必须是 four-segment、cpa 或 sub2api")
    return normalized


def _cpa_payload(record: Mapping[str, Any]) -> dict[str, Any]:
    token = record.get("token") if isinstance(record.get("token"), Mapping) else record
    email = str(record.get("email") or token.get("email") or "").strip().lower()
    access_token = str(token.get("access_token") or "").strip()
    refresh_token = str(token.get("refresh_token") or "").strip()
    if not email or not access_token or not refresh_token:
        raise ValueError(f"{email or '账号'} 缺少可刷新的 OAuth Token")
    id_token = str(token.get("id_token") or record.get("id_token") or "").strip()
    account_id = str(
        token.get("account_id")
        or token.get("chatgpt_account_id")
        or record.get("account_id")
        or record.get("chatgpt_account_id")
        or ""
    ).strip()
    client_id = str(token.get("client_id") or record.get("oauth_client_id") or DEFAULT_CODEX_CLIENT_ID).strip()
    payload: dict[str, Any] = {
        "type": "codex",
        "email": email,
        "access_token": access_token,
        "refresh_token": refresh_token,
        "id_token": id_token,
        "account_id": account_id,
        "client_id": client_id,
        "priority": 9999,
    }
    return payload


def _jwt_payload(token: Any) -> dict[str, Any]:
    """Decode a JWT payload without validating it or retaining its contents."""

    value = str(token or "").strip()
    parts = value.split(".")
    if len(parts) < 2:
        return {}
    try:
        padding = "=" * (-len(parts[1]) % 4)
        decoded = base64.urlsafe_b64decode((parts[1] + padding).encode("ascii"))
        payload = json.loads(decoded.decode("utf-8"))
    except (ValueError, UnicodeError, json.JSONDecodeError, base64.binascii.Error):
        return {}
    return payload if isinstance(payload, dict) else {}


def _jwt_auth(payload: Mapping[str, Any]) -> Mapping[str, Any]:
    value = payload.get("https://api.openai.com/auth")
    return value if isinstance(value, Mapping) else {}


def _jwt_profile(payload: Mapping[str, Any]) -> Mapping[str, Any]:
    value = payload.get("https://api.openai.com/profile")
    return value if isinstance(value, Mapping) else {}


def _iso_expiry(value: Any) -> str:
    try:
        numeric = float(value)
    except (TypeError, ValueError):
        numeric = 0
    if numeric:
        # JWT exp is expressed in seconds; tolerate millisecond timestamps too.
        if numeric > 100_000_000_000:
            numeric /= 1000
        try:
            return datetime.fromtimestamp(numeric, tz=timezone.utc).isoformat().replace("+00:00", "Z")
        except (OverflowError, OSError, ValueError):
            return ""
    if isinstance(value, str) and value.strip():
        text = value.strip()
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            return ""
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    return ""


def _email_key(email: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", email.lower()).strip("_")


def _sub2api_account(record: Mapping[str, Any], *, require_jwt: bool = False) -> dict[str, Any]:
    """Convert one CPA-shaped record using CPA2sub2API's OpenAI rules."""

    payload = _cpa_payload(record)
    access_payload = _jwt_payload(payload["access_token"])
    id_payload = _jwt_payload(payload["id_token"])
    email_hint = str(payload.get("email") or "账号").strip().lower()
    if require_jwt and not access_payload:
        raise ValueError(f"{email_hint} 的 access_token 不是有效 JWT，无法导出 Sub2API")
    if require_jwt and not id_payload:
        raise ValueError(f"{email_hint} 的 id_token 不是有效 JWT，无法导出 Sub2API")
    access_auth = _jwt_auth(access_payload)
    id_auth = _jwt_auth(id_payload)
    access_profile = _jwt_profile(access_payload)
    account_id = str(
        payload.get("account_id")
        or access_auth.get("chatgpt_account_id")
        or id_auth.get("chatgpt_account_id")
        or ""
    ).strip()
    user_id = str(
        access_auth.get("chatgpt_user_id")
        or access_auth.get("user_id")
        or id_auth.get("chatgpt_user_id")
        or id_auth.get("user_id")
        or ""
    ).strip()
    email = str(
        payload["email"]
        or access_profile.get("email")
        or access_payload.get("email")
        or id_payload.get("email")
    ).strip().lower()
    expires_at = _iso_expiry(record.get("expired")) or _iso_expiry(access_payload.get("exp"))
    now = datetime.now(timezone.utc)
    expires_in = None
    if expires_at:
        try:
            expires_in = max(0, int((datetime.fromisoformat(expires_at.replace("Z", "+00:00")) - now).total_seconds()))
        except ValueError:
            expires_in = None
    credentials = {
        "access_token": payload["access_token"],
        "refresh_token": payload["refresh_token"],
        "email": email,
        "id_token": payload["id_token"],
    }
    if account_id:
        credentials["chatgpt_account_id"] = account_id
    if user_id:
        credentials["chatgpt_user_id"] = user_id
    if expires_at:
        credentials["expires_at"] = expires_at
    if expires_in is not None:
        credentials["expires_in"] = expires_in
    plan_type = access_auth.get("chatgpt_plan_type") or id_auth.get("chatgpt_plan_type")
    if plan_type:
        credentials["plan_type"] = str(plan_type)
    organization_id = ""
    for auth in (id_auth, access_auth):
        organizations = auth.get("organizations")
        if not isinstance(organizations, list):
            continue
        preferred = next((item for item in organizations if isinstance(item, Mapping) and item.get("is_default") and item.get("id")), None)
        selected = preferred or next((item for item in organizations if isinstance(item, Mapping) and item.get("id")), None)
        if isinstance(selected, Mapping):
            organization_id = str(selected.get("id") or "").strip()
        if organization_id:
            break
    if organization_id:
        credentials["organization_id"] = organization_id
    last_refresh = _iso_expiry(record.get("last_refresh") or record.get("token_updated_at"))
    extra: dict[str, Any] = {
        "email": email,
        "email_key": _email_key(email),
    }
    if last_refresh:
        extra["last_refresh"] = last_refresh
    return {
        "name": email,
        "platform": "openai",
        "type": "oauth",
        "concurrency": 10,
        "priority": 1,
        "credentials": credentials,
        "extra": extra,
    }


def build_export_document(records: Sequence[Mapping[str, Any]], format: str = "cpa") -> tuple[bytes, str, str]:
    """Serialize authorized account records for an explicit download."""

    selected = _export_format(format)
    rows = list(records)
    if not rows:
        raise ValueError("没有已保存 OAuth Token 的账号可导出")
    if selected == "four-segment":
        lines: list[str] = []
        for record in rows:
            fields = (
                str(record.get("email") or "").strip(),
                str(record.get("password") or "").strip(),
                str(record.get("client_id") or "").strip(),
                str(record.get("mailbox_refresh_token") or "").strip(),
            )
            if not all(fields):
                raise ValueError(f"{fields[0] or '账号'} 缺少邮箱四段凭据")
            lines.append("----".join(fields))
        content = ("\ufeff" + "\n".join(lines) + ("\n" if lines else "")).encode("utf-8")
        return content, "text/plain; charset=utf-8", f"codex-account-four-segment-{len(lines)}.txt"

    if selected == "sub2api":
        # Sub2API 导入器识别的是“每个账号一个认证文件”的格式：文件本身
        # 是包含单个 accounts 元素的 JSON，而不是带 type/version 的批量封装。
        archive = io.BytesIO()
        used: set[str] = set()
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
            for record in rows:
                account = _sub2api_account(record, require_jwt=True)
                document = {
                    "exported_at": datetime.now(timezone.utc).isoformat(),
                    "proxies": [],
                    "accounts": [account],
                    "original_email": str(record.get("original_email") or account["name"]).strip().lower(),
                }
                base = f"sub2api-{_safe_download_part(account.get('name'))}"
                filename = f"{base}.sub2api.json"
                suffix = 2
                while filename.lower() in used:
                    filename = f"{base}-{suffix}.sub2api.json"
                    suffix += 1
                used.add(filename.lower())
                bundle.writestr(filename, json.dumps(document, ensure_ascii=False, indent=2) + "\n")
        return archive.getvalue(), "application/zip", f"sub2api-{len(rows)}-accounts.zip"

    payloads = [_cpa_payload(record) for record in rows]
    archive = io.BytesIO()
    used: set[str] = set()
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
        for payload in payloads:
            base = f"codex-{_safe_download_part(payload.get('email'))}-free"
            filename = f"{base}.json"
            suffix = 2
            while filename.lower() in used:
                filename = f"{base}-{suffix}.json"
                suffix += 1
            used.add(filename.lower())
            bundle.writestr(filename, json.dumps(payload, ensure_ascii=False, indent=2) + "\n")
    return archive.getvalue(), "application/zip", f"codex-free-{len(payloads)}-accounts.zip"


def normalize_upload_url(value: Any, label: str, *, allow_empty: bool = False) -> str:
    raw = str(value or "").strip().rstrip("/")
    if not raw:
        if allow_empty:
            return ""
        raise UploadConfigError(f"{label} 地址未配置")
    if len(raw) > 2048 or "\r" in raw or "\n" in raw:
        raise UploadConfigError(f"{label} 地址格式无效")
    try:
        parsed = urlsplit(raw)
    except ValueError as error:
        raise UploadConfigError(f"{label} 地址格式无效") from error
    if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.username or parsed.password:
        raise UploadConfigError(f"{label} 地址必须是不含账号密码的 HTTP 或 HTTPS 地址")
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), "", ""))


def _cli_proxy_endpoint(api_url: str | None = None) -> tuple[str, str]:
    raw = os.getenv("CLI_PROXY_API_URL", "") if api_url is None else api_url
    base = normalize_upload_url(raw, "CLI Proxy API")
    path = urlsplit(base).path.rstrip("/")
    if path.lower().endswith("/v0/management/auth-files"):
        return base, "CLI_PROXY"
    if path.lower().endswith("/v0/management"):
        return base + "/auth-files", "CLI_PROXY"
    marker = base.lower().find("/management.html")
    if marker >= 0:
        base = base[:marker]
    return base + "/v0/management/auth-files", "CLI_PROXY"


def _management_key(management_key: str | None = None) -> str:
    raw = management_key
    if raw is None:
        raw = str(
            os.getenv("CLI_PROXY_MANAGEMENT_KEY")
            or os.getenv("CLI_PROXY_API_TOKEN")
            or os.getenv("CLI_PROXY_MANAGEMENT_TOKEN")
            or ""
        )
    key = str(raw or "").strip()
    if not key:
        raise UploadConfigError("CLI Proxy 管理员密码未配置")
    if len(key) > 512 or "\r" in key or "\n" in key:
        raise UploadConfigError("CLI Proxy 管理员密码格式无效")
    return key


def split_upload_records(
    repository: Repository,
    platform: str,
    records: Sequence[Mapping[str, Any]],
    *,
    force: bool = False,
) -> tuple[list[Mapping[str, Any]], list[dict[str, Any]]]:
    """Split records into remote work and locally-known successful uploads.

    The local marker only protects against repeated clicks or scheduled runs
    in this tool; it is not a claim about state in a remote CPA/Sub2API
    installation.  ``force=True`` deliberately bypasses the marker.
    """

    rows = list(records)
    if force or not rows:
        return rows, []
    account_ids = [str(row.get("id") or "").strip() for row in rows]
    already_uploaded = repository.successful_upload_account_ids(platform, account_ids)
    pending: list[Mapping[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    for row in rows:
        account_id = str(row.get("id") or "").strip()
        if account_id and account_id in already_uploaded:
            skipped.append({
                "email": str(row.get("email") or "").strip().lower(),
                "uploaded": False,
                "skipped": True,
                "reason": "already_uploaded",
            })
        else:
            pending.append(row)
    return pending, skipped


def merge_upload_skip_result(result: Mapping[str, Any], skipped: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Add locally skipped rows to an upload response without counting them twice."""

    merged = dict(result)
    result_items = result.get("items", [])
    items = list(result_items) if isinstance(result_items, list) else []
    items.extend(dict(item) for item in skipped)
    merged["items"] = items
    merged["skipped"] = len(skipped)
    merged["requested"] = int(result.get("requested") or 0) + len(skipped)
    return merged


def skipped_upload_result(records: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Build a response when every selected row was already uploaded locally."""

    skipped = [
        {
            "email": str(row.get("email") or "").strip().lower(),
            "uploaded": False,
            "skipped": True,
            "reason": "already_uploaded",
        }
        for row in records
    ]
    return {"requested": len(skipped), "uploaded": 0, "failed": 0, "skipped": len(skipped), "items": skipped}


async def upload_cpa_records(
    records: Sequence[Mapping[str, Any]],
    *,
    api_url: str | None = None,
    management_key: str | None = None,
    timeout_seconds: int | float | None = None,
) -> dict[str, Any]:
    """Upload CPA files one-by-one to CLIProxyAPI without echoing secrets."""

    import httpx

    rows = list(records)
    if not rows:
        return {"requested": 0, "uploaded": 0, "failed": 0, "items": []}
    endpoint, _ = _cli_proxy_endpoint(api_url)
    key = _management_key(management_key)
    items: list[dict[str, Any]] = []
    try:
        raw_timeout = os.getenv("CLI_PROXY_API_TIMEOUT_SECONDS", "30") if timeout_seconds is None else timeout_seconds
        timeout = max(1.0, min(float(raw_timeout or 30), 120.0))
    except (TypeError, ValueError):
        timeout = 30.0
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
        for record in rows:
            email = str(record.get("email") or "").strip().lower()
            try:
                payload = _cpa_payload(record)
                filename = f"codex-{_safe_download_part(email)}-free.json"
                content = (json.dumps(payload, ensure_ascii=False) + "\n").encode("utf-8")
                response = await client.post(
                    endpoint,
                    headers={"Accept": "application/json", "Authorization": f"Bearer {key}"},
                    files={"file": (filename, content, "application/json")},
                )
                if response.status_code < 200 or response.status_code >= 300:
                    raise RuntimeError(f"CLI Proxy 上传失败（HTTP {response.status_code}）")
                items.append({"email": email, "uploaded": True, "filename": filename, "status_code": response.status_code})
            except Exception as error:
                items.append({"email": email, "uploaded": False, "error": safe_error(error)[:300]})
    return {
        "requested": len(rows),
        "uploaded": sum(1 for item in items if item.get("uploaded")),
        "failed": sum(1 for item in items if not item.get("uploaded")),
        "items": items,
    }


def _sub2api_endpoint(api_url: str | None = None) -> tuple[str, str]:
    raw = os.getenv("SUB2API_API_URL", "") if api_url is None else api_url
    base = normalize_upload_url(raw, "Sub2API")
    path = urlsplit(base).path.rstrip("/")
    if path.lower().endswith("/api/v1/admin/accounts/batch"):
        return base, "SUB2API"
    return base + "/api/v1/admin/accounts/batch", "SUB2API"


def _sub2api_key(admin_api_key: str | None = None) -> str:
    raw = admin_api_key
    if raw is None:
        raw = str(os.getenv("SUB2API_ADMIN_API_KEY") or os.getenv("SUB2API_API_KEY") or "")
    key = str(raw or "").strip()
    if not key:
        raise UploadConfigError("Sub2API 管理员 API Key 未配置")
    if len(key) > 512 or "\r" in key or "\n" in key:
        raise UploadConfigError("Sub2API 管理员 API Key 格式无效")
    return key


def _sub2api_accounts_endpoint(batch_endpoint: str) -> str:
    """Return the account collection endpoint from the batch endpoint."""

    marker = "/batch"
    if batch_endpoint.rstrip("/").lower().endswith(marker):
        return batch_endpoint.rstrip("/")[: -len(marker)]
    return batch_endpoint.rstrip("/")


def _sub2api_response_data(response: Any) -> Any:
    """Read the standard Sub2API response envelope without retaining secrets."""

    try:
        parser = getattr(response, "json", None)
        payload = parser() if callable(parser) else None
    except (TypeError, ValueError, json.JSONDecodeError, AttributeError):
        return None
    if isinstance(payload, Mapping) and "data" in payload:
        return payload.get("data")
    return payload


def _sub2api_existing_ids(data: Any, email: str) -> list[str]:
    """Extract exact name matches from list responses (search is substring-based)."""

    if isinstance(data, Mapping):
        items = data.get("items")
    else:
        items = data
    if not isinstance(items, list):
        return []
    normalized_email = str(email or "").strip().lower()
    result: list[str] = []
    for item in items:
        if not isinstance(item, Mapping):
            continue
        name = str(item.get("name") or item.get("email") or "").strip().lower()
        account_id = str(item.get("id") or "").strip()
        if name == normalized_email and account_id:
            result.append(account_id)
    return list(dict.fromkeys(result))


def _sub2api_created_ids(data: Any, email: str) -> list[str]:
    """Extract successfully-created account IDs from a batch-create response."""

    if isinstance(data, Mapping):
        items = data.get("results") or data.get("items")
    else:
        items = data
    if not isinstance(items, list):
        return []
    normalized_email = str(email or "").strip().lower()
    result: list[str] = []
    for item in items:
        if not isinstance(item, Mapping) or item.get("success") is False:
            continue
        name = str(item.get("name") or item.get("email") or "").strip().lower()
        account_id = str(item.get("id") or item.get("account_id") or "").strip()
        if account_id and (not name or name == normalized_email):
            result.append(account_id)
    return list(dict.fromkeys(result))


def _sub2api_test_result(response: Any) -> tuple[bool, int, bool, bool, str]:
    """Interpret the admin account-test SSE response without retaining its body."""

    status = int(getattr(response, "status_code", 0) or 0)
    if status < 200 or status >= 300:
        return False, status, False, False, ""
    text = str(getattr(response, "text", "") or "")
    saw_complete = False
    saw_error = False
    error_message = ""
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("data:"):
            continue
        try:
            event = json.loads(line[5:].strip())
        except (TypeError, ValueError, json.JSONDecodeError):
            continue
        if not isinstance(event, Mapping):
            continue
        if str(event.get("type") or "").strip().lower() == "error":
            saw_error = True
            error_message = safe_error(event.get("error") or event.get("message") or "")
        if str(event.get("type") or "").strip().lower() == "test_complete":
            saw_complete = bool(event.get("success"))
    return saw_complete and not saw_error, status, saw_complete, saw_error, error_message


async def upload_sub2api_records(
    records: Sequence[Mapping[str, Any]],
    *,
    api_url: str | None = None,
    admin_api_key: str | None = None,
    timeout_seconds: int | float | None = None,
    group_id: int | None = None,
) -> dict[str, Any]:
    """Upload authorized records, optionally assigning them to one group."""

    import httpx

    rows = list(records)
    if not rows:
        return {"requested": 0, "uploaded": 0, "failed": 0, "items": []}
    endpoint, _ = _sub2api_endpoint(api_url)
    key = _sub2api_key(admin_api_key)
    accounts = [_sub2api_account(record, require_jwt=True) for record in rows]
    normalized_group_id: int | None = None
    if group_id is not None:
        if isinstance(group_id, bool) or isinstance(group_id, float) and not group_id.is_integer():
            raise UploadConfigError("Sub2API 分组 ID 必须是正整数")
        try:
            normalized_group_id = int(group_id)
        except (TypeError, ValueError, OverflowError) as error:
            raise UploadConfigError("Sub2API 分组 ID 必须是正整数") from error
        if normalized_group_id <= 0 or normalized_group_id > 9_223_372_036_854_775_807:
            raise UploadConfigError("Sub2API 分组 ID 必须是正整数")
        for account in accounts:
            account["group_ids"] = [normalized_group_id]
    body = {"accounts": accounts}
    try:
        raw_timeout = os.getenv("SUB2API_API_TIMEOUT_SECONDS", "30") if timeout_seconds is None else timeout_seconds
        timeout = max(1.0, min(float(raw_timeout or 30), 120.0))
    except (TypeError, ValueError):
        timeout = 30.0
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "X-API-Key": key,
    }
    updated: list[dict[str, Any]] = []
    created: list[dict[str, Any]] = []
    pending_create: list[dict[str, Any]] = []
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
        accounts_endpoint = _sub2api_accounts_endpoint(endpoint)
        # The batch endpoint is create-only.  Repeated uploads would otherwise
        # leave duplicate email accounts and Sub2API could continue testing an
        # older, invalid credential.  Resolve exact email matches first and
        # replace their credentials through the normal account update endpoint.
        for account in accounts:
            email = str(account.get("name") or "").strip().lower()
            existing_ids: list[str] = []
            lookup = await client.get(
                accounts_endpoint,
                params={"page": 1, "page_size": 100, "search": email, "platform": "openai", "type": "oauth"},
                headers={"Accept": "application/json", "X-API-Key": key},
            )
            if 200 <= lookup.status_code < 300:
                existing_ids = _sub2api_existing_ids(_sub2api_response_data(lookup), email)
            elif lookup.status_code not in {404, 405}:
                raise RuntimeError(f"Sub2API 账号查询失败（HTTP {lookup.status_code}）")

            for account_id in existing_ids:
                update_payload: dict[str, Any] = {"credentials": account["credentials"]}
                if normalized_group_id is not None:
                    update_payload["group_ids"] = [normalized_group_id]
                update = await client.put(
                    f"{accounts_endpoint}/{account_id}",
                    headers=headers,
                    content=json.dumps(update_payload, ensure_ascii=False).encode("utf-8"),
                )
                if update.status_code < 200 or update.status_code >= 300:
                    raise RuntimeError(f"Sub2API 账号更新失败（HTTP {update.status_code}）")
                tested = await client.post(
                    f"{accounts_endpoint}/{account_id}/test",
                    headers=headers,
                    content=json.dumps({"model_id": "gpt-5.6-luna", "prompt": "hi"}, ensure_ascii=False).encode("utf-8"),
                )
                valid, test_status, saw_complete, saw_error, test_error = _sub2api_test_result(tested)
                if not valid:
                    suffix = f"：{test_error}" if test_error else ""
                    raise RuntimeError(
                        f"Sub2API 账号验活失败（HTTP {test_status or '未知'}，完成事件={'有' if saw_complete else '无'}，错误事件={'有' if saw_error else '无'}）{suffix}，请重新授权后再上传"
                    )

            if existing_ids:
                updated.append({
                    "email": email,
                    "uploaded": True,
                    "updated": True,
                    "validated": True,
                    "updated_accounts": len(existing_ids),
                })

            if not existing_ids:
                pending_create.append(account)
        if pending_create:
            response = await client.post(
                endpoint,
                headers={**headers, "Idempotency-Key": f"codex-account-tool-{uuid.uuid4().hex}"},
                content=json.dumps({"accounts": pending_create}, ensure_ascii=False).encode("utf-8"),
            )
            if response.status_code < 200 or response.status_code >= 300:
                raise RuntimeError(f"Sub2API 上传失败（HTTP {response.status_code}）")
            # BatchCreate returns the new numeric IDs.  Validate them too;
            # otherwise deleting an old duplicate and uploading again could
            # appear successful while the newly-created account still holds a
            # revoked OAuth token.
            created_data = _sub2api_response_data(response)
            for account in pending_create:
                email = str(account.get("name") or "").strip().lower()
                for account_id in _sub2api_created_ids(created_data, email):
                    tested = await client.post(
                        f"{accounts_endpoint}/{account_id}/test",
                        headers=headers,
                        content=json.dumps({"model_id": "gpt-5.6-luna", "prompt": "hi"}, ensure_ascii=False).encode("utf-8"),
                    )
                    valid, test_status, saw_complete, saw_error, test_error = _sub2api_test_result(tested)
                    if not valid:
                        suffix = f"：{test_error}" if test_error else ""
                        raise RuntimeError(
                            f"Sub2API 新账号验活失败（HTTP {test_status or '未知'}，完成事件={'有' if saw_complete else '无'}，错误事件={'有' if saw_error else '无'}）{suffix}，请重新授权后再上传"
                        )
            created.extend(
                {"email": str(account.get("name") or "").strip().lower(), "uploaded": True, "created": True}
                for account in pending_create
            )
    items = [*updated, *created]
    return {
        "requested": len(rows),
        "uploaded": len(rows),
        "failed": 0,
        "items": items or [{"email": str(row.get("email") or "").strip().lower(), "uploaded": True} for row in rows],
    }


def safe_error(value: Any) -> str:
    text = str(value or "").replace("\r", " ").replace("\n", " ").strip()
    text = re.sub(r"https?://\S+", "[redacted-url]", text, flags=re.I)
    text = re.sub(r"(?i)\bBearer\s+[^\s,;]+", "Bearer [redacted]", text)
    text = re.sub(r"(?i)\b(password|authorization|cookie|access[_ -]?token|refresh[_ -]?token|id[_ -]?token|api[_ -]?key|management[_ -]?key)\s*[:=]\s*[^\s,;]+", r"\1=[redacted]", text)
    text = re.sub(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b", "[redacted-token]", text)
    return re.sub(r"\s+", " ", text)[:500]


def account_is_disabled_error(value: Any) -> bool:
    """Recognize the explicit upstream signal for a deleted/deactivated account."""

    text = str(value or "").lower()
    return any(marker in text for marker in (
        "account_deactivated",
        "account_disabled",
        "account disabled",
        "has been deleted or deactivated",
    ))


def reauth_error_is_retryable(value: Any) -> bool:
    """Return whether an authorization error is likely to be transient.

    Full protocol login is safe to retry only for transport/upstream capacity
    failures.  Explicit account, password, region, and mailbox OAuth errors
    remain terminal so an automatic retry cannot hide a credential problem.
    """

    if account_is_disabled_error(value):
        return False
    if isinstance(value, OutlookMailError):
        return not value.terminal
    if isinstance(value, ProxyPoolError):
        return value.code in {"PROXY_POOL_EMPTY", "PROXY_POOL_BUSY"}

    text = str(value or "").strip().lower()
    if not text:
        return False
    terminal_markers = (
        "unsupported_country_region_territory",
        "invalid_grant",
        "invalid_client",
        "unauthorized_client",
        "interaction_required",
        "consent_required",
        "invalid_login",
        "invalid_credentials",
        "incorrect_password",
        "wrong_password",
        "password is incorrect",
        "未提供真实密码",
    )
    if any(marker in text for marker in terminal_markers):
        return False
    if re.search(r"\bhttp\s*(?:403|408|409|425|429|500|502|503|504|520|521|522|523|524)\b", text):
        return True
    transient_markers = (
        "timeout",
        "timed out",
        "超时",
        "network",
        "connection",
        "disconnected",
        "reset by peer",
        "proxy error",
        "tls",
        "ssl",
        "连接",
        "temporarily unavailable",
        "temporary failure",
        "rate_limit",
        "rate limit",
        "代理池当前没有可用代理",
        "代理池竞争失败",
    )
    return any(marker in text for marker in transient_markers)


def parse_four_segment_line(value: str) -> dict[str, str] | None:
    """Parse only ``email----password----client_id----refresh_token``.

    Email-only lines and six-field exports are intentionally rejected in v1;
    this keeps the first import contract explicit and prevents credentials
    from another application being silently misinterpreted.
    """

    raw = str(value or "").strip()
    if not raw or raw.startswith("#"):
        return None
    parts = [part.strip() for part in raw.split("----")]
    if len(parts) != 4:
        return None
    email, password, client_id, mailbox_refresh_token = parts
    email = email.lower()
    if not re.fullmatch(r"[^@\s]+@[^@\s]+", email):
        return None
    if not password or not client_id or len(mailbox_refresh_token) < 20:
        return None
    return {"email": email, "password": password, "client_id": client_id, "mailbox_refresh_token": mailbox_refresh_token}


def parse_import_text(text: str) -> tuple[list[dict[str, str]], int, int]:
    records: dict[str, dict[str, str]] = {}
    invalid = duplicates = 0
    for line in str(text or "").splitlines():
        if not line.strip() or line.strip().startswith("#"):
            continue
        record = parse_four_segment_line(line)
        if record is None:
            invalid += 1
            continue
        if record["email"] in records:
            duplicates += 1
        records[record["email"]] = record
    return list(records.values()), invalid, duplicates


class ReauthMailProvider:
    kind = "outlook-4-segment"
    pooled = False

    def __init__(self, account: dict[str, Any], repository: Repository, settings: Settings, proxy_url: str, emit, cancel_check):
        self.account = account
        self.repository = repository
        self.settings = settings
        self.proxy_url = proxy_url
        self.emit = emit
        self.cancel_check = cancel_check
        self._dead = False

    @property
    def exhausted(self) -> bool:
        return self._dead

    def create_mailbox(self) -> str:
        self.emit("info", "使用导入账号自身的 Outlook 邮箱接收验证码")
        return str(self.account["email"])

    def wait_for_otp(self, email: str, timeout: int = 120, issued_after: float | None = None) -> str:
        since = datetime.now(timezone.utc)
        if issued_after is not None:
            since = datetime.fromtimestamp(float(issued_after) - 5, tz=timezone.utc)
        mailbox = OutlookAccount(str(self.account["email"]), str(self.account["password"]), str(self.account["client_id"]), str(self.account["mailbox_refresh_token"]))
        try:
            code, rotated = asyncio.run(OutlookMailClient(imap_host=self.settings.outlook_imap_host, imap_port=self.settings.outlook_imap_port, proxy_url=self.proxy_url).poll_verification_code(mailbox, since=since, interval_seconds=self.settings.otp_poll_seconds, timeout_seconds=min(self.settings.otp_timeout_seconds, max(30, int(timeout))), cancel_check=self.cancel_check))
        except OutlookMailError as error:
            if error.code == "OUTLOOK_CODE_TIMEOUT":
                self._dead = True
            raise TimeoutError(str(error)) if error.code == "OUTLOOK_CODE_TIMEOUT" else error
        if rotated and rotated != self.account["mailbox_refresh_token"]:
            self.account["mailbox_refresh_token"] = rotated
            self.repository.update_mailbox_refresh_token(str(self.account["id"]), rotated)
        self.emit("info", "已收到邮箱验证码")
        return str(code)

    def mark_dead(self, reason: str = "") -> None:
        self._dead = True


class ReauthService:
    def __init__(self, repository: Repository, settings: Settings, proxy_pool: ProxyPool):
        self.repository = repository
        self.settings = settings
        self.proxy_pool = proxy_pool
        self.queue: asyncio.Queue[str] = asyncio.Queue()
        self._queued: set[str] = set()
        self._tasks: list[asyncio.Task[None]] = []
        self._executor = ThreadPoolExecutor(max_workers=settings.worker_count, thread_name_prefix="reauth")
        self._stopping = False

    @property
    def worker_count(self) -> int:
        """Number of workers currently running (used by the settings API)."""

        return len(self._tasks) or int(self.settings.worker_count)

    async def start(self) -> None:
        self.repository.recover_running_jobs()
        self._stopping = False
        self._tasks = [asyncio.create_task(self._worker(i), name=f"reauth-worker-{i + 1}") for i in range(self.settings.worker_count)]
        for job_id in self.repository.pending_job_ids():
            await self.submit(job_id)

    async def stop(self) -> None:
        self._stopping = True
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()
        self._executor.shutdown(wait=False, cancel_futures=False)

    async def submit(self, job_id: str) -> None:
        if job_id in self._queued:
            return
        self._queued.add(job_id)
        await self.queue.put(job_id)

    async def queue_accounts(
        self,
        account_ids: list[str] | None = None,
        *,
        use_proxy: bool = False,
        event_message: str = "",
    ) -> dict[str, Any]:
        if account_ids is None:
            accounts, _ = self.repository.list_accounts(limit=5000)
            account_ids = [str(item["id"]) for item in accounts]
        queued = duplicate = skipped = 0
        disabled_skipped = 0
        jobs = []
        for account_id in dict.fromkeys(str(value).strip() for value in account_ids if str(value).strip()):
            account = self.repository.get_account(account_id)
            if account is None:
                skipped += 1
                continue
            if str(account.get("status") or "").strip().lower() == "disabled":
                skipped += 1
                disabled_skipped += 1
                continue
            active = self.repository.active_job(account_id)
            if active:
                duplicate += 1
                jobs.append(active)
                continue
            job = self.repository.create_job(account_id, use_proxy)
            message = safe_error(event_message) if event_message else "已加入重新授权队列"
            self.repository.add_event(job["id"], "info", message)
            if event_message:
                self.repository.update_account(account_id, status="pending", error=message)
            jobs.append(job)
            queued += 1
            await self.submit(str(job["id"]))
        return {
            "queued": queued,
            "duplicate": duplicate,
            "skipped": skipped,
            "disabled_skipped": disabled_skipped,
            "use_proxy": bool(use_proxy),
            "jobs": jobs,
        }

    async def _worker(self, index: int) -> None:
        while not self._stopping:
            job_id = await self.queue.get()
            self._queued.discard(job_id)
            try:
                await self._run(job_id, index)
            except asyncio.CancelledError:
                raise
            except Exception as error:
                reason = safe_error(error)
                self.repository.update_job(job_id, status="failed", current_step="finished", error=reason, finished_at=utc_now())
                self.repository.add_event(job_id, "error", f"重新授权失败：{reason}")
            finally:
                self.queue.task_done()

    async def _run(self, job_id: str, worker_index: int) -> None:
        job = self.repository.get_job(job_id)
        if not job or job["status"] in {"success", "failed", "cancelled"}:
            return
        account = self.repository.get_account(str(job["account_id"]))
        if not account:
            self.repository.update_job(job_id, status="failed", current_step="finished", error="账号不存在", finished_at=utc_now())
            return
        if str(account.get("status") or "").strip().lower() == "disabled":
            message = "账号已禁用，跳过重新授权"
            self.repository.update_job(
                job_id,
                status="cancelled",
                current_step="finished",
                error=message,
                finished_at=utc_now(),
            )
            self.repository.add_event(job_id, "warning", message)
            return
        use_proxy = bool(job["use_proxy"])
        retry_count = len(REAUTH_RETRY_DELAYS_SECONDS)
        max_attempts = retry_count + 1
        started_at = utc_now()
        for attempt in range(max_attempts):
            self.repository.update_job(
                job_id,
                status="running",
                proxy_state="requested" if use_proxy else "direct",
                proxy_endpoint="",
                current_step="proxy" if use_proxy else "login",
                started_at=started_at,
                error="",
            )
            self.repository.update_account(account["id"], status="running", error="")
            try:
                await self._run_attempt(job_id, worker_index, account, use_proxy)
                return
            except asyncio.CancelledError:
                raise
            except Exception as error:
                error_message = safe_error(error)
                retryable = reauth_error_is_retryable(error)
                if retryable and attempt < retry_count:
                    delay = float(REAUTH_RETRY_DELAYS_SECONDS[attempt])
                    retry_number = attempt + 2
                    self.repository.update_job(
                        job_id,
                        status="pending",
                        current_step="queued",
                        proxy_state="requested" if use_proxy else "direct",
                        proxy_endpoint="",
                        error="",
                        finished_at=None,
                    )
                    self.repository.add_event(
                        job_id,
                        "warning",
                        f"授权暂时失败：{error_message or '未知临时错误'}，{delay:g} 秒后自动重试（第 {retry_number}/{max_attempts} 次）",
                    )
                    await asyncio.sleep(delay)
                    account = self.repository.get_account(str(account["id"])) or account
                    continue

                account_disabled = account_is_disabled_error(error)
                changes: dict[str, Any] = {
                    "status": "failed",
                    "current_step": "finished",
                    "error": error_message,
                    "finished_at": utc_now(),
                }
                if use_proxy and isinstance(error, ProxyPoolError):
                    changes["proxy_state"] = "failed"
                self.repository.update_job(job_id, **changes)
                self.repository.update_account(
                    account["id"],
                    status="disabled" if account_disabled else "failed",
                    error=error_message,
                )
                event_prefix = "检测到账号已禁用" if account_disabled else "重新授权失败"
                self.repository.add_event(job_id, "error", f"{event_prefix}：{error_message}")
                return

    async def _run_attempt(
        self,
        job_id: str,
        worker_index: int,
        account: dict[str, Any],
        use_proxy: bool,
    ) -> None:
        """Run one authorization attempt and release its proxy lease."""

        lease: ProxyLease | None = None
        success = False
        error_message = ""
        try:
            if use_proxy:
                self.repository.add_event(job_id, "info", "正在从代理池领取代理")
                lease = self.proxy_pool.claim(f"reauth:{job_id}:{worker_index}")
                proxy_endpoint = redact_proxy(lease.url)
                self.repository.update_job(job_id, current_step="login", proxy_state="claimed", proxy_endpoint=proxy_endpoint)
                self.repository.add_event(job_id, "info", f"已领取代理 {proxy_endpoint}，开始建立登录会话")
            else:
                self.repository.add_event(job_id, "info", "本次授权使用直连")
            loop = asyncio.get_running_loop()
            result = await loop.run_in_executor(self._executor, self._reauthorize_sync, account, lease.url if lease else "", job_id)
            self.repository.update_job(job_id, current_step="save_token")
            self.repository.save_token(account["id"], result)
            await self._auto_upload(account["id"], job_id)
            self.repository.update_job(job_id, status="success", current_step="finished", error="", finished_at=utc_now())
            self.repository.add_event(job_id, "info", "重新授权成功，Token 已保存")
            success = True
        except asyncio.CancelledError:
            raise
        except Exception as error:
            error_message = safe_error(error)
            if use_proxy and lease is None:
                self.repository.update_job(job_id, proxy_state="failed")
            raise
        finally:
            if lease:
                with contextlib.suppress(Exception):
                    self.proxy_pool.complete(lease, success=success, error=error_message)

    async def _auto_upload(self, account_id: str, job_id: str) -> None:
        """Optionally forward a newly authorized account without failing auth."""

        if not (self.settings.auto_upload_cpa or self.settings.auto_upload_sub2api):
            return
        records = self.repository.export_account_records([account_id])
        if not records:
            self.repository.add_event(job_id, "warning", "授权成功，但没有可上传的授权记录")
            return
        if self.settings.auto_upload_cpa:
            skipped: list[dict[str, Any]] = []
            try:
                upload_records, skipped = split_upload_records(self.repository, "cpa", records, force=bool(self.settings.force_upload))
                if not upload_records:
                    result = skipped_upload_result(records)
                else:
                    result = await upload_cpa_records(
                        upload_records,
                        api_url=self.settings.cpa_api_url,
                        management_key=self.settings.cpa_management_key,
                        timeout_seconds=self.settings.cpa_api_timeout_seconds,
                    )
                    result = merge_upload_skip_result(result, skipped)
                self.repository.save_upload_statuses("cpa", records, result)
                if result.get("failed"):
                    self.repository.add_event(job_id, "warning", f"授权成功，自动上传 CPA 失败 {result['failed']} 个")
                elif result.get("skipped"):
                    self.repository.add_event(job_id, "info", "授权成功，CPA 已是最新上传状态")
                else:
                    self.repository.add_event(job_id, "info", "授权成功，已自动上传 CPA")
            except Exception as error:
                with contextlib.suppress(Exception):
                    self.repository.save_upload_statuses("cpa", records, {"items": skipped}, error=safe_error(error))
                self.repository.add_event(job_id, "warning", f"授权成功，自动上传 CPA 失败：{safe_error(error)}")
        if self.settings.auto_upload_sub2api:
            skipped = []
            try:
                upload_records, skipped = split_upload_records(self.repository, "sub2api", records, force=bool(self.settings.force_upload))
                if not upload_records:
                    result = skipped_upload_result(records)
                else:
                    result = await upload_sub2api_records(
                        upload_records,
                        api_url=self.settings.sub2api_api_url,
                        admin_api_key=self.settings.sub2api_admin_api_key,
                        timeout_seconds=self.settings.sub2api_api_timeout_seconds,
                        group_id=self.settings.sub2api_group_id or None,
                    )
                    result = merge_upload_skip_result(result, skipped)
                self.repository.save_upload_statuses("sub2api", records, result)
                if result.get("failed"):
                    self.repository.add_event(job_id, "warning", f"授权成功，自动上传 Sub2API 失败 {result['failed']} 个")
                elif result.get("skipped"):
                    self.repository.add_event(job_id, "info", "授权成功，Sub2API 已是最新上传状态")
                else:
                    self.repository.add_event(job_id, "info", "授权成功，已自动上传 Sub2API")
            except Exception as error:
                with contextlib.suppress(Exception):
                    self.repository.save_upload_statuses("sub2api", records, {"items": skipped}, error=safe_error(error))
                self.repository.add_event(job_id, "warning", f"授权成功，自动上传 Sub2API 失败：{safe_error(error)}")

    def _reauthorize_sync(self, account: dict[str, Any], proxy_url: str, job_id: str) -> dict[str, Any]:
        self.repository.add_event(job_id, "info", "正在执行协议登录")
        flow = AuthFlow(ProtocolConfig(proxy=proxy_url or None), env_overrides={"OAUTH_CODEX_RT_EXCHANGE": "1", "OAUTH_CODEX_RT_BEFORE_CALLBACK": "1", "OAUTH_REQUIRE_REFRESH_TOKEN": "1", "OAUTH_TOKEN_EXCHANGE_FROM_CALLBACK": "0", "OAUTH_SECONDARY_AUTHORIZE_EXCHANGE": "0", "OAUTH_REFRESH_ONLY": "0", "OTP_TIMEOUT": str(self.settings.otp_timeout_seconds)})
        provider = ReauthMailProvider(account=account, repository=self.repository, settings=self.settings, proxy_url=proxy_url, emit=lambda level, message: self.repository.add_event(job_id, level, safe_error(message)), cancel_check=lambda: self._stopping)
        result = flow.run_protocol_login(provider, str(account["email"]), str(account["password"]))
        payload = result.to_dict()
        payload["email"] = str(payload.get("email") or account["email"])
        if not payload.get("access_token") or not payload.get("refresh_token"):
            raise RuntimeError("登录完成但未获取可刷新的 Codex Token")
        return payload


class QuotaService:
    def __init__(self, repository: Repository, settings: Settings, proxy_pool: ProxyPool):
        self.repository = repository
        self.settings = settings
        self.proxy_pool = proxy_pool
        self._lock = asyncio.Lock()
        self.progress: dict[str, Any] = {
            "running": False,
            "total": 0,
            "completed": 0,
            "success": 0,
            "failed": 0,
            "active_account_id": "",
            "active_account_ids": [],
        }

    async def refresh(self, account_ids: list[str] | None = None, *, use_proxy: bool = False) -> dict[str, Any]:
        async with self._lock:
            if self.progress["running"]:
                raise RuntimeError("额度查询正在进行")
            rows = self.repository.token_rows(account_ids)
            self.progress = {
                "running": True,
                "total": len(rows),
                "completed": 0,
                "success": 0,
                "failed": 0,
                "active_account_id": "",
                "active_account_ids": [],
            }
            results = []
            try:
                for row in rows:
                    lease = None
                    self.progress["active_account_id"] = str(row["account_id"])
                    self.progress["active_account_ids"] = [str(row["account_id"])]
                    try:
                        if use_proxy:
                            lease = self.proxy_pool.claim(f"quota:{row['account_id']}")
                        client = create_codex_usage_client(usage_url=self.settings.usage_url, client_version=self.settings.usage_version, timeout_ms=self.settings.quota_timeout_ms)
                        result = await client.query(row, proxy_url=lease.url if lease else None)
                        self.repository.save_quota(str(row["account_id"]), result)
                        result = {"account_id": row["account_id"], "email": row["email"], **result}
                        results.append(result)
                        self.progress["success"] += int(bool(result.get("success")))
                        self.progress["failed"] += int(not bool(result.get("success")))
                        if lease:
                            self.proxy_pool.complete(lease, success=bool(result.get("success")), error=str(result.get("error_message") or ""))
                    except Exception as error:
                        message = safe_error(error)
                        result = {"success": False, "status": "failed", "error_code": "QUOTA_FAILED", "error_message": message, "account_id": row["account_id"], "email": row["email"]}
                        self.repository.save_quota(str(row["account_id"]), result)
                        results.append(result)
                        self.progress["failed"] += 1
                        if lease:
                            self.proxy_pool.complete(lease, success=False, error=message)
                    self.progress["completed"] += 1
            finally:
                self.progress["running"] = False
                self.progress["active_account_id"] = ""
                self.progress["active_account_ids"] = []
            # Return the same aggregate view that the list endpoint exposes so
            # a manual refresh immediately reports Free/Plus and limit-window
            # counts without waiting for the next browser poll.
            return {"total": len(rows), "results": results, "summary": self.repository.quota_summary()}

    def get_progress(self) -> dict[str, Any]:
        return dict(self.progress)


def liveness_failure_is_terminal(result: Mapping[str, Any]) -> bool:
    """Apply the conservative invalid-token boundary to models validation.

    Only missing/expired credentials and an explicit upstream HTTP 401 are
    terminal. Permission errors, rate limits, malformed responses and network
    failures must not trigger a potentially expensive reauthorization.
    """

    if bool(result.get("success")):
        return False
    # The models validator exposes this explicit boundary for missing,
    # expired, or unauthorized credentials.  Keep the legacy status/code
    # checks below for compatible custom clients and older results.
    if result.get("terminal") is True:
        return True
    try:
        if int(result.get("http_status") or 0) == 401:
            return True
    except (TypeError, ValueError, OverflowError):
        pass
    status = str(result.get("status") or "").strip().lower()
    code = str(result.get("error_code") or "").strip().upper()
    return status in {"unauthorized", "invalid"} or code in {
        "TOKEN_MISSING",
        "TOKEN_EXPIRED",
        "TOKEN_EXPIRES_TOO_SOON",
        "TOKEN_INVALID",
        "TOKEN_UNAUTHORIZED",
        "CREDENTIAL_INVALID",
    }


class ScheduledLivenessService:
    """Periodically validate saved Codex tokens and reauthorize invalid ones."""

    STATE_NAME = "liveness"

    def __init__(
        self,
        repository: Repository,
        settings: Settings,
        proxy_pool: ProxyPool,
        reauth: ReauthService,
        *,
        client_factory: Callable[..., Any] | None = None,
    ) -> None:
        self.repository = repository
        self.settings = settings
        self.proxy_pool = proxy_pool
        self.reauth = reauth
        # Liveness is an authentication check, so use the Codex models
        # endpoint.  Quota refresh remains on create_codex_usage_client and
        # continues to use /backend-api/wham/usage.
        self.client_factory = client_factory or create_codex_token_validator
        self._task: asyncio.Task[None] | None = None
        self._wake = asyncio.Event()
        self._run_lock = asyncio.Lock()
        self._stopping = False
        self._next_run_at = ""

    async def start(self) -> None:
        if self._task and not self._task.done():
            return
        previous = self.repository.get_scheduler_state(self.STATE_NAME)
        if str(previous.get("status") or "") == "running":
            self.repository.save_scheduler_state(
                self.STATE_NAME,
                status="failed",
                finished_at=utc_now(),
                last_error="服务重启，上一次定时验活未完成",
            )
        self._stopping = False
        self._task = asyncio.create_task(self._loop(), name="scheduled-liveness")

    async def stop(self) -> None:
        self._stopping = True
        self._wake.set()
        if self._task:
            self._task.cancel()
            await asyncio.gather(self._task, return_exceptions=True)
        self._task = None
        self._next_run_at = ""

    def notify_configuration_changed(self) -> None:
        """Wake the timer so enablement and interval changes apply now."""

        self._wake.set()

    def get_status(self) -> dict[str, Any]:
        state = self.repository.get_scheduler_state(self.STATE_NAME)
        return {
            "enabled": bool(self.settings.scheduled_liveness_enabled),
            "interval_minutes": int(self.settings.scheduled_liveness_interval_minutes),
            "running": self._run_lock.locked(),
            "next_run_at": self._next_run_at,
            "last_run": {
                "status": str(state.get("status") or "idle"),
                "checked": int(state.get("checked_count") or 0),
                "valid": int(state.get("valid_count") or 0),
                "invalid": int(state.get("invalid_count") or 0),
                "temporary_failed": int(state.get("temporary_failed_count") or 0),
                "queued": int(state.get("queued_count") or 0),
                "duplicate": int(state.get("duplicate_count") or 0),
                "started_at": str(state.get("started_at") or ""),
                "finished_at": str(state.get("finished_at") or ""),
                "error": str(state.get("last_error") or ""),
            },
        }

    async def _loop(self) -> None:
        while not self._stopping:
            self._wake.clear()
            if not self.settings.scheduled_liveness_enabled:
                self._next_run_at = ""
                await self._wake.wait()
                continue
            interval_minutes = min(10_080, max(5, int(self.settings.scheduled_liveness_interval_minutes)))
            self._next_run_at = (
                datetime.now(timezone.utc) + timedelta(minutes=interval_minutes)
            ).isoformat(timespec="milliseconds")
            try:
                await asyncio.wait_for(self._wake.wait(), timeout=interval_minutes * 60)
                continue
            except TimeoutError:
                self._next_run_at = ""
            try:
                await self.run_once()
            except asyncio.CancelledError:
                raise
            except Exception as error:
                logger.error("定时验活执行失败：%s", type(error).__name__)

    async def _check_account(self, row: Mapping[str, Any], run_id: str) -> dict[str, Any]:
        lease: ProxyLease | None = None
        result: dict[str, Any] = {}
        try:
            if self.settings.use_proxy_default:
                lease = self.proxy_pool.claim(f"liveness:{run_id}:{row['account_id']}")
            client = self.client_factory(
                client_version=self.settings.usage_version,
                timeout_ms=self.settings.quota_timeout_ms,
            )
            # The production validator exposes validate()/valid, while the
            # fallback query() path keeps existing test/integration fakes
            # compatible with the scheduler contract.
            validate = getattr(client, "validate", None)
            if callable(validate):
                queried = await validate(row, proxy_url=lease.url if lease else None)
            else:
                query = getattr(client, "query", None)
                if not callable(query):
                    queried = None
                else:
                    queried = await query(row, proxy_url=lease.url if lease else None)
            if isinstance(queried, Mapping):
                result = dict(queried)
                if "success" not in result and "valid" in result:
                    result["success"] = bool(result.get("valid"))
                if not result.get("error_message") and result.get("message"):
                    result["error_message"] = str(result.get("message"))
            else:
                result = {
                    "success": False,
                    "status": "invalid_response",
                    "http_status": 0,
                    "error_code": "INVALID_LIVENESS_RESULT",
                    "error_message": "验活响应格式无效",
                }
        except asyncio.CancelledError:
            raise
        except Exception as error:
            result = {
                "success": False,
                "status": "network_error",
                "http_status": 0,
                "error_code": "LIVENESS_CHECK_FAILED",
                "error_message": safe_error(error) or "验活执行失败",
            }
        finally:
            if lease:
                try:
                    upstream_responded = int(result.get("http_status") or 0) > 0
                except (TypeError, ValueError, OverflowError):
                    upstream_responded = False
                proxy_success = bool(result.get("success")) or upstream_responded or liveness_failure_is_terminal(result)
                with contextlib.suppress(Exception):
                    self.proxy_pool.complete(
                        lease,
                        success=proxy_success,
                        error="" if proxy_success else str(result.get("error_message") or ""),
                    )
        try:
            http_status = int(result.get("http_status") or 0)
        except (TypeError, ValueError, OverflowError):
            http_status = 0
        return {
            "account_id": str(row.get("account_id") or ""),
            "success": bool(result.get("success")),
            "status": str(result.get("status") or ""),
            "http_status": http_status,
            "error_code": str(result.get("error_code") or ""),
        }

    async def run_once(self, account_ids: list[str] | None = None) -> dict[str, Any]:
        if self._run_lock.locked():
            return {"status": "running", "skipped": True}
        async with self._run_lock:
            started_at = utc_now()
            run_id = uuid.uuid4().hex
            self.repository.save_scheduler_state(
                self.STATE_NAME,
                status="running",
                checked_count=0,
                valid_count=0,
                invalid_count=0,
                temporary_failed_count=0,
                queued_count=0,
                duplicate_count=0,
                started_at=started_at,
                finished_at="",
                last_error="",
            )
            try:
                rows = self.repository.token_rows(account_ids)
                concurrency = min(20, max(1, int(self.settings.worker_count)))
                semaphore = asyncio.Semaphore(concurrency)

                async def checked(row: Mapping[str, Any]) -> dict[str, Any]:
                    async with semaphore:
                        return await self._check_account(row, run_id)

                results = await asyncio.gather(*(checked(row) for row in rows))
                invalid_ids = [
                    result["account_id"]
                    for result in results
                    if result["account_id"] and liveness_failure_is_terminal(result)
                ]
                valid_count = sum(1 for result in results if result["success"])
                temporary_failed_count = len(results) - valid_count - len(invalid_ids)
                queued = {"queued": 0, "duplicate": 0, "skipped": 0}
                if invalid_ids:
                    queued = await self.reauth.queue_accounts(
                        invalid_ids,
                        use_proxy=bool(self.settings.use_proxy_default),
                        event_message="定时验活检测到 Token 明确失效，已加入重新授权队列",
                    )
                summary = {
                    "status": "success",
                    "checked": len(results),
                    "valid": valid_count,
                    "invalid": len(invalid_ids),
                    "temporary_failed": temporary_failed_count,
                    "queued": int(queued.get("queued") or 0),
                    "duplicate": int(queued.get("duplicate") or 0),
                    "skipped": int(queued.get("skipped") or 0),
                    "started_at": started_at,
                    "finished_at": utc_now(),
                }
                self.repository.save_scheduler_state(
                    self.STATE_NAME,
                    status=summary["status"],
                    checked_count=summary["checked"],
                    valid_count=summary["valid"],
                    invalid_count=summary["invalid"],
                    temporary_failed_count=summary["temporary_failed"],
                    queued_count=summary["queued"],
                    duplicate_count=summary["duplicate"],
                    started_at=summary["started_at"],
                    finished_at=summary["finished_at"],
                    last_error="",
                )
                return summary
            except asyncio.CancelledError:
                raise
            except Exception as error:
                message = safe_error(error) or "定时验活执行失败"
                finished_at = utc_now()
                self.repository.save_scheduler_state(
                    self.STATE_NAME,
                    status="failed",
                    started_at=started_at,
                    finished_at=finished_at,
                    last_error=message,
                )
                return {
                    "status": "failed",
                    "checked": 0,
                    "valid": 0,
                    "invalid": 0,
                    "temporary_failed": 0,
                    "queued": 0,
                    "duplicate": 0,
                    "skipped": 0,
                    "started_at": started_at,
                    "finished_at": finished_at,
                    "error": message,
                }


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")

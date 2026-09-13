"""Codex usage/quota lookup helpers.

The usage endpoint is intentionally kept separate from the models validator:
the latter only answers whether a credential can access Codex, while this
module extracts the small, operator-useful quota summary.  Raw upstream
responses are never persisted or returned by the API.
"""

from __future__ import annotations

import inspect
import json
import math
import os
import re
import time
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Any, Callable, Mapping
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import httpx

from app.oauth.codex_validator import token_material


DEFAULT_CODEX_USAGE_URL = "https://chatgpt.com/backend-api/wham/usage"
DEFAULT_CODEX_CLIENT_VERSION = "0.144.1"
DEFAULT_CODEX_USAGE_TIMEOUT_MS = 15_000
MAX_RESPONSE_BYTES = 8 * 1024 * 1024


def _clean_error_code(value: Any, fallback: str = "") -> str:
    text = str(value or fallback or "").strip()
    return re.sub(r"[^A-Za-z0-9_.:-]", "_", text)[:100] or str(fallback or "")[:100]


def _safe_message(value: Any, fallback: str, *, max_length: int = 500) -> str:
    text = str(value or fallback).replace("\r", " ").replace("\n", " ").strip()
    text = re.sub(r"https?://\S+", "[redacted-url]", text, flags=re.IGNORECASE)
    text = re.sub(
        r"(?i)\b(authorization|cookie|access[_ -]?token|refresh[_ -]?token|id[_ -]?token)\s*[:=]\s*[^\s,;]+",
        r"\1=[redacted]",
        text,
    )
    text = re.sub(r"\s+", " ", text)
    return text[:max_length]


def _as_bool(value: Any, default: bool | None = None) -> bool | None:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    normalized = str(value).strip().lower()
    if normalized in {"1", "true", "yes", "on", "y"}:
        return True
    if normalized in {"0", "false", "no", "off", "n", ""}:
        return False
    return default


def _walk_mappings(value: Any, *, max_depth: int = 4) -> list[Mapping[str, Any]]:
    result: list[Mapping[str, Any]] = []
    pending: list[tuple[Any, int]] = [(value, 0)]
    seen: set[int] = set()
    while pending:
        current, depth = pending.pop(0)
        if not isinstance(current, Mapping) or depth > max_depth:
            continue
        identity = id(current)
        if identity in seen:
            continue
        seen.add(identity)
        result.append(current)
        if depth >= max_depth:
            continue
        for child in current.values():
            if isinstance(child, Mapping):
                pending.append((child, depth + 1))
    return result


def _value_from(mapping: Mapping[str, Any], names: tuple[str, ...]) -> Any:
    for name in names:
        if name in mapping and mapping[name] not in (None, ""):
            return mapping[name]
    return None


def _find_value(root: Mapping[str, Any], names: tuple[str, ...]) -> Any:
    for mapping in _walk_mappings(root):
        value = _value_from(mapping, names)
        if value is not None:
            return value
    return None


def _find_mapping(root: Mapping[str, Any], names: tuple[str, ...]) -> Mapping[str, Any] | None:
    for mapping in _walk_mappings(root):
        for name in names:
            candidate = mapping.get(name)
            if isinstance(candidate, Mapping):
                return candidate
    return None


_WINDOW_FIELD_NAMES = (
    "used_percent", "usedPercent", "percent", "usage_percent", "usagePercent",
    "reset_at", "resetAt", "reset_time", "resetTime", "reset_after_seconds",
    "resetAfterSeconds", "reset_after", "limit", "max", "maximum", "total",
    "remaining", "available", "remaining_percent", "limit_reached", "limitReached",
)


def _window_key(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(value or "").strip().lower()).strip("_")


def _window_label(key: Any, window: Mapping[str, Any], index: int, plan_type: Any = "") -> str:
    explicit = _value_from(window, ("label", "name", "window_name", "windowName", "limit_name", "limitName", "window_type", "windowType", "period", "title"))
    if explicit not in (None, ""):
        label = str(explicit).strip()
    else:
        normalized = _window_key(key)
        normalized_plan = _window_key(plan_type)
        primary_label = "Monthly" if "free" in normalized_plan.split("_") else "5h"
        aliases = {
            "primary_window": primary_label,
            "primary": primary_label,
            "five_hour": "5h",
            "five_hours": "5h",
            "5h": "5h",
            "secondary_window": "Weekly",
            "secondary": "Weekly",
            "weekly": "Weekly",
            "week": "Weekly",
            "monthly": "Monthly",
            "month": "Monthly",
            "daily": "Daily",
            "day": "Daily",
            "gpt_reserve_weekly": "gpt-reserve Weekly",
            "gpt_reserve_week": "gpt-reserve Weekly",
        }
        label = aliases.get(normalized, str(key or "").strip().replace("_", " ").replace("-", " ").title())
    label = re.sub(r"[^A-Za-z0-9 +_.:/()\-]", " ", label).strip()
    label = re.sub(r"\s+", " ", label)[:60]
    return label or f"限额 {index + 1}"


def _window_number(window: Mapping[str, Any], names: tuple[str, ...]) -> tuple[float | None, str]:
    value = _value_from(window, names)
    number = _decimal_value(value)
    if number is None:
        return None, ""
    return float(number), _display_number(number)


def _parse_limit_window(key: Any, window: Mapping[str, Any], index: int, plan_type: Any = "") -> dict[str, Any] | None:
    """Extract one safe rate-limit window without retaining upstream JSON."""

    used, _ = _window_number(window, ("used_percent", "usedPercent", "percent", "usage_percent", "usagePercent"))
    limit, limit_display = _window_number(window, ("limit", "max", "maximum", "total"))
    remaining, remaining_display = _window_number(window, ("remaining", "available"))
    reset_at = _timestamp_iso(_value_from(window, ("reset_at", "resetAt", "reset_time", "resetTime")))
    reset_after = _value_from(window, ("reset_after_seconds", "resetAfterSeconds", "reset_after"))
    try:
        reset_after_int = max(0, int(float(reset_after))) if reset_after not in (None, "") else 0
    except (TypeError, ValueError, OverflowError):
        reset_after_int = 0
    reached = _as_bool(_value_from(window, ("limit_reached", "limitReached", "exhausted")))
    has_window_data = any(
        value is not None and value != ""
        for value in (used, limit, remaining, reset_at, (reset_after_int if reset_after_int > 0 else None), reached)
    )
    if not has_window_data:
        return None
    result: dict[str, Any] = {
        "label": _window_label(key, window, index, plan_type),
        "used_percent": used,
        "limit": limit,
        "limit_display": limit_display,
        "remaining": remaining,
        "remaining_display": remaining_display,
        "reset_at": reset_at,
        "reset_after_seconds": reset_after_int,
        "limit_reached": reached,
    }
    return result


def _extract_limit_windows(
    payload: Mapping[str, Any],
    rate_limit: Mapping[str, Any] | None,
    plan_type: Any = "",
) -> list[dict[str, Any]]:
    """Find primary/secondary and newer multi-window quota shapes."""

    candidates: list[tuple[str, Mapping[str, Any]]] = []
    visited: set[int] = set()
    container_names = {"windows", "limits", "rate_limits", "ratelimits", "periods", "quotas", "usage_windows"}
    explicit_names = {"primary_window", "secondary_window", "primary", "secondary", "5h", "weekly", "monthly", "daily"}

    def visit(value: Any, depth: int = 0) -> None:
        if depth > 4:
            return
        if isinstance(value, list):
            for item in value:
                if isinstance(item, Mapping):
                    key = _value_from(item, ("label", "name", "window_name", "windowName", "limit_name", "limitName", "window_type", "windowType", "period", "title")) or "window"
                    candidates.append((str(key), item))
                    visit(item, depth + 1)
            return
        if not isinstance(value, Mapping):
            return
        identity = id(value)
        if identity in visited:
            return
        visited.add(identity)
        for key, child in value.items():
            if isinstance(child, Mapping):
                normalized = _window_key(key)
                has_data_fields = any(field in child for field in _WINDOW_FIELD_NAMES if field not in {"limit_reached", "limitReached"})
                if normalized in explicit_names or "window" in normalized or has_data_fields:
                    candidates.append((str(key), child))
                if normalized in container_names or depth < 3:
                    visit(child, depth + 1)
            elif isinstance(child, list) and (_window_key(key) in container_names or depth < 2):
                visit(child, depth + 1)

    visit(rate_limit or payload)
    if rate_limit is not payload:
        visit(payload)

    result: list[dict[str, Any]] = []
    seen_keys: set[tuple[Any, ...]] = set()
    for index, (key, window) in enumerate(candidates):
        parsed = _parse_limit_window(key, window, index, plan_type)
        if parsed is None:
            continue
        dedupe_key = (
            parsed["label"], parsed["used_percent"], parsed["limit"], parsed["remaining"],
            parsed["reset_at"], parsed["reset_after_seconds"], parsed["limit_reached"],
        )
        if dedupe_key in seen_keys:
            continue
        seen_keys.add(dedupe_key)
        result.append(parsed)
    return result[:12]


def _decimal_value(value: Any) -> Decimal | None:
    if isinstance(value, bool) or value in (None, ""):
        return None
    try:
        number = Decimal(str(value).strip().replace(",", ""))
    except (InvalidOperation, TypeError, ValueError):
        return None
    if not number.is_finite():
        return None
    return number


def _display_number(value: Decimal) -> str:
    text = format(value, "f")
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    if text in {"", "-0"}:
        return "0"
    return text[:80]


def _timestamp_iso(value: Any) -> str:
    if value in (None, ""):
        return ""
    try:
        if isinstance(value, (int, float, Decimal)) or str(value).strip().isdigit():
            number = float(value)
            if not math.isfinite(number) or number <= 0:
                return ""
            if number > 10_000_000_000:
                number /= 1000
            return datetime.fromtimestamp(number, tz=timezone.utc).isoformat(timespec="milliseconds")
        parsed = datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc).isoformat(timespec="milliseconds")
    except (TypeError, ValueError, OverflowError, OSError):
        return ""


def parse_usage_payload(payload: Any) -> dict[str, Any]:
    """Extract a normalized, non-sensitive quota summary from an API body."""

    if not isinstance(payload, Mapping):
        raise ValueError("额度接口响应不是 JSON 对象")

    credits = _find_mapping(payload, ("credits", "credit", "codex_credits"))
    rate_limit = _find_mapping(payload, ("rate_limit", "rateLimit", "ratelimit"))
    plan_type = _find_value(payload, ("plan_type", "planType", "plan", "subscription_plan"))
    balance = None
    has_credits: bool | None = None
    unlimited: bool | None = None
    if credits is not None:
        balance = _value_from(credits, ("balance", "remaining", "available", "amount", "credits"))
        has_credits = _as_bool(_value_from(credits, ("has_credits", "hasCredits", "available")))
        unlimited = _as_bool(_value_from(credits, ("unlimited", "is_unlimited", "isUnlimited")))
    if balance is None:
        balance = _find_value(payload, ("credits_balance", "creditsBalance", "quota", "remaining_credits"))
    if has_credits is None:
        has_credits = _as_bool(_find_value(payload, ("has_credits", "hasCredits")))
    if unlimited is None:
        unlimited = _as_bool(_find_value(payload, ("unlimited", "is_unlimited", "isUnlimited")))

    balance_number = _decimal_value(balance)
    balance_display = _display_number(balance_number) if balance_number is not None else ""
    if unlimited:
        balance_display = "不限"
    if has_credits is None:
        has_credits = bool(unlimited or balance_number is not None)

    primary_window = None
    if rate_limit is not None:
        primary_window = _find_mapping(rate_limit, ("primary_window", "primaryWindow", "window"))
    used_percent = _value_from(primary_window or {}, ("used_percent", "usedPercent", "percent"))
    if used_percent is None:
        used_percent = _find_value(payload, ("used_percent", "usedPercent"))
    used_number = _decimal_value(used_percent)
    reset_at = _value_from(primary_window or {}, ("reset_at", "resetAt", "reset_time", "resetTime"))
    if reset_at is None:
        reset_at = _find_value(payload, ("reset_at", "resetAt"))
    reset_after = _value_from(primary_window or {}, ("reset_after_seconds", "resetAfterSeconds", "reset_after"))
    if reset_after is None:
        reset_after = _find_value(payload, ("reset_after_seconds", "resetAfterSeconds"))
    try:
        reset_after_int = max(0, int(float(reset_after))) if reset_after not in (None, "") else 0
    except (TypeError, ValueError, OverflowError):
        reset_after_int = 0

    limit_windows = _extract_limit_windows(payload, rate_limit, plan_type)
    if used_number is None and limit_windows:
        used_number = _decimal_value(limit_windows[0].get("used_percent"))
    if not reset_at and limit_windows:
        reset_at = limit_windows[0].get("reset_at") or ""
    if not reset_after_int and limit_windows:
        reset_after_int = int(limit_windows[0].get("reset_after_seconds") or 0)

    recognized = any(
        value is not None
        for value in (credits, rate_limit, plan_type, balance, used_percent, reset_at)
    ) or bool(limit_windows)
    if not recognized:
        raise ValueError("额度接口响应缺少可识别的额度字段")

    return {
        "plan_type": re.sub(r"[^A-Za-z0-9_.:-]", "_", str(plan_type or "").strip())[:80],
        "credits_balance": float(balance_number) if balance_number is not None else None,
        "credits_balance_display": balance_display,
        "credits_has": bool(has_credits),
        "credits_unlimited": bool(unlimited),
        "used_percent": float(used_number) if used_number is not None else None,
        "reset_at": _timestamp_iso(reset_at),
        "reset_after_seconds": reset_after_int,
        "limit_windows": limit_windows,
    }


def build_usage_url(base_url: str | None = None, client_version: str | None = None) -> str:
    raw = str(base_url or DEFAULT_CODEX_USAGE_URL).strip() or DEFAULT_CODEX_USAGE_URL
    parts = urlsplit(raw)
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    if client_version:
        query["client_version"] = str(client_version).strip()
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))


async def _response_status_body(response: Any) -> tuple[int, str]:
    def as_text(value: Any) -> str:
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="replace")
        return str(value or "")

    if isinstance(response, dict):
        status = response.get("status", response.get("status_code", 0))
        body = response.get("body", "")
        json_value = response.get("json")
        if not body and isinstance(json_value, (Mapping, list)):
            body = json.dumps(json_value, ensure_ascii=False)
        try:
            return int(status or 0), as_text(body)[:MAX_RESPONSE_BYTES]
        except (TypeError, ValueError, OverflowError):
            return 0, as_text(body)[:MAX_RESPONSE_BYTES]
    status = getattr(response, "status_code", getattr(response, "status", 0))
    body = getattr(response, "text", getattr(response, "body", ""))
    if not body:
        content = getattr(response, "content", b"")
        if isinstance(content, bytes) and len(content) <= MAX_RESPONSE_BYTES:
            body = content
    try:
        normalized_status = int(status or 0)
    except (TypeError, ValueError, OverflowError):
        normalized_status = 0
    return normalized_status, as_text(body)[:MAX_RESPONSE_BYTES]


def _body_error_code(body: str) -> str:
    try:
        payload = json.loads(body or "")
    except (TypeError, ValueError, json.JSONDecodeError):
        return ""
    if not isinstance(payload, Mapping):
        return ""
    error = payload.get("error")
    if isinstance(error, Mapping):
        return _clean_error_code(error.get("code") or error.get("type"))
    return _clean_error_code(payload.get("code") or payload.get("type"))


RequestCallable = Callable[..., Any]


class CodexUsageClient:
    def __init__(
        self,
        *,
        usage_url: str | None = None,
        client_version: str | None = None,
        timeout_ms: int | None = None,
        proxy_url: str = "",
        transport: httpx.AsyncBaseTransport | None = None,
        request: RequestCallable | None = None,
    ) -> None:
        self.client_version = str(client_version or DEFAULT_CODEX_CLIENT_VERSION).strip()
        self.usage_url = build_usage_url(usage_url, self.client_version)
        try:
            configured = int(timeout_ms or DEFAULT_CODEX_USAGE_TIMEOUT_MS)
        except (TypeError, ValueError, OverflowError):
            configured = DEFAULT_CODEX_USAGE_TIMEOUT_MS
        self.timeout_ms = max(1_000, configured)
        self.proxy_url = str(proxy_url or "").strip()
        self.transport = transport
        self.request = request

    async def _request(self, headers: dict[str, str], proxy_url: str) -> Any:
        if self.request is not None:
            names: set[str] = set()
            use_compact = True
            try:
                names = {parameter.name for parameter in inspect.signature(self.request).parameters.values()}
                use_compact = not bool(names & {"headers", "proxy_url", "proxyUrl", "timeout_ms", "timeoutMs"})
            except (TypeError, ValueError):
                pass
            if use_compact:
                result = self.request(
                    self.usage_url,
                    {"headers": headers, "proxyUrl": proxy_url, "timeoutMs": self.timeout_ms},
                )
            else:
                proxy_name = "proxyUrl" if "proxyUrl" in names and "proxy_url" not in names else "proxy_url"
                timeout_name = "timeoutMs" if "timeoutMs" in names and "timeout_ms" not in names else "timeout_ms"
                result = self.request(
                    self.usage_url,
                    headers=headers,
                    **{proxy_name: proxy_url, timeout_name: self.timeout_ms},
                )
            return await result if inspect.isawaitable(result) else result

        kwargs: dict[str, Any] = {
            "timeout": self.timeout_ms / 1000,
            "follow_redirects": True,
            "trust_env": True,
        }
        if proxy_url:
            kwargs["proxy"] = proxy_url
        if self.transport is not None:
            kwargs["transport"] = self.transport
        async with httpx.AsyncClient(**kwargs) as client:
            response = await client.get(self.usage_url, headers=headers)
            if len(response.content) > MAX_RESPONSE_BYTES:
                raise RuntimeError("Codex 额度响应过大")
            return response

    async def query(self, row: Any = None, *, proxy_url: str | None = None) -> dict[str, Any]:
        started = time.monotonic()
        material = token_material(row)
        if not material["access_token"]:
            return {
                "success": False,
                "status": "invalid",
                "http_status": 0,
                "error_code": "TOKEN_MISSING",
                "error_message": "Codex Token 缺少 access_token",
            }
        if material["expires_at_ms"] and material["expires_at_ms"] <= int(time.time() * 1000):
            return {
                "success": False,
                "status": "invalid",
                "http_status": 0,
                "error_code": "TOKEN_EXPIRED",
                "error_message": "Codex access_token 已过期",
            }

        headers = {
            "Authorization": f"Bearer {material['access_token']}",
            "Accept": "application/json",
            "Accept-Encoding": "gzip",
            "Originator": "codex_cli_rs",
            "Version": self.client_version,
            "User-Agent": f"codex_cli_rs/{self.client_version} (Windows 10.0.0; x86_64) WindowsTerminal",
        }
        if material["account_id"]:
            headers["ChatGPT-Account-ID"] = material["account_id"]
        effective_proxy = str(proxy_url if proxy_url is not None else self.proxy_url).strip()
        try:
            response = await self._request(headers, effective_proxy)
        except Exception as error:
            code = _clean_error_code(getattr(error, "code", "") or "CODEX_USAGE_NETWORK_ERROR", "CODEX_USAGE_NETWORK_ERROR")
            return {
                "success": False,
                "status": "network_error",
                "http_status": 0,
                "error_code": code,
                "error_message": _safe_message(f"Codex 额度查询网络失败（{code}）", "Codex 额度查询网络失败"),
                "latency_ms": max(0, int((time.monotonic() - started) * 1000)),
            }

        http_status, body = await _response_status_body(response)
        elapsed = max(0, int((time.monotonic() - started) * 1000))
        upstream_code = _body_error_code(body)
        if 200 <= http_status < 300:
            try:
                payload = json.loads(body)
                summary = parse_usage_payload(payload)
            except (TypeError, ValueError, json.JSONDecodeError) as error:
                return {
                    "success": False,
                    "status": "invalid_response",
                    "http_status": http_status,
                    "error_code": "INVALID_USAGE_ENVELOPE",
                    "error_message": _safe_message(str(error), "Codex 额度响应格式无效"),
                    "latency_ms": elapsed,
                }
            return {
                "success": True,
                "status": "success",
                "http_status": http_status,
                "error_code": "",
                "error_message": "",
                "latency_ms": elapsed,
                **summary,
            }

        if http_status == 401:
            status = "unauthorized"
            code = upstream_code or "TOKEN_UNAUTHORIZED"
            message = "Codex Token 无效、已撤销或未授权（HTTP 401）"
        elif http_status == 403:
            status = "forbidden"
            code = upstream_code or "CODEX_USAGE_FORBIDDEN"
            message = "Codex 额度接口暂无访问权限（HTTP 403）"
        elif http_status == 429:
            status = "rate_limited"
            code = upstream_code or "CODEX_USAGE_RATE_LIMITED"
            message = "Codex 额度查询触发限流（HTTP 429）"
        else:
            status = "upstream_error"
            code = upstream_code or "CODEX_USAGE_UPSTREAM_ERROR"
            message = f"Codex 额度接口返回 HTTP {http_status or '未知'}"
        return {
            "success": False,
            "status": status,
            "http_status": http_status,
            "error_code": _clean_error_code(code),
            "error_message": message,
            "latency_ms": elapsed,
        }


def create_codex_usage_client(options: dict[str, Any] | None = None, **kwargs: Any) -> CodexUsageClient:
    values = {**dict(options or {}), **kwargs}
    return CodexUsageClient(
        usage_url=values.get("usage_url")
        or values.get("usageUrl")
        or os.getenv("CODEX_USAGE_URL")
        or DEFAULT_CODEX_USAGE_URL,
        client_version=values.get("client_version")
        or values.get("clientVersion")
        or os.getenv("CODEX_USAGE_VERSION")
        or os.getenv("CODEX_TOKEN_CHECK_VERSION")
        or DEFAULT_CODEX_CLIENT_VERSION,
        timeout_ms=values.get("timeout_ms")
        or values.get("timeoutMs")
        or os.getenv("CODEX_USAGE_TIMEOUT_MS")
        or DEFAULT_CODEX_USAGE_TIMEOUT_MS,
        proxy_url=values.get("proxy_url")
        or values.get("proxyUrl")
        or os.getenv("CODEX_USAGE_PROXY_URL")
        or os.getenv("CODEX_TOKEN_CHECK_PROXY_URL", ""),
        transport=values.get("transport"),
        request=values.get("request"),
    )


__all__ = [
    "CodexUsageClient",
    "DEFAULT_CODEX_USAGE_TIMEOUT_MS",
    "DEFAULT_CODEX_USAGE_URL",
    "build_usage_url",
    "create_codex_usage_client",
    "parse_usage_payload",
]

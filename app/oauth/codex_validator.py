"""Codex access-token health checks.

The validator intentionally performs a small authenticated request to the
Codex models endpoint.  It never returns the token itself and keeps upstream
response bodies out of logs/results; only a stable HTTP/error code is kept for
diagnostics.
"""

from __future__ import annotations

import base64
import inspect
import json
import os
import re
import time
from datetime import datetime, timezone
from typing import Any, Callable
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

import httpx


DEFAULT_CODEX_MODELS_URL = "https://chatgpt.com/backend-api/codex/models"
DEFAULT_CODEX_CLIENT_VERSION = "0.144.1"
DEFAULT_CODEX_TIMEOUT_MS = 15_000
MAX_RESPONSE_BYTES = 8 * 1024 * 1024


def _row_value(row: Any, key: str, default: Any = "") -> Any:
    """Read a value from a dict, sqlite Row, or small test object."""

    if row is None:
        return default
    try:
        value = row[key]
    except (KeyError, IndexError, TypeError):
        value = getattr(row, key, default)
    return default if value is None else value


def _clean_error_code(value: Any, fallback: str = "") -> str:
    text = str(value or fallback or "").strip()
    # Error codes are identifiers.  Do not allow an upstream body to inject
    # newlines or arbitrary markup into the admin page/logs.
    return re.sub(r"[^A-Za-z0-9_.:-]", "_", text)[:100]


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


def parse_token_payload(row: Any = None) -> dict[str, Any]:
    raw = _row_value(row, "payload_json", "")
    if isinstance(raw, dict):
        return raw
    try:
        payload = json.loads(str(raw or "{}"))
    except (TypeError, ValueError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def decode_jwt_claims(token: str) -> dict[str, Any]:
    parts = str(token or "").split(".")
    if len(parts) != 3:
        return {}
    try:
        encoded = parts[1] + "=" * (-len(parts[1]) % 4)
        claims = json.loads(base64.urlsafe_b64decode(encoded.encode("ascii")).decode("utf-8"))
    except (ValueError, UnicodeError, json.JSONDecodeError):
        return {}
    return claims if isinstance(claims, dict) else {}


def _timestamp_ms(value: Any) -> int:
    if value in (None, ""):
        return 0
    if isinstance(value, (int, float)):
        try:
            number = float(value)
        except (TypeError, ValueError, OverflowError):
            return 0
        if not number == number or number in (float("inf"), float("-inf")):
            return 0
        if number <= 0:
            return 0
        return int(number if number > 10_000_000_000 else number * 1000)
    text = str(value).strip()
    if text.isdigit():
        return _timestamp_ms(int(text))
    try:
        normalized = text.replace("Z", "+00:00")
        parsed = datetime.fromisoformat(normalized)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return int(parsed.timestamp() * 1000)
    except (TypeError, ValueError, OverflowError):
        return 0


def token_material(row: Any = None) -> dict[str, Any]:
    payload = parse_token_payload(row)
    access_token = str(
        _row_value(row, "access_token", "")
        or payload.get("access_token")
        or payload.get("accessToken")
        or ""
    ).strip()
    claims = decode_jwt_claims(access_token)
    auth_claims = claims.get("https://api.openai.com/auth", {})
    if not isinstance(auth_claims, dict):
        auth_claims = {}
    account_id = str(
        _row_value(row, "account_id", "")
        or payload.get("account_id")
        or payload.get("accountId")
        or auth_claims.get("chatgpt_account_id")
        or ""
    ).strip()
    expires_at_ms = _timestamp_ms(claims.get("exp"))
    if not expires_at_ms:
        expires_at_ms = _timestamp_ms(
            _row_value(row, "expires_at", "")
            or payload.get("expired")
            or payload.get("expires_at")
        )
    return {
        "access_token": access_token,
        "account_id": account_id,
        "expires_at_ms": expires_at_ms,
    }


def error_code_from_body(body: str) -> str:
    try:
        parsed = json.loads(str(body or ""))
    except (TypeError, ValueError, json.JSONDecodeError):
        return ""
    if not isinstance(parsed, dict):
        return ""
    error = parsed.get("error")
    if isinstance(error, dict):
        return _clean_error_code(error.get("code") or error.get("type"))
    return _clean_error_code(parsed.get("code") or parsed.get("type"))


def has_valid_models_envelope(body: str) -> bool:
    try:
        parsed = json.loads(str(body or ""))
    except (TypeError, ValueError, json.JSONDecodeError):
        return False
    return isinstance(parsed, dict) and isinstance(parsed.get("models"), list)


def build_models_url(base_url: str | None = None, client_version: str | None = None) -> str:
    raw = str(base_url or DEFAULT_CODEX_MODELS_URL).strip() or DEFAULT_CODEX_MODELS_URL
    parts = urlsplit(raw)
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    query["client_version"] = str(client_version or DEFAULT_CODEX_CLIENT_VERSION).strip()
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))


async def _response_status_body(response: Any) -> tuple[int, str]:
    """Read status and a bounded textual body from common response shapes."""

    def as_text(value: Any) -> str:
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="replace")
        return str(value or "")

    if isinstance(response, dict):
        status = response.get("status", response.get("status_code", 0))
        body = response.get("body", "")
        json_value = response.get("json")
        if not body and callable(json_value):
            try:
                parsed = json_value()
                if inspect.isawaitable(parsed):
                    parsed = await parsed
                if isinstance(parsed, dict):
                    body = json.dumps(parsed, ensure_ascii=False)
                elif isinstance(parsed, list):
                    body = json.dumps(parsed, ensure_ascii=False)
            except Exception:
                body = ""
        elif not body and isinstance(json_value, (dict, list)):
            body = json.dumps(json_value, ensure_ascii=False)
        try:
            return int(status or 0), as_text(body)
        except (TypeError, ValueError, OverflowError):
            return 0, as_text(body)
    status = getattr(response, "status_code", None)
    if status is None:
        status = getattr(response, "status", 0)
    body = getattr(response, "text", getattr(response, "body", ""))
    if not body:
        try:
            parser = getattr(response, "json", None)
            parsed = parser() if callable(parser) else parser
            if inspect.isawaitable(parsed):
                parsed = await parsed
            body = json.dumps(parsed, ensure_ascii=False)
        except Exception:
            body = ""
    try:
        normalized_status = int(status or 0)
    except (TypeError, ValueError, OverflowError):
        normalized_status = 0
    return normalized_status, as_text(body)


RequestCallable = Callable[..., Any]


def _with_result_aliases(result: dict[str, Any]) -> dict[str, Any]:
    """Expose both Python snake_case and admin-compatible camelCase fields."""

    normalized = dict(result)
    try:
        http_status = int(normalized.get("http_status") or normalized.get("httpStatus") or 0)
    except (TypeError, ValueError, OverflowError):
        http_status = 0
    try:
        latency_ms = max(0, int(normalized.get("latency_ms") or normalized.get("latencyMs") or 0))
    except (TypeError, ValueError, OverflowError):
        latency_ms = 0
    error_code = str(normalized.get("error_code") or normalized.get("errorCode") or "")[:100]
    normalized["http_status"] = http_status
    normalized["httpStatus"] = http_status
    normalized["latency_ms"] = latency_ms
    normalized["latencyMs"] = latency_ms
    normalized["error_code"] = error_code
    normalized["errorCode"] = error_code
    return normalized


class CodexTokenValidator:
    def __init__(
        self,
        *,
        models_url: str | None = None,
        client_version: str | None = None,
        timeout_ms: int | None = None,
        proxy_url: str = "",
        transport: httpx.AsyncBaseTransport | None = None,
        request: RequestCallable | None = None,
    ) -> None:
        self.client_version = str(client_version or DEFAULT_CODEX_CLIENT_VERSION).strip()
        self.models_url = build_models_url(models_url, self.client_version)
        try:
            configured_timeout = int(timeout_ms or DEFAULT_CODEX_TIMEOUT_MS)
        except (TypeError, ValueError):
            configured_timeout = DEFAULT_CODEX_TIMEOUT_MS
        self.timeout_ms = max(1_000, configured_timeout)
        self.proxy_url = str(proxy_url or "").strip()
        self.transport = transport
        self.request = request

    async def _request(self, headers: dict[str, str], proxy_url: str) -> Any:
        if self.request is not None:
            # Support both the compact `(url, options)` shape used by the
            # reference implementation and keyword-style test fakes.  Do not
            # blindly retry on every TypeError: a validator/request that
            # failed internally should only be called once.
            request_callable = self.request
            use_compact = True
            keyword_names: set[str] = set()
            try:
                parameters = inspect.signature(request_callable).parameters.values()
                names = [parameter.name for parameter in parameters]
                keyword_names = set(names)
                # A function exposing explicit keyword options is most likely
                # a Python-style fake; a two-positional-argument callable is
                # the admin-compatible compact form.
                if any(
                    name in {"headers", "proxy_url", "proxyUrl", "timeout_ms", "timeoutMs"}
                    for name in names
                ):
                    use_compact = False
            except (TypeError, ValueError):
                pass

            if use_compact:
                result = request_callable(
                    self.models_url,
                    {"headers": headers, "proxyUrl": proxy_url, "timeoutMs": self.timeout_ms},
                )
            else:
                options: dict[str, Any] = {"headers": headers}
                proxy_name = "proxyUrl" if "proxyUrl" in keyword_names and "proxy_url" not in keyword_names else "proxy_url"
                timeout_name = "timeoutMs" if "timeoutMs" in keyword_names and "timeout_ms" not in keyword_names else "timeout_ms"
                options[proxy_name] = proxy_url
                options[timeout_name] = self.timeout_ms
                result = request_callable(self.models_url, **options)
            if inspect.isawaitable(result):
                return await result
            return result

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
            response = await client.get(self.models_url, headers=headers)
            # Avoid retaining an unexpectedly large upstream body in memory.
            if len(response.content) > MAX_RESPONSE_BYTES:
                raise RuntimeError("Codex 模型清单响应过大")
            return response

    async def validate(self, row: Any = None, *, proxy_url: str | None = None) -> dict[str, Any]:
        started = time.monotonic()
        material = token_material(row)
        if not material["access_token"]:
            return _with_result_aliases({
                "valid": False,
                "terminal": True,
                "status": "invalid",
                "http_status": 0,
                "latency_ms": 0,
                "error_code": "TOKEN_MISSING",
                "message": "Codex Token 缺少 access_token",
            })
        if material["expires_at_ms"] and material["expires_at_ms"] <= int(time.time() * 1000):
            return _with_result_aliases({
                "valid": False,
                "terminal": True,
                "status": "invalid",
                "http_status": 0,
                "latency_ms": 0,
                "error_code": "TOKEN_EXPIRED",
                "message": "Codex access_token 已过期",
            })

        headers = {
            "Authorization": f"Bearer {material['access_token']}",
            "Accept": "application/json",
            # httpx only decodes Brotli when an optional brotli extra is
            # installed.  Advertising ``br`` without that decoder leaves the
            # compressed bytes in ``response.text`` and makes a valid 200
            # models response look like INVALID_MODELS_ENVELOPE.  gzip is
            # handled by httpx itself and is sufficient here.
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
        except Exception as error:  # network failures are retryable
            elapsed = int((time.monotonic() - started) * 1000)
            code = _clean_error_code(
                getattr(error, "code", "")
                or getattr(getattr(error, "__cause__", None), "code", "")
                or "TOKEN_CHECK_NETWORK_ERROR",
                "TOKEN_CHECK_NETWORK_ERROR",
            )
            return _with_result_aliases({
                "valid": False,
                "terminal": False,
                "status": "network_error",
                "http_status": 0,
                "latency_ms": max(0, elapsed),
                "error_code": code,
                "message": _safe_message(
                    f"Codex Token 验活网络失败（{code}）",
                    "Codex Token 验活网络失败",
                ),
            })

        http_status, body = await _response_status_body(response)
        elapsed = int((time.monotonic() - started) * 1000)
        upstream_code = error_code_from_body(body)
        if 200 <= http_status < 300:
            if not has_valid_models_envelope(body):
                return _with_result_aliases({
                    "valid": False,
                    "terminal": False,
                    "status": "invalid_response",
                    "http_status": http_status,
                    "latency_ms": max(0, elapsed),
                    "error_code": "INVALID_MODELS_ENVELOPE",
                    "message": "Codex Token 验活返回了无效模型清单",
                })
            return _with_result_aliases({
                "valid": True,
                "terminal": False,
                "status": "valid",
                "http_status": http_status,
                "latency_ms": max(0, elapsed),
                "error_code": "",
                "message": "Codex Token 有效",
            })
        if http_status == 401:
            return _with_result_aliases({
                "valid": False,
                "terminal": True,
                "status": "invalid",
                "http_status": http_status,
                "latency_ms": max(0, elapsed),
                "error_code": upstream_code or "TOKEN_UNAUTHORIZED",
                "message": "Codex Token 无效、已撤销或未授权（HTTP 401）",
            })
        if http_status == 403:
            return _with_result_aliases({
                "valid": False,
                "terminal": False,
                "status": "forbidden",
                "http_status": http_status,
                "latency_ms": max(0, elapsed),
                "error_code": upstream_code or "TOKEN_FORBIDDEN",
                "message": "Codex Token 暂无访问权限（HTTP 403）",
            })
        if http_status == 429:
            return _with_result_aliases({
                "valid": False,
                "terminal": False,
                "status": "rate_limited",
                "http_status": http_status,
                "latency_ms": max(0, elapsed),
                "error_code": upstream_code or "TOKEN_RATE_LIMITED",
                "message": "Codex Token 验活触发限流（HTTP 429）",
            })
        return _with_result_aliases({
            "valid": False,
            "terminal": False,
            "status": "upstream_error",
            "http_status": http_status,
            "latency_ms": max(0, elapsed),
            "error_code": upstream_code or "TOKEN_CHECK_UPSTREAM_ERROR",
            "message": f"Codex Token 验活返回 HTTP {http_status or '未知'}",
        })


def create_codex_token_validator(
    options: dict[str, Any] | None = None,
    **kwargs: Any,
) -> CodexTokenValidator:
    values = {**dict(options or {}), **kwargs}
    return CodexTokenValidator(
        models_url=values.get("models_url") or values.get("modelsUrl") or os.getenv("CODEX_TOKEN_CHECK_URL") or None,
        client_version=values.get("client_version") or values.get("clientVersion") or os.getenv("CODEX_TOKEN_CHECK_VERSION") or None,
        timeout_ms=values.get("timeout_ms")
        or values.get("timeoutMs")
        or os.getenv("CODEX_TOKEN_CHECK_TIMEOUT_MS")
        or DEFAULT_CODEX_TIMEOUT_MS,
        proxy_url=values.get("proxy_url") or values.get("proxyUrl") or os.getenv("CODEX_TOKEN_CHECK_PROXY_URL", ""),
        transport=values.get("transport"),
        request=values.get("request"),
    )


__all__ = [
    "CodexTokenValidator",
    "DEFAULT_CODEX_CLIENT_VERSION",
    "DEFAULT_CODEX_MODELS_URL",
    "build_models_url",
    "create_codex_token_validator",
    "decode_jwt_claims",
    "error_code_from_body",
    "has_valid_models_envelope",
    "parse_token_payload",
    "token_material",
]

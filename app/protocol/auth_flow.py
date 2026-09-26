"""HTTP authorization and Codex OAuth protocol flow."""
import json
import base64
import hashlib
import hmac
import logging
import os
import random
import re
import secrets
import struct
import time
import uuid
from datetime import datetime
from typing import Optional, Any
from urllib.parse import urlparse, parse_qs, parse_qsl, quote, urljoin, urlencode, urlunparse

from .config import Config
from .fingerprint import (
    generate_fingerprint,
    ua_for_impersonate,
    fingerprint_for_impersonate,
)
from .mail_providers import MailProvider
from .http_client import create_http_session, USER_AGENT

logger = logging.getLogger(__name__)


def _safe_error_token(value: Any, *, limit: int = 120) -> str:
    """Return a stable, log-safe API error code/type token."""

    text = str(value or "").replace("\r", " ").replace("\n", " ").strip()
    # Error codes and types are identifiers.  Restricting them to a small
    # alphabet prevents an API response from injecting log lines or URLs.
    text = re.sub(r"[^A-Za-z0-9_.:-]", "_", text)
    return text[:limit]


def _safe_error_message(value: Any, *, limit: int = 260) -> str:
    """Keep a useful error message while removing common credential carriers."""

    text = str(value or "").replace("\r", " ").replace("\n", " ").strip()
    if not text:
        return ""
    # Never copy URLs, bearer/cookie values, JWT-like strings, or long opaque
    # values into the job event stream.  The structured code/type remain
    # available for diagnosis even when the message is redacted.
    text = re.sub(r"https?://\S+", "[redacted-url]", text, flags=re.IGNORECASE)
    text = re.sub(
        r"(?i)\b(authorization|cookie|access[_ -]?token|refresh[_ -]?token|id[_ -]?token|session[_ -]?token)\s*[:=]\s*[^\s,;]+",
        r"\1=[redacted]",
        text,
    )
    text = re.sub(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b", "[redacted-token]", text)
    # Phone numbers, request IDs, and other long digit sequences are not
    # needed to identify the server-side error and should not be persisted.
    text = re.sub(r"(?<!\w)\+?\d[\d ()-]{7,}\d(?!\w)", "[redacted-number]", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:limit]


def _safe_http_error_summary(response: Any, *, limit: int = 260) -> str:
    """Extract a small, non-sensitive API error summary.

    Error responses can contain redirect URLs, auth-session fragments, or
    other data that ends up in the job event log. Keep only structured
    ``error`` fields and never serialize the complete response body.
    """

    status = getattr(response, "status_code", "N/A")
    payload: Any = None
    try:
        payload = response.json() if response is not None else None
    except Exception:
        payload = None
    error = payload.get("error") if isinstance(payload, dict) else None
    if (not isinstance(error, dict) or not error) and isinstance(payload, dict):
        # 部分网关会把 code/type/message 放在 JSON 顶层，仍然提取稳定
        # 字段，避免一次接口格式变化又退化成只有 ``body_len``。
        if any(key in payload for key in ("code", "type", "message", "error_code", "error_type")):
            error = {
                "code": payload.get("code", payload.get("error_code", "")),
                "type": payload.get("type", payload.get("error_type", "")),
                "message": payload.get("message", ""),
            }
    if isinstance(error, dict):
        parts: list[str] = []
        for key in ("code", "type", "message"):
            if key == "message":
                value = _safe_error_message(error.get(key), limit=limit)
            else:
                value = _safe_error_token(error.get(key), limit=limit)
            if value:
                parts.append(f"{key}={value[:limit]}")
        if parts:
            return f"HTTP {status} " + " ".join(parts)
    # Plain-text error pages are not a trusted diagnostic channel: they may
    # contain callback URLs, cookies, JWTs, or echoed request data.  Keep the
    # useful size/status information, plus a tiny allowlist of stable markers
    # used by retry/proxy classification, but do not copy an arbitrary body
    # into job events or exception strings.
    raw = str(getattr(response, "text", "") or "")
    lowered = raw.lower()
    marker = next(
        (
            value
            for value in (
                "unsupported_country_region_territory",
                "invalid_state",
                "rate_limit",
            )
            if value in lowered
        ),
        "",
    )
    suffix = f" marker={marker}" if marker else ""
    return f"HTTP {status} body_len={len(raw)}{suffix}"


# ── RFC 6238 TOTP 实现（用于 mfa-challenge 计算动态码）────────────
def _hotp(secret_b32: str, counter: int, digits: int = 6) -> str:
    """HOTP 算法（RFC 4226）"""
    key = base64.b32decode(secret_b32 + "=" * (-len(secret_b32) % 8))
    msg = struct.pack(">Q", counter)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    o = h[-1] & 0x0F
    code = (struct.unpack(">I", h[o:o + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


def _totp_now(secret_b32: str) -> str:
    """当前 30 秒窗口的 6 位 TOTP 码"""
    return _hotp(secret_b32, int(time.time()) // 30)


class AuthResult:
    """认证结果"""

    def __init__(self):
        self.email: str = ""
        # Optional phone identifier returned by the authorization flow.
        self.phone_number: str = ""
        self.password: str = ""
        self.session_token: str = ""
        self.access_token: str = ""
        self.device_id: str = ""
        self.csrf_token: str = ""
        self.id_token: str = ""
        self.refresh_token: str = ""
        self.cookie_header: str = ""
        self.totp_secret: str = ""

    def is_valid(self) -> bool:
        return bool(self.session_token and self.access_token)

    def has_codex_oauth_credentials(self) -> bool:
        """Return whether this result contains a refreshable Codex OAuth pair."""

        # An access token alone is also produced by the web session flow.  It
        # is not sufficient for Token-pool jobs because CLIProxyAPI needs the
        # refresh token to rotate credentials later.
        return bool(self.access_token and self.refresh_token)

    def to_dict(self) -> dict:
        return {
            "email": self.email,
            "phone_number": self.phone_number,
            "password": self.password,
            "session_token": self.session_token,
            "access_token": self.access_token,
            "device_id": self.device_id,
            "csrf_token": self.csrf_token,
            "id_token": self.id_token,
            "refresh_token": self.refresh_token,
            "cookie_header": self.cookie_header,
            "totp_secret": self.totp_secret,
        }


class AuthFlow:
    """HTTP authorization and Codex OAuth protocol flow."""

    def __init__(
        self,
        config: Config,
        env_overrides: Optional[dict] = None,
        on_session_ready: Optional[Any] = None,
        account_callback: Optional[Any] = None,
    ):
        # 本次流程专属的配置覆盖（OTP_TIMEOUT / OAuth 开关等）。
        # ⚠️ 旧实现曾直接写 os.environ 再在 finally 里还原，
        #    但 auto_loop 会并发跑多个 worker —— A 写的 OTP_TIMEOUT 会被 B 看见，
        #    B 跑完还原成 A 之前的值，A 后半程就读到别人的配置了。
        #    现在覆盖值只挂在实例上，进程全局环境一个字节都不动。
        self._env_overrides = dict(env_overrides or {})
        self.config = config
        self._country_code = ""  # IP 地理国家码，check_proxy() 时填充
        self._fingerprint = generate_fingerprint()  # 先生成默认指纹
        self._ua = self._fingerprint["user_agent"]
        self._impersonate_candidates = self._fingerprint.get(
            "fallback_impersonates",
            [self._fingerprint["impersonate"], "safari17_0", "safari15_5"],
        )
        self._impersonate_idx = 0
        self.session = create_http_session(
            proxy=config.proxy,
            impersonate=self._impersonate_candidates[self._impersonate_idx],
            user_agent=self._ua,
        )
        self.result = AuthResult()
        # 拿到 session（access_token）之后、Codex 授权之前的钩子。
        # 签名 (flow: AuthFlow, access_token: str) -> None，异常由调用点吞掉。
        # 用于在拿到 session 后、Codex 授权前插入调用方自定义步骤。
        self._on_session_ready = on_session_ready
        # Credential callback used to load a password and TOTP secret.
        # Signature: (email: str) -> {"password": "...", "totp_secret": "..."}.
        self._account_callback = account_callback
        self._http_trace_enabled = str(os.getenv("AUTH_HTTP_TRACE", "0")).lower() in ("1", "true", "yes", "on")
        # 登录流程使用这些状态决定 OTP 重发策略。
        self._is_existing_account = False
        self._existing_email_verification_mode = ""
        self._existing_page_type = ""
        self._manual_login_verifier = (os.getenv("LOGIN_VERIFIER", "") or "").strip()
        self._captured_login_verifier = ""
        self._oauth_client_secret = (os.getenv("OAUTH_CLIENT_SECRET", "") or "").strip()
        self._oauth_client_id = "YOUR_OPENAI_WEB_CLIENT_ID"
        self._oauth_redirect_uri = "https://chatgpt.com/api/auth/callback/openai"
        self._oauth_scope = ""
        self._oauth_state = ""
        self._oauth_auth_url = ""
        self._client_auth_session_dump: dict[str, Any] = {}
        self._client_auth_session_id: str = ""
        self._dump_login_verifier: str = ""
        self._codex_rt_attempted: bool = False
        self._trace_dump_enabled = str(os.getenv("AUTH_TRACE_DUMP", "0")).lower() in ("1", "true", "yes", "on")
        self._trace_include_cookie = str(os.getenv("AUTH_TRACE_INCLUDE_COOKIE", "0")).lower() in (
            "1", "true", "yes", "on"
        )
        self._trace_dump_path = ""
        logger.debug(
            f"指纹: impersonate={self._fingerprint['impersonate']} "
            f"screen={self._fingerprint['screen']} lang={self._fingerprint['lang']} "
            f"ua={self._ua}"
        )
        if self._trace_dump_enabled:
            try:
                os.makedirs("outputs", exist_ok=True)
                ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
                self._trace_dump_path = os.path.join("outputs", f"auth_trace_{ts}_{os.getpid()}.jsonl")
                logger.info("HTTP 明文抓包已启用: %s", self._trace_dump_path)
            except Exception as error:
                logger.warning("初始化 HTTP 抓包文件失败: %s", type(error).__name__)
                self._trace_dump_enabled = False

    def _build_chatgpt_cookie_header(self) -> str:
        """
        导出当前会话中的 chatgpt.com 相关 cookie。

        说明：
        - `/backend-api/payments/checkout` 的 modern/custom 入口不仅依赖
          `__Secure-next-auth.session-token`，还会校验若干同域 cookie
          （如 csrf / oai-sc / Cloudflare 相关 cookie 等）。
        - 因此这里不能只回传 session_token，需要尽量保留当前会话里已经拿到的
          `chatgpt.com` 域 cookie 集合。
        """
        cookie_pairs: list[tuple[str, str]] = []
        seen: set[str] = set()

        try:
            jar_iter = list(self.session.cookies)
        except Exception:
            jar_iter = []

        for cookie in jar_iter:
            try:
                name = (getattr(cookie, "name", "") or "").strip()
                value = getattr(cookie, "value", "") or ""
                domain = (getattr(cookie, "domain", "") or "").strip().lower()
            except Exception:
                continue
            if not name or not value:
                continue
            if domain and "chatgpt.com" not in domain:
                continue
            if name in seen:
                continue
            seen.add(name)
            cookie_pairs.append((name, value))

        # 兜底补齐关键 cookie，避免某些 cookiejar 迭代行为差异导致遗漏
        critical_names = [
            "__Secure-next-auth.session-token",
            "__Host-next-auth.csrf-token",
            "__Secure-next-auth.callback-url",
            "oai-did",
            "oai-sc",
            "cf_clearance",
            "__cf_bm",
            "_cfuvid",
            "__cflb",
            "__stripe_mid",
            "__stripe_sid",
            "oai-client-auth-info",
            "oai-gn",
            "oai-nav-state",
            "oai-hlib",
            "_account_is_fedramp",
            "oai_consent_analytics",
            "oai_consent_marketing",
            "oai-allow-ne",
            "_ga",
            "_ga_9SHBSK2D9J",
            "_gcl_au",
            "_fbp",
            "_puid",
            "_dd_s",
            "g_state",
        ]
        for name in critical_names:
            if name in seen:
                continue
            try:
                value = self.session.cookies.get(name, "")
            except Exception:
                value = ""
            if value:
                seen.add(name)
                cookie_pairs.append((name, value))

        return "; ".join(f"{name}={value}" for name, value in cookie_pairs if name and value)

    def _trace_http(self, step: str, resp, extra_request: dict | None = None):
        """可选 HTTP 细粒度追踪（用于协议调试）"""
        if (not self._http_trace_enabled and not self._trace_dump_enabled) or resp is None:
            return
        try:
            req = getattr(resp, "request", None)
            method = getattr(req, "method", "") if req else ""
            req_url = getattr(req, "url", "") if req else ""
            req_body = ""
            req_headers = {}
            if req is not None:
                raw_req_body = getattr(req, "body", None)
                if raw_req_body is None:
                    raw_req_body = getattr(req, "content", None)
                if raw_req_body is None:
                    raw_req_body = getattr(req, "data", None)
                if isinstance(raw_req_body, bytes):
                    req_body = raw_req_body.decode("utf-8", errors="replace")
                elif raw_req_body is not None:
                    req_body = str(raw_req_body)
                try:
                    req_headers = dict(getattr(req, "headers", {}) or {})
                except Exception:
                    req_headers = {}

            # 手动补充请求信息（curl_cffi 某些场景 request.body/headers 为空）
            if isinstance(extra_request, dict):
                if not method:
                    method = str(extra_request.get("method", "") or "")
                if not req_url:
                    req_url = str(extra_request.get("url", "") or "")
                if not req_body:
                    maybe_body = extra_request.get("body", "")
                    if isinstance(maybe_body, bytes):
                        req_body = maybe_body.decode("utf-8", errors="replace")
                    else:
                        req_body = str(maybe_body or "")
                extra_headers = extra_request.get("headers", {})
                if isinstance(extra_headers, dict):
                    merged = dict(req_headers or {})
                    merged.update(extra_headers)
                    req_headers = merged

            status = getattr(resp, "status_code", "N/A")
            final_url = str(getattr(resp, "url", "") or "")
            req_cookie = (req_headers.get("Cookie", "") or "")
            location = (resp.headers.get("Location", "") or "")[:180]
            req_id = (resp.headers.get("x-request-id", "") or "")[:120]
            ctype = (resp.headers.get("Content-Type", "") or "")[:120]
            # 尽量保留完整 Set-Cookie（某些关键 cookie 可能在后续片段）
            set_cookie_list: list[str] = []
            try:
                get_list = getattr(resp.headers, "get_list", None) or getattr(resp.headers, "getlist", None)
                if callable(get_list):
                    vals = get_list("Set-Cookie")
                    if isinstance(vals, list):
                        set_cookie_list = [str(x) for x in vals if x]
            except Exception:
                set_cookie_list = []
            if not set_cookie_list:
                one = (resp.headers.get("Set-Cookie", "") or "")
                if one:
                    set_cookie_list = [one]
            set_cookie_raw = " || ".join(set_cookie_list)
            set_cookie = set_cookie_raw[:260]
            body = (resp.text or "").replace("\n", " ").replace("\r", " ")
            body = body[:260]
            req_headers_lc = {(str(k).lower()): v for k, v in (req_headers or {}).items()}

            if self._http_trace_enabled:
                logger.info(
                    "[HTTP TRACE] %s | %s %s -> %s | url=%s | location=%s | req_id=%s | ctype=%s | set_cookie=%s | body=%s",
                    step,
                    method,
                    req_url[:180],
                    status,
                    final_url[:180],
                    location,
                    req_id,
                    ctype,
                    set_cookie,
                    body,
                )
                if self._trace_include_cookie and req_cookie:
                    logger.info("[HTTP TRACE] %s | req_cookie=%s", step, req_cookie[:360])

            # 从多处信息中抓取 login_verifier/code_verifier
            self._sniff_login_verifier(req_url, f"{step}:req_url")
            self._sniff_login_verifier(req_body, f"{step}:req_body")
            self._sniff_login_verifier(final_url, f"{step}:final_url")
            self._sniff_login_verifier(location, f"{step}:location")
            raw_text = resp.text or ""
            self._sniff_login_verifier(raw_text, f"{step}:resp_body")

            # 明文 HTTP 抓包落盘（jsonl）
            if self._trace_dump_enabled and self._trace_dump_path:
                try:
                    include_req_cookie = self._env_flag("AUTH_TRACE_INCLUDE_REQ_COOKIE", "0")
                    record = {
                        "ts": datetime.utcnow().isoformat() + "Z",
                        "step": step,
                        "request": {
                            "method": method,
                            "url": req_url,
                            "body": req_body[:120000],
                            "headers": {
                                "Content-Type": (req_headers_lc.get("content-type", "") or "")[:240],
                                "Accept": (req_headers_lc.get("accept", "") or "")[:240],
                                "Referer": (req_headers_lc.get("referer", "") or "")[:500],
                                "Origin": (req_headers_lc.get("origin", "") or "")[:120],
                                **(
                                    {
                                        "Cookie": (req_headers_lc.get("cookie", "") or "")[:6000],
                                    }
                                    if include_req_cookie
                                    else {}
                                ),
                            },
                        },
                        "response": {
                            "status_code": status,
                            "url": final_url,
                            "location": resp.headers.get("Location", ""),
                            "x_request_id": resp.headers.get("x-request-id", ""),
                            "content_type": resp.headers.get("Content-Type", ""),
                            "set_cookie": set_cookie_raw,
                            "set_cookie_list": set_cookie_list,
                            "body": raw_text[:120000],
                        },
                        "captured_login_verifier": self._captured_login_verifier,
                    }
                    if self._trace_include_cookie and req_cookie:
                        record["request"]["headers"]["Cookie"] = req_cookie[:8000]
                    with open(self._trace_dump_path, "a", encoding="utf-8") as fw:
                        fw.write(json.dumps(record, ensure_ascii=False) + "\n")
                except Exception as e:
                    logger.debug(f"HTTP 抓包写入失败: {e}")
        except Exception as e:
            logger.debug(f"HTTP trace 输出失败: {e}")

    def _sniff_login_verifier(self, text: str, source: str = ""):
        """从任意文本中提取 login_verifier/code_verifier。"""
        if not text:
            return
        try:
            patterns = [
                r"(?:login_verifier|code_verifier|verifier)=([A-Za-z0-9._~-]{8,})",
                r'"(?:login_verifier|code_verifier|verifier)"\s*:\s*"([^"]{8,})"',
            ]
            for p in patterns:
                m = re.search(p, text)
                if not m:
                    continue
                v = (m.group(1) or "").strip()
                if not v:
                    continue
                if v != self._captured_login_verifier:
                    self._captured_login_verifier = v
                    logger.info("捕获 login_verifier 来源=%s len=%s", source or "unknown", len(v))
                return
        except Exception:
            return

    @staticmethod
    def _walk_collect_str_fields(obj: Any, wanted_keys: set[str], out: dict[str, str], depth: int = 0, max_depth: int = 6):
        """递归收集目标字段（仅字符串值）。"""
        if depth > max_depth or obj is None:
            return
        if isinstance(obj, dict):
            for k, v in obj.items():
                kk = (str(k) or "").strip().lower()
                if kk in wanted_keys and isinstance(v, str) and v.strip():
                    out[kk] = v.strip()
                AuthFlow._walk_collect_str_fields(v, wanted_keys, out, depth + 1, max_depth)
        elif isinstance(obj, list):
            for it in obj:
                AuthFlow._walk_collect_str_fields(it, wanted_keys, out, depth + 1, max_depth)

    def fetch_client_auth_session_dump(self, stage: str = "") -> dict:
        """
        尝试读取 auth.openai 的 client_auth_session_dump：
        - 可能包含 session_id / client_auth_session 的额外状态
        - 若出现 verifier/refresh 相关字段，自动注入当前流程
        """
        headers = self._common_headers("https://auth.openai.com/email-verification")
        headers["Accept"] = "application/json"
        try:
            resp = self.session.get(
                "https://auth.openai.com/api/accounts/client_auth_session_dump",
                headers=headers,
                timeout=30,
            )
            self._trace_http(f"client_auth_session_dump_{stage or 'default'}", resp)
        except Exception as e:
            logger.debug(f"client_auth_session_dump 请求异常({stage}): {e}")
            return {}

        if resp.status_code != 200:
            logger.info(
                "client_auth_session_dump(%s) 非 200: %s",
                stage or "default",
                resp.status_code,
            )
            return {}

        try:
            data = resp.json()
        except Exception:
            logger.warning(f"client_auth_session_dump({stage}) JSON 解析失败")
            return {}

        if not isinstance(data, dict):
            return {}

        self._client_auth_session_dump = data
        cas = data.get("client_auth_session", {}) if isinstance(data.get("client_auth_session"), dict) else {}

        sid = (data.get("session_id", "") or "").strip() or (cas.get("session_id", "") or "").strip()
        if sid:
            self._client_auth_session_id = sid

        # 同步 OAuth client_id（若 dump 给出更准确值）
        dump_client_id = (cas.get("openai_client_id", "") or data.get("openai_client_id", "") or "").strip()
        if dump_client_id:
            self._oauth_client_id = dump_client_id

        wanted = {
            "login_verifier", "code_verifier", "verifier", "pkce_verifier", "oauth_code_verifier",
            "refresh_token", "oauth_refresh_token", "access_token", "id_token",
        }
        found: dict[str, str] = {}
        self._walk_collect_str_fields(data, wanted, found)

        # verifier 候选
        for key in ("login_verifier", "code_verifier", "verifier", "pkce_verifier", "oauth_code_verifier"):
            v = (found.get(key, "") or "").strip()
            if v and len(v) >= 8:
                self._dump_login_verifier = v
                self._captured_login_verifier = v
                logger.info("client_auth_session_dump 捕获 verifier: key=%s len=%s", key, len(v))
                break

        # Token 候选（极少见，但若有只能按同一来源的成对凭据处理）。
        # 该接口也可能返回网页 Session access_token；如果此时已有
        # Codex OAuth refresh_token，单独覆盖 access_token 会再次制造
        # “网页 access_token + OAuth refresh_token”的混合凭据，最终在
        # Sub2API 验活时表现为 token_revoked。
        refresh = (found.get("refresh_token", "") or found.get("oauth_refresh_token", "")).strip()
        acc = (found.get("access_token", "") or "").strip()
        if acc and refresh:
            self.result.access_token = acc
            self.result.refresh_token = refresh
        elif acc and not self.result.refresh_token:
            self.result.access_token = acc
        elif refresh and not self.result.access_token:
            self.result.refresh_token = refresh
        idt = (found.get("id_token", "") or "").strip()
        if idt and (acc and refresh or not self.result.has_codex_oauth_credentials()):
            self.result.id_token = idt

        logger.debug(
            "client_auth_session_dump(%s) 成功: top_keys=%s cas_keys=%s session_id=%s refresh=%s verifier=%s",
            stage or "default",
            list(data.keys())[:12],
            list(cas.keys())[:18] if isinstance(cas, dict) else [],
            (self._client_auth_session_id[:24] if self._client_auth_session_id else ""),
            "有" if self.result.refresh_token else "无",
            "有" if self._dump_login_verifier else "无",
        )
        return data

    @staticmethod
    def _is_tls_error(exc: Exception) -> bool:
        msg = str(exc).lower()
        markers = ["curl: (35)", "tls connect error", "openssl_internal", "sslerror"]
        return any(m in msg for m in markers)

    def _get_cookie_value_by_name(self, name: str) -> str:
        """按 cookie 名称获取值（忽略 domain 冲突）。"""
        try:
            jar = getattr(self.session.cookies, "jar", None)
            if jar is None:
                return ""
            target = (name or "").strip().lower()
            for c in jar:
                if (getattr(c, "name", "") or "").strip().lower() == target:
                    return (getattr(c, "value", "") or "").strip()
        except Exception:
            pass
        return ""

    def _extract_login_challenge_from_cookie(self) -> str:
        """
        从 login_session cookie 中提取 login_challenge。
        login_session 的第一段通常是 base64url(JSON)。
        """
        raw = self._get_cookie_value_by_name("login_session")
        if not raw:
            return ""
        try:
            p0 = raw.split(".")[0]
            p0 += "=" * (-len(p0) % 4)
            payload = json.loads(base64.urlsafe_b64decode(p0.encode("utf-8")).decode("utf-8"))
            return (payload.get("login_challenge", "") or "").strip()
        except Exception:
            return ""

    @staticmethod
    def _extract_query_first(url: str, keys: list[str]) -> str:
        if not url:
            return ""
        try:
            qs = parse_qs(urlparse(url).query)
        except Exception:
            return ""
        for k in keys:
            val = qs.get(k, [None])[0]
            if val:
                return val
        return ""

    @staticmethod
    def _extract_page_type(resp_json: dict | None) -> str:
        if not isinstance(resp_json, dict):
            return ""
        page = resp_json.get("page", {})
        if not isinstance(page, dict):
            return ""
        return (page.get("type", "") or "").strip()

    @staticmethod
    def _extract_continue_url_from_step(resp_json: dict | None) -> str:
        """
        从 auth step 响应提取 continue_url：
        - 顶层 continue_url
        - page.type=external_url 时 payload.url
        """
        if not isinstance(resp_json, dict):
            return ""
        continue_url = (resp_json.get("continue_url", "") or "").strip()
        if continue_url:
            return continue_url
        # A few revisions of the auth API put the next URL in a top-level
        # ``next_url``/``next`` field.  Accepting those aliases keeps this
        # login flow resilient to the server's page-schema variation.
        for key in ("next_url", "next", "redirect_url"):
            value = resp_json.get(key, "")
            if isinstance(value, str) and value.strip():
                return value.strip()

        page = resp_json.get("page", {})
        if not isinstance(page, dict):
            return ""
        payload = page.get("payload", {})
        if not isinstance(payload, dict):
            return ""
        # ``external_url`` uses ``url``; auth step pages commonly use
        # ``continue_url`` or ``next_url``.  Only return strings so malformed
        # JSON cannot leak an object into URL handling.
        for key in ("url", "continue_url", "next_url", "redirect_url"):
            value = payload.get(key, "")
            if isinstance(value, str) and value.strip():
                return value.strip()
        return ""

    def _get_env(self, name: str, default: str = "") -> str:
        """读配置：本次流程的 env_overrides 优先，回退进程环境变量。

        service 通过 AuthFlow(env_overrides=...) 传入，不再写 os.environ，
        所以并发跑多个号时互不干扰。
        """
        v = self._env_overrides.get(name)
        return os.getenv(name, default) if v is None else str(v)

    def _env_flag(self, name: str, default: str = "0") -> bool:
        # 原本是 @staticmethod，为了读 self._env_overrides 改成实例方法。
        # 调用点全是 self._env_flag(...)，签名不变。
        return self._get_env(name, default).lower() in ("1", "true", "yes", "on")

    @staticmethod
    def _b64url_no_pad(raw: bytes) -> str:
        return base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")

    def _remember_oauth_params(self, auth_url: str):
        """从 authorize URL 记住 OAuth 参数，供后续 token exchange 使用。"""
        if not auth_url:
            return
        self._oauth_auth_url = auth_url
        try:
            qs = parse_qs(urlparse(auth_url).query)
            self._oauth_client_id = (qs.get("client_id", [self._oauth_client_id])[0] or self._oauth_client_id).strip()
            self._oauth_redirect_uri = (
                qs.get("redirect_uri", [self._oauth_redirect_uri])[0] or self._oauth_redirect_uri
            ).strip()
            self._oauth_scope = (qs.get("scope", [""])[0] or "").strip()
            self._oauth_state = (qs.get("state", [""])[0] or "").strip()
        except Exception:
            return

    def _build_pkce_pair(self, raw_bytes: int = 64) -> tuple[str, str]:
        """生成 (code_verifier, code_challenge)。"""
        verifier = self._b64url_no_pad(secrets.token_bytes(max(32, int(raw_bytes))))
        if len(verifier) < 43:
            verifier = (verifier + ("A" * 43))[:43]
        if len(verifier) > 128:
            verifier = verifier[:128]
        challenge = self._b64url_no_pad(hashlib.sha256(verifier.encode("utf-8")).digest())
        return verifier, challenge

    def _build_codex_authorize(self, prompt_override: Optional[str] = None) -> tuple[str, str, str, str, str]:
        """
        构建用于获取 refresh_token 的 Codex OAuth 授权 URL。
        使用独立 client_id + redirect_uri + 可控 PKCE 获取 Codex OAuth 凭证。
        """
        client_id = (os.getenv("OAUTH_CODEX_CLIENT_ID", "") or "").strip() or "app_EMoamEEZ73f0CkXaXp7hrann"
        redirect_uri = (os.getenv("OAUTH_CODEX_REDIRECT_URI", "") or "").strip() or "http://localhost:1455/auth/callback"
        scope = (os.getenv("OAUTH_CODEX_SCOPE", "") or "").strip() or "openid email profile offline_access"
        state = self._b64url_no_pad(secrets.token_bytes(24))
        verifier, challenge = self._build_pkce_pair()
        prompt = (
            (os.getenv("OAUTH_CODEX_PROMPT", "login") or "").strip()
            if prompt_override is None
            else (prompt_override or "").strip()
        )
        params = {
            "client_id": client_id,
            "response_type": "code",
            "redirect_uri": redirect_uri,
            "scope": scope,
            "state": state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "id_token_add_organizations": "true",
            "codex_cli_simplified_flow": "true",
        }
        if prompt:
            params["prompt"] = prompt
        auth_url = f"https://auth.openai.com/oauth/authorize?{urlencode(params)}"
        return auth_url, state, verifier, redirect_uri, client_id

    @staticmethod
    def _callback_has_code(url: str, redirect_uri: str) -> bool:
        if not url:
            return False
        try:
            cb_base = (redirect_uri or "").split("?", 1)[0].rstrip("/")
            target = url.split("?", 1)[0].rstrip("/")
            if cb_base and target == cb_base:
                qs = parse_qs(urlparse(url).query)
                return bool((qs.get("code", [""])[0] or "").strip())
        except Exception:
            return False
        return False

    def _follow_authorize_for_callback(self, start_url: str, redirect_uri: str, trace_prefix: str) -> tuple[str, str]:
        """
        跟随 auth.openai.com 授权链路，捕获 callback（不消费 callback）。
        返回 (callback_url, final_url)。
        """
        current = start_url
        callback_url = ""
        chose_account = False  # /choose-an-account 每条链路只选一次，防 200/同 URL 循环
        for i in range(12):
            if self._callback_has_code(current, redirect_uri):
                callback_url = current
                break
            resp = self.session.get(
                current,
                headers={
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Referer": "https://chatgpt.com/",
                    "User-Agent": self._ua,
                },
                timeout=30,
                allow_redirects=False,
            )
            self._trace_http(f"{trace_prefix}_hop_{i+1}", resp)

            # workspace/consent 页面 200 时，主动选择 workspace，拿下一跳 continue_url
            if resp.status_code == 200:
                is_workspace_like = (
                    ("/workspace" in current)
                    or ("/sign-in-with-chatgpt/" in current)
                    or ("/consent" in current)
                )
                if is_workspace_like:
                    workspace_id = self._extract_workspace_id() or self._extract_workspace_id_from_html(resp.text or "")
                    if workspace_id:
                        next_url = self._workspace_select(workspace_id)
                        if next_url:
                            if next_url.startswith("/"):
                                next_url = urljoin("https://auth.openai.com", next_url)
                            current = next_url
                            continue

                # /choose-an-account：OpenAI 已登录多账号的选择页（react-router SSR）。
                # HTML 里 streamController.enqueue 注入 unified_sessions[].id (us_*) 和
                # authsess_*。protocol 端要主动选第一个 us_*，否则 codex callback 拿不到。
                if "/choose-an-account" in current and not chose_account:
                    chose_account = True
                    next_url = self._choose_account_select(resp.text or "", current)
                    if next_url:
                        if next_url.startswith("/"):
                            next_url = urljoin("https://auth.openai.com", next_url)
                        current = next_url
                        continue

            if resp.status_code not in (301, 302, 303, 307, 308):
                break
            loc = (resp.headers.get("Location", "") or "").strip()
            if not loc:
                break
            if loc.startswith("/"):
                loc = urljoin(current, loc)
            if self._callback_has_code(loc, redirect_uri):
                callback_url = loc
                current = loc
                break
            current = loc
        return callback_url, current

    @staticmethod
    def _drop_query_keys(url: str, drop_keys: set[str]) -> str:
        if not url:
            return ""
        try:
            parsed = urlparse(url)
            params = parse_qsl(parsed.query, keep_blank_values=True)
            kept = [(k, v) for (k, v) in params if (k or "").strip() not in drop_keys]
            return urlunparse(parsed._replace(query=urlencode(kept)))
        except Exception:
            return url

    def _exchange_codex_callback_code(
        self,
        callback_url: str,
        expected_state: str,
        verifier: str,
        redirect_uri: str,
        client_id: str,
    ) -> bool:
        qs = parse_qs(urlparse(callback_url).query)
        code = (qs.get("code", [""])[0] or "").strip()
        got_state = (qs.get("state", [""])[0] or "").strip()
        if not code:
            logger.warning("Codex callback 缺少 code")
            return False
        if expected_state and got_state and got_state != expected_state:
            logger.warning("Codex callback state 不匹配，期望=%s 实际=%s", expected_state[:20], got_state[:20])
            return False

        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
            "Origin": "https://auth.openai.com",
            "Referer": "https://auth.openai.com/sign-in-with-chatgpt/codex/consent",
            "User-Agent": self._ua,
        }
        form = {
            "grant_type": "authorization_code",
            "client_id": client_id,
            "code": code,
            "redirect_uri": redirect_uri,
            "code_verifier": verifier,
        }
        encoded_form = urlencode(form)
        resp = self.session.post(
            "https://auth.openai.com/oauth/token",
            headers=headers,
            data=encoded_form,
            timeout=30,
        )
        self._trace_http(
            "oauth_token_exchange_codex_pkce",
            resp,
            extra_request={
                "method": "POST",
                "url": "https://auth.openai.com/oauth/token",
                "body": encoded_form,
                "headers": headers,
            },
        )
        if resp.status_code != 200:
            logger.warning("Codex oauth/token 失败: %s", _safe_http_error_summary(resp))
            return False
        data = resp.json() if resp is not None else {}
        self.result.id_token = data.get("id_token", self.result.id_token)
        self.result.access_token = data.get("access_token", self.result.access_token)
        self.result.refresh_token = data.get("refresh_token", self.result.refresh_token)
        logger.info(
            "Codex OAuth 交换成功: access=%s refresh=%s",
            "有" if self.result.access_token else "无",
            "有" if self.result.refresh_token else "无",
        )
        return True

    def _codex_drive_login_from_log_in(self, mail_provider: Optional[MailProvider] = None) -> str:
        """
        当 Codex 授权回落到 /log-in 时，补走一次纯协议登录推进状态机。
        返回可继续跟随的 continue_url（若无则返回空字符串）。
        """
        email = (self.result.email or "").strip()
        if not email:
            logger.warning("Codex 登录推进缺少 email")
            return ""
        password, pw_is_real = self._resolve_login_password(email)
        if pw_is_real:
            self.result.password = password

        device_id = (self.result.device_id or "").strip() or (self.session.cookies.get("oai-did", "") or "").strip()
        if not device_id:
            device_id = str(uuid.uuid4())
            self.result.device_id = device_id

        sentinel = self.get_sentinel_token(device_id)
        username_kind = "phone_number" if (
            self.result.phone_number
            and email == self.result.phone_number
            and "@" not in email
        ) else "email"
        step = self.authorize_continue_identity(
            value=email,
            kind=username_kind,
            sentinel_token=sentinel,
            screen_hint="login",
            referer=(
                "https://auth.openai.com/log-in?usernameKind=phone_number"
                if username_kind == "phone_number"
                else "https://auth.openai.com/log-in"
            ),
            trace_step="authorize_continue_login_codex",
        )
        page_type = self._extract_page_type(step)
        continue_url = self._normalize_continue_url(self._extract_continue_url_from_step(step))

        if page_type == "login_password" or "/log-in/password" in continue_url:
            if not password:
                raise RuntimeError("已有账号需要密码登录，但未提供真实密码")
            step = self.login_password_verify(password)
            page_type = self._extract_page_type(step)
            continue_url = self._normalize_continue_url(self._extract_continue_url_from_step(step))

        # mfa-challenge 分支（密码验证后需要 TOTP 2FA）
        if self._is_mfa_challenge_state(page_type, continue_url):
            step, continue_url = self.complete_mfa_totp(step, continue_url, email)
            page_type = self._extract_page_type(step)

        need_otp = (page_type == "email_otp_verification") or ("/email-verification" in (continue_url or ""))
        if need_otp:
            if mail_provider is None:
                logger.warning("Codex 登录推进需要 OTP，但未提供 mail_provider")
                return continue_url or ""
            try:
                otp_timeout = max(10, int(self._get_env("OTP_TIMEOUT", "60")))
            except Exception:
                otp_timeout = 180
            otp_sent_at = time.time()
            if not self.kickoff_otp_delivery("codex_login_need_otp"):
                self.send_otp()
            otp_code = mail_provider.wait_for_otp(
                email,
                timeout=otp_timeout,
                issued_after=otp_sent_at,
            )
            otp_resp = self.verify_otp(otp_code)
            continue_url = self._normalize_continue_url(self._extract_continue_url_from_step(otp_resp))

        return continue_url or ""

    @staticmethod
    def _is_mfa_challenge_state(page_type: str = "", continue_url: str = "") -> bool:
        """Return whether the response requires a TOTP challenge."""
        pt = (page_type or "").strip().lower()
        cu = (continue_url or "").strip().lower()
        return (pt == "mfa_challenge") or ("/mfa-challenge/" in cu)

    def oauth_codex_rt_exchange(self, mail_provider: Optional[MailProvider] = None) -> bool:
        """
        纯协议方式获取 Codex RT：
        - 使用独立 Codex OAuth 参数重新授权（可控 PKCE）
        - 捕获 callback code（不消费）
        - 直接调 /oauth/token 交换 access_token + refresh_token
        """
        allow_retry = self._env_flag("OAUTH_CODEX_RT_ALLOW_RETRY", "0")
        if self._codex_rt_attempted and (not allow_retry):
            logger.debug("Codex RT 本轮已尝试过，跳过重复尝试")
            return False
        self._codex_rt_attempted = True

        logger.info("尝试 Codex OAuth 直连换取 refresh_token ...")
        try:
            auth_url, state, verifier, redirect_uri, client_id = self._build_codex_authorize()
            self._oauth_auth_url = auth_url
            self._oauth_client_id = client_id
            self._oauth_redirect_uri = redirect_uri
            self._oauth_state = state
            self._manual_login_verifier = verifier
            self._captured_login_verifier = verifier
            callback_url, final_url = self._follow_authorize_for_callback(
                auth_url, redirect_uri, "codex_authorize"
            )

            # 若被打回 /log-in，补走一次协议登录，再继续授权链路
            if (not callback_url) and "/log-in" in (final_url or ""):
                logger.info("Codex 授权回落到 /log-in，尝试协议推进登录状态...")
                continue_url = ""
                try:
                    continue_url = self._codex_drive_login_from_log_in(mail_provider=mail_provider)
                except Exception as e:
                    logger.warning(f"Codex 登录推进失败，改走 no-prompt 兜底: {e}")
                if continue_url:
                    callback_url, final_url = self._follow_authorize_for_callback(
                        continue_url,
                        redirect_uri,
                        "codex_post_login",
                    )

            # 兜底：去掉 prompt=login 再发起一次授权
            if not callback_url:
                no_prompt_url = self._drop_query_keys(auth_url, {"prompt"})
                if no_prompt_url and no_prompt_url != auth_url:
                    callback_url, final_url = self._follow_authorize_for_callback(
                        no_prompt_url,
                        redirect_uri,
                        "codex_authorize_noprompt",
                    )

            exchanged = False
            if callback_url:
                exchanged = self._exchange_codex_callback_code(
                    callback_url=callback_url,
                    expected_state=state,
                    verifier=verifier,
                    redirect_uri=redirect_uri,
                    client_id=client_id,
                )
                if exchanged and self.result.refresh_token:
                    return True
                # A 200 response can still contain only the web access token
                # when the first authorize pass reused an existing session.
                # Do not report success in that case: start one fresh PKCE
                # authorize pass without ``prompt=login``.  The callback code
                # and verifier are independent, so this retry does not replay
                # or invalidate the first request.
                logger.warning(
                    "Codex OAuth 首次交换未返回 refresh_token，执行一次无 prompt 的独立重试"
                )
            else:
                logger.debug("Codex OAuth 未捕获 callback code, final=%s", (final_url or "")[:180])

            if self._env_flag("OAUTH_CODEX_RT_ALLOW_RETRY", "1"):
                retry_url, retry_state, retry_verifier, retry_redirect, retry_client = self._build_codex_authorize(
                    prompt_override=""
                )
                self._oauth_auth_url = retry_url
                self._oauth_client_id = retry_client
                self._oauth_redirect_uri = retry_redirect
                self._oauth_state = retry_state
                self._manual_login_verifier = retry_verifier
                self._captured_login_verifier = retry_verifier
                retry_callback, retry_final = self._follow_authorize_for_callback(
                    retry_url,
                    retry_redirect,
                    "codex_authorize_retry_no_prompt",
                )
                if retry_callback:
                    retry_exchanged = self._exchange_codex_callback_code(
                        callback_url=retry_callback,
                        expected_state=retry_state,
                        verifier=retry_verifier,
                        redirect_uri=retry_redirect,
                        client_id=retry_client,
                    )
                    if retry_exchanged and self.result.refresh_token:
                        return True
                else:
                    logger.debug(
                        "Codex OAuth 无 prompt 重试未捕获 callback code, final=%s",
                        (retry_final or "")[:180],
                    )
            return bool(exchanged and self.result.refresh_token)
        except Exception as e:
            logger.warning(f"Codex OAuth 交换异常: {e}")
            return False

    def _inject_pkce_into_auth_url(self, auth_url: str) -> str:
        """为 authorize URL 注入 PKCE 参数（可选）。"""
        if not auth_url:
            return auth_url
        if not self._env_flag("OAUTH_SECONDARY_PKCE", "0"):
            return auth_url

        try:
            parsed = urlparse(auth_url)
            params = dict(parse_qsl(parsed.query, keep_blank_values=True))
            if params.get("code_challenge") and params.get("code_challenge_method"):
                return auth_url

            verifier, challenge = self._build_pkce_pair()
            params["code_challenge"] = challenge
            params["code_challenge_method"] = "S256"
            new_url = urlunparse(parsed._replace(query=urlencode(params)))
            # 若用户未手动指定 verifier，则自动注入本轮 verifier
            if not self._manual_login_verifier:
                self._manual_login_verifier = verifier
            logger.info(
                "已启用二次 PKCE 注入: verifier_len=%s challenge=%s...",
                len(verifier),
                challenge[:16],
            )
            return new_url
        except Exception as e:
            logger.warning(f"注入 PKCE 参数失败，回退原始 auth_url: {e}")
            return auth_url

    @staticmethod
    def _safe_b64url_decode_text(data: str) -> str:
        if not data:
            return ""
        try:
            s = data + "=" * (-len(data) % 4)
            return base64.urlsafe_b64decode(s.encode("utf-8")).decode("utf-8", errors="replace")
        except Exception:
            return ""

    def _extract_hydra_redirect_values(self) -> list[str]:
        """从 hydra_redirect cookie 中提取可能的会话值。"""
        raw = self._get_cookie_value_by_name("hydra_redirect")
        if not raw:
            return []
        out: list[str] = []
        try:
            p0 = (raw.split(".", 1)[0] or "").strip()
            text = self._safe_b64url_decode_text(p0)
            if text:
                obj = json.loads(text)
                if isinstance(obj, dict):
                    for v in obj.values():
                        if isinstance(v, str) and v.strip():
                            vv = v.strip()
                            out.append(vv)
                            if "|" in vv:
                                out.extend([x for x in vv.split("|") if isinstance(x, str) and x.strip()])
        except Exception:
            return out
        return out

    def _collect_code_verifier_candidates(self, callback_url: str, continue_url: str) -> list[tuple[str, str]]:
        """收集 code_verifier 候选（来源 + 值）。"""
        raw_candidates: list[tuple[str, str]] = [
            ("query", self._extract_query_first(continue_url, ["login_verifier", "code_verifier", "verifier"])),
            ("query_callback", self._extract_query_first(callback_url, ["login_verifier", "code_verifier", "verifier"])),
            ("dump", self._dump_login_verifier),
            ("captured", self._captured_login_verifier),
            ("manual", self._manual_login_verifier),
            ("cookie_login_verifier", self._get_cookie_value_by_name("login_verifier")),
            ("cookie_code_verifier", self._get_cookie_value_by_name("code_verifier")),
            ("cookie_login_challenge", self._extract_login_challenge_from_cookie()),
            ("cookie_nextauth_state", self._get_cookie_value_by_name("__Secure-next-auth.state")),
        ]

        # hydra_redirect 中可能包含编码后的 csrf/session 串，作为实验候选
        for i, hv in enumerate(self._extract_hydra_redirect_values()):
            raw_candidates.append((f"hydra_{i}", hv))

        out: list[tuple[str, str]] = []
        seen: set[str] = set()

        max_len = max(128, int(os.getenv("OAUTH_MAX_VERIFIER_LEN", "4096")))
        for src, val in raw_candidates:
            v = (val or "").strip()
            if not v:
                continue
            if len(v) > max_len:
                v = v[:max_len]
            if v not in seen:
                seen.add(v)
                out.append((src, v))
            # PKCE 标准长度 43~128；对超长候选补一个截断版本
            if len(v) > 128:
                v128 = v[:128]
                if v128 not in seen:
                    seen.add(v128)
                    out.append((f"{src}_trunc128", v128))

        return out

    def _rotate_impersonate_session(self) -> bool:
        """仅在 curl_cffi 指纹模式内切换 UA 指纹版本重试，同时联动更新 UA。

        ⚠️ 这里必须连 self._fingerprint 里的 client hints 一起换掉。
        旧版只更新了 self._ua 和 session —— 但 _common_headers / _navigation_headers
        的 sec-ch-ua* 全是从 self._fingerprint 取的，于是换完会变成
        「UA 说 Chrome/136、sec-ch-ua 说 v=146」，连 not_a_brand 都对不上
        （三个版本各不相同："Not.A/Brand";v="99" / "Not/A)Brand";v="8" /
        "Not?A_Brand";v="99"）—— 这正是上一轮刚消灭的「UA 与头自相矛盾」，
        是 CF 最容易抓的特征。之前没爆只因这条路几乎没走到过。

        fallback_impersonates 是**同家族**构造的（见 fingerprint.py 各 _gen_*），
        所以只会 chrome→chrome、safari→safari，不会跨族；但同族换版本一样要同步头。
        """
        if self._impersonate_idx >= len(self._impersonate_candidates) - 1:
            return False
        self._impersonate_idx += 1
        imp = self._impersonate_candidates[self._impersonate_idx]
        self._ua = ua_for_impersonate(imp, self._ua)
        # 让 client hints 跟上新版本，保持 UA 与头自洽
        try:
            self._fingerprint = fingerprint_for_impersonate(imp, self._fingerprint)
        except Exception as e:  # 兜底：宁可维持旧指纹也不要把流程搞崩
            logger.warning(f"client hints 同步失败（沿用旧指纹）: {e}")
        logger.warning(f"TLS 异常，切换指纹重试: impersonate={imp}, ua={self._ua[:60]}...")
        self.session = create_http_session(
            proxy=self.config.proxy, impersonate=imp, user_agent=self._ua,
        )
        return True

    @staticmethod
    def _datadog_trace_headers() -> dict:
        """生成 Datadog RUM 追踪头。"""
        tid = f"{random.getrandbits(64):016x}"
        sid = str(random.getrandbits(63))
        pid = str(random.getrandbits(63))
        ts_hex = f"{int(time.time()):08x}"
        return {
            "traceparent": f"00-0000000000000000{tid}-{random.getrandbits(64):016x}-01",
            "x-datadog-trace-id": sid,
            "x-datadog-parent-id": pid,
            "x-datadog-sampling-priority": "1",
            "x-datadog-origin": "rum",
            "x-datadog-tags": f"_dd.p.id={tid},_dd.p.tid={ts_hex}00000000,_dd.b.sr=1",
        }

    def _common_headers(self, referer: str = "https://chatgpt.com/") -> dict:
        """
        构造通用请求头。

        关键点：
        - Origin 必须与 Referer 同源（尤其 auth.openai.com 的状态机接口），
          否则容易触发 invalid_state / 风控分支。
        - 在 auth.openai.com 域下，尽量补充 oai-device-id，提升状态机连续性。
        - 全请求注入 Datadog trace 头，避免 OTP silent-drop。
        """
        origin = "https://chatgpt.com"
        try:
            parsed = urlparse(referer or "")
            if parsed.scheme and parsed.netloc:
                origin = f"{parsed.scheme}://{parsed.netloc}"
        except Exception:
            pass

        fp = self._fingerprint
        headers = {
            "Accept": "application/json",
            "Referer": referer,
            "Origin": origin,
            "User-Agent": self._ua,
            "Accept-Language": fp["lang_full"],
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
            "priority": "u=1, i",
        }
        if fp.get("sec_ch_ua"):
            headers["sec-ch-ua"] = fp["sec_ch_ua"]
            headers["sec-ch-ua-mobile"] = fp.get("sec_ch_ua_mobile") or "?0"
            headers["sec-ch-ua-platform"] = fp["sec_ch_ua_platform"]
            # Client Hints 全套（仅 Chromium 有值，其他浏览器为空串不下发）
            if fp.get("sec_ch_ua_full_version_list"):
                headers["sec-ch-ua-full-version-list"] = fp["sec_ch_ua_full_version_list"]
            if fp.get("sec_ch_ua_arch"):
                headers["sec-ch-ua-arch"] = fp["sec_ch_ua_arch"]
            if fp.get("sec_ch_ua_bitness"):
                headers["sec-ch-ua-bitness"] = fp["sec_ch_ua_bitness"]
            if fp.get("sec_ch_ua_model"):
                headers["sec-ch-ua-model"] = fp["sec_ch_ua_model"]
            if fp.get("sec_ch_ua_platform_version"):
                headers["sec-ch-ua-platform-version"] = fp["sec_ch_ua_platform_version"]

        # auth.openai.com 侧请求补设备标识（若可得）
        try:
            host = (urlparse(origin).netloc or "").lower()
        except Exception:
            host = ""
        if "auth.openai.com" in host:
            device_id = (self.result.device_id or "").strip() or (self.session.cookies.get("oai-did", "") or "").strip()
            if device_id:
                headers["oai-device-id"] = device_id

        headers.update(self._datadog_trace_headers())
        return headers

    def _navigation_headers(self) -> dict:
        """文档导航请求（地址栏直达那种）的头，含 client hints。

        和 _common_headers 的区别只在 Sec-Fetch-* 那组：那边是 XHR（empty/cors/
        same-origin），这里是整页导航（document/navigate/none + user + UIR）。
        **client hints 两边必须一致**，都从 self._fingerprint 取：Chrome 指纹发
        全套，Safari/Firefox 指纹 sec_ch_ua 为空串、一个都不发——这正是真实浏览器
        的行为。旧 warmup 手搓头漏了这段，导致 Chrome UA 裸奔，实测 403 率 4/5，
        补齐后 5/5 通过（详见 warmup docstring）。
        """
        fp = self._fingerprint
        headers = {
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,"
                      "image/avif,image/webp,image/apng,*/*;q=0.8",
            "Accept-Language": fp["lang_full"],
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "sec-fetch-dest": "document",
            "sec-fetch-mode": "navigate",
            "sec-fetch-site": "none",
            "sec-fetch-user": "?1",
            "upgrade-insecure-requests": "1",
            "priority": "u=0, i",
            "User-Agent": self._ua,
        }
        if fp.get("sec_ch_ua"):
            headers["sec-ch-ua"] = fp["sec_ch_ua"]
            headers["sec-ch-ua-mobile"] = fp.get("sec_ch_ua_mobile") or "?0"
            headers["sec-ch-ua-platform"] = fp["sec_ch_ua_platform"]
            for key, name in (
                ("sec_ch_ua_full_version_list", "sec-ch-ua-full-version-list"),
                ("sec_ch_ua_arch", "sec-ch-ua-arch"),
                ("sec_ch_ua_bitness", "sec-ch-ua-bitness"),
                ("sec_ch_ua_model", "sec-ch-ua-model"),
                ("sec_ch_ua_platform_version", "sec-ch-ua-platform-version"),
            ):
                if fp.get(key):
                    headers[name] = fp[key]
        return headers

    def warmup(self) -> bool:
        """GET chatgpt.com 种全套 cookie（含 oai-did），成功返回 True。

        为什么这步不能失败（2026-08-10 实测 26 轮，跨 40+ 出口 IP）：
        `POST /api/auth/signin/openai` 依据 chatgpt.com 的 cookie 决定返回什么——
        有 oai-did 就返 auth.openai.com/authorize URL，没有就返 NextAuth 页，
        后者到 authorize/continue 必然 409 invalid_state。
        实测：无 oai-did 的 5 轮 **5/5 全 409**；有 oai-did 的 17 轮只有 3 次 409。

        旧实现两个问题，实测各占一半失败：
        1. 单次无重试 + timeout=15。实测种 cookie 失败率 19%，形态有三种：
           TLS curl(35) 断连、15s 超时、CF 403。成功轮实际耗时 3.4~10.9s，
           15s 卡边缘，40s 才有富余。
        2. **返回值和实际结果对不上**：只 catch 异常，不看 status_code——
           403 照样 return True（实测 3 轮 True 但没 cookie），
           而超时前 cookie 其实已经种上了却 return False（实测 1 轮）。
           所以判据改成直接查 cookie jar，这是唯一可信的信号。

        3. **没发 client hints，自称 Chrome 却不带 sec-ch-ua —— CF 一眼假。**
           这是 403 的真因。真 Chrome 每个导航请求必带 sec-ch-ua/-mobile/-platform，
           而旧 warmup 是手搓 headers、一个都没带（_common_headers 带了，只有这里漏）。
           2026-08-10 实测，同一 impersonate 各打 5 次（每次新 IP）：

               impersonate   裸头(旧)   补 CH 全套
               chrome146      1/5        5/5
               chrome136      1/5        5/5
               chrome142      4/5        4/5   ← 唯一失败是 SSL 断连，不是 403

           补齐后 403 **全部消失**。此前"chrome 族被 CF 拦"的结论是误判：
           safari/firefox 当时 4/4 不是因为它们更干净，而是**它们本来就不该发
           client hints**，裸头对它们恰好是正确的头。所以修法是把头补齐，
           不是换成 safari —— 换指纹只是绕开症状，且会让 self._fingerprint 与
           self._ua 不一致（后续 _common_headers 会拿旧家族的 CH 配新 UA，更假）。

        重试只换出口 IP，不换指纹（指纹本来就没问题，见上）：代理池按会话分配
        出口，新 session ≈ 新 IP，绕开连不上的坏 IP。cookie 跟着 session 一起
        清掉是对的：失败轮本来就没种到有用的东西。

        注：URL 保持首页 `/`。实测对比过 `/auth/login`（16 轮 vs 10 轮），
        失败率 18.75% vs 20%，无差异，不值得换。

        【最终验证 2026-08-10】本处 + auth_oauth_init + _follow_redirects 三处
        统一走 _navigation_headers 后，用真实 CF 域名跑完整登录授权链路
        **3/3 全成功**（各约 100s，password + access_token 齐全），409 = 0。
        """
        headers = self._navigation_headers()

        for attempt in range(4):
            if attempt:
                # 只换出口 IP（新 session = 新出口），指纹保持不变：
                # 403 是缺 client hints 导致的，已在头里修好，不是指纹的锅。
                time.sleep(3 + attempt * 2)
                self.session = create_http_session(
                    proxy=self.config.proxy,
                    impersonate=self._impersonate_candidates[self._impersonate_idx],
                    user_agent=self._ua,
                )
            try:
                resp = self.session.get(
                    "https://chatgpt.com", headers=headers, timeout=40,
                )
                status = resp.status_code
            except Exception as e:
                status = None
                logger.warning(f"warmup 第 {attempt + 1}/4 次请求失败: {e}")

            # 唯一判据：cookie 到底种上没有。HTTP 200 不代表拿到 oai-did（CF 403 只给
            # __cf_bm），请求抛异常也不代表没拿到（超时前可能已经种上了）。
            try:
                cookies = self.session.cookies.get_dict()
            except Exception:
                cookies = {}
            if "oai-did" in cookies:
                logger.info(
                    f"chatgpt.com warmup 完成（第 {attempt + 1} 次，oai-did 已种，"
                    f"共 {len(cookies)} 个 cookie）"
                )
                return True

            logger.warning(
                f"warmup 第 {attempt + 1}/4 次未种到 oai-did"
                + (f"（HTTP {status}）" if status is not None else "")
                + (f"，已有 cookie: {sorted(cookies)}" if cookies else "，无任何 cookie")
            )

        logger.error("warmup 4 次均未种到 oai-did cookie —— 此时继续登录必然 409 invalid_state")
        return False

    # ── Step 1: 检查代理连通性 ──
    def check_proxy(self) -> bool:
        logger.info("检查网络连通性...")
        try:
            resp = self.session.get("https://cloudflare.com/cdn-cgi/trace", timeout=15)
            if resp.status_code == 200:
                loc = re.search(r"loc=(\w+)", resp.text)
                ip = re.search(r"ip=([^\n]+)", resp.text)
                country_code = loc.group(1) if loc else ""
                logger.info(f"网络正常 - IP: {ip.group(1) if ip else 'N/A'}, "
                            f"地区: {country_code or 'N/A'}")

                # IP 地理联动：检测到国家码后，重新生成指纹（带时区/语言联动）
                if country_code and country_code != self._country_code:
                    self._country_code = country_code
                    import random
                    session_seed = id(self.session) % (2**32)
                    rng = random.Random(session_seed)
                    self._fingerprint = generate_fingerprint(rng=rng, country_code=country_code)
                    self._ua = self._fingerprint["user_agent"]
                    new_imp = self._fingerprint["impersonate"]
                    self._impersonate_candidates = self._fingerprint.get(
                        "fallback_impersonates",
                        [new_imp, "safari17_0", "safari15_5"],
                    )
                    self._impersonate_idx = 0
                    self.session = create_http_session(
                        proxy=self.config.proxy,
                        impersonate=new_imp,
                        user_agent=self._ua,
                    )
            else:
                logger.warning(f"网络探测异常: cloudflare trace {resp.status_code}")

            return True
        except Exception as e:
            logger.error(f"网络检查失败: {e}")
        return False

    # ── Step 2: 获取 CSRF Token ──
    def get_csrf_token(self) -> str:
        logger.info("[1/10] 获取 CSRF Token...")
        headers = self._common_headers("https://chatgpt.com/auth/login")

        # Cloudflare 可能在短时间内多次请求后返回 403，重试 3 次
        for attempt in range(3):
            try:
                resp = self.session.get(
                    "https://chatgpt.com/api/auth/csrf",
                    headers=headers,
                    timeout=30,
                )
            except Exception as e:
                if self._is_tls_error(e) and self._rotate_impersonate_session():
                    continue
                if self._is_tls_error(e):
                    raise RuntimeError(
                        "chatgpt.com TLS 握手失败，当前网络无法建立到 /api/auth/csrf 的 HTTPS 连接。"
                        "请切换可直连 chatgpt.com 的网络或在界面中配置可用代理后重试。"
                    ) from e
                raise
            if resp.status_code == 403 and attempt < 2:
                wait = (attempt + 1) * 5
                logger.warning(f"Cloudflare 403, {wait}s 后重试 ({attempt + 1}/3)...")
                import time
                time.sleep(wait)
                continue
            resp.raise_for_status()
            break

        self._trace_http("chatgpt_csrf", resp)
        csrf = resp.json().get("csrfToken", "")
        if not csrf:
            raise RuntimeError("CSRF Token 获取失败")
        self.result.csrf_token = csrf
        logger.debug(f"CSRF Token: {csrf[:20]}...")
        return csrf

    # ── Step 3: 获取 auth URL ──
    def get_auth_url(self, csrf_token: str, email: str = "") -> str:
        logger.info("[2/10] 获取 OpenAI 授权地址...")
        headers = self._common_headers("https://chatgpt.com/auth/login")
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        if not self.result.device_id:
            self.result.device_id = str(uuid.uuid4())
        query_params: dict[str, str] = {
            "prompt": "login",
            "screen_hint": "login",
            "ext-oai-did": self.result.device_id,
            "auth_session_logging_id": str(uuid.uuid4()),
            "ext-passkey-client-capabilities": "1111",
        }
        if email:
            query_params["login_hint"] = email
        signin_url = f"https://chatgpt.com/api/auth/signin/openai?{urlencode(query_params)}"
        resp = self.session.post(
            signin_url,
            headers=headers,
            data={
                "csrfToken": csrf_token,
                "callbackUrl": "https://chatgpt.com/",
                "json": "true",
            },
            timeout=30,
        )
        resp.raise_for_status()
        self._trace_http("chatgpt_signin_openai", resp)
        auth_url = resp.json().get("url", "")
        if not auth_url:
            raise RuntimeError("Auth URL 获取失败")
        # 记住 OAuth 参数，并根据开关可选注入 PKCE
        self._remember_oauth_params(auth_url)
        auth_url = self._inject_pkce_into_auth_url(auth_url)
        self._remember_oauth_params(auth_url)
        logger.debug(f"Auth URL: {auth_url[:80]}...")
        return auth_url

    # ── Step 4: OAuth 初始化 & 获取 device_id ──
    def auth_oauth_init(self, auth_url: str) -> str:
        """跟随 authorize 链，落 authorize 会话状态并取回 oai-did。

        这一步**建立的就是后面 authorize/continue 要用的那个 state**，头不像真
        浏览器就拿不到有效状态，下一步必 409 invalid_state。

        旧实现只发 Accept/Referer/UA，缺 client hints、**整组 Sec-Fetch-* 也没有**
        （真浏览器跳转必带 document/navigate/cross-site）。2026-08-10 实测 A/B
        对照各 6 轮（400 invalid_username 视为会话正常，只是 .test 域名被拒）：

            A 现状裸头        会话正常 2/6，**409 = 3**
            B 补齐 CH+SecFetch 会话正常 5/6，**409 = 0**

        和 warmup 那处是同一个病（详见 warmup docstring），当时只修了 warmup，
        漏了这里，所以主人实跑仍 409。头统一从 _navigation_headers 派生，
        保证 client hints 与 self._fingerprint / self._ua 同族。
        """
        logger.info("[3/10] OAuth 初始化...")
        headers = self._navigation_headers()
        headers["Referer"] = "https://chatgpt.com/"
        # chatgpt.com -> auth.openai.com 是跨站跳转，不是首次直达
        headers["sec-fetch-site"] = "cross-site"
        # 302 自动跟随不是用户手动点击，真浏览器此时不发 sec-fetch-user
        headers.pop("sec-fetch-user", None)
        resp = self.session.get(auth_url, headers=headers, timeout=30, allow_redirects=True)
        self._trace_http("auth_oauth_init", resp)

        # 从 cookie 获取 oai-did
        device_id = ""
        for cookie in self.session.cookies:
            if hasattr(cookie, "name"):
                if cookie.name == "oai-did":
                    device_id = cookie.value
                    break
            elif isinstance(cookie, str) and cookie == "oai-did":
                device_id = self.session.cookies.get("oai-did", "")
                break

        # curl_cffi cookies 访问方式
        if not device_id:
            try:
                device_id = self.session.cookies.get("oai-did", "")
            except Exception:
                pass

        # fallback: 从 HTML 提取
        if not device_id:
            m = re.search(r'oai-did["\s:=]+([a-f0-9-]{36})', resp.text)
            if m:
                device_id = m.group(1)

        if not device_id:
            device_id = str(uuid.uuid4())
            logger.warning(f"未从响应中获取 device_id，使用生成值: {device_id}")

        self.result.device_id = device_id
        logger.debug(f"Device ID: {device_id}")
        return device_id

    # ── Step 5: 获取 Sentinel Token ──
    def _sentinel_fp_kwargs(self) -> dict:
        """从 self._fingerprint 抽出 sentinel 需要的指纹/硬件字段。

        保证授权链路中的 sentinel 调用使用同一套一致画像——
        UA↔platform↔vendor↔硬件全程不变。
        """
        fp = self._fingerprint or {}
        return {
            "user_agent": self._ua,
            "sec_ch_ua": fp.get("sec_ch_ua", ""),
            "sec_ch_ua_platform": fp.get("sec_ch_ua_platform", ""),
            "sec_ch_ua_mobile": fp.get("sec_ch_ua_mobile", ""),
            # Client Hints 全套（仅 Chromium 有值）
            "sec_ch_ua_full_version_list": fp.get("sec_ch_ua_full_version_list", ""),
            "sec_ch_ua_arch": fp.get("sec_ch_ua_arch", ""),
            "sec_ch_ua_bitness": fp.get("sec_ch_ua_bitness", ""),
            "sec_ch_ua_model": fp.get("sec_ch_ua_model", ""),
            "sec_ch_ua_platform_version": fp.get("sec_ch_ua_platform_version", ""),
            "screen": fp.get("screen", ""),
            "lang": fp.get("lang", ""),
            "lang_full": fp.get("lang_full", ""),
            "browser_type": fp.get("browser_type", ""),
            "navigator_platform": fp.get("navigator_platform", ""),
            "navigator_vendor": fp.get("navigator_vendor"),
            "hardware_concurrency": fp.get("hardware_concurrency", 0),
            "device_memory": fp.get("device_memory"),
            "max_touch_points": fp.get("max_touch_points", 0),
            "device_pixel_ratio": fp.get("device_pixel_ratio", 0.0),
            "timezone": fp.get("timezone", ""),  # IP 联动时区
        }

    def get_sentinel_token(self, device_id: str) -> str:
        logger.info("[4/10] 获取 Sentinel Token (PoW)...")
        from .sentinel import get_sentinel_token
        result = get_sentinel_token(
            self.session,
            device_id=device_id,
            flow="authorize_continue",
            **self._sentinel_fp_kwargs(),
        )
        token, so_token = result
        self._last_sentinel_token = token or ""
        self._last_sentinel_so_token = so_token or ""
        logger.debug("Sentinel Token 获取成功")
        return token

    # ── Step 6: submit the login identifier ──
    def authorize_continue_identity(
        self,
        value: str,
        kind: str,
        sentinel_token: str,
        screen_hint: str = "login",
        referer: str = "https://auth.openai.com/log-in",
        trace_step: str = "",
    ) -> dict:
        """Submit an email or phone login identifier."""
        normalized_value = str(value or "").strip()
        normalized_kind = str(kind or "email").strip().lower() or "email"
        if normalized_kind not in {"email", "phone_number"}:
            raise ValueError(f"不支持的登录标识类型: {normalized_kind}")
        headers = self._common_headers(referer)
        headers["Content-Type"] = "application/json"
        if sentinel_token:
            headers["openai-sentinel-token"] = sentinel_token
        if getattr(self, "_last_sentinel_so_token", ""):
            headers["openai-sentinel-so-token"] = self._last_sentinel_so_token
        payload = {
            "username": {"value": normalized_value, "kind": normalized_kind},
            "screen_hint": screen_hint,
        }
        resp = self.session.post(
            "https://auth.openai.com/api/accounts/authorize/continue",
            headers=headers,
            json=payload,
            timeout=30,
        )
        self._trace_http(trace_step or f"authorize_continue_{screen_hint}", resp)
        if resp.status_code != 200:
            # 额外打日志：headers/req_id 帮排查是不是 IP 风控
            req_id = (resp.headers.get("x-request-id", "") or "")[:80]
            ct = (resp.headers.get("Content-Type", "") or "")[:60]
            summary = _safe_http_error_summary(resp)
            logger.error(
                "authorize/continue 非 200: status=%s screen_hint=%s req_id=%s content_type=%s %s",
                resp.status_code, screen_hint, req_id, ct, summary,
            )
            raise RuntimeError(
                f"authorize/continue 失败(screen_hint={screen_hint}): "
                f"{summary} req_id={req_id}"
            )
        try:
            return resp.json() if resp is not None else {}
        except Exception:
            return {}

    def authorize_continue(
        self,
        email: str,
        sentinel_token: str,
        screen_hint: str = "login",
        referer: str = "https://auth.openai.com/log-in",
        trace_step: str = "",
        username_kind: str = "email",
    ) -> dict:
        """Call /api/accounts/authorize/continue and return the next step."""
        return self.authorize_continue_identity(
            value=email,
            kind=username_kind,
            sentinel_token=sentinel_token,
            screen_hint=screen_hint,
            referer=referer,
            trace_step=trace_step,
        )

    # ── Step 7: 发送登录 OTP ──
    def send_otp(self, referer: str = "https://auth.openai.com/email-verification"):
        logger.info(f"[6/10] 发送 OTP (referer={referer.split('/')[-1]})...")
        headers = self._common_headers(referer)
        if self._last_sentinel_token:
            headers["openai-sentinel-token"] = self._last_sentinel_token
        if getattr(self, "_last_sentinel_so_token", ""):
            headers["openai-sentinel-so-token"] = self._last_sentinel_so_token
        resp = self.session.get(
            "https://auth.openai.com/api/accounts/email-otp/send",
            headers=headers,
            timeout=30,
        )
        self._trace_http("send_email_otp", resp)
        if resp.status_code != 200:
            raise RuntimeError(f"发送 OTP 失败: {_safe_http_error_summary(resp)}")
        logger.info("OTP 已发送到邮箱")

    def resend_otp(self, referer: str = "https://auth.openai.com/email-verification") -> bool:
        """
        重发 OTP（适用于 passwordless/login_challenge）。
        返回 True 代表请求成功。
        """
        headers = self._common_headers(referer)
        headers["Content-Type"] = "application/json"
        if self._last_sentinel_token:
            headers["openai-sentinel-token"] = self._last_sentinel_token
        if getattr(self, "_last_sentinel_so_token", ""):
            headers["openai-sentinel-so-token"] = self._last_sentinel_so_token
        resp = self.session.post(
            "https://auth.openai.com/api/accounts/email-otp/resend",
            headers=headers,
            timeout=30,
        )
        self._trace_http("resend_email_otp", resp)
        if resp.status_code == 200:
            logger.info("OTP 已重发")
            return True
        logger.warning("重发 OTP 失败: %s", _safe_http_error_summary(resp))
        return False

    def kickoff_otp_delivery(self, mode: str = "") -> bool:
        """Resend an OTP and fall back to the send endpoint if needed."""
        if self.resend_otp("https://auth.openai.com/email-verification"):
            return True
        try:
            self.send_otp(referer="https://auth.openai.com/email-verification")
            return True
        except Exception as e:
            logger.warning(f"登录 OTP 发码失败(mode={mode or 'unknown'}): {e}")
            return False

    def _resolve_login_password(self, email: str) -> tuple[str, bool]:
        """Read the supplied password and return ``(password, is_real)``."""
        pwd = (self.result.password or "").strip()
        if pwd:
            return pwd, True
        pwd = (os.getenv("LOGIN_PASSWORD", "") or "").strip()
        if pwd:
            return pwd, True
        if self._account_callback:
            try:
                cred = self._account_callback(email) or {}
                pwd = (cred.get("password") or "").strip()
                if pwd:
                    logger.info("已从数据库加载密码")
                    return pwd, True
            except Exception as e:
                logger.warning(f"account_callback 加载密码异常: {e}")
        return "", False

    def login_password_verify(self, password: str) -> dict:
        """Submit the password verification step."""
        headers = self._common_headers("https://auth.openai.com/log-in/password")
        headers["Content-Type"] = "application/json"
        if self._last_sentinel_token:
            headers["openai-sentinel-token"] = self._last_sentinel_token
        if getattr(self, "_last_sentinel_so_token", ""):
            headers["openai-sentinel-so-token"] = self._last_sentinel_so_token
        resp = self.session.post(
            "https://auth.openai.com/api/accounts/password/verify",
            headers=headers,
            json={"password": password},
            timeout=30,
        )
        self._trace_http("login_password_verify", resp)
        if resp.status_code != 200:
            raise RuntimeError(f"密码登录失败: {_safe_http_error_summary(resp)}")
        try:
            return resp.json()
        except Exception:
            return {}

    # ── Step 7.5: 提交 TOTP 2FA 验证码 ──
    def submit_mfa_totp(self, totp_code: str, challenge_id: str) -> dict:
        """Submit a TOTP 2FA code after a password challenge.

        Args:
            totp_code: 6 位 TOTP 动态码
            challenge_id: 从 continue_url 提取的 challenge ID（如 /mfa-challenge/6a76f2e8...）

        Returns:
            服务端响应 dict，包含 continue_url 指向 callback
        """
        headers = self._common_headers("https://auth.openai.com/mfa-challenge")
        headers["Content-Type"] = "application/json"
        if self._last_sentinel_token:
            headers["openai-sentinel-token"] = self._last_sentinel_token
        if getattr(self, "_last_sentinel_so_token", ""):
            headers["openai-sentinel-so-token"] = self._last_sentinel_so_token

        resp = self.session.post(
            "https://auth.openai.com/api/accounts/mfa/verify",
            headers=headers,
            json={"code": totp_code, "type": "totp", "id": challenge_id},
            timeout=30,
        )
        self._trace_http("submit_mfa_totp", resp)
        if resp.status_code != 200:
            raise RuntimeError(f"TOTP 验证失败: {_safe_http_error_summary(resp)}")
        try:
            return resp.json()
        except Exception:
            return {}

    def issue_mfa_challenge(self, factor_id: str) -> dict:
        """Issue the server-side TOTP challenge before submitting a code."""

        headers = self._common_headers("https://auth.openai.com/mfa-challenge")
        headers["Content-Type"] = "application/json"
        if self._last_sentinel_token:
            headers["openai-sentinel-token"] = self._last_sentinel_token
        if getattr(self, "_last_sentinel_so_token", ""):
            headers["openai-sentinel-so-token"] = self._last_sentinel_so_token
        resp = self.session.post(
            "https://auth.openai.com/api/accounts/mfa/issue_challenge",
            headers=headers,
            json={"type": "totp", "id": factor_id, "force_fresh_challenge": False},
            timeout=30,
        )
        self._trace_http("issue_mfa_challenge", resp)
        if resp.status_code != 200:
            raise RuntimeError(f"TOTP challenge 初始化失败: {_safe_http_error_summary(resp)}")
        try:
            return resp.json()
        except Exception:
            return {}

    @staticmethod
    def _extract_mfa_factor_id(step: dict | None) -> str:
        """Extract the TOTP factor id from the auth session payload."""

        if not isinstance(step, dict):
            return ""
        session = step.get("oai-client-auth-session") or {}
        if not isinstance(session, dict):
            return ""
        factors = []
        for key in ("mfa_challenge_factors", "mfa_factors"):
            values = session.get(key)
            if isinstance(values, list):
                factors.extend(values)
        for factor in factors:
            if not isinstance(factor, dict):
                continue
            factor_type = str(factor.get("factor_type") or factor.get("type") or "").lower()
            factor_id = str(factor.get("id") or "").strip()
            if factor_id and (not factor_type or factor_type == "totp"):
                return factor_id
        return ""

    def complete_mfa_totp(self, step: dict | None, continue_url: str, email: str) -> tuple[dict, str]:
        """Complete a TOTP challenge using the configured account secret."""

        totp_secret = re.sub(r"[\s=]", "", str(self.result.totp_secret or "")).upper()
        if not totp_secret and self._account_callback:
            try:
                cred = self._account_callback(email) or {}
                totp_secret = re.sub(r"[\s=]", "", str(cred.get("totp_secret") or "")).upper()
                if totp_secret:
                    self.result.totp_secret = totp_secret
            except Exception as error:
                logger.warning("account_callback 加载 2FA 密钥异常: %s", type(error).__name__)
        if not totp_secret:
            raise RuntimeError("账号需要 2FA 验证，但未配置 TOTP 密钥")
        if not re.fullmatch(r"[A-Z2-7]{16,128}", totp_secret):
            raise RuntimeError("账号需要 2FA 验证，但 TOTP 密钥格式无效")
        factor_id = self._extract_mfa_factor_id(step)
        if not factor_id and "/mfa-challenge/" in (continue_url or ""):
            factor_id = continue_url.rstrip("/").split("/")[-1]
        if not factor_id:
            raise RuntimeError("账号需要 2FA 验证，但响应缺少 TOTP 因子")
        self.issue_mfa_challenge(factor_id)
        code = _totp_now(totp_secret)
        logger.info("提交 TOTP 码进行 2FA 验证（factor_id=%s...）", factor_id[:16])
        response = self.submit_mfa_totp(code, factor_id)
        return response, self._normalize_continue_url(self._extract_continue_url_from_step(response))

    # ── Step 8: 验证 OTP ──
    def verify_otp(self, otp_code: str) -> dict:
        logger.info("[7/10] 验证 OTP...")
        headers = self._common_headers("https://auth.openai.com/email-verification")
        headers["Content-Type"] = "application/json"
        resp = self.session.post(
            "https://auth.openai.com/api/accounts/email-otp/validate",
            headers=headers,
            json={"code": otp_code},
            timeout=30,
        )
        self._trace_http("validate_email_otp", resp)
        if resp.status_code != 200:
            summary = _safe_http_error_summary(resp)
            logger.warning("verify_otp 失败: %s", summary)
            raise RuntimeError(f"OTP 验证失败: {summary}")
        logger.info("OTP 验证成功")
        try:
            return resp.json()
        except Exception:
            return {}

    # ── Step 9: 创建账户 ──
    def _extract_workspace_id(self) -> str:
        """从 cookie 中提取 workspace_id"""
        try:
            auth_session = self.session.cookies.get("oai-client-auth-session", "")
            if auth_session:
                parts = auth_session.split(".")
                # 兼容不同 cookie 形态：workspace_id 可能在第 1 段/第 2 段，也可能在 workspaces[0].id
                for idx in range(min(2, len(parts))):
                    segment = (parts[idx] or "").strip()
                    if not segment:
                        continue
                    payload_b64 = segment + "=" * (-len(segment) % 4)
                    decoded = json.loads(base64.urlsafe_b64decode(payload_b64.encode("utf-8")).decode("utf-8"))
                    if not isinstance(decoded, dict):
                        continue
                    wid = (decoded.get("workspace_id", "") or "").strip()
                    if wid:
                        return wid
                    workspaces = decoded.get("workspaces", [])
                    if isinstance(workspaces, list):
                        for it in workspaces:
                            if isinstance(it, dict):
                                wid = (it.get("id", "") or "").strip()
                                if wid:
                                    return wid
        except Exception:
            pass
        return ""

    def _workspace_select(self, workspace_id: str) -> str:
        logger.info("执行 workspace 选择...")
        headers = self._common_headers("https://auth.openai.com/sign-in-with-chatgpt/codex/consent")
        headers["Content-Type"] = "application/json"
        resp = self.session.post(
            "https://auth.openai.com/api/accounts/workspace/select",
            headers=headers,
            json={"workspace_id": workspace_id},
            timeout=30,
        )
        self._trace_http("workspace_select", resp)
        return resp.json().get("continue_url", "") if resp.status_code == 200 else ""

    def _choose_account_select(self, html_text: str, current_url: str) -> str:
        """处理 /choose-an-account 多账号选择页（react-router SSR）。

        HTML 里 streamController.enqueue 注入 `unified_sessions[].id` (us_*) 和
        `session_id` (authsess_*)。这里 regex 抽 us_*，按 react-router action 惯例
        POST 回 /choose-an-account，并 fallback 试几个候选 JSON endpoint。
        返回 next continue_url 或空串。
        """
        m = re.search(r"us_[A-Za-z0-9]{16,}", html_text or "")
        if not m:
            logger.warning("/choose-an-account HTML 里没找到 us_* session id, 跳过")
            return ""
        session_id = m.group(0)
        logger.debug(f"/choose-an-account 选 session_id={session_id}")
        headers = self._common_headers("https://auth.openai.com/choose-an-account")
        headers["Origin"] = "https://auth.openai.com"

        # 真实 endpoint 从 nextStepHandler-*.js 反编译解出：
        #   const {path, method} = r.data.intent === "select"
        #     ? {path: "/session/select", method: "POST"}
        #     : {path: "/session/remove", method: "DELETE"};
        #   fetch(`${authapi_base}/session/select`, {method, body: JSON.stringify({session_id})})
        # 即 POST https://auth.openai.com/api/accounts/session/select JSON {session_id}
        # （intent 决定 path 不进 body；body 只有 session_id 一个字段）
        # 之前直接 POST /choose-an-account 会先经过 react-router action loader 再被
        # nextStepHandler 转发，但 server-side 那一段似乎对 CT/form 字段强敏感，500。
        # 直接命中底层 /api/accounts/session/select 绕开 react-router 层。
        candidates = [
            ("POST", "https://auth.openai.com/api/accounts/session/select",
             {"session_id": session_id}, "json"),
            # 兜底：万一上面被风控，回退到 react-router 路径 + zod schema 字段
            ("POST", "https://auth.openai.com/choose-an-account",
             {"intent": "select", "session_id": session_id}, "form"),
        ]
        for method, url, body, kind in candidates:
            try:
                h = dict(headers)
                if kind == "json":
                    h["Content-Type"] = "application/json"
                    h["Accept"] = "application/json"
                    resp = self.session.post(url, headers=h, json=body, timeout=30)
                else:
                    h["Content-Type"] = "application/x-www-form-urlencoded"
                    h["Accept"] = "application/json, text/html;q=0.9"
                    body_str = "&".join(f"{k}={v}" for k, v in body.items())
                    resp = self.session.post(url, headers=h, data=body_str, timeout=30)
                self._trace_http(f"choose_account_try_{kind}_{url.rsplit('/', 1)[-1][:30]}", resp)
                status = getattr(resp, "status_code", 0)
                loc = (getattr(resp, "headers", {}) or {}).get("Location", "") or \
                      (getattr(resp, "headers", {}) or {}).get("location", "") or ""
                # 不把完整响应 body / Cookie / session 信息写入 stdout。
                # 该输出会被服务日志和 SSE 收集，原先的 body 泄露了
                # auth session 细节；这里只保留状态、脱敏后的跳转前缀和
                # JSON 顶层字段，足够诊断选号分支。
                body_len = len(getattr(resp, "text", "") or "")
                json_keys = ""
                try:
                    payload = resp.json() if resp is not None else {}
                    if isinstance(payload, dict):
                        json_keys = ",".join(str(key) for key in list(payload)[:12])
                except Exception:
                    pass
                logger.info(
                    "[choose-an-account] %s %s [%s] -> status=%s loc=%s body_len=%s json_keys=%s",
                    method,
                    url,
                    kind,
                    status,
                    loc[:120],
                    body_len,
                    json_keys,
                )
                if status in (200, 201, 302, 303):
                    next_url = ""
                    try:
                        j = resp.json() if resp is not None else {}
                        next_url = j.get("continue_url", "") if isinstance(j, dict) else ""
                    except Exception:
                        pass
                    if not next_url and loc:
                        next_url = loc
                    if next_url:
                        logger.debug(f"choose-an-account 选号成功 endpoint={url} next={next_url[:120]}")
                        return next_url
                    # 200 但没 continue_url：可能 set 了 cookie，直接让 caller 重 GET authorize
                    if status == 200:
                        logger.debug(f"choose-an-account POST {url} 200 OK 无 continue_url，假定 cookie 已 set")
                        return current_url  # 让外层重 GET 一次，cookie 已被 server set
            except Exception as e:
                logger.warning(
                    "[choose-an-account] %s %s [%s] -> %s",
                    method,
                    url,
                    kind,
                    type(e).__name__,
                )
                continue
        logger.warning("/choose-an-account 全部候选 endpoint 都失败")
        return ""

    def _normalize_continue_url(self, continue_url: str) -> str:
        """
        标准化 continue_url：
        1) 相对路径 -> 绝对路径
        2) workspace 页面 -> 调用 workspace/select 取下一跳
        """
        if not continue_url:
            return ""
        out = continue_url.strip()
        if out.startswith("/"):
            out = urljoin("https://auth.openai.com", out)
        if "/workspace" in out:
            workspace_id = self._extract_workspace_id() or self._extract_query_first(out, ["workspace_id", "id"])
            if workspace_id:
                logger.info("检测到 workspace 页面，尝试 workspace/select: workspace_id=%s", workspace_id)
                next_url = self._workspace_select(workspace_id)
                if next_url:
                    out = next_url
        return out

    @staticmethod
    def _extract_workspace_id_from_html(html_text: str) -> str:
        """从 workspace 页面 HTML 文本中提取 workspace_id（兜底）。"""
        if not html_text:
            return ""
        try:
            # 先把转义引号还原，便于正则匹配
            text = html_text.replace('\\"', '"')
            patterns = [
                r'workspaces".{0,1600}?"id","([0-9a-fA-F-]{36})"',
                r'"workspace_id"\s*:\s*"([0-9a-fA-F-]{36})"',
                r'"workspaceId"\s*:\s*"([0-9a-fA-F-]{36})"',
            ]
            for p in patterns:
                m = re.search(p, text, flags=re.DOTALL | re.IGNORECASE)
                if m:
                    return (m.group(1) or "").strip()
        except Exception:
            return ""
        return ""

    # ── Step 10: 跟踪重定向链 ──
    def follow_redirect_chain(self, start_url: str) -> tuple[str, str]:
        """手动跟踪重定向，返回 (callback_url, final_url)"""
        logger.info("[9/10] 跟踪重定向链...")
        current_url = start_url
        callback_url = ""
        max_hops = 12
        referer = "https://auth.openai.com/"

        for i in range(max_hops):
            # 逐跳整页导航，头必须像浏览器：同 auth_oauth_init，旧版只发
            # Accept/Referer/UA，缺 client hints 和 Sec-Fetch-*（实测那正是
            # 409 invalid_state 的来源，见 auth_oauth_init docstring）。
            headers = self._navigation_headers()
            headers["Referer"] = referer
            headers.pop("sec-fetch-user", None)   # 302 跟随非用户点击
            # 跨站跳转（chatgpt.com <-> auth.openai.com）标 cross-site，同站标 same-origin
            try:
                headers["sec-fetch-site"] = (
                    "same-origin"
                    if urlparse(current_url).netloc == urlparse(referer).netloc
                    else "cross-site"
                )
            except Exception:
                headers["sec-fetch-site"] = "cross-site"
            resp = self.session.get(
                current_url, headers=headers, timeout=30, allow_redirects=False
            )
            self._trace_http(f"redirect_hop_{i+1}", resp)
            referer = current_url

            if "/api/auth/callback/openai" in current_url:
                callback_url = current_url
                self._sniff_login_verifier(current_url, f"redirect_hop_{i+1}_callback_url")

            # workspace 页面常见为 200，需要主动调 workspace/select 获取下一跳
            if "/workspace" in current_url and resp.status_code == 200:
                workspace_id = self._extract_workspace_id() or self._extract_workspace_id_from_html(resp.text or "")
                if workspace_id:
                    logger.info("workspace 页面提取到 workspace_id=%s，尝试继续授权", workspace_id)
                    next_url = self._workspace_select(workspace_id)
                    if next_url:
                        if next_url.startswith("/"):
                            next_url = urljoin("https://auth.openai.com", next_url)
                        current_url = next_url
                        continue

            if resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("Location", "")
                if not location:
                    break
                if location.startswith("/"):
                    parsed = urlparse(current_url)
                    location = f"{parsed.scheme}://{parsed.netloc}{location}"
                # 关键：不要主动 GET callback，避免 code 被服务端回调消费
                if "/api/auth/callback/openai" in location and "code=" in location:
                    callback_url = location
                    current_url = location
                    self._sniff_login_verifier(location, f"redirect_hop_{i+1}_location_callback")
                    logger.info("捕获 callback URL（未消费）")
                    break
                current_url = location
                logger.debug(f"  重定向 {i + 1}: {current_url[:80]}...")
            else:
                break

        # 补一跳首页
        if (not callback_url) and (not current_url.rstrip("/").endswith("chatgpt.com")):
            self.session.get(
                "https://chatgpt.com/",
                headers={"Referer": current_url},
                timeout=30,
            )

        logger.info(f"重定向链完成, callback: {'有' if callback_url else '无'}")
        return callback_url, current_url

    def _reauthorize_for_session(self, original_auth_url: str) -> str | None:
        """Re-run authorization after OTP verification to obtain a callback URL."""
        logger.info("[9.5/10] 重新 authorize 获取 session ...")
        try:
            # 去掉 prompt=login 参数，利用已有的 auth session cookie
            from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
            parsed = urlparse(original_auth_url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            params.pop("prompt", None)
            # 重新构建 URL
            new_query = urlencode({k: v[0] for k, v in params.items()})
            authorize_url = urlunparse(parsed._replace(query=new_query))

            resp = self.session.get(
                authorize_url,
                allow_redirects=False,
                timeout=15,
            )
            self._trace_http("reauthorize_start", resp)
            logger.info(f"reauthorize status={resp.status_code}")

            # 跟随 redirect chain 找到 callback URL
            current_url = resp.headers.get("Location", "")
            logger.info(f"reauthorize Location: {current_url[:150]}")
            if resp.status_code in (301, 302, 303, 307, 308) and current_url:
                for hop in range(10):
                    logger.debug(f"reauthorize redirect hop {hop+1}: {current_url[:100]}")
                    if "code=" in current_url and "state=" in current_url:
                        logger.info("reauthorize: 找到 callback URL")
                        return current_url
                    try:
                        hop_resp = self.session.get(
                            current_url,
                            allow_redirects=False,
                            timeout=15,
                        )
                        self._trace_http(f"reauthorize_hop_{hop+1}", hop_resp)
                        next_loc = hop_resp.headers.get("Location", "")
                        if hop_resp.status_code not in (301, 302, 303, 307, 308) or not next_loc:
                            # 检查最终 URL
                            final_url = str(getattr(hop_resp, 'url', current_url))
                            if "code=" in final_url:
                                return final_url
                            break
                        current_url = next_loc
                        if not current_url.startswith("http"):
                            from urllib.parse import urljoin
                            current_url = urljoin(authorize_url, current_url)
                    except Exception:
                        break
            logger.warning("reauthorize: 未能获取 callback URL")
            return None
        except Exception as e:
            logger.warning(f"reauthorize 失败: {e}")
            return None

    # ── Step 11: 获取 session ──
    def _extract_session_cookie(self) -> str:
        """多路兜底提取 __Secure-next-auth.session-token cookie。

        curl_cffi 在某些情况下按 domain 隔离 cookie，session.cookies.get(name) 拿不到，
        所以这里把所有 cookie 都遍历一遍，按名字精确匹配。
        """
        target = "__Secure-next-auth.session-token"
        # 路径1：直接 get
        try:
            v = self.session.cookies.get(target, "")
            if v:
                return v
        except Exception:
            pass
        # 路径2：遍历 jar
        try:
            for c in self.session.cookies:
                name = getattr(c, "name", "") if hasattr(c, "name") else str(c)
                if name == target:
                    val = getattr(c, "value", "") or ""
                    if val:
                        return val
        except Exception:
            pass
        # 路径3：用 _get_cookie_value_by_name（不挑 domain）
        try:
            return self._get_cookie_value_by_name(target)
        except Exception:
            return ""

    def get_auth_session(self) -> tuple[str, str]:
        """获取 session_token 和 access_token。

        session_token 三路兜底（按优先级）：
          1. cookie `__Secure-next-auth.session-token`（NextAuth 数据库 session 策略）
          2. JSON 响应里的 `sessionToken` 字段（NextAuth JWT session 策略，某些路径）
          3. 兼容大小写 / 下划线变体
        access_token 取 JSON 响应里的 `accessToken`。
        """
        first_call = not getattr(self, "_auth_session_fetched", False)
        self._auth_session_fetched = True
        if first_call:
            logger.info("[10/10] 获取认证 Session...")
        headers = self._common_headers("https://chatgpt.com/")
        resp = self.session.get(
            "https://chatgpt.com/api/auth/session",
            headers=headers,
            timeout=30,
        )
        self._trace_http("chatgpt_auth_session", resp)
        resp.raise_for_status()

        try:
            sess_json = resp.json() if resp is not None else {}
        except Exception:
            sess_json = {}
        if not isinstance(sess_json, dict):
            sess_json = {}

        cookie_st = self._extract_session_cookie()
        json_st = (
            sess_json.get("sessionToken", "")
            or sess_json.get("session_token", "")
            or ""
        )
        session_token = cookie_st or json_st
        access_token = sess_json.get("accessToken", "") or sess_json.get("access_token", "") or ""

        if session_token:
            self.result.session_token = session_token
        if access_token:
            # A Codex OAuth exchange returns a refreshable access/refresh pair.
            # The web session endpoint can expose a different, short-lived
            # session access token.  Once a refresh token is present, replacing
            # the OAuth access token here would leave Sub2API/CLIProxyAPI with
            # credentials from two different token families and make the pair
            # fail validation.  Keep the OAuth access token in that case while
            # still recording the session token and cookie state.
            if not self.result.refresh_token:
                self.result.access_token = access_token
        self.result.cookie_header = self._build_chatgpt_cookie_header()

        _log = logger.info if first_call else logger.debug
        _log(f"session: st={'有' if session_token else '无'} at={'有' if access_token else '无'}")
        return session_token, access_token

    def _consume_callback_for_session(self, callback_url: str) -> bool:
        """主动 GET callback URL 让 chatgpt.com NextAuth 设 session cookie。

        协议层 follow_redirect_chain 故意不消费 callback（为后续 OAuth token exchange 留 code），
        但这导致 NextAuth 永远不会写 __Secure-next-auth.session-token cookie。
        在拿不到 session_token 时主动消费一次 callback：跟随到 chatgpt.com 主页，
        服务器会 Set-Cookie session-token。
        """
        if not callback_url or "code=" not in callback_url:
            return False
        try:
            current = callback_url
            for hop in range(8):
                resp = self.session.get(
                    current,
                    headers={
                        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                        "Referer": "https://auth.openai.com/",
                        "User-Agent": self._ua,
                    },
                    timeout=30,
                    allow_redirects=False,
                )
                self._trace_http(f"consume_callback_hop_{hop+1}", resp)
                if resp.status_code not in (301, 302, 303, 307, 308):
                    break
                loc = (resp.headers.get("Location", "") or "").strip()
                if not loc:
                    break
                if loc.startswith("/"):
                    loc = urljoin(current, loc)
                current = loc
                # 已到 chatgpt.com 主页就够
                parsed = urlparse(current)
                if "chatgpt.com" in (parsed.netloc or "") and "/api/auth/callback" not in current:
                    # 再 GET 一下主页，让 cookie 全部落地
                    try:
                        self.session.get(current, timeout=20, allow_redirects=True)
                    except Exception:
                        pass
                    break
            return bool(self.session.cookies.get("__Secure-next-auth.session-token", ""))
        except Exception as e:
            logger.warning(f"消费 callback 失败: {e}")
            return False

    # ── 可选: OAuth Token 交换 ──
    def oauth_token_exchange(self, callback_url: str, continue_url: str) -> bool:
        """
        交换 OAuth token（尽力模式）：
        1) 尝试多来源 code_verifier（query/cookie/dump/hydra）
        2) 回退无 verifier
        """
        auth_code = self._extract_query_first(callback_url, ["code"]) or self._extract_query_first(continue_url, ["code"])

        if not auth_code:
            logger.info("缺少 auth_code，跳过 token 交换")
            return False

        verifier_candidates = self._collect_code_verifier_candidates(callback_url, continue_url)
        if not verifier_candidates:
            logger.info("当前未获取到可用 code_verifier，将先尝试无 verifier 交换")
        else:
            show = ", ".join([f"{src}:{len(v)}" for src, v in verifier_candidates[:8]])
            logger.info("code_verifier 候选数=%s 示例=%s", len(verifier_candidates), show)

        logger.info("执行 OAuth Token 交换...")
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
            "Origin": "https://auth.openai.com",
            "Referer": "https://auth.openai.com/sign-in-with-chatgpt/codex/consent",
        }
        base_form = {
            "grant_type": "authorization_code",
            "client_id": self._oauth_client_id or "YOUR_OPENAI_WEB_CLIENT_ID",
            "code": auth_code,
            "redirect_uri": self._oauth_redirect_uri or "https://chatgpt.com/api/auth/callback/openai",
        }
        logger.info(
            "Token 交换参数: client_id=%s redirect_uri=%s",
            base_form["client_id"],
            base_form["redirect_uri"],
        )

        candidates: list[tuple[str, dict]] = []
        if self._oauth_client_secret:
            d = dict(base_form)
            d["client_secret"] = self._oauth_client_secret
            candidates.append(("with_client_secret", d))

        try:
            max_verifier_try = max(1, int(os.getenv("OAUTH_MAX_VERIFIER_TRY", "18")))
        except Exception:
            max_verifier_try = 18

        for src, verifier in verifier_candidates[:max_verifier_try]:
            d = dict(base_form)
            d["code_verifier"] = verifier
            candidates.append((f"with_verifier_{src}", d))
            if self._oauth_client_secret:
                d2 = dict(d)
                d2["client_secret"] = self._oauth_client_secret
                candidates.append((f"with_verifier_{src}_and_client_secret", d2))

        # 一些服务端可能要求额外参数（实验候选）
        audience = self._extract_query_first(self._oauth_auth_url, ["audience"])
        if audience:
            d = dict(base_form)
            d["audience"] = audience
            candidates.append(("without_verifier_with_audience", d))
        if self._oauth_scope:
            d = dict(base_form)
            d["scope"] = self._oauth_scope
            candidates.append(("without_verifier_with_scope", d))

        candidates.append(("without_verifier", dict(base_form)))

        seen_fingerprints: set[str] = set()
        for mode, form in candidates:
            fp = json.dumps(form, sort_keys=True, ensure_ascii=False)
            if fp in seen_fingerprints:
                continue
            seen_fingerprints.add(fp)
            try:
                self._sniff_login_verifier(urlencode(form), f"oauth_token_exchange_{mode}:form")
            except Exception:
                pass
            encoded_form = urlencode(form)
            extra_request = {
                "method": "POST",
                "url": "https://auth.openai.com/oauth/token",
                "body": encoded_form,
                "headers": headers,
            }

            resp = self.session.post(
                "https://auth.openai.com/oauth/token",
                headers=headers,
                data=encoded_form,
                timeout=30,
            )
            self._trace_http(f"oauth_token_exchange_{mode}", resp, extra_request=extra_request)
            if resp.status_code == 200:
                data = resp.json()
                self.result.id_token = data.get("id_token", "")
                self.result.access_token = data.get("access_token", self.result.access_token)
                self.result.refresh_token = data.get("refresh_token", "")
                logger.info(
                    "Token 交换成功(mode=%s): refresh_token=%s",
                    mode,
                    "有" if self.result.refresh_token else "无",
                )
                return True

            logger.warning("Token 交换失败(mode=%s): %s", mode, _safe_http_error_summary(resp))

        return False

    def oauth_secondary_authorize_exchange(self) -> bool:
        """
        二次授权实验：
        - 在当前已登录会话上，重新发起一条带 PKCE 的 authorize
        - 仅提取 callback code，不消费 callback
        - 再走 oauth/token 交换
        """
        logger.info("尝试二次 authorize + PKCE 换 refresh_token ...")
        try:
            csrf = self.get_csrf_token()
            auth_url = self.get_auth_url(csrf)
        except Exception as e:
            logger.warning(f"二次 authorize 初始化失败: {e}")
            return False

        try:
            verifier, challenge = self._build_pkce_pair()
            parsed = urlparse(auth_url)
            params = dict(parse_qsl(parsed.query, keep_blank_values=True))
            params["code_challenge"] = challenge
            params["code_challenge_method"] = "S256"
            if not params.get("state"):
                params["state"] = self._b64url_no_pad(os.urandom(16))
            sec_url = urlunparse(parsed._replace(query=urlencode(params)))

            self._manual_login_verifier = verifier
            self._captured_login_verifier = verifier
            self._remember_oauth_params(sec_url)

            current = sec_url
            callback_url = ""
            max_hops = 10
            for i in range(max_hops):
                resp = self.session.get(
                    current,
                    headers={
                        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                        "Referer": "https://chatgpt.com/",
                        "User-Agent": self._ua,
                    },
                    timeout=30,
                    allow_redirects=False,
                )
                self._trace_http(f"secondary_authorize_hop_{i+1}", resp)

                loc = (resp.headers.get("Location", "") or "").strip()
                if loc and loc.startswith("/"):
                    loc = urljoin(current, loc)

                if loc and "/api/auth/callback/openai" in loc and "code=" in loc:
                    callback_url = loc
                    break
                if resp.status_code not in (301, 302, 303, 307, 308) or not loc:
                    break
                current = loc

            if not callback_url:
                logger.warning("二次 authorize 未捕获 callback code")
                return False

            ok = self.oauth_token_exchange(callback_url, callback_url)
            logger.info("二次 authorize 交换结果: %s", "成功" if ok else "失败")
            return ok
        except Exception as e:
            logger.warning(f"二次 authorize 交换异常: {e}")
            return False

    @staticmethod
    def _mfa_info_has_totp(payload: Any) -> bool:
        """Return whether the ChatGPT account has an active TOTP factor."""

        if not isinstance(payload, dict):
            return False
        factors = payload.get("factors")
        totp_factors = factors.get("totp") if isinstance(factors, dict) else None
        if not isinstance(totp_factors, list):
            return False
        return bool(payload.get("mfa_enabled_v2") and any(
            isinstance(item, dict)
            and (str(item.get("factor_type") or item.get("type") or "").lower() == "totp" or item.get("id"))
            for item in totp_factors
        ))

    @staticmethod
    def _normalize_enrolled_totp_secret(value: Any) -> str:
        normalized = re.sub(r"[\s=]", "", str(value or "")).upper()
        return normalized if re.fullmatch(r"[A-Z2-7]{16,128}", normalized) else ""

    def _chatgpt_mfa_headers(self, access_token: str, target_path: str) -> dict[str, str]:
        """Build the browser-like headers required by ChatGPT MFA endpoints."""

        headers = self._common_headers("https://chatgpt.com/")
        headers.update({
            "Authorization": f"Bearer {access_token}",
            "oai-device-id": self.result.device_id or self.session.cookies.get("oai-did", "") or str(uuid.uuid4()),
            "oai-session-id": str(uuid.uuid4()),
            "oai-language": "zh-CN",
            "x-openai-target-path": target_path,
            "x-openai-target-route": target_path,
        })
        return headers

    @staticmethod
    def _extract_chatgpt_page_access_token(html: Any) -> str:
        """Extract the web access token embedded in the TOTP enable page."""

        text = str(html or "")
        for source in (text, text.replace("&quot;", '"').replace("&#x27;", "'")):
            match = re.search(r"[\"']accessToken[\"']\s*:\s*[\"']((?:\\.|[^\"'\\])+)[\"']", source)
            if not match:
                continue
            value = match.group(1)
            try:
                value = json.loads(f'"{value}"')
            except (TypeError, ValueError, json.JSONDecodeError):
                pass
            if isinstance(value, str) and len(value) >= 20:
                return value
        return ""

    def setup_totp(self, email: str = "") -> dict[str, Any]:
        """Enroll and activate ChatGPT TOTP 2FA in the current web session.

        The returned secret is intended for the private account store only;
        callers must not put it into ordinary job events or public responses.
        """

        _, session_access_token = self.get_auth_session()
        # Normal web sessions expose ``accessToken``.  Keep the existing
        # result as a fallback for protocol revisions that only return the
        # token through the earlier auth payload.
        access_token = str(session_access_token or self.result.access_token or "").strip()
        enable_page = self.session.get(
            "https://chatgpt.com/?action=enable&factor=totp",
            headers={**self._navigation_headers(), "Referer": "https://chatgpt.com/"},
            timeout=30,
        )
        self._trace_http("mfa_totp_enable_page", enable_page)
        page_access_token = self._extract_chatgpt_page_access_token(getattr(enable_page, "text", ""))
        if page_access_token:
            access_token = page_access_token
        if not access_token:
            raise RuntimeError("开通 2FA 失败：未获取 ChatGPT 网页会话 Token")

        info_path = "/backend-api/accounts/mfa_info"
        info_url = f"https://chatgpt.com{info_path}"
        info_resp = self.session.get(
            info_url,
            headers=self._chatgpt_mfa_headers(access_token, info_path),
            timeout=30,
        )
        self._trace_http("mfa_info_before_totp_setup", info_resp)
        if not 200 <= int(info_resp.status_code or 0) < 300:
            raise RuntimeError(f"查询 2FA 状态失败: {_safe_http_error_summary(info_resp)}")
        try:
            current_info = info_resp.json()
        except Exception:
            current_info = {}
        if self._mfa_info_has_totp(current_info):
            return {
                "email": str(email or self.result.email or "").strip().lower(),
                "already_enabled": True,
                "activation_succeeded": False,
                "secret": "",
                "otpauth_uri": "",
            }

        enroll_path = "/backend-api/accounts/mfa/enroll"
        enroll_resp = self.session.post(
            f"https://chatgpt.com{enroll_path}",
            headers=self._chatgpt_mfa_headers(access_token, enroll_path),
            json={"factor_type": "totp"},
            timeout=30,
        )
        # The enrollment response contains the new secret. Do not send it
        # through the optional HTTP trace/dump path.
        if not 200 <= int(enroll_resp.status_code or 0) < 300:
            raise RuntimeError(f"申请 2FA 密钥失败: {_safe_http_error_summary(enroll_resp)}")
        try:
            enrollment = enroll_resp.json()
        except Exception:
            enrollment = {}
        secret = self._normalize_enrolled_totp_secret(enrollment.get("secret") if isinstance(enrollment, dict) else "")
        session_id = str(enrollment.get("session_id") or "").strip() if isinstance(enrollment, dict) else ""
        if not secret or not session_id:
            raise RuntimeError("申请 2FA 密钥失败：响应缺少有效密钥或会话 ID")

        account_email = str(email or self.result.email or "").strip().lower()
        otpauth_uri = (
            f"otpauth://totp/{quote(f'OpenAI:{account_email}', safe='')}"
            f"?{urlencode({'secret': secret, 'issuer': 'OpenAI', 'algorithm': 'SHA1', 'digits': '6', 'period': '30'})}"
        )
        activate_path = "/backend-api/accounts/mfa/user/activate_enrollment"
        activate_resp = self.session.post(
            f"https://chatgpt.com{activate_path}",
            headers=self._chatgpt_mfa_headers(access_token, activate_path),
            json={"code": _totp_now(secret), "factor_type": "totp", "session_id": session_id},
            timeout=30,
        )
        self._trace_http("mfa_activate_totp", activate_resp)
        if not 200 <= int(activate_resp.status_code or 0) < 300:
            raise RuntimeError(f"激活 2FA 失败: {_safe_http_error_summary(activate_resp)}")
        try:
            activation = activate_resp.json()
        except Exception:
            activation = {}
        if not isinstance(activation, dict) or activation.get("success") is not True:
            raise RuntimeError("激活 2FA 失败：服务端未确认激活成功")

        confirm_resp = self.session.get(
            info_url,
            headers=self._chatgpt_mfa_headers(access_token, info_path),
            timeout=30,
        )
        self._trace_http("mfa_info_after_totp_setup", confirm_resp)
        if not 200 <= int(confirm_resp.status_code or 0) < 300:
            raise RuntimeError(f"确认 2FA 状态失败: {_safe_http_error_summary(confirm_resp)}")
        try:
            confirmed_info = confirm_resp.json()
        except Exception:
            confirmed_info = {}
        if not self._mfa_info_has_totp(confirmed_info):
            raise RuntimeError("激活 2FA 后状态确认失败")
        self.result.totp_secret = secret
        return {
            "email": account_email,
            "already_enabled": False,
            "activation_succeeded": True,
            "secret": secret,
            "otpauth_uri": otpauth_uri,
        }

    # ── Protocol login flow (target: callback/session/refresh) ──
    def run_protocol_login(
        self,
        mail_provider: MailProvider,
        email: str,
        password: str = "",
    ) -> AuthResult:
        """
        纯协议登录：
        - 适配 passwordless / login_password 两类登录入口
        - 可配合 OAUTH_EXCHANGE_BEFORE_CALLBACK / OAUTH_REFRESH_ONLY 尝试优先拿 refresh_token
        """
        if not (email or "").strip():
            raise RuntimeError("run_protocol_login 缺少邮箱")

        if not self.check_proxy():
            logger.warning("网络预检查未通过，继续尝试登录链路以获取精确错误...")
        # 没 oai-did 就走不通 authorize 链，早失败早换 IP。
        # 这里不花钱建邮箱，但报错说清原因，省得当成"密码错"排查。
        if not self.warmup():
            raise RuntimeError(
                "warmup 失败：4 次重试均未拿到 chatgpt.com 的 oai-did cookie，"
                "继续登录必然 409 invalid_state（多为代理出口 IP 不通或被 CF 拦），"
                "请检查代理后重试"
            )

        # Mark the login mode so OTP delivery uses the current session.
        self._is_existing_account = True

        email = email.strip()
        self.result.email = email
        login_password = (password or "").strip()
        if login_password:
            self.result.password = login_password
        else:
            login_password, pw_is_real = self._resolve_login_password(email)
            if pw_is_real:
                self.result.password = login_password
            else:
                logger.info("协议登录：调用方没给密码、库里也没有，仅保留 passwordless 登录路径")

        csrf_token = self.get_csrf_token()
        auth_url = self.get_auth_url(csrf_token, email=email)
        device_id = self.auth_oauth_init(auth_url)
        sentinel = self.get_sentinel_token(device_id)

        continue_url = ""
        try:
            otp_timeout = max(10, int(self._get_env("OTP_TIMEOUT", "60")))
        except Exception:
            otp_timeout = 180

        page_type = ""
        mode = ""
        # Probe the login screen first.
        prefer_login_screen_first = True

        if prefer_login_screen_first:
            try:
                logger.info("协议登录：优先走 login screen_hint 探测 password/otp 分支")
                login_step = self.authorize_continue(
                    email=email,
                    sentinel_token=sentinel,
                    screen_hint="login",
                    referer="https://auth.openai.com/log-in",
                    trace_step="authorize_continue_login_protocol",
                )
                page_type = (self._extract_page_type(login_step) or "").lower()
                continue_url = self._normalize_continue_url(
                    self._extract_continue_url_from_step(login_step)
                )
                page = (login_step.get("page") or {}) if isinstance(login_step, dict) else {}
                payload = (page.get("payload") or {}) if isinstance(page, dict) else {}
                mode = (payload.get("email_verification_mode", "") or "").lower()
                self._existing_page_type = page_type
                self._existing_email_verification_mode = mode

                if page_type == "login_password" or "/log-in/password" in (continue_url or ""):
                    logger.info("登录分支: login_password -> password/verify")
                    # Mark the password path so OTP delivery uses resend.
                    self._is_existing_account = True
                    if not login_password:
                        raise RuntimeError("已有账号需要密码登录，但未提供真实密码")
                    login_resp = self.login_password_verify(login_password)
                    page_type = (self._extract_page_type(login_resp) or "").lower()
                    continue_url = self._normalize_continue_url(
                        self._extract_continue_url_from_step(login_resp)
                    )

                    # mfa-challenge 分支（密码验证后需要 TOTP 2FA）
                    if self._is_mfa_challenge_state(page_type, continue_url):
                        login_resp, continue_url = self.complete_mfa_totp(login_resp, continue_url, email)
                        page_type = (self._extract_page_type(login_resp) or "").lower()

                elif page_type == "email_otp_verification" or "/email-verification" in (continue_url or ""):
                    logger.info("登录分支: email_otp_verification")
                    # 同上：authorize/continue 已 trigger 发码，kickoff_otp_delivery 优先 resend。
                    self._is_existing_account = True
                else:
                    logger.info(
                        "login screen_hint 未直接命中完成态: page_type=%s continue_url=%s",
                        page_type or "(empty)",
                        (continue_url or "")[:180] or "(empty)",
                    )
            except Exception as e:
                logger.warning(f"login screen_hint 探测失败: {e}")
                continue_url = ""
                page_type = ""
                mode = ""

        recognized_login_pages = {
            "login_password",
            "email_otp_verification",
            "login_otp",
            "passwordless_login",
        }
        if not continue_url and page_type not in recognized_login_pages:
            raise RuntimeError(
                "登录入口未识别，请确认账号状态或更新协议"
            )
        else:
            page_type = (page_type or self._existing_page_type or "").lower()
            mode = (mode or self._existing_email_verification_mode or "").lower()

        if (
            not continue_url
            or "/email-verification" in continue_url
            or "/log-in/otp" in continue_url
            or page_type in {"email_otp_verification", "login_otp", "passwordless_login"}
        ):
            # 仍需 OTP：优先 resend 获取新码
            otp_sent_at = time.time()
            resend_ok = self.kickoff_otp_delivery("protocol_need_otp")
            if not resend_ok:
                self.send_otp(referer="https://auth.openai.com/email-verification")
                otp_sent_at = time.time()

            otp_code = mail_provider.wait_for_otp(
                email,
                timeout=otp_timeout,
                issued_after=otp_sent_at,
            )
            try:
                otp_resp = self.verify_otp(otp_code)
                self.fetch_client_auth_session_dump("post_verify_otp_protocol")
            except RuntimeError as e:
                if any(code in str(e) for code in ("401", "409")):
                    logger.warning(f"OTP 首次验证失败，重发重试: {e}")
                    otp_sent_at = time.time()
                    if not self.kickoff_otp_delivery("protocol_verify_retry"):
                        self.send_otp()
                    otp_code = mail_provider.wait_for_otp(
                        email,
                        timeout=otp_timeout,
                        issued_after=otp_sent_at,
                    )
                    otp_resp = self.verify_otp(otp_code)
                    self.fetch_client_auth_session_dump("post_verify_otp_retry_protocol")
                else:
                    raise
            continue_url = self._extract_continue_url_from_step(otp_resp)
            continue_url = self._normalize_continue_url(continue_url)
        continue_url = self._normalize_continue_url(continue_url)
        # 某些边缘态 OTP 后未返回 callback，回退 reauthorize
        if not continue_url:
            continue_url = self._reauthorize_for_session(auth_url) or ""

        refresh_only_mode = self._env_flag("OAUTH_REFRESH_ONLY", "0")
        callback_url = ""
        if continue_url:
            continue_url = self._normalize_continue_url(continue_url)
            if (not self.result.refresh_token) and self._env_flag("OAUTH_CODEX_RT_BEFORE_CALLBACK", "1"):
                self.oauth_codex_rt_exchange(mail_provider=mail_provider)
            pre_exchange_default = "1" if refresh_only_mode else "0"
            pre_exchange = self._env_flag("OAUTH_EXCHANGE_BEFORE_CALLBACK", pre_exchange_default)
            if pre_exchange:
                self.oauth_token_exchange(continue_url, continue_url)
            callback_url, final_url = self.follow_redirect_chain(continue_url)
            if (not callback_url) and final_url and ("/workspace" in final_url):
                normalized = self._normalize_continue_url(final_url)
                if normalized and normalized != final_url:
                    callback_url, final_url = self.follow_redirect_chain(normalized)

        if not refresh_only_mode:
            self.get_auth_session()

        if callback_url or continue_url:
            self.fetch_client_auth_session_dump("pre_oauth_exchange_protocol")
            # A successful dedicated Codex PKCE exchange already produced the
            # refreshable credential. Replaying the web callback code here is
            # redundant and commonly returns token_exchange_user_error.
            if not self.result.refresh_token:
                self.oauth_token_exchange(callback_url or "", continue_url or "")
            if (not self.result.refresh_token) and self._env_flag("OAUTH_CODEX_RT_EXCHANGE", "1"):
                self.oauth_codex_rt_exchange(mail_provider=mail_provider)
            if (not self.result.refresh_token) and self._env_flag("OAUTH_SECONDARY_AUTHORIZE_EXCHANGE", "0"):
                self.oauth_secondary_authorize_exchange()
            if not refresh_only_mode:
                self.get_auth_session()

        if refresh_only_mode:
            if not (self.result.refresh_token or self.result.access_token):
                raise RuntimeError("协议登录完成，但未拿到 refresh_token/access_token")
        elif not self.result.is_valid():
            raise RuntimeError("协议登录完成，但未拿到有效 session/access token")

        if self._env_flag("OAUTH_REQUIRE_REFRESH_TOKEN", "0") \
                and not self.result.has_codex_oauth_credentials():
            raise RuntimeError(
                "协议登录完成但未获取 Codex OAuth refresh_token，拒绝使用网页 access token"
            )

        logger.info("纯协议登录流程完成")
        return self.result

    # ── 从已有凭证初始化 ──
    def from_existing_credentials(
        self, session_token: str, access_token: str, device_id: str
    ) -> AuthResult:
        """使用已有凭证初始化会话（跳过登录流程）。"""
        self.result.device_id = device_id or str(uuid.uuid4())
        self.session.cookies.set("oai-did", self.result.device_id, domain=".chatgpt.com")
        detected_email = ""

        # 如果有 session_token, 用它刷新 access_token (旧 access_token 可能已过期)
        if session_token:
            self.session.cookies.set(
                "__Secure-next-auth.session-token",
                session_token,
                domain=".chatgpt.com",
            )
            logger.info("使用 session_token 刷新 access_token...")
            try:
                headers = self._common_headers("https://chatgpt.com/")
                resp = self.session.get(
                    "https://chatgpt.com/api/auth/session",
                    headers=headers,
                    timeout=30,
                )
                session_data = resp.json() if resp is not None else {}
                new_access_token = session_data.get("accessToken", "")
                user_obj = session_data.get("user", {}) if isinstance(session_data, dict) else {}
                if isinstance(user_obj, dict):
                    detected_email = detected_email or (user_obj.get("email", "") or "")
                new_session_token = self.session.cookies.get("__Secure-next-auth.session-token", "")
                if new_access_token:
                    access_token = new_access_token
                    logger.info("access_token 刷新成功")
                else:
                    logger.warning(f"access_token 刷新失败 (status={resp.status_code}), 使用原 token")
                if new_session_token:
                    session_token = new_session_token
            except Exception as e:
                logger.warning(f"刷新 access_token 失败: {e}, 使用原 token")
        elif access_token:
            # 没有 session_token, 尝试通过 access_token 获取
            logger.info("未提供 session_token, 尝试通过 access_token 获取...")
            try:
                headers = self._common_headers("https://chatgpt.com/")
                headers["Authorization"] = f"Bearer {access_token}"
                resp = self.session.get(
                    "https://chatgpt.com/api/auth/session",
                    headers=headers,
                    timeout=30,
                )
                session_data = resp.json() if resp is not None else {}
                user_obj = session_data.get("user", {}) if isinstance(session_data, dict) else {}
                if isinstance(user_obj, dict):
                    detected_email = detected_email or (user_obj.get("email", "") or "")
                session_token = self.session.cookies.get("__Secure-next-auth.session-token", "")
                if session_token:
                    logger.info("通过 access_token 获取 session_token 成功")
                else:
                    logger.warning("未能获取 session_token, 可能需要手动提供")
            except Exception as e:
                logger.warning(f"获取 session_token 失败: {e}")

        self.result.access_token = access_token
        self.result.session_token = session_token
        if session_token:
            self.session.cookies.set(
                "__Secure-next-auth.session-token",
                session_token,
                domain=".chatgpt.com",
            )
        self.result.cookie_header = self._build_chatgpt_cookie_header()

        # 回填 email（已有凭证模式下常用于账单 email）
        if not detected_email and access_token and access_token.count(".") >= 2:
            try:
                payload_b64 = access_token.split(".")[1]
                payload_b64 += "=" * (-len(payload_b64) % 4)
                payload = json.loads(base64.urlsafe_b64decode(payload_b64.encode("utf-8")).decode("utf-8"))
                prof = payload.get("https://api.openai.com/profile", {}) if isinstance(payload, dict) else {}
                if isinstance(prof, dict):
                    detected_email = detected_email or (prof.get("email", "") or "")
            except Exception:
                pass
        self.result.email = detected_email or ""
        logger.info("使用已有凭证初始化完成")
        return self.result

from __future__ import annotations

import asyncio
import base64
import email
import inspect
import imaplib
import json
import os
from pathlib import Path
import re
import shutil
import ssl
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email.header import decode_header, make_header
from email.message import Message
from email.policy import default
from email.utils import parsedate_to_datetime
from typing import Any, Awaitable, Callable

import httpx

from app.pools.outlook_pool import OutlookAccount


GRAPH_TOKEN_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
TOKEN_ENDPOINTS = (
    GRAPH_TOKEN_URL,
    "https://login.microsoftonline.com/consumers/oauth2/v2.0/token",
    "https://login.live.com/oauth20_token.srf",
)
IMAP_SCOPE = "https://outlook.office.com/IMAP.AccessAsUser.All offline_access"
GRAPH_SCOPE = "https://graph.microsoft.com/.default"
GRAPH_BASE_URL = "https://graph.microsoft.com/v1.0"
GRAPH_FOLDERS = ("inbox", "junkemail", "deleteditems")
OPENAI_SENDER_MARKERS = ("openai.com", "auth.openai", "tm.openai", "chatgpt.com", "tm.open")
DEFAULT_VALIDATION_REQUEST_INTERVAL_SECONDS = 0.05
DEFAULT_VALIDATION_LOOP_COOLDOWN_SECONDS = 2.0
DEFAULT_VALIDATION_RETRY_DELAYS_SECONDS = (2.0,)
DEFAULT_VALIDATION_LOOP_TRIP_COUNT = 3
VALIDATION_REQUEST_HEADERS = {
    # Keep the health-check wire headers aligned with Node's global fetch used
    # by the reference admin service.  Microsoft may include client metadata
    # in its adaptive request-loop protection decisions.
    "Accept": "*/*",
    "Accept-Language": "*",
    "Sec-Fetch-Mode": "cors",
    "User-Agent": "node",
    "Accept-Encoding": "gzip, deflate",
    "Content-Type": "application/x-www-form-urlencoded",
}


class OutlookMailError(RuntimeError):
    def __init__(
        self,
        message: str,
        *,
        code: str = "OUTLOOK_MAIL_ERROR",
        terminal: bool = False,
        http_status: int = 0,
        stage: str = "unknown",
    ):
        super().__init__(message)
        self.code = code
        self.terminal = bool(terminal)
        try:
            self.http_status = int(http_status or 0)
        except (TypeError, ValueError, OverflowError):
            self.http_status = 0
        self.stage = str(stage or "unknown")
        # CamelCase aliases keep integrations written for the reference admin
        # service source-compatible while the Python code continues to use
        # snake_case internally.
        self.errorCode = self.code
        self.httpStatus = self.http_status


OUTLOOK_TERMINAL_OAUTH_CODES = {
    "invalid_grant",
    "invalid_client",
    "unauthorized_client",
    "interaction_required",
    "consent_required",
}


async def _oauth_failure_payload(response: Any) -> tuple[str, str]:
    """Extract only stable OAuth error fields from a Microsoft response.

    The production client uses ``httpx.Response`` (whose ``json`` method is
    synchronous), while a few integrations expose a fetch-like asynchronous
    ``json()`` method.  Reusing the common async response decoder keeps both
    forms from silently losing ``invalid_grant`` and other terminal codes.
    """

    try:
        payload = await _response_json(response)
    except (TypeError, ValueError, UnicodeError, RuntimeError):
        payload = {}
    if not isinstance(payload, dict):
        return "", ""
    raw_code = payload.get("error") or payload.get("error_code") or ""
    if isinstance(raw_code, dict):
        raw_code = raw_code.get("code") or raw_code.get("type") or ""
    code = re.sub(r"[^A-Za-z0-9_.:-]", "_", str(raw_code).strip())[:100]
    description = str(
        payload.get("error_description")
        or payload.get("errorDescription")
        or payload.get("message")
        or ""
    ).replace("\r", " ").replace("\n", " ").strip()
    # Do not persist a response body that could contain a credential or URL.
    description = re.sub(r"https?://\S+", "[redacted-url]", description, flags=re.IGNORECASE)
    description = re.sub(
        r"(?i)\b(authorization|cookie|access[_ -]?token|refresh[_ -]?token|id[_ -]?token)\s*[:=]\s*[^\s,;]+",
        r"\1=[redacted]",
        description,
    )
    return code, re.sub(r"\s+", " ", description)[:500]


def _oauth_failure_is_terminal(code: str, description: str, status: int) -> bool:
    normalized = str(code or "").strip().lower()
    # AADSTS50196 is Microsoft's "client request loop" response.  It is
    # commonly emitted as an ``invalid_grant`` envelope when a large batch
    # refreshes too aggressively, but it does not prove that this mailbox's
    # refresh token is revoked.  Keep it retryable instead of permanently
    # moving the account to the invalid bucket.
    if re.search(r"AADSTS50196\b", description, re.IGNORECASE):
        return False
    if re.search(r"AADSTS700016\b", description, re.IGNORECASE):
        return True
    if normalized in OUTLOOK_TERMINAL_OAUTH_CODES:
        return True
    if re.search(r"AADSTS(?:50057|50173|65001|70000|70008|700082|700084)\b", description, re.IGNORECASE):
        return True
    return int(status or 0) == 401


def _oauth_failure_code(code: str, description: str) -> str:
    """Return a safe, actionable code for a Microsoft OAuth failure."""

    if re.search(r"AADSTS50196\b", description, re.IGNORECASE):
        return "OAUTH_CLIENT_REQUEST_LOOP"
    return re.sub(r"[^A-Za-z0-9_.:-]", "_", str(code or "").strip())[:100]


def _response_status_code(response: Any) -> int:
    """Read a status from httpx responses and the small fakes used in tests."""

    raw = getattr(response, "status_code", None)
    if raw is None and isinstance(response, dict):
        raw = response.get("status_code", response.get("status"))
    if raw is None:
        raw = getattr(response, "status", 0)
    try:
        return int(raw or 0)
    except (TypeError, ValueError, OverflowError):
        return 0


def _response_is_success(response: Any, status: int) -> bool:
    try:
        marker = getattr(response, "is_success", None)
    except Exception:
        marker = None
    if marker is None:
        try:
            marker = getattr(response, "ok", None)
        except Exception:
            marker = None
    if marker is None and isinstance(response, dict):
        marker = response.get("is_success", response.get("ok"))
    return bool(marker) if marker is not None else 200 <= int(status or 0) < 300


async def _response_json(response: Any) -> Any:
    """Extract JSON from httpx responses, fetch-like fakes, or plain mappings."""

    if isinstance(response, dict):
        value = response.get("json")
        if callable(value):
            value = value()
            if inspect.isawaitable(value):
                value = await value
            return value
        if value is not None:
            return value
        body = response.get("body") or response.get("text")
        if isinstance(body, (dict, list)):
            return body
        if body:
            return json.loads(str(body))
        return {}

    parser = getattr(response, "json", None)
    if callable(parser):
        value = parser()
        if inspect.isawaitable(value):
            value = await value
        return value
    if parser is not None:
        return parser
    body = getattr(response, "text", getattr(response, "body", ""))
    if isinstance(body, (dict, list)):
        return body
    if body:
        return json.loads(str(body))
    return {}


@dataclass(slots=True)
class MicrosoftAccessToken:
    access_token: str
    refresh_token: str
    expires_in: int


@dataclass(slots=True)
class MailRecord:
    sender: str
    subject: str
    body: str
    received_at: datetime | None


CancelCheck = Callable[[], bool | Awaitable[bool]]


class _NodeValidationWorker:
    """Long-lived Node fetch worker used for admin-compatible OAuth checks."""

    def __init__(self, *, node_binary: str, script_path: str) -> None:
        self.node_binary = node_binary
        self.script_path = script_path
        self.process: asyncio.subprocess.Process | None = None
        self.reader_task: asyncio.Task[None] | None = None
        self.stderr_task: asyncio.Task[None] | None = None
        self.pending: dict[str, asyncio.Future[dict[str, Any]]] = {}
        self.start_lock = asyncio.Lock()
        self.write_lock = asyncio.Lock()

    async def start(self) -> None:
        if self.process is not None:
            return
        async with self.start_lock:
            if self.process is not None:
                return
            try:
                self.process = await asyncio.create_subprocess_exec(
                    self.node_binary,
                    self.script_path,
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
            except FileNotFoundError as error:
                raise OutlookMailError(
                    "Outlook Node 验活需要 Node.js，但未找到可执行文件",
                    code="OUTLOOK_NODE_MISSING",
                    stage="worker",
                ) from error
            self.reader_task = asyncio.create_task(self._read_results())
            self.stderr_task = asyncio.create_task(self._drain_stderr())

    async def _read_results(self) -> None:
        process = self.process
        stdout = process.stdout if process is not None else None
        if stdout is None:
            return
        try:
            while True:
                raw = await stdout.readline()
                if not raw:
                    break
                try:
                    payload = json.loads(raw.decode("utf-8", errors="replace"))
                except (TypeError, ValueError, UnicodeError):
                    continue
                if not isinstance(payload, dict):
                    continue
                request_id = str(payload.pop("id", "") or "")
                future = self.pending.pop(request_id, None)
                if future is not None and not future.done():
                    future.set_result(payload)
        finally:
            error = OutlookMailError(
                "Node Outlook 验活进程已退出",
                code="OUTLOOK_NODE_WORKER_EXITED",
                stage="worker",
            )
            for future in self.pending.values():
                if not future.done():
                    future.set_exception(error)
            self.pending.clear()

    async def _drain_stderr(self) -> None:
        process = self.process
        stderr = process.stderr if process is not None else None
        if stderr is not None:
            while await stderr.readline():
                pass

    async def validate(self, account: OutlookAccount) -> dict[str, Any]:
        await self.start()
        process = self.process
        stdin = process.stdin if process is not None else None
        if stdin is None:
            raise OutlookMailError(
                "Node Outlook 验活进程不可用",
                code="OUTLOOK_NODE_WORKER_UNAVAILABLE",
                stage="worker",
            )
        request_id = uuid.uuid4().hex
        loop = asyncio.get_running_loop()
        future: asyncio.Future[dict[str, Any]] = loop.create_future()
        self.pending[request_id] = future
        payload = {
            "id": request_id,
            "account": {
                "client_id": str(account.client_id or ""),
                "refresh_token": str(account.refresh_token or ""),
            },
        }
        try:
            async with self.write_lock:
                stdin.write((json.dumps(payload, ensure_ascii=False) + "\n").encode("utf-8"))
                await stdin.drain()
            return await future
        except (BrokenPipeError, ConnectionError, OSError, RuntimeError) as error:
            self.pending.pop(request_id, None)
            raise OutlookMailError(
                "Node Outlook 验活进程写入失败",
                code="OUTLOOK_NODE_WORKER_UNAVAILABLE",
                stage="worker",
            ) from error
        except asyncio.CancelledError:
            self.pending.pop(request_id, None)
            raise

    async def close(self) -> None:
        process, self.process = self.process, None
        for task in (self.reader_task, self.stderr_task):
            if task is not None:
                task.cancel()
        tasks = [task for task in (self.reader_task, self.stderr_task) if task is not None]
        self.reader_task = None
        self.stderr_task = None
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        for future in self.pending.values():
            if not future.done():
                future.set_exception(
                    OutlookMailError(
                        "Node Outlook 验活已关闭",
                        code="OUTLOOK_NODE_WORKER_CLOSED",
                        stage="worker",
                    )
                )
        self.pending.clear()
        if process is None:
            return
        if process.stdin is not None:
            process.stdin.close()
        try:
            await asyncio.wait_for(process.wait(), timeout=3)
        except (asyncio.TimeoutError, ProcessLookupError):
            try:
                process.kill()
            except ProcessLookupError:
                return
            await process.wait()


class OutlookMailClient:
    def __init__(
        self,
        *,
        token_url: str = GRAPH_TOKEN_URL,
        imap_host: str = "outlook.office365.com",
        imap_port: int = 993,
        proxy_url: str = "",
        transport: httpx.AsyncBaseTransport | None = None,
        imap_factory: Callable[..., Any] | None = None,
        graph_enabled: bool = True,
        graph_probe_seconds: float = 10.0,
        validation_request_interval_seconds: float | None = None,
        validation_retry_delays: tuple[float, ...] | None = None,
        validation_loop_cooldown_seconds: float = DEFAULT_VALIDATION_LOOP_COOLDOWN_SECONDS,
        validation_engine: str | None = None,
        node_binary: str | None = None,
    ) -> None:
        self.token_url = token_url
        self.imap_host = imap_host
        self.imap_port = int(imap_port)
        self.proxy_url = str(proxy_url or "")
        self.transport = transport
        self.imap_factory = imap_factory or imaplib.IMAP4_SSL
        self.graph_enabled = bool(graph_enabled)
        self.graph_probe_seconds = max(5.0, float(graph_probe_seconds))
        if validation_request_interval_seconds is None:
            try:
                validation_request_interval_seconds = float(
                    os.getenv(
                        "OUTLOOK_VALIDATION_REQUEST_INTERVAL_SECONDS",
                        str(DEFAULT_VALIDATION_REQUEST_INTERVAL_SECONDS),
                    )
                )
            except (TypeError, ValueError):
                validation_request_interval_seconds = DEFAULT_VALIDATION_REQUEST_INTERVAL_SECONDS
        self.validation_request_interval_seconds = max(
            0.0,
            min(5.0, float(validation_request_interval_seconds)),
        )
        if validation_retry_delays is None:
            validation_retry_delays = DEFAULT_VALIDATION_RETRY_DELAYS_SECONDS
        self.validation_retry_delays = tuple(
            max(0.0, min(60.0, float(delay)))
            for delay in validation_retry_delays
        )
        self.validation_loop_cooldown_seconds = max(
            0.0,
            min(60.0, float(validation_loop_cooldown_seconds)),
        )
        configured_engine = str(
            validation_engine
            if validation_engine is not None
            else os.getenv("OUTLOOK_VALIDATION_ENGINE", "node")
        ).strip().lower()
        self.validation_engine = configured_engine if configured_engine in {"node", "python"} else "node"
        self.node_binary = (
            str(node_binary or os.getenv("OPENAI_SENTINEL_NODE_PATH", "")).strip()
            or shutil.which("node")
            or "node"
        )
        self._node_worker: _NodeValidationWorker | None = None
        # A validation batch can contain thousands of accounts.  Keeping one
        # client open for that batch lets httpx reuse the Microsoft connection
        # instead of repeating DNS/TLS setup for every refresh token.
        self._shared_client: Any | None = None
        # Microsoft can return AADSTS50196 (LoopDetected) when one public
        # client redeems too many refresh tokens in a short window.  These
        # fields provide one limiter/cooldown for all workers sharing this
        # client's batch connection instead of letting every worker retry at
        # once and extending the lockout.
        self._validation_schedule_lock = asyncio.Lock()
        self._next_validation_request_at = 0.0
        self._validation_cooldown_until = 0.0
        # Once Microsoft returns several LoopDetected responses in one batch,
        # continuing to submit refresh requests only extends the server-side
        # protection window.  Open a per-batch circuit after a small number of
        # confirmations; remaining accounts are reported as temporary and can
        # be retried after the provider cooldown has elapsed.
        self._validation_loop_count = 0
        self._validation_circuit_open = False

    def _validation_loop_error(self) -> OutlookMailError:
        return OutlookMailError(
            "Microsoft OAuth 验活触发临时限流，本批次已暂停后续请求",
            code="OAUTH_CLIENT_REQUEST_LOOP",
            http_status=429,
            stage="oauth",
        )

    async def _wait_for_validation_request_slot(self) -> None:
        """Throttle health-check OAuth requests made by a shared client."""

        async with self._validation_schedule_lock:
            if self._validation_circuit_open:
                raise self._validation_loop_error()
            loop = asyncio.get_running_loop()
            now = loop.time()
            scheduled = max(
                now,
                self._next_validation_request_at,
                self._validation_cooldown_until,
            )
            self._next_validation_request_at = scheduled + self.validation_request_interval_seconds
        delay = scheduled - now
        if delay > 0:
            await asyncio.sleep(delay)

    async def _note_validation_request_loop(self) -> None:
        """Pause the shared schedule after Microsoft's loop-detected response."""

        async with self._validation_schedule_lock:
            self._validation_loop_count += 1
            if self._validation_loop_count >= DEFAULT_VALIDATION_LOOP_TRIP_COUNT:
                self._validation_circuit_open = True
            loop = asyncio.get_running_loop()
            cooldown_until = loop.time() + self.validation_loop_cooldown_seconds
            self._validation_cooldown_until = max(
                self._validation_cooldown_until,
                cooldown_until,
            )
            self._next_validation_request_at = max(
                self._next_validation_request_at,
                self._validation_cooldown_until,
            )

    def _client_options(self) -> dict[str, Any]:
        options: dict[str, Any] = {
            # Keep the same 20-second OAuth budget as the reference admin
            # validator.  The previous 15-second limit turned slow but valid
            # Microsoft responses into local temporary failures.
            "timeout": 20,
            "follow_redirects": True,
            # The reference admin uses Node's direct fetch.  Do not silently
            # route Microsoft OAuth through HTTP(S)_PROXY from the host
            # environment; an explicit ``proxy_url`` remains supported below.
            "trust_env": False,
            # The pool caps validation workers at 50.  Matching that upper
            # bound prevents a large batch from opening an unbounded number
            # of sockets while still allowing all workers to reuse keep-alive
            # connections to Microsoft.
            "limits": httpx.Limits(max_connections=50, max_keepalive_connections=50),
        }
        if self.transport is not None:
            options["transport"] = self.transport
        if self.proxy_url:
            options["proxy"] = self.proxy_url
        return options

    async def open(self) -> None:
        """Open a reusable HTTP client for a bounded batch operation.

        Standalone mail operations deliberately remain lazy and create a
        short-lived client.  The API opens this client only around a batch
        health check, so persistent batch workers do not retain stale
        sockets indefinitely.
        """

        if self.validation_engine == "node":
            # Node's long-lived worker owns its fetch connections; creating an
            # unused httpx client here would only add sockets during a health
            # check and make cleanup harder to reason about.
            return
        if self._shared_client is None:
            self._shared_client = httpx.AsyncClient(**self._client_options())

    async def aclose(self) -> None:
        """Release a client previously opened by :meth:`open`."""

        node_worker, self._node_worker = self._node_worker, None
        if node_worker is not None:
            await node_worker.close()
        client, self._shared_client = self._shared_client, None
        close = getattr(client, "aclose", None)
        if callable(close):
            result = close()
            if inspect.isawaitable(result):
                await result

    async def _node_refresh_access_token(
        self,
        account: OutlookAccount,
        *,
        scope: str,
    ) -> MicrosoftAccessToken:
        if self._node_worker is None:
            self._node_worker = _NodeValidationWorker(
                node_binary=self.node_binary,
                script_path=str(Path(__file__).with_name("node_validation_worker.js")),
            )
        result = await self._node_worker.validate(account)
        if not result.get("valid") or not result.get("accessToken"):
            code = str(result.get("errorCode") or "OUTLOOK_TOKEN_REFRESH_FAILED")
            description = str(result.get("message") or "Microsoft OAuth 请求失败")
            status = int(result.get("httpStatus") or 0)
            raise OutlookMailError(
                description,
                code=code,
                terminal=bool(result.get("terminal")),
                http_status=status,
                stage="oauth",
            )
        return MicrosoftAccessToken(
            access_token=str(result.get("accessToken") or ""),
            refresh_token=str(result.get("refreshToken") or account.refresh_token),
            expires_in=3600,
        )

    def _token_endpoints(self, *, allow_endpoint_fallback: bool) -> list[str]:
        """Return the OAuth endpoints for the requested operation.

        The reference admin verifies refresh tokens only through the stable
        ``common`` endpoint.  That is the appropriate fast path for a health
        check.  Mail reading retains the historic fallback
        list for compatibility with imported credentials.
        """

        endpoints = [str(self.token_url or "").strip()]
        if allow_endpoint_fallback:
            endpoints.extend(TOKEN_ENDPOINTS)
        return list(dict.fromkeys(endpoint for endpoint in endpoints if endpoint))

    async def _refresh_access_token_with_client(
        self,
        client: Any,
        account: OutlookAccount,
        *,
        scope: str,
        allow_endpoint_fallback: bool,
    ) -> MicrosoftAccessToken:
        last_error: Exception | None = None
        for endpoint in self._token_endpoints(
            allow_endpoint_fallback=allow_endpoint_fallback,
        ):
            try:
                if not allow_endpoint_fallback:
                    await self._wait_for_validation_request_slot()
                response = await client.post(
                    endpoint,
                    # Match the reference admin's URLSearchParams field order
                    # and names.  Microsoft treats this as a form, but keeping
                    # the wire contract identical makes diagnostics reliable.
                    data=str(httpx.QueryParams([
                        ("grant_type", "refresh_token"),
                        ("refresh_token", str(account.refresh_token or "").strip()),
                        ("client_id", str(account.client_id or "").strip()),
                        ("scope", scope),
                    ])).replace("~", "%7E"),
                    headers=(
                        VALIDATION_REQUEST_HEADERS
                        if not allow_endpoint_fallback
                        else {"Content-Type": "application/x-www-form-urlencoded"}
                    ),
                )
                response_status = _response_status_code(response)
                response_success = _response_is_success(response, response_status)
                if not response_success:
                    error_code, description = await _oauth_failure_payload(response)
                    safe_error_code = _oauth_failure_code(error_code, description)
                    error = OutlookMailError(
                        description
                        or f"Microsoft OAuth 请求失败（HTTP {response_status}）",
                        code=safe_error_code or "OUTLOOK_TOKEN_REFRESH_FAILED",
                        terminal=_oauth_failure_is_terminal(
                            error_code,
                            description,
                            response_status,
                        ),
                        http_status=response_status,
                        stage="oauth",
                    )
                    if safe_error_code == "OAUTH_CLIENT_REQUEST_LOOP":
                        await self._note_validation_request_loop()
                    # A revoked refresh token or rejected client cannot become
                    # valid by trying another Microsoft hostname.  Returning
                    # immediately avoids up to two extra 15-second requests
                    # for every invalid account in a large batch.
                    if error.terminal:
                        raise error
                    last_error = error
                    continue
                try:
                    payload = await _response_json(response)
                except Exception:
                    last_error = OutlookMailError(
                        "Microsoft OAuth 返回非 JSON",
                        code="OUTLOOK_TOKEN_BAD_RESPONSE",
                        http_status=response_status,
                        stage="oauth",
                    )
                    continue
                if not isinstance(payload, dict):
                    last_error = OutlookMailError(
                        "Microsoft OAuth 返回格式无效",
                        code="OUTLOOK_TOKEN_BAD_RESPONSE",
                        http_status=response_status,
                        stage="oauth",
                    )
                    continue
                access_token = str(payload.get("access_token", ""))
                if not access_token:
                    last_error = OutlookMailError(
                        "Microsoft OAuth 响应缺少 access_token",
                        code="OUTLOOK_TOKEN_BAD_RESPONSE",
                        http_status=response_status,
                        stage="oauth",
                    )
                    continue
                try:
                    expires_in = int(payload.get("expires_in", 3600) or 3600)
                except (TypeError, ValueError):
                    last_error = OutlookMailError(
                        "Microsoft OAuth 响应的 expires_in 无效",
                        code="OUTLOOK_TOKEN_BAD_RESPONSE",
                        http_status=response_status,
                        stage="oauth",
                    )
                    continue
                return MicrosoftAccessToken(
                    access_token=access_token,
                    refresh_token=str(payload.get("refresh_token", "") or account.refresh_token),
                    expires_in=expires_in,
                )
            except OutlookMailError:
                raise
            except (httpx.TimeoutException, TimeoutError):
                last_error = OutlookMailError(
                    "Microsoft OAuth 请求超时",
                    code="OAUTH_TIMEOUT",
                    stage="oauth",
                )
            except httpx.NetworkError:
                last_error = OutlookMailError(
                    "Microsoft OAuth 网络错误",
                    code="OAUTH_NETWORK_ERROR",
                    stage="oauth",
                )
            except httpx.HTTPError:
                last_error = OutlookMailError(
                    "Microsoft OAuth 请求失败",
                    code="OAUTH_REQUEST_FAILED",
                    stage="oauth",
                )

        if isinstance(last_error, OutlookMailError):
            raise last_error
        raise OutlookMailError(
            "Outlook refresh_token 换 access_token 失败",
            code="OUTLOOK_TOKEN_REFRESH_FAILED",
            stage="oauth",
        ) from last_error

    async def refresh_access_token(
        self,
        account: OutlookAccount,
        *,
        scope: str = IMAP_SCOPE,
        allow_endpoint_fallback: bool = True,
    ) -> MicrosoftAccessToken:
        if not str(account.client_id or "").strip():
            raise OutlookMailError(
                "Outlook OAuth 缺少 client_id",
                code="OUTLOOK_CLIENT_ID_MISSING",
                terminal=True,
                stage="oauth",
            )
        if not str(account.refresh_token or "").strip():
            raise OutlookMailError(
                "Outlook OAuth 缺少 refresh_token",
                code="OUTLOOK_REFRESH_TOKEN_MISSING",
                terminal=True,
                stage="oauth",
            )
        # The fast health-check path intentionally delegates to the same
        # long-lived Node/fetch worker used by the admin project.  Normal mail
        # operations keep the Python/httpx implementation (they may need
        # Graph/IMAP endpoint fallback and proxy plumbing).
        if self.validation_engine == "node" and not allow_endpoint_fallback:
            return await self._node_refresh_access_token(account, scope=scope)
        if self._shared_client is not None:
            return await self._refresh_access_token_with_client(
                self._shared_client,
                account,
                scope=scope,
                allow_endpoint_fallback=allow_endpoint_fallback,
            )
        async with httpx.AsyncClient(**self._client_options()) as client:
            return await self._refresh_access_token_with_client(
                client,
                account,
                scope=scope,
                allow_endpoint_fallback=allow_endpoint_fallback,
            )

    async def test_account(self, account: OutlookAccount) -> dict[str, Any]:
        token = await self.refresh_access_token(account)
        records = await asyncio.to_thread(
            self._fetch_recent_messages,
            account.email,
            token.access_token,
            datetime.now(timezone.utc) - timedelta(days=1),
            3,
            account.password,
        )
        return {
            "ok": True,
            "email": account.email,
            "recent_openai_messages": len(records),
            "refresh_token": token.refresh_token,
        }

    async def fetch_recent_openai_messages(
        self,
        account: OutlookAccount,
        *,
        since: datetime,
        limit: int = 50,
    ) -> tuple[list[MailRecord], str]:
        """Read recent OpenAI/ChatGPT messages without exposing mailbox credentials.

        The caller receives only parsed message fields needed for a local,
        short-lived decision and a potentially rotated refresh token.  It is
        responsible for persisting a rotation through the Outlook pool.
        """

        token = await self.refresh_access_token(account)
        records = await asyncio.to_thread(
            self._fetch_recent_messages,
            account.email,
            token.access_token,
            since,
            min(100, max(1, int(limit))),
            account.password,
        )
        return records, token.refresh_token

    async def validate_account(self, account: OutlookAccount) -> dict[str, Any]:
        """快速验活 Outlook refresh token，不登录 IMAP 或读取邮件。

        This mirrors the admin project's health-check mechanism: a successful
        Microsoft OAuth refresh is enough to establish that the mailbox
        credential is currently usable.  IMAP/Graph probing remains available
        through :meth:`test_account` and the mail-reading flow.
        """

        started = time.monotonic()
        loop_attempt = 0
        try:
            while True:
                try:
                    token = await self.refresh_access_token(
                        account,
                        # Match the reference admin fast health check: one request to
                        # the common Microsoft OAuth endpoint is enough to establish
                        # whether a refresh token is usable.
                        allow_endpoint_fallback=False,
                    )
                    break
                except OutlookMailError as error:
                    # LoopDetected is a server-side anti-abuse throttle, not
                    # evidence that this mailbox's refresh token was revoked.
                    # Wait for the shared cooldown and retry the same account a
                    # bounded number of times before reporting a temporary
                    # failure.  Other OAuth errors retain their normal terminal
                    # classification immediately.
                    if (
                        error.code != "OAUTH_CLIENT_REQUEST_LOOP"
                        or self._validation_circuit_open
                        or loop_attempt >= len(self.validation_retry_delays)
                    ):
                        raise
                    delay = self.validation_retry_delays[loop_attempt]
                    loop_attempt += 1
                    if delay > 0:
                        await asyncio.sleep(delay)
            latency_ms = max(0, int((time.monotonic() - started) * 1000))
            return {
                "valid": True,
                "terminal": False,
                "status": "valid",
                "stage": "oauth",
                "error_code": "",
                "errorCode": "",
                "http_status": 200,
                "httpStatus": 200,
                "message": "Microsoft OAuth refresh token 有效",
                "refresh_token": token.refresh_token,
                "refreshToken": token.refresh_token,
                "latency_ms": latency_ms,
                "latencyMs": latency_ms,
            }
        except OutlookMailError as error:
            latency_ms = max(0, int((time.monotonic() - started) * 1000))
            error_code = str(error.code or "OUTLOOK_CHECK_FAILED")[:100]
            http_status = int(error.http_status or 0)
            return {
                "valid": False,
                "terminal": bool(error.terminal),
                "status": "invalid" if error.terminal else "temporary_failed",
                "stage": error.stage or "oauth",
                "error_code": error_code,
                "errorCode": error_code,
                "http_status": http_status,
                "httpStatus": http_status,
                "message": str(error)[:1000],
                "refresh_token": "",
                "refreshToken": "",
                "latency_ms": latency_ms,
                "latencyMs": latency_ms,
            }
        except Exception as error:
            latency_ms = max(0, int((time.monotonic() - started) * 1000))
            return {
                "valid": False,
                "terminal": False,
                "status": "temporary_failed",
                "stage": "oauth",
                "error_code": "OUTLOOK_CHECK_INTERNAL_ERROR",
                "errorCode": "OUTLOOK_CHECK_INTERNAL_ERROR",
                "http_status": 0,
                "httpStatus": 0,
                "message": "Outlook 邮箱验活执行失败",
                "refresh_token": "",
                "refreshToken": "",
                "latency_ms": latency_ms,
                "latencyMs": latency_ms,
            }

    async def poll_verification_code(
        self,
        account: OutlookAccount,
        *,
        since: datetime,
        interval_seconds: float = 5,
        timeout_seconds: float = 180,
        cancel_check: CancelCheck | None = None,
    ) -> tuple[str, str]:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + max(30, float(timeout_seconds))
        interval = max(2, float(interval_seconds))
        last_error: Exception | None = None

        # Reference implementation先试 Graph（能覆盖 INBOX/Junk/Deleted），
        # 供应商 refresh token 没有 Graph 权限时再快速回退到 IMAP。探测窗口
        # 有上限，不会把 Graph 失败叠加成一次完整的 IMAP 超时。
        if self.graph_enabled:
            graph_timeout = min(
                self.graph_probe_seconds,
                max(5.0, deadline - loop.time()),
            )
            try:
                return await self._poll_graph_verification_code(
                    account,
                    since=since,
                    interval_seconds=interval,
                    timeout_seconds=graph_timeout,
                    cancel_check=cancel_check,
                )
            except OutlookMailError as error:
                if error.code == "JOB_CANCELLED":
                    raise
                last_error = error
            except Exception as error:
                last_error = error

        token = await self.refresh_access_token(account)
        refreshed_after_imap_error = False

        while loop.time() < deadline:
            if cancel_check is not None:
                cancelled = cancel_check()
                if inspect.isawaitable(cancelled):
                    cancelled = await cancelled
                if cancelled:
                    raise OutlookMailError("任务已取消", code="JOB_CANCELLED")
            try:
                records = await asyncio.to_thread(
                    self._fetch_recent_messages,
                    account.email,
                    token.access_token,
                    since - timedelta(seconds=5),
                    15,
                    account.password,
                )
                for record in records:
                    code = extract_verification_code(
                        f"{record.subject}\n{record.body}"
                    )
                    if code:
                        return code, token.refresh_token
                last_error = None
            except Exception as error:
                last_error = error
                if not refreshed_after_imap_error:
                    token = await self.refresh_access_token(account)
                    refreshed_after_imap_error = True
                else:
                    await asyncio.sleep(interval)
            await asyncio.sleep(min(interval, max(0.0, deadline - loop.time())))

        detail = f"，最后错误: {last_error}" if last_error else ""
        raise OutlookMailError(
            f"Outlook 邮箱验证码超时（{int(timeout_seconds)} 秒）{detail}",
            code="OUTLOOK_CODE_TIMEOUT",
        )

    async def _poll_graph_verification_code(
        self,
        account: OutlookAccount,
        *,
        since: datetime,
        interval_seconds: float,
        timeout_seconds: float,
        cancel_check: CancelCheck | None,
    ) -> tuple[str, str]:
        """Poll Microsoft Graph for an OpenAI verification message.

        This is deliberately a bounded probe.  Some Outlook refresh tokens are
        scoped only for IMAP; a Graph 401/403 is therefore treated as a normal
        fallback condition by ``poll_verification_code``.
        """

        token = await self.refresh_access_token(account, scope=GRAPH_SCOPE)
        loop = asyncio.get_running_loop()
        deadline = loop.time() + max(5.0, float(timeout_seconds))
        interval = max(2.0, float(interval_seconds))
        refreshed = False

        kwargs: dict[str, Any] = {
            "timeout": max(5.0, min(15.0, float(timeout_seconds))),
            "follow_redirects": True,
        }
        if self.transport is not None:
            kwargs["transport"] = self.transport
        if self.proxy_url:
            kwargs["proxy"] = self.proxy_url

        async with httpx.AsyncClient(**kwargs) as client:
            while loop.time() < deadline:
                if cancel_check is not None:
                    cancelled = cancel_check()
                    if inspect.isawaitable(cancelled):
                        cancelled = await cancelled
                    if cancelled:
                        raise OutlookMailError("任务已取消", code="JOB_CANCELLED")

                for folder in GRAPH_FOLDERS:
                    if loop.time() >= deadline:
                        break
                    url = f"{GRAPH_BASE_URL}/me/mailFolders/{folder}/messages"
                    params = {
                        "$top": "15",
                        "$orderby": "receivedDateTime DESC",
                        "$select": "id,subject,bodyPreview,body,receivedDateTime,from,toRecipients",
                    }
                    try:
                        response = await client.get(
                            url,
                            params=params,
                            headers={
                                "Authorization": f"Bearer {token.access_token}",
                                "Accept": "application/json",
                            },
                        )
                        if response.status_code == 401 and not refreshed:
                            token = await self.refresh_access_token(
                                account,
                                scope=GRAPH_SCOPE,
                            )
                            refreshed = True
                            response = await client.get(
                                url,
                                params=params,
                                headers={
                                    "Authorization": f"Bearer {token.access_token}",
                                    "Accept": "application/json",
                                },
                            )
                        if response.status_code in {401, 403}:
                            raise OutlookMailError(
                                f"Graph API 无邮件权限（HTTP {response.status_code}）",
                                code="OUTLOOK_GRAPH_PERMISSION",
                            )
                        if response.status_code == 404:
                            continue
                        response.raise_for_status()
                        payload = response.json()
                    except OutlookMailError:
                        raise
                    except (httpx.HTTPError, ValueError) as error:
                        raise OutlookMailError(
                            f"Graph API 请求失败: {error}",
                            code="OUTLOOK_GRAPH_UNAVAILABLE",
                        ) from error

                    messages = payload.get("value", []) if isinstance(payload, dict) else []
                    if not isinstance(messages, list):
                        continue
                    for message in messages:
                        if not isinstance(message, dict):
                            continue
                        received = _parse_graph_datetime(message.get("receivedDateTime"))
                        if received is not None and received < since:
                            continue
                        sender = _graph_sender(message)
                        if not _is_openai_sender(sender):
                            continue
                        recipients = _graph_recipients(message)
                        if recipients and account.email.lower() not in recipients:
                            continue
                        body = _graph_body(message)
                        code = extract_verification_code(
                            f"{message.get('subject', '')}\n{body}"
                        )
                        if code:
                            return str(code), token.refresh_token

                await asyncio.sleep(min(interval, max(0.0, deadline - loop.time())))

        raise OutlookMailError(
            f"Outlook Graph 验证码探测超时（{int(timeout_seconds)} 秒）",
            code="OUTLOOK_GRAPH_TIMEOUT",
        )

    def _fetch_recent_messages(
        self,
        mailbox: str,
        access_token: str,
        since: datetime,
        limit: int,
        password: str = "",
    ) -> list[MailRecord]:
        """Read recent OpenAI messages using the compatible Outlook IMAP hosts.

        Personal ``@outlook.com`` mailboxes are served by either
        ``outlook.live.com`` or ``outlook.office365.com`` depending on the
        account.  The reference implementation tries both.  XOAUTH2 remains
        the primary authentication method; the account password is only a
        fallback for tenants that reject the OAuth IMAP token.

        The configured host is tried first.  The second host is consulted
        only when authentication fails or the first host has no matching
        messages, so existing callers and test doubles retain their original
        one-connection behaviour in the common case.
        """

        hosts = self._imap_host_candidates()
        last_error: Exception | None = None
        authenticated = False
        saw_authenticated = False

        for host in hosts:
            client: Any | None = None
            try:
                context = ssl.create_default_context()
                client = self.imap_factory(
                    host,
                    self.imap_port,
                    ssl_context=context,
                    timeout=30,
                )

                # Prefer OAuth2.  If it fails, reconnect before attempting
                # password authentication because some IMAP servers leave a
                # failed AUTH command in a non-reusable state.
                oauth_error: Exception | None = None
                if access_token:
                    try:
                        xoauth = f"user={mailbox}\x01auth=Bearer {access_token}\x01\x01".encode()
                        client.authenticate("XOAUTH2", lambda _: xoauth)
                        authenticated = True
                    except Exception as error:
                        oauth_error = error
                        try:
                            client.logout()
                        except Exception:
                            pass
                        client = None

                if not authenticated and password:
                    try:
                        client = self.imap_factory(
                            host,
                            self.imap_port,
                            ssl_context=ssl.create_default_context(),
                            timeout=30,
                        )
                        client.login(mailbox, password)
                        authenticated = True
                    except Exception as error:
                        last_error = error
                        if oauth_error is not None:
                            last_error = error
                        try:
                            if client is not None:
                                client.logout()
                        except Exception:
                            pass
                        client = None

                if not authenticated:
                    if oauth_error is not None:
                        last_error = oauth_error
                    continue

                saw_authenticated = True
                records = self._scan_imap_messages(client, since=since, limit=limit)
                if records:
                    return records
                # An authenticated but empty endpoint is not fatal; the
                # account may be hosted on the alternate Outlook endpoint.
            except Exception as error:
                last_error = error
            finally:
                try:
                    if client is not None:
                        client.logout()
                except Exception:
                    pass
                authenticated = False

        # No matching mail is a normal polling result.  Raise only when every
        # host failed before authentication, so callers can distinguish an
        # empty inbox from an unusable mailbox and retry appropriately.
        if last_error is not None and not saw_authenticated:
            raise OutlookMailError(
                f"Outlook IMAP 登录或读取失败: {last_error}",
                code="OUTLOOK_IMAP_FAILED",
            ) from last_error
        return []

    def _imap_host_candidates(self) -> list[str]:
        configured = str(self.imap_host or "").strip()
        result: list[str] = []
        for host in (
            configured,
            "outlook.live.com" if configured.lower() in {"", "outlook.office365.com"} else "",
            "outlook.office365.com" if configured.lower() == "outlook.live.com" else "",
        ):
            host = str(host or "").strip()
            if host and host.lower() not in {item.lower() for item in result}:
                result.append(host)
        return result or ["outlook.office365.com"]

    def _scan_imap_messages(
        self,
        client: Any,
        *,
        since: datetime,
        limit: int,
    ) -> list[MailRecord]:
        folders = self._list_candidate_folders(client)
        records: list[MailRecord] = []
        seen: set[tuple[str, str, str]] = set()
        for folder in folders:
            try:
                status, _ = client.select(
                    f'"{folder.replace(chr(34), chr(92) + chr(34))}"',
                    readonly=True,
                )
                if status != "OK":
                    continue
                status, data = client.uid("search", None, "ALL")
                if status != "OK" or not data:
                    continue
                ids = data[0].split()[-40:]
                for message_id in reversed(ids):
                    status, payload = client.uid("fetch", message_id, "(RFC822)")
                    if status != "OK":
                        continue
                    raw = next(
                        (
                            item[1]
                            for item in payload
                            if isinstance(item, tuple)
                            and len(item) > 1
                            and isinstance(item[1], bytes)
                        ),
                        None,
                    )
                    if not raw:
                        continue
                    record = parse_mail_record(raw)
                    sender_lower = record.sender.lower()
                    if "tm1.openai" in sender_lower:
                        continue
                    if not any(marker in sender_lower for marker in OPENAI_SENDER_MARKERS):
                        continue
                    if record.received_at and record.received_at < since:
                        continue
                    key = (
                        sender_lower,
                        record.subject,
                        record.received_at.isoformat() if record.received_at else "",
                    )
                    if key in seen:
                        continue
                    seen.add(key)
                    records.append(record)
                    if len(records) >= limit:
                        return self._sort_mail_records(records, limit)
            except imaplib.IMAP4.error:
                continue
        return self._sort_mail_records(records, limit)

    @staticmethod
    def _sort_mail_records(records: list[MailRecord], limit: int) -> list[MailRecord]:
        return sorted(
            records,
            key=lambda item: item.received_at
            or datetime.min.replace(tzinfo=timezone.utc),
            reverse=True,
        )[:limit]

    @staticmethod
    def _list_candidate_folders(client: Any) -> list[str]:
        result = ["INBOX", "Junk", "Junk Email"]
        try:
            status, rows = client.list()
            if status == "OK" and rows:
                for raw in rows:
                    text = raw.decode(errors="replace") if isinstance(raw, bytes) else str(raw)
                    match = re.search(r'"([^"]+)"\s*$', text)
                    name = match.group(1) if match else text.rsplit(" ", 1)[-1].strip('"')
                    if name and name not in result:
                        result.append(name)
        except Exception:
            pass
        return result


def _parse_graph_datetime(value: Any) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _graph_sender(message: dict[str, Any]) -> str:
    sender = message.get("from")
    if isinstance(sender, dict):
        address = sender.get("emailAddress")
        if isinstance(address, dict):
            return str(address.get("address") or address.get("name") or "")
    return str(sender or "")


def _graph_recipients(message: dict[str, Any]) -> set[str]:
    recipients = message.get("toRecipients")
    if not isinstance(recipients, list):
        return set()
    result: set[str] = set()
    for item in recipients:
        if not isinstance(item, dict):
            continue
        address = item.get("emailAddress")
        if isinstance(address, dict) and address.get("address"):
            result.add(str(address["address"]).strip().lower())
    return result


def _graph_body(message: dict[str, Any]) -> str:
    body = message.get("body")
    if isinstance(body, dict):
        content = body.get("content")
        if content:
            return str(content)
    return str(message.get("bodyPreview") or "")


def _is_openai_sender(sender: str) -> bool:
    lowered = str(sender or "").lower()
    return bool(
        any(marker in lowered for marker in OPENAI_SENDER_MARKERS)
        and "tm1.openai" not in lowered
    )


def parse_mail_record(raw: bytes) -> MailRecord:
    message = email.message_from_bytes(raw, policy=default)
    sender = _decode_header_value(message.get("From", ""))
    subject = _decode_header_value(message.get("Subject", ""))
    body = _message_text(message)
    received_at: datetime | None = None
    try:
        received_at = parsedate_to_datetime(message.get("Date", ""))
        if received_at and received_at.tzinfo is None:
            received_at = received_at.replace(tzinfo=timezone.utc)
        elif received_at:
            received_at = received_at.astimezone(timezone.utc)
    except (TypeError, ValueError):
        received_at = None
    return MailRecord(sender=sender, subject=subject, body=body, received_at=received_at)


def extract_verification_code(value: str) -> str | None:
    text = str(value or "")
    patterns = (
        r"(?:verification\s*code|one[-\s]*time\s*code|code(?:\s+is)?|验证码|驗證碼|代码)[^\d]{0,120}(\d{6})\b",
        r"(?:openai|chatgpt)[^\d]{0,120}(\d{6})\b",
        r">\s*(\d{6})\s*<",
    )
    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE | re.DOTALL)
        if match:
            return match.group(1)
    plain = re.sub(r"https?://\S+", " ", text)
    candidates = re.findall(r"(?<![#\w])(\d{6})(?!\w)", plain)
    return candidates[0] if candidates else None


def _decode_header_value(value: str) -> str:
    try:
        return str(make_header(decode_header(value)))
    except Exception:
        return str(value or "")


def _message_text(message: Message) -> str:
    parts: list[str] = []
    if message.is_multipart():
        for part in message.walk():
            if part.get_content_maintype() == "multipart":
                continue
            if part.get_content_type() not in {"text/plain", "text/html"}:
                continue
            try:
                parts.append(part.get_content())
            except Exception:
                payload = part.get_payload(decode=True) or b""
                parts.append(payload.decode(part.get_content_charset() or "utf-8", errors="replace"))
    else:
        try:
            parts.append(message.get_content())
        except Exception:
            payload = message.get_payload(decode=True) or b""
            parts.append(payload.decode(message.get_content_charset() or "utf-8", errors="replace"))
    return "\n".join(str(part) for part in parts)

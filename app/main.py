from __future__ import annotations

import json
import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, AsyncIterator

import uvicorn
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, HTMLResponse, Response
from fastapi.staticfiles import StaticFiles

from app.config import Settings
from app.db import Database, Repository
from app.proxy import ProxyPool
from app.service import (
    QuotaService,
    ReauthService,
    ScheduledLivenessService,
    UploadConfigError,
    build_export_document,
    normalize_upload_url,
    parse_import_text,
    safe_error,
    merge_upload_skip_result,
    skipped_upload_result,
    split_upload_records,
    upload_cpa_records,
    upload_sub2api_records,
)


logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)
STATIC_DIR = Path(__file__).resolve().parent / "static"


async def json_body(request: Request) -> dict[str, Any]:
    raw = await request.body()
    if not raw.strip():
        return {}
    try:
        body = json.loads(raw)
    except (TypeError, ValueError, json.JSONDecodeError) as error:
        raise HTTPException(status_code=400, detail="请求体必须是有效 JSON") from error
    if not isinstance(body, dict):
        raise HTTPException(status_code=422, detail="请求体必须是 JSON 对象")
    return body


def ids_from_body(body: dict[str, Any]) -> list[str] | None:
    if "ids" not in body or body["ids"] is None:
        return None
    if not isinstance(body["ids"], list):
        raise HTTPException(status_code=422, detail="ids 必须是数组")
    return [str(value).strip() for value in body["ids"] if str(value).strip()]


def bool_from_body(body: dict[str, Any], key: str, default: bool = False) -> bool:
    value = body.get(key, default)
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def create_app(settings: Settings | None = None) -> FastAPI:
    config = settings or Settings.from_env()

    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[None]:
        config.data_dir.mkdir(parents=True, exist_ok=True)
        database = Database(config.db_path)
        database.initialize()
        repository = Repository(database)
        preferences = repository.load_preferences({
            "use_proxy_default": config.use_proxy_default,
            "auto_upload_cpa": config.auto_upload_cpa,
            "auto_upload_sub2api": config.auto_upload_sub2api,
            "force_upload": config.force_upload,
            "scheduled_liveness_enabled": config.scheduled_liveness_enabled,
            "scheduled_liveness_interval_minutes": config.scheduled_liveness_interval_minutes,
            "worker_count": config.worker_count,
            "cpa_api_url": config.cpa_api_url,
            "cpa_management_key": config.cpa_management_key,
            "cpa_api_timeout_seconds": config.cpa_api_timeout_seconds,
            "sub2api_api_url": config.sub2api_api_url,
            "sub2api_admin_api_key": config.sub2api_admin_api_key,
            "sub2api_api_timeout_seconds": config.sub2api_api_timeout_seconds,
            "sub2api_group_id": config.sub2api_group_id,
        })
        config.use_proxy_default = bool(preferences.get("use_proxy_default", config.use_proxy_default))
        config.auto_upload_cpa = bool(preferences.get("auto_upload_cpa", config.auto_upload_cpa))
        config.auto_upload_sub2api = bool(preferences.get("auto_upload_sub2api", config.auto_upload_sub2api))
        config.force_upload = bool(preferences.get("force_upload", config.force_upload))
        config.scheduled_liveness_enabled = bool(preferences.get("scheduled_liveness_enabled", config.scheduled_liveness_enabled))
        config.cpa_api_url = str(preferences.get("cpa_api_url", config.cpa_api_url) or "")
        config.cpa_management_key = str(preferences.get("cpa_management_key", config.cpa_management_key) or "")
        config.sub2api_api_url = str(preferences.get("sub2api_api_url", config.sub2api_api_url) or "")
        config.sub2api_admin_api_key = str(preferences.get("sub2api_admin_api_key", config.sub2api_admin_api_key) or "")
        try:
            config.worker_count = min(32, max(1, int(preferences.get("worker_count", config.worker_count))))
            config.scheduled_liveness_interval_minutes = min(10_080, max(5, int(preferences.get("scheduled_liveness_interval_minutes", config.scheduled_liveness_interval_minutes))))
            config.cpa_api_timeout_seconds = min(120, max(1, int(preferences.get("cpa_api_timeout_seconds", config.cpa_api_timeout_seconds))))
            config.sub2api_api_timeout_seconds = min(120, max(1, int(preferences.get("sub2api_api_timeout_seconds", config.sub2api_api_timeout_seconds))))
            config.sub2api_group_id = max(0, int(preferences.get("sub2api_group_id", config.sub2api_group_id)))
        except (TypeError, ValueError):
            config.worker_count = min(32, max(1, int(config.worker_count)))
            config.scheduled_liveness_interval_minutes = min(10_080, max(5, int(config.scheduled_liveness_interval_minutes)))
            config.cpa_api_timeout_seconds = min(120, max(1, int(config.cpa_api_timeout_seconds)))
            config.sub2api_api_timeout_seconds = min(120, max(1, int(config.sub2api_api_timeout_seconds)))
            config.sub2api_group_id = max(0, int(config.sub2api_group_id))
        proxy_pool = ProxyPool(database, lease_seconds=config.proxy_lease_seconds, cooldown_seconds=config.proxy_cooldown_seconds)
        proxy_pool.load_from_environment()
        reauth = ReauthService(repository, config, proxy_pool)
        quota = QuotaService(repository, config, proxy_pool)
        scheduler = ScheduledLivenessService(repository, config, proxy_pool, reauth)
        application.state.settings = config
        application.state.database = database
        application.state.repository = repository
        application.state.proxy_pool = proxy_pool
        application.state.reauth = reauth
        application.state.quota = quota
        application.state.scheduler = scheduler
        application.state.preferences = preferences
        await reauth.start()
        await scheduler.start()
        try:
            yield
        finally:
            await scheduler.stop()
            await reauth.stop()

    application = FastAPI(title="Codex 账号授权与额度工具", version="0.1.0", lifespan=lifespan)
    if STATIC_DIR.exists():
        application.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    @application.get("/", response_class=HTMLResponse)
    async def index() -> HTMLResponse:
        # The local UI changes frequently during operation; avoid showing a stale
        # cached shell after an upgrade or a restart.
        return HTMLResponse(
            content=(STATIC_DIR / "index.html").read_text(encoding="utf-8"),
            headers={"Cache-Control": "no-store"},
        )

    @application.get("/accounts", response_class=HTMLResponse)
    async def accounts_page() -> HTMLResponse:
        return HTMLResponse(
            content=(STATIC_DIR / "index.html").read_text(encoding="utf-8"),
            headers={"Cache-Control": "no-store"},
        )

    @application.get("/favicon.ico", include_in_schema=False)
    async def favicon() -> FileResponse:
        return FileResponse(STATIC_DIR / "favicon.svg", media_type="image/svg+xml", headers={"Cache-Control": "no-cache"})

    @application.get("/api/health")
    async def health(request: Request) -> dict[str, Any]:
        repository: Repository = request.app.state.repository
        _, total = repository.list_accounts(limit=1)
        return {"ok": True, "version": "0.1.0", "accounts": total, "proxy": request.app.state.proxy_pool.stats(), "queue": request.app.state.reauth.queue.qsize()}

    @application.post("/api/accounts/import")
    async def import_accounts(request: Request) -> dict[str, Any]:
        body = await json_body(request)
        text = body.get("text", body.get("content", ""))
        if not isinstance(text, str):
            raise HTTPException(status_code=422, detail="text 必须是字符串")
        records, invalid, duplicates = parse_import_text(text)
        result = request.app.state.repository.import_accounts(records)
        result.update({"invalid": invalid, "duplicates": duplicates})
        return result

    @application.get("/api/accounts")
    async def list_accounts(
        request: Request,
        limit: int = Query(200, ge=1, le=5000),
        offset: int = Query(0, ge=0),
        page: int | None = Query(None, ge=1),
        page_size: int | None = Query(None, ge=1, le=5000),
        q: str = Query("", max_length=200),
        status: str = Query("", max_length=40),
    ) -> dict[str, Any]:
        paged = page is not None or page_size is not None
        effective_size = int(page_size if page_size is not None else limit)
        effective_page = int(page if page is not None else (offset // effective_size) + 1)
        effective_offset = (effective_page - 1) * effective_size if paged else offset
        items, total = request.app.state.repository.list_accounts(effective_size, effective_offset, q, status)
        total_pages = max(1, (total + effective_size - 1) // effective_size)
        if paged and total and effective_page > total_pages:
            effective_page = total_pages
            effective_offset = (effective_page - 1) * effective_size
            items, total = request.app.state.repository.list_accounts(effective_size, effective_offset, q, status)
        return {
            "items": items,
            "total": total,
            "limit": effective_size,
            "offset": effective_offset,
            "page": effective_page,
            "page_size": effective_size,
            "total_pages": total_pages,
            "q": q.strip(),
            "status": status.strip().lower() if status.strip().lower() in {"pending", "running", "success", "failed", "disabled"} else "",
        }

    @application.delete("/api/accounts")
    async def delete_accounts(request: Request) -> dict[str, Any]:
        body = await json_body(request)
        account_ids = ids_from_body(body)
        if account_ids is None or not account_ids:
            raise HTTPException(status_code=422, detail="删除账号必须提供非空 ids 数组")
        return request.app.state.repository.delete_accounts(account_ids)

    @application.delete("/api/accounts/disabled")
    async def delete_disabled_accounts(request: Request) -> dict[str, int]:
        """Delete all accounts classified as deleted or deactivated."""

        return request.app.state.repository.delete_disabled_accounts()

    @application.get("/api/settings")
    async def get_settings(request: Request) -> dict[str, Any]:
        settings: Settings = request.app.state.settings
        reauth: ReauthService = request.app.state.reauth
        return {
            "settings": {
                "use_proxy_default": bool(settings.use_proxy_default),
                "auto_upload_cpa": bool(settings.auto_upload_cpa),
                "auto_upload_sub2api": bool(settings.auto_upload_sub2api),
                "force_upload": bool(settings.force_upload),
                "scheduled_liveness_enabled": bool(settings.scheduled_liveness_enabled),
                "scheduled_liveness_interval_minutes": int(settings.scheduled_liveness_interval_minutes),
                "worker_count": int(settings.worker_count),
                "running_worker_count": int(reauth.worker_count),
                "cpa_api_url": settings.cpa_api_url,
                "cpa_management_key_configured": bool(settings.cpa_management_key),
                "cpa_api_timeout_seconds": int(settings.cpa_api_timeout_seconds),
                "sub2api_api_url": settings.sub2api_api_url,
                "sub2api_admin_api_key_configured": bool(settings.sub2api_admin_api_key),
                "sub2api_api_timeout_seconds": int(settings.sub2api_api_timeout_seconds),
                "sub2api_group_id": int(settings.sub2api_group_id),
            },
            "scheduler": request.app.state.scheduler.get_status(),
            "restart_required": int(settings.worker_count) != int(reauth.worker_count),
        }

    @application.patch("/api/settings")
    async def update_settings(request: Request) -> dict[str, Any]:
        body = await json_body(request)
        settings: Settings = request.app.state.settings
        reauth: ReauthService = request.app.state.reauth

        def read_bool(name: str, current: bool) -> bool:
            if name not in body:
                return current
            value = body[name]
            if isinstance(value, bool):
                return value
            if isinstance(value, str) and value.strip().lower() in {"1", "true", "yes", "on"}:
                return True
            if isinstance(value, str) and value.strip().lower() in {"0", "false", "no", "off"}:
                return False
            raise HTTPException(status_code=422, detail=f"{name} 必须是布尔值")

        def read_timeout(name: str, current: int) -> int:
            if name not in body:
                return current
            value = body[name]
            if isinstance(value, bool):
                raise HTTPException(status_code=422, detail=f"{name} 必须是 1 到 120 的整数")
            try:
                timeout = int(value)
            except (TypeError, ValueError, OverflowError) as error:
                raise HTTPException(status_code=422, detail=f"{name} 必须是 1 到 120 的整数") from error
            if timeout < 1 or timeout > 120:
                raise HTTPException(status_code=422, detail=f"{name} 必须是 1 到 120 的整数")
            return timeout

        def read_url(name: str, current: str, label: str) -> str:
            if name not in body:
                return current
            value = body[name]
            if not isinstance(value, str):
                raise HTTPException(status_code=422, detail=f"{name} 必须是字符串")
            try:
                return normalize_upload_url(value, label, allow_empty=True)
            except UploadConfigError as error:
                raise HTTPException(status_code=422, detail=safe_error(error)) from error

        def read_secret(name: str, clear_name: str, current: str, label: str) -> str:
            value = body.get(name, "")
            if name in body and not isinstance(value, str):
                raise HTTPException(status_code=422, detail=f"{name} 必须是字符串")
            secret = str(value or "").strip()
            if secret:
                if len(secret) > 512 or "\r" in secret or "\n" in secret:
                    raise HTTPException(status_code=422, detail=f"{label}格式无效")
                return secret
            if read_bool(clear_name, False):
                return ""
            return current

        def read_group_id(name: str, current: int) -> int:
            if name not in body:
                return current
            value = body[name]
            if value is None or (isinstance(value, str) and not value.strip()):
                return 0
            if isinstance(value, bool):
                raise HTTPException(status_code=422, detail=f"{name} 必须是正整数或留空")
            if isinstance(value, float) and not value.is_integer():
                raise HTTPException(status_code=422, detail=f"{name} 必须是正整数或留空")
            try:
                group_id = int(value)
            except (TypeError, ValueError, OverflowError) as error:
                raise HTTPException(status_code=422, detail=f"{name} 必须是正整数或留空") from error
            if group_id < 0 or group_id > 9_223_372_036_854_775_807:
                raise HTTPException(status_code=422, detail=f"{name} 必须是正整数或留空")
            return group_id

        use_proxy_default = read_bool("use_proxy_default", bool(settings.use_proxy_default))
        auto_upload_cpa = read_bool("auto_upload_cpa", bool(settings.auto_upload_cpa))
        auto_upload_sub2api = read_bool("auto_upload_sub2api", bool(settings.auto_upload_sub2api))
        force_upload = read_bool("force_upload", bool(settings.force_upload))
        scheduled_liveness_enabled = read_bool("scheduled_liveness_enabled", bool(settings.scheduled_liveness_enabled))
        cpa_api_url = read_url("cpa_api_url", settings.cpa_api_url, "CLI Proxy API")
        cpa_management_key = read_secret("cpa_management_key", "clear_cpa_management_key", settings.cpa_management_key, "CLI Proxy 管理员密码")
        cpa_api_timeout_seconds = read_timeout("cpa_api_timeout_seconds", settings.cpa_api_timeout_seconds)
        sub2api_api_url = read_url("sub2api_api_url", settings.sub2api_api_url, "Sub2API")
        sub2api_admin_api_key = read_secret("sub2api_admin_api_key", "clear_sub2api_admin_api_key", settings.sub2api_admin_api_key, "Sub2API 管理员 API Key")
        sub2api_api_timeout_seconds = read_timeout("sub2api_api_timeout_seconds", settings.sub2api_api_timeout_seconds)
        sub2api_group_id = read_group_id("sub2api_group_id", int(settings.sub2api_group_id))
        previous_sub2api_group_id = int(settings.sub2api_group_id)
        worker_count = int(settings.worker_count)
        if "worker_count" in body:
            value = body["worker_count"]
            if isinstance(value, bool):
                raise HTTPException(status_code=422, detail="worker_count 必须是 1 到 32 的整数")
            try:
                worker_count = int(value)
            except (TypeError, ValueError, OverflowError) as error:
                raise HTTPException(status_code=422, detail="worker_count 必须是 1 到 32 的整数") from error
            if worker_count < 1 or worker_count > 32:
                raise HTTPException(status_code=422, detail="worker_count 必须是 1 到 32 的整数")
        scheduled_liveness_interval_minutes = int(settings.scheduled_liveness_interval_minutes)
        if "scheduled_liveness_interval_minutes" in body:
            value = body["scheduled_liveness_interval_minutes"]
            if isinstance(value, bool):
                raise HTTPException(status_code=422, detail="scheduled_liveness_interval_minutes 必须是 5 到 10080 的整数")
            try:
                scheduled_liveness_interval_minutes = int(value)
            except (TypeError, ValueError, OverflowError) as error:
                raise HTTPException(status_code=422, detail="scheduled_liveness_interval_minutes 必须是 5 到 10080 的整数") from error
            if scheduled_liveness_interval_minutes < 5 or scheduled_liveness_interval_minutes > 10_080:
                raise HTTPException(status_code=422, detail="scheduled_liveness_interval_minutes 必须是 5 到 10080 的整数")

        settings.use_proxy_default = use_proxy_default
        settings.auto_upload_cpa = auto_upload_cpa
        settings.auto_upload_sub2api = auto_upload_sub2api
        settings.force_upload = force_upload
        settings.scheduled_liveness_enabled = scheduled_liveness_enabled
        settings.scheduled_liveness_interval_minutes = scheduled_liveness_interval_minutes
        settings.worker_count = worker_count
        settings.cpa_api_url = cpa_api_url
        settings.cpa_management_key = cpa_management_key
        settings.cpa_api_timeout_seconds = cpa_api_timeout_seconds
        settings.sub2api_api_url = sub2api_api_url
        settings.sub2api_admin_api_key = sub2api_admin_api_key
        settings.sub2api_api_timeout_seconds = sub2api_api_timeout_seconds
        settings.sub2api_group_id = sub2api_group_id
        saved_preferences = {
            "use_proxy_default": use_proxy_default,
            "auto_upload_cpa": auto_upload_cpa,
            "auto_upload_sub2api": auto_upload_sub2api,
            "force_upload": force_upload,
            "scheduled_liveness_enabled": scheduled_liveness_enabled,
            "scheduled_liveness_interval_minutes": scheduled_liveness_interval_minutes,
            "worker_count": worker_count,
            "cpa_api_url": cpa_api_url,
            "cpa_management_key": cpa_management_key,
            "cpa_api_timeout_seconds": cpa_api_timeout_seconds,
            "sub2api_api_url": sub2api_api_url,
            "sub2api_admin_api_key": sub2api_admin_api_key,
            "sub2api_api_timeout_seconds": sub2api_api_timeout_seconds,
            "sub2api_group_id": sub2api_group_id,
        }
        request.app.state.repository.save_preferences(saved_preferences)
        if sub2api_group_id != previous_sub2api_group_id:
            request.app.state.repository.reset_upload_statuses("sub2api")
        request.app.state.preferences.update(saved_preferences)
        request.app.state.scheduler.notify_configuration_changed()
        restart_required = worker_count != reauth.worker_count
        return {
            "settings": {
                "use_proxy_default": use_proxy_default,
                "auto_upload_cpa": auto_upload_cpa,
                "auto_upload_sub2api": auto_upload_sub2api,
                "force_upload": force_upload,
                "scheduled_liveness_enabled": scheduled_liveness_enabled,
                "scheduled_liveness_interval_minutes": scheduled_liveness_interval_minutes,
                "worker_count": worker_count,
                "running_worker_count": reauth.worker_count,
                "cpa_api_url": cpa_api_url,
                "cpa_management_key_configured": bool(cpa_management_key),
                "cpa_api_timeout_seconds": cpa_api_timeout_seconds,
                "sub2api_api_url": sub2api_api_url,
                "sub2api_admin_api_key_configured": bool(sub2api_admin_api_key),
                "sub2api_api_timeout_seconds": sub2api_api_timeout_seconds,
                "sub2api_group_id": sub2api_group_id,
            },
            "scheduler": request.app.state.scheduler.get_status(),
            "restart_required": restart_required,
        }

    @application.api_route("/api/accounts/export", methods=["GET", "POST"])
    @application.api_route("/api/tokens/export", methods=["GET", "POST"])
    async def export_authorized_accounts(request: Request, format: str = Query("cpa")) -> Response:
        """Download authorized account credentials in an explicit format.

        The account list endpoint never exposes secrets.  This route is the
        deliberate download boundary and returns only rows with saved OAuth
        tokens; an empty ``ids`` array is a no-op, while omitted ids exports
        all authorized accounts.
        """

        body = await json_body(request)
        account_ids = ids_from_body(body) if request.method == "POST" else None
        selected_format = str(body.get("format") or format).strip().lower()
        try:
            records = request.app.state.repository.export_account_records(account_ids)
            content, media_type, filename = build_export_document(records, selected_format)
        except ValueError as error:
            raise HTTPException(status_code=400, detail=safe_error(error)) from error
        return Response(
            content=content,
            media_type=media_type,
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "Cache-Control": "no-store",
                "X-Content-Type-Options": "nosniff",
            },
        )

    @application.api_route("/api/accounts/upload-cpa", methods=["POST"])
    @application.api_route("/api/tokens/upload-cpa", methods=["POST"])
    async def upload_authorized_cpa(request: Request) -> dict[str, Any]:
        body = await json_body(request)
        repository: Repository = request.app.state.repository
        all_records = repository.export_account_records(ids_from_body(body))
        force = bool_from_body(body, "force", bool(request.app.state.settings.force_upload))
        records, skipped = split_upload_records(repository, "cpa", all_records, force=force)
        try:
            if records:
                settings: Settings = request.app.state.settings
                result = await upload_cpa_records(
                    records,
                    api_url=settings.cpa_api_url,
                    management_key=settings.cpa_management_key,
                    timeout_seconds=settings.cpa_api_timeout_seconds,
                )
                result = merge_upload_skip_result(result, skipped)
            else:
                result = skipped_upload_result(all_records)
            repository.save_upload_statuses("cpa", all_records, result)
            return result
        except UploadConfigError as error:
            repository.save_upload_statuses("cpa", all_records, {"items": skipped}, error=safe_error(error))
            raise HTTPException(status_code=503, detail=safe_error(error)) from error
        except ValueError as error:
            repository.save_upload_statuses("cpa", all_records, {"items": skipped}, error=safe_error(error))
            raise HTTPException(status_code=409, detail=safe_error(error)) from error
        except Exception as error:
            repository.save_upload_statuses("cpa", all_records, {"items": skipped}, error=safe_error(error))
            logger.warning("CLI Proxy 批量上传失败：%s", type(error).__name__)
            raise HTTPException(status_code=502, detail="CLI Proxy 上传失败，请检查地址、管理员密码和网络") from error

    @application.api_route("/api/accounts/upload-sub2api", methods=["POST"])
    @application.api_route("/api/tokens/upload-sub2api", methods=["POST"])
    async def upload_authorized_sub2api(request: Request) -> dict[str, Any]:
        body = await json_body(request)
        repository: Repository = request.app.state.repository
        all_records = repository.export_account_records(ids_from_body(body))
        force = bool_from_body(body, "force", bool(request.app.state.settings.force_upload))
        records, skipped = split_upload_records(repository, "sub2api", all_records, force=force)
        try:
            if records:
                settings: Settings = request.app.state.settings
                result = await upload_sub2api_records(
                    records,
                    api_url=settings.sub2api_api_url,
                    admin_api_key=settings.sub2api_admin_api_key,
                    timeout_seconds=settings.sub2api_api_timeout_seconds,
                    group_id=settings.sub2api_group_id or None,
                )
                result = merge_upload_skip_result(result, skipped)
            else:
                result = skipped_upload_result(all_records)
            repository.save_upload_statuses("sub2api", all_records, result)
            return result
        except UploadConfigError as error:
            repository.save_upload_statuses("sub2api", all_records, {"items": skipped}, error=safe_error(error))
            raise HTTPException(status_code=503, detail=safe_error(error)) from error
        except ValueError as error:
            repository.save_upload_statuses("sub2api", all_records, {"items": skipped}, error=safe_error(error))
            raise HTTPException(status_code=409, detail=safe_error(error)) from error
        except Exception as error:
            repository.save_upload_statuses("sub2api", all_records, {"items": skipped}, error=safe_error(error))
            logger.warning("Sub2API 批量上传失败：%s", type(error).__name__)
            raise HTTPException(status_code=502, detail=f"Sub2API 上传失败：{safe_error(error)}") from error

    @application.post("/api/reauth/queue")
    async def queue_reauth(request: Request) -> dict[str, Any]:
        body = await json_body(request)
        use_proxy = body.get("use_proxy", request.app.state.settings.use_proxy_default)
        use_proxy = str(use_proxy).lower() in {"1", "true", "yes", "on"} if not isinstance(use_proxy, bool) else use_proxy
        return await request.app.state.reauth.queue_accounts(ids_from_body(body), use_proxy=use_proxy)

    @application.post("/api/reauth/retry-failed")
    async def retry_failed_reauth(request: Request) -> dict[str, Any]:
        """Retry only accounts whose latest authorization attempt failed."""

        body = await json_body(request)
        use_proxy = body.get("use_proxy", request.app.state.settings.use_proxy_default)
        use_proxy = str(use_proxy).lower() in {"1", "true", "yes", "on"} if not isinstance(use_proxy, bool) else use_proxy
        account_ids = request.app.state.repository.account_ids_by_status("failed")
        result = await request.app.state.reauth.queue_accounts(account_ids, use_proxy=use_proxy)
        result["matched"] = len(account_ids)
        return result

    @application.get("/api/reauth/jobs")
    async def list_jobs(request: Request, limit: int = Query(200, ge=1, le=5000)) -> dict[str, Any]:
        return {"items": request.app.state.repository.list_jobs(limit)}

    @application.get("/api/reauth/jobs/{job_id}")
    async def get_job(job_id: str, request: Request) -> dict[str, Any]:
        job = request.app.state.repository.get_job(job_id)
        if not job:
            raise HTTPException(status_code=404, detail="任务不存在")
        job["events"] = request.app.state.repository.list_events(job_id)
        return job

    @application.get("/api/quotas")
    async def list_quotas(request: Request, limit: int = Query(200, ge=1, le=5000), offset: int = Query(0, ge=0)) -> dict[str, Any]:
        items, total = request.app.state.repository.list_quotas(limit, offset)
        return {
            "items": items,
            "total": total,
            "limit": limit,
            "offset": offset,
            "summary": request.app.state.repository.quota_summary(),
        }

    @application.post("/api/quotas/refresh")
    async def refresh_quotas(request: Request) -> dict[str, Any]:
        body = await json_body(request)
        use_proxy = body.get("use_proxy", request.app.state.settings.use_proxy_default)
        use_proxy = str(use_proxy).lower() in {"1", "true", "yes", "on"} if not isinstance(use_proxy, bool) else use_proxy
        try:
            return await request.app.state.quota.refresh(ids_from_body(body), use_proxy=use_proxy)
        except RuntimeError as error:
            raise HTTPException(status_code=409, detail=safe_error(error)) from error

    @application.post("/api/quotas/refresh-failed")
    async def refresh_failed_quotas(request: Request) -> dict[str, Any]:
        """Retry only accounts whose latest quota query failed."""

        body = await json_body(request)
        use_proxy = body.get("use_proxy", request.app.state.settings.use_proxy_default)
        use_proxy = str(use_proxy).lower() in {"1", "true", "yes", "on"} if not isinstance(use_proxy, bool) else use_proxy
        account_ids = request.app.state.repository.failed_quota_account_ids()
        try:
            result = await request.app.state.quota.refresh(account_ids, use_proxy=use_proxy)
        except RuntimeError as error:
            raise HTTPException(status_code=409, detail=safe_error(error)) from error
        result["matched"] = len(account_ids)
        return result

    @application.get("/api/quotas/progress")
    async def quota_progress(request: Request) -> dict[str, Any]:
        return request.app.state.quota.get_progress()

    @application.post("/api/proxies/import")
    async def import_proxies(request: Request) -> dict[str, Any]:
        body = await json_body(request)
        text = body.get("text", "")
        if not isinstance(text, str):
            raise HTTPException(status_code=422, detail="text 必须是字符串")
        return request.app.state.proxy_pool.import_text(text)

    @application.get("/api/proxies")
    async def list_proxies(
        request: Request,
        limit: int = Query(200, ge=1, le=5000),
        offset: int = Query(0, ge=0),
        page: int | None = Query(None, ge=1),
        page_size: int | None = Query(None, ge=1, le=5000),
    ) -> dict[str, Any]:
        paged = page is not None or page_size is not None
        effective_size = int(page_size if page_size is not None else limit)
        effective_page = int(page if page is not None else (offset // effective_size) + 1)
        effective_offset = (effective_page - 1) * effective_size if paged else offset
        pool = request.app.state.proxy_pool
        stats = pool.stats()
        total = int(stats.get("total") or 0)
        total_pages = max(1, (total + effective_size - 1) // effective_size)
        if paged and total and effective_page > total_pages:
            effective_page = total_pages
            effective_offset = (effective_page - 1) * effective_size
        return {
            "items": pool.list_public(effective_size, effective_offset),
            "stats": stats,
            "total": total,
            "limit": effective_size,
            "offset": effective_offset,
            "page": effective_page,
            "page_size": effective_size,
            "total_pages": total_pages,
        }

    return application


app = create_app()


if __name__ == "__main__":
    settings = Settings.from_env()
    uvicorn.run("app.main:app", host=settings.host, port=settings.port, reload=False)

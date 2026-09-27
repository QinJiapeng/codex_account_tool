from pathlib import Path

from app.config import Settings


def test_project_defaults_match_shared_settings(monkeypatch, tmp_path: Path):
    for name in (
        "REAUTH_WORKERS",
        "USE_PROXY_DEFAULT",
        "AUTO_UPLOAD_CPA",
        "AUTO_UPLOAD_SUB2API",
        "SCHEDULED_LIVENESS_ENABLED",
        "SCHEDULED_LIVENESS_INTERVAL_MINUTES",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("DATA_DIR", str(tmp_path))

    settings = Settings.from_env()

    assert settings.worker_count == 20
    assert settings.use_proxy_default is True
    assert settings.auto_upload_cpa is True
    assert settings.auto_upload_sub2api is False
    assert settings.sub2api_group_id == 0
    assert settings.scheduled_liveness_enabled is True
    assert settings.scheduled_liveness_interval_minutes == 5


def test_worker_count_is_capped_at_1000(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("REAUTH_WORKERS", "1250")

    settings = Settings.from_env()

    assert settings.worker_count == 1000

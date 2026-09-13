import pytest

from app.oauth.codex_usage import parse_usage_payload


def test_parse_usage_payload_extracts_primary_and_secondary_limit_windows():
    result = parse_usage_payload(
        {
            "plan_type": "plus",
            "rate_limit": {
                "primary_window": {
                    "used_percent": 50,
                    "reset_at": 1_700_000_000,
                    "reset_after_seconds": 3600,
                },
                "secondary_window": {
                    "used_percent": 84,
                    "reset_after_seconds": 259200,
                },
            },
            "credits": {"balance": "569.71", "has_credits": True},
        }
    )

    assert result["plan_type"] == "plus"
    assert [window["label"] for window in result["limit_windows"]] == ["5h", "Weekly"]
    assert result["limit_windows"][0]["used_percent"] == 50
    assert result["limit_windows"][1]["reset_after_seconds"] == 259200
    assert result["used_percent"] == 50
    assert result["reset_after_seconds"] == 3600


def test_parse_usage_payload_accepts_window_list_and_keeps_only_safe_fields():
    result = parse_usage_payload(
        {
            "planType": "free",
            "rateLimit": {
                "windows": [
                    {"name": "Monthly", "usedPercent": 10, "limit": 100, "remaining": 90, "resetAfterSeconds": 7200},
                    {"name": "gpt-reserve Weekly", "used_percent": 100, "limitReached": True},
                ]
            },
        }
    )

    assert [window["label"] for window in result["limit_windows"]] == ["Monthly", "gpt-reserve Weekly"]
    assert result["limit_windows"][0]["limit_display"] == "100"
    assert result["limit_windows"][0]["remaining_display"] == "90"
    assert result["limit_windows"][1]["limit_reached"] is True
    assert all("access_token" not in window for window in result["limit_windows"])


def test_parse_usage_payload_labels_free_primary_window_as_monthly():
    result = parse_usage_payload(
        {
            "plan_type": "free",
            "rate_limit": {
                "primary_window": {
                    "used_percent": 16,
                    "reset_after_seconds": 2_529_678,
                }
            },
        }
    )

    assert result["limit_windows"][0]["label"] == "Monthly"


def test_parse_usage_payload_rejects_an_empty_object():
    with pytest.raises(ValueError, match="缺少可识别"):
        parse_usage_payload({})

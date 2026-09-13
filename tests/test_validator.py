from __future__ import annotations

import pytest

from app.oauth.codex_validator import create_codex_token_validator


@pytest.mark.asyncio
async def test_token_validator_uses_codex_models_endpoint_and_models_envelope() -> None:
    requests: list[tuple[str, dict[str, object]]] = []

    async def request(url: str, options: dict[str, object]) -> dict[str, object]:
        requests.append((url, options))
        return {"status": 200, "body": '{"models":[{"slug":"gpt-5-codex"}]}' }

    validator = create_codex_token_validator(
        client_version="0.144.1",
        timeout_ms=2_000,
        request=request,
    )
    result = await validator.validate({"access_token": "access-token", "account_id": "account-1"})

    assert result["valid"] is True
    assert requests[0][0] == "https://chatgpt.com/backend-api/codex/models?client_version=0.144.1"
    headers = requests[0][1]["headers"]
    assert isinstance(headers, dict)
    assert headers["Authorization"] == "Bearer access-token"
    assert headers["ChatGPT-Account-ID"] == "account-1"


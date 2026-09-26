from app.protocol.auth_flow import AuthFlow
from app.protocol.config import Config


class _SessionResponse:
    status_code = 200
    text = ""
    headers = {}

    def __init__(self, payload):
        self._payload = payload

    def json(self):
        return self._payload

    def raise_for_status(self):
        return None


class _SessionClient:
    def __init__(self, payload):
        self.payload = payload

    def get(self, *args, **kwargs):
        return _SessionResponse(self.payload)


def _flow_with_session(payload):
    flow = AuthFlow(Config())
    flow.session = _SessionClient(payload)
    flow.result.device_id = "test-device"
    flow._build_chatgpt_cookie_header = lambda: ""
    flow._extract_session_cookie = lambda: "session-cookie"
    return flow


def test_web_session_does_not_replace_codex_oauth_access_token():
    flow = _flow_with_session({
        "sessionToken": "session-cookie",
        "accessToken": "web-session-access",
    })
    flow.result.access_token = "codex-oauth-access"
    flow.result.refresh_token = "codex-oauth-refresh"

    session_token, access_token = flow.get_auth_session()

    assert session_token == "session-cookie"
    assert access_token == "web-session-access"
    assert flow.result.session_token == "session-cookie"
    assert flow.result.access_token == "codex-oauth-access"
    assert flow.result.refresh_token == "codex-oauth-refresh"


def test_web_session_access_token_is_used_without_oauth_refresh_token():
    flow = _flow_with_session({
        "sessionToken": "session-cookie",
        "accessToken": "web-session-access",
    })

    flow.get_auth_session()

    assert flow.result.access_token == "web-session-access"


def test_session_dump_does_not_replace_codex_oauth_access_token():
    flow = _flow_with_session({
        "client_auth_session": {
            "access_token": "web-session-access",
        },
    })
    flow.result.access_token = "codex-oauth-access"
    flow.result.refresh_token = "codex-oauth-refresh"
    flow.result.id_token = "codex-oauth-id"

    flow.fetch_client_auth_session_dump("test")

    assert flow.result.access_token == "codex-oauth-access"
    assert flow.result.refresh_token == "codex-oauth-refresh"
    assert flow.result.id_token == "codex-oauth-id"


def test_session_dump_replaces_oauth_credentials_only_as_a_pair():
    flow = _flow_with_session({
        "client_auth_session": {
            "access_token": "new-oauth-access",
            "refresh_token": "new-oauth-refresh",
            "id_token": "new-oauth-id",
        },
    })
    flow.result.access_token = "old-oauth-access"
    flow.result.refresh_token = "old-oauth-refresh"
    flow.result.id_token = "old-oauth-id"

    flow.fetch_client_auth_session_dump("test")

    assert flow.result.access_token == "new-oauth-access"
    assert flow.result.refresh_token == "new-oauth-refresh"
    assert flow.result.id_token == "new-oauth-id"


def test_totp_mfa_completion_issues_challenge_and_submits_factor(monkeypatch):
    flow = AuthFlow(Config())
    flow.result.totp_secret = "JBSWY3DPEHPK3PXP"
    calls = []
    monkeypatch.setattr(flow, "issue_mfa_challenge", lambda factor_id: calls.append(("issue", factor_id)) or {})
    monkeypatch.setattr(
        flow,
        "submit_mfa_totp",
        lambda code, factor_id: calls.append(("verify", code, factor_id)) or {"continue_url": "https://auth.openai.com/callback"},
    )
    response, continue_url = flow.complete_mfa_totp(
        {"oai-client-auth-session": {"mfa_challenge_factors": [{"factor_type": "totp", "id": "factor-1"}]}},
        "https://auth.openai.com/mfa-challenge/factor-1",
        "mfa@example.com",
    )
    assert calls[0] == ("issue", "factor-1")
    assert calls[1][0] == "verify" and calls[1][2] == "factor-1"
    assert len(calls[1][1]) == 6 and calls[1][1].isdigit()
    assert response["continue_url"].endswith("callback")
    assert continue_url.endswith("callback")

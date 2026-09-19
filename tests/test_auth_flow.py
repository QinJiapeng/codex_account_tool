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

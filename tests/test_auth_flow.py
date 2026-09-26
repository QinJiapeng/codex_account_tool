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


def test_setup_totp_enrolls_activates_and_confirms(monkeypatch):
    class Response(_SessionResponse):
        def __init__(self, payload, status_code=200):
            super().__init__(payload)
            self.status_code = status_code

    class Session:
        def __init__(self):
            self.cookies = {"oai-did": "device-id"}
            self.calls = []
            self.info_calls = 0

        def get(self, url, **kwargs):
            self.calls.append(("GET", url, kwargs))
            if "action=enable" in url:
                response = Response({})
                response.text = '{"accessToken":"web-access-token-from-page"}'
                return response
            if url.endswith("mfa_info"):
                self.info_calls += 1
                return Response({
                    "mfa_enabled_v2": self.info_calls > 1,
                    "factors": {"totp": ([{"factor_type": "totp", "id": "factor-1"}] if self.info_calls > 1 else [])},
                })
            raise AssertionError(url)

        def post(self, url, **kwargs):
            self.calls.append(("POST", url, kwargs))
            if url.endswith("mfa/enroll"):
                return Response({"secret": "JBSWY3DPEHPK3PXP", "session_id": "session-1"})
            if url.endswith("activate_enrollment"):
                assert kwargs["json"]["factor_type"] == "totp"
                assert kwargs["json"]["session_id"] == "session-1"
                assert kwargs["json"]["code"] == "123456"
                return Response({"success": True})
            raise AssertionError(url)

    flow = AuthFlow(Config())
    flow.session = Session()
    flow.result.device_id = "device-id"
    flow.get_auth_session = lambda: ("session-cookie", "web-access-token")
    flow._trace_http = lambda *args, **kwargs: None
    monkeypatch.setattr("app.protocol.auth_flow._totp_now", lambda secret: "123456")

    result = flow.setup_totp("mfa@example.com")

    assert result["activation_succeeded"] is True
    assert result["secret"] == "JBSWY3DPEHPK3PXP"
    assert result["otpauth_uri"].startswith("otpauth://totp/OpenAI%3Amfa%40example.com?")
    assert [call[0] for call in flow.session.calls] == ["GET", "GET", "POST", "POST", "GET"]


def test_setup_totp_skips_existing_factor():
    class Session:
        cookies = {"oai-did": "device-id"}

        def get(self, url, **kwargs):
            if "action=enable" in url:
                response = _SessionResponse({})
                response.text = '{"accessToken":"web-access-token-from-page"}'
                return response
            return _SessionResponse({
                "mfa_enabled_v2": True,
                "factors": {"totp": [{"factor_type": "totp", "id": "factor-1"}]},
            })

        def post(self, *args, **kwargs):
            raise AssertionError("existing TOTP must not enroll again")

    flow = AuthFlow(Config())
    flow.session = Session()
    flow.get_auth_session = lambda: ("session-cookie", "web-access-token")
    flow._trace_http = lambda *args, **kwargs: None

    result = flow.setup_totp("mfa@example.com")

    assert result["already_enabled"] is True
    assert result["secret"] == ""

from __future__ import annotations

from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import BytesIO
from threading import Thread
from urllib.parse import parse_qs
from urllib.error import HTTPError

import pytest

from padv.dynamic.http.runner import HttpSession, RequestError, send_request


@contextmanager
def _serve(handler: type[BaseHTTPRequestHandler]):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def test_send_request_returns_http_error_responses(monkeypatch: pytest.MonkeyPatch) -> None:
    def _fake_urlopen(*args, **kwargs):
        raise HTTPError(
            url="http://127.0.0.1/fail",
            code=500,
            msg="Internal Server Error",
            hdrs={"Content-Type": "text/plain"},
            fp=BytesIO(b"boom"),
        )

    monkeypatch.setattr("urllib.request.urlopen", _fake_urlopen)

    response = send_request(
        url="http://127.0.0.1/fail",
        method="GET",
        headers={},
        timeout_seconds=5,
    )

    assert response.status_code == 500
    assert response.headers["Content-Type"] == "text/plain"
    assert response.body == "boom"


def test_send_request_raises_for_transport_failures(monkeypatch: pytest.MonkeyPatch) -> None:
    def _fake_urlopen(*args, **kwargs):
        raise OSError("record layer failure")

    monkeypatch.setattr("urllib.request.urlopen", _fake_urlopen)

    with pytest.raises(RequestError, match="request_failed:record layer failure"):
        send_request(
            url="http://127.0.0.1/fail",
            method="GET",
            headers={},
            timeout_seconds=5,
        )


def test_http_session_learns_set_cookie_between_requests() -> None:
    seen_cookie_headers: list[str] = []

    class _CookieHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            seen_cookie_headers.append(self.headers.get("Cookie", ""))
            if self.path == "/set-cookie":
                self.send_response(200)
                self.send_header("Set-Cookie", "sessionid=abc123; Path=/; HttpOnly")
                self.end_headers()
                self.wfile.write(b"seeded")
                return
            if self.path == "/needs-cookie":
                if "sessionid=abc123" in self.headers.get("Cookie", ""):
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"authorized")
                    return
                self.send_response(401)
                self.end_headers()
                self.wfile.write(b"missing-cookie")
                return
            self.send_response(404)
            self.end_headers()

        def log_message(self, format: str, *args) -> None:  # pragma: no cover
            return

    session = HttpSession()
    with _serve(_CookieHandler) as base_url:
        seeded = send_request(
            url=f"{base_url}/set-cookie",
            method="GET",
            headers={},
            timeout_seconds=5,
            session=session,
        )
        protected = send_request(
            url=f"{base_url}/needs-cookie",
            method="GET",
            headers={},
            timeout_seconds=5,
            session=session,
        )

    assert seeded.status_code == 200
    assert protected.status_code == 200
    assert session.cookies == {"sessionid": "abc123"}
    assert seen_cookie_headers == ["", "sessionid=abc123"]


def test_http_session_isolated_between_candidates() -> None:
    seen_cookie_headers: list[str] = []

    class _CookieHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            seen_cookie_headers.append(self.headers.get("Cookie", ""))
            if self.path == "/set-cookie":
                self.send_response(200)
                self.send_header("Set-Cookie", "sessionid=abc123; Path=/")
                self.end_headers()
                self.wfile.write(b"seeded")
                return
            if self.path == "/needs-cookie":
                if "sessionid=abc123" in self.headers.get("Cookie", ""):
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"authorized")
                    return
                self.send_response(401)
                self.end_headers()
                self.wfile.write(b"missing-cookie")
                return
            self.send_response(404)
            self.end_headers()

        def log_message(self, format: str, *args) -> None:  # pragma: no cover
            return

    candidate_one = HttpSession()
    candidate_two = HttpSession()
    with _serve(_CookieHandler) as base_url:
        send_request(
            url=f"{base_url}/set-cookie",
            method="GET",
            headers={},
            timeout_seconds=5,
            session=candidate_one,
        )
        candidate_one_response = send_request(
            url=f"{base_url}/needs-cookie",
            method="GET",
            headers={},
            timeout_seconds=5,
            session=candidate_one,
        )
        candidate_two_response = send_request(
            url=f"{base_url}/needs-cookie",
            method="GET",
            headers={},
            timeout_seconds=5,
            session=candidate_two,
        )

    assert candidate_one_response.status_code == 200
    assert candidate_two_response.status_code == 401
    assert candidate_one.cookies == {"sessionid": "abc123"}
    assert candidate_two.cookies == {}
    assert seen_cookie_headers == ["", "sessionid=abc123", ""]


def test_http_session_reuses_cookie_and_cached_token_for_csrf_flow() -> None:
    seen_requests: list[tuple[str, str, str]] = []

    class _CsrfHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            seen_requests.append((self.command, self.path, self.headers.get("Cookie", "")))
            if self.path == "/login":
                self.send_response(200)
                self.send_header("Set-Cookie", "sessionid=abc123; Path=/; HttpOnly")
                self.end_headers()
                self.wfile.write(b"logged-in")
                return
            if self.path == "/token":
                if "sessionid=abc123" not in self.headers.get("Cookie", ""):
                    self.send_response(401)
                    self.end_headers()
                    self.wfile.write(b"missing-cookie")
                    return
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("X-CSRF-Token", "token-123")
                self.end_headers()
                self.wfile.write(b'{"csrf_token":"token-123"}')
                return
            self.send_response(404)
            self.end_headers()

        def do_POST(self) -> None:  # noqa: N802
            content_length = int(self.headers.get("Content-Length", "0") or "0")
            body = self.rfile.read(content_length).decode("utf-8", errors="replace")
            seen_requests.append((self.command, f"{self.path}?{body}", self.headers.get("Cookie", "")))
            if self.path != "/action":
                self.send_response(404)
                self.end_headers()
                return
            form = parse_qs(body, keep_blank_values=True)
            if "sessionid=abc123" not in self.headers.get("Cookie", ""):
                self.send_response(401)
                self.end_headers()
                self.wfile.write(b"missing-cookie")
                return
            if form.get("csrf_token") != ["token-123"]:
                self.send_response(403)
                self.end_headers()
                self.wfile.write(b"missing-token")
                return
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"action-ok")

        def log_message(self, format: str, *args) -> None:  # pragma: no cover
            return

    session = HttpSession()
    with _serve(_CsrfHandler) as base_url:
        login = send_request(
            url=f"{base_url}/login",
            method="GET",
            headers={},
            timeout_seconds=5,
            session=session,
        )
        token = send_request(
            url=f"{base_url}/token",
            method="GET",
            headers={},
            timeout_seconds=5,
            session=session,
            token_extraction_rules={"csrf_token": "X-CSRF-Token"} # or we'll adjust the test handler to send header
        )
        action = send_request(
            url=f"{base_url}/action",
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout_seconds=5,
            body={"csrf_token": "{{token:csrf_token}}", "action": "apply"},
            session=session,
        )

    assert login.status_code == 200
    assert token.status_code == 200
    assert action.status_code == 200
    assert session.cookies == {"sessionid": "abc123"}
    assert session.tokens == {"csrf_token": "token-123"}
    assert seen_requests == [
        ("GET", "/login", ""),
        ("GET", "/token", "sessionid=abc123"),
        ("POST", "/action?csrf_token=token-123&action=apply", "sessionid=abc123"),
    ]

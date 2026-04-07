from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread
from typing import Any

import pytest

from padv.models import AuthBoundaryContract
from padv.discovery.auth import discover_auth_contract, AuthDiscoveryError

class MockAppHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/login":
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(b"login page")
            return
            
        cookie = self.headers.get("Cookie", "")
        if "session=" in cookie:
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(b"welcome admin")
        else:
            self.send_response(302)
            self.send_header("Location", "/login")
            self.end_headers()
            
    def do_POST(self):
        if self.path == "/login":
            self.send_response(302)
            self.send_header("Set-Cookie", "session=12345; HttpOnly")
            self.send_header("Location", "/dashboard")
            self.end_headers()
        else:
            self.send_response(403)
            self.end_headers()

@pytest.fixture(scope="module")
def mock_server():
    server = HTTPServer(("localhost", 0), MockAppHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://localhost:{server.server_port}"
    server.shutdown()

def test_auth_discovery_infers_contract(mock_server):
    # Probes the app with correct config/auth params and outputs contract
    # Mock LLM or just run probes directly
    class MockLLM:
        def invoke(self, messages, **kwargs):
            class FakeResp:
                content = json.dumps({
                    "unauth_status_codes": [302],
                    "unauth_redirect_patterns": ["/login"],
                    "expected_session_cookies": ["session"],
                    "csrf_token_name": None
                })
            return FakeResp()
            
    # Mock runtime probe returning the actual requests
    contract = discover_auth_contract(
        llm=MockLLM(),
        base_url=mock_server,
        login_url=f"{mock_server}/login",
        username="admin",
        password="password"
    )
    
    assert contract.unauth_status_codes == [302]
    assert "/login" in contract.unauth_redirect_patterns
    assert "session" in contract.expected_session_cookies

def test_auth_discovery_fails_closed(mock_server):
    class BadLLM:
        def invoke(self, messages, **kwargs):
            class FakeResp:
                content = "I could not figure it out"
            return FakeResp()
            
    with pytest.raises(AuthDiscoveryError, match="NEEDS_HUMAN_SETUP"):
        discover_auth_contract(
            llm=BadLLM(),
            base_url=mock_server,
            login_url=f"{mock_server}/login",
            username="admin",
            password="password"
        )
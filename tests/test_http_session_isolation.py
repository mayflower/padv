from __future__ import annotations

import pytest
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread

from padv.dynamic.http.runner import HttpSession, send_request

class MockSessionHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/set-cookie":
            self.send_response(200)
            self.send_header("Set-Cookie", "session=123")
            self.end_headers()
            self.wfile.write(b"ok")
        elif self.path == "/check-cookie":
            cookie = self.headers.get("Cookie", "")
            self.send_response(200)
            self.send_header("X-Echo-Cookie", cookie)
            self.end_headers()
            self.wfile.write(b"ok")
        elif self.path == "/set-token":
            self.send_response(200)
            self.send_header("X-CSRF-Token", "token123")
            self.end_headers()
            self.wfile.write(b"ok")
        elif self.path == "/check-token":
            token = self.headers.get("X-CSRF-Token", "")
            self.send_response(200)
            self.send_header("X-Echo-Token", token)
            self.end_headers()
            self.wfile.write(b"ok")
        else:
            self.send_response(404)
            self.end_headers()

@pytest.fixture(scope="module")
def mock_server():
    server = HTTPServer(("localhost", 0), MockSessionHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://localhost:{server.server_port}"
    server.shutdown()

def test_local_server_cookie_learning(mock_server):
    session = HttpSession()
    # Request 1 sets cookie
    resp1 = send_request(f"{mock_server}/set-cookie", "GET", {}, 5, session=session)
    assert resp1.status_code == 200
    assert session.cookies.get("session") == "123"
    
    # Request 2 should send it
    resp2 = send_request(f"{mock_server}/check-cookie", "GET", {}, 5, session=session)
    assert resp2.headers.get("X-Echo-Cookie") == "session=123"

def test_per_candidate_isolation(mock_server):
    session_a = HttpSession()
    session_b = HttpSession()
    
    # Session A gets cookie
    send_request(f"{mock_server}/set-cookie", "GET", {}, 5, session=session_a)
    assert session_a.cookies.get("session") == "123"
    assert "session" not in session_b.cookies
    
    # Session B checks cookie - shouldn't have it
    resp_b = send_request(f"{mock_server}/check-cookie", "GET", {}, 5, session=session_b)
    assert resp_b.headers.get("X-Echo-Cookie", "") == ""

def test_token_flow_with_structured_extraction(mock_server):
    session = HttpSession()
    # Learn token using extraction rules instead of body scanning
    send_request(
        f"{mock_server}/set-token", 
        "GET", {}, 5, 
        session=session, 
        token_extraction_rules={"csrf": "X-CSRF-Token"}
    )
    assert session.tokens.get("csrf") == "token123"
    
    # Use token via template placeholder
    resp = send_request(
        f"{mock_server}/check-token", 
        "GET", 
        {"X-CSRF-Token": "{{token:csrf}}"}, 
        5, 
        session=session
    )
    assert resp.headers.get("X-Echo-Token") == "token123"
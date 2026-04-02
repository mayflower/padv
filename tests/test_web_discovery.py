from __future__ import annotations

from pathlib import Path
import asyncio

import pytest

from padv.config.schema import load_config
from padv.discovery.web import _install_dialog_guards, _safe_dismiss_dialog, discover_web_hints, discover_web_inventory


def test_web_discovery_http_extract(monkeypatch: pytest.MonkeyPatch) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    config.target.base_url = "http://127.0.0.1:18080/index.php"

    async def _ok(*args, **kwargs):
        return {"/index.php": ["padv_canary"], "/admin": ["id"]}

    monkeypatch.setattr("padv.discovery.web._discover_with_playwright_async", _ok)

    hints, error = discover_web_hints(config)
    assert error is None
    assert "/admin" in hints
    assert "id" in hints["/admin"]


def test_web_discovery_playwright_failure_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")

    async def _fail(*args, **kwargs):
        raise RuntimeError("browser failed")

    monkeypatch.setattr("padv.discovery.web._discover_with_playwright_async", _fail)

    with pytest.raises(RuntimeError, match="playwright_discovery_error:browser failed"):
        discover_web_hints(config)


def test_web_discovery_inventory_exposes_pages_and_requests(monkeypatch: pytest.MonkeyPatch) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")

    async def _ok(*args, **kwargs):
        return {
            "hints": {"/index.php": ["page"]},
            "artifacts": {
                "seed_urls": [config.target.base_url],
                "visited_urls": [config.target.base_url],
                "pages": [{"url": config.target.base_url, "path": "/index.php", "forms": [{"method": "post", "inputs": [{"name": "username"}]}]}],
                "requests": [{"url": config.target.base_url, "path": "/index.php", "method": "GET", "params": []}],
                "errors": [],
            },
        }

    monkeypatch.setattr("padv.discovery.web._discover_with_playwright_async", _ok)

    hints, artifacts, error = discover_web_inventory(config)
    assert error is None
    assert hints["/index.php"] == ["page"]
    assert artifacts["pages"][0]["forms"][0]["inputs"][0]["name"] == "username"
    assert artifacts["requests"][0]["method"] == "GET"


def test_web_discovery_inventory_forwards_auth_state(monkeypatch: pytest.MonkeyPatch) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    seen: dict[str, object] = {}

    async def _ok(_config, seed_urls=None, auth_state=None):
        seen["seed_urls"] = list(seed_urls or [])
        seen["auth_state"] = dict(auth_state or {})
        return {
            "hints": {"/account": ["id"]},
            "artifacts": {
                "seed_urls": list(seed_urls or []),
                "visited_urls": [config.target.base_url],
                "pages": [{"url": config.target.base_url, "path": "/account"}],
                "requests": [],
                "errors": [],
            },
        }

    monkeypatch.setattr("padv.discovery.web._discover_with_playwright_async", _ok)

    hints, artifacts, error = discover_web_inventory(
        config,
        seed_urls=["http://127.0.0.1:8080/index.php"],
        auth_state={"cookies": {"PHPSESSID": "abc"}},
    )
    assert error is None
    assert hints["/account"] == ["id"]
    assert seen["seed_urls"] == ["http://127.0.0.1:8080/index.php"]
    assert seen["auth_state"] == {"cookies": {"PHPSESSID": "abc"}}
    assert artifacts["pages"][0]["path"] == "/account"


def test_safe_dismiss_dialog_swallows_page_lifecycle_errors() -> None:
    class _Dialog:
        async def dismiss(self) -> None:
            raise RuntimeError("Not attached to an active page")

    asyncio.run(_safe_dismiss_dialog(_Dialog()))


def test_install_dialog_guards_wires_page_and_future_pages() -> None:
    seen: list[str] = []

    class _Page:
        def __init__(self, label: str) -> None:
            self.label = label
            self.handlers: dict[str, object] = {}

        def on(self, event: str, handler: object) -> None:
            self.handlers[event] = handler
            seen.append(f"{self.label}:{event}")

    class _Context:
        def __init__(self) -> None:
            self.handlers: dict[str, object] = {}

        def on(self, event: str, handler: object) -> None:
            self.handlers[event] = handler

    context = _Context()
    page = _Page("root")
    _install_dialog_guards(context, page)

    assert "dialog" in page.handlers
    assert "page" in context.handlers

    popup = _Page("popup")
    page_handler = context.handlers["page"]
    assert callable(page_handler)
    page_handler(popup)
    assert "dialog" in popup.handlers
    assert seen == ["root:dialog", "popup:dialog"]

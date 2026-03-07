from __future__ import annotations

from pathlib import Path

import pytest

from padv.config.schema import load_config
from padv.discovery.web import discover_web_hints


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

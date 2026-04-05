from __future__ import annotations

from io import BytesIO
from urllib.error import HTTPError

import pytest

from padv.dynamic.http.runner import RequestError, send_request


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

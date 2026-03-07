from __future__ import annotations

import json
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any


class RequestError(RuntimeError):
    pass


@dataclass(slots=True)
class HttpResponse:
    status_code: int
    headers: dict[str, str]
    body: str


def _encode_body(body: dict[str, Any] | None) -> bytes | None:
    if body is None:
        return None
    return json.dumps(body, ensure_ascii=True).encode("utf-8")


def send_request(
    url: str,
    method: str,
    headers: dict[str, str],
    timeout_seconds: int,
    query: dict[str, str] | None = None,
    body: dict[str, Any] | None = None,
    cookie_jar: dict[str, str] | None = None,
) -> HttpResponse:
    full_url = url
    if query:
        parsed = urllib.parse.urlsplit(url)
        existing = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        for key, value in query.items():
            existing[key] = [value]
        new_query = urllib.parse.urlencode(existing, doseq=True)
        full_url = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, new_query, parsed.fragment))

    data = _encode_body(body)
    req = urllib.request.Request(full_url, method=method.upper(), data=data)
    for key, value in headers.items():
        req.add_header(key, value)
    if cookie_jar:
        cookie_value = "; ".join(
            f"{str(k).strip()}={str(v)}"
            for k, v in cookie_jar.items()
            if str(k).strip()
        )
        if cookie_value:
            req.add_header("Cookie", cookie_value)
    if data is not None:
        req.add_header("Content-Type", "application/json")

    try:
        with urllib.request.urlopen(req, timeout=timeout_seconds) as resp:
            body_text = resp.read().decode("utf-8", errors="replace")
            return HttpResponse(
                status_code=getattr(resp, "status", 200),
                headers={k: v for k, v in resp.headers.items()},
                body=body_text,
            )
    except Exception as exc:  # pragma: no cover
        raise RequestError(f"request_failed:{exc}") from exc

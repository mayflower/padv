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


def _encode_body(body: Any, content_type: str | None) -> bytes | None:
    if body is None:
        return None
    if isinstance(body, bytes):
        return body
    if isinstance(body, str):
        return body.encode("utf-8")
    if isinstance(body, dict):
        normalized_content_type = (content_type or "").casefold()
        if "application/x-www-form-urlencoded" in normalized_content_type:
            return urllib.parse.urlencode(
                {str(k): str(v) for k, v in body.items()},
                doseq=True,
            ).encode("utf-8")
        return json.dumps(body, ensure_ascii=True).encode("utf-8")
    return json.dumps(body, ensure_ascii=True).encode("utf-8")


def send_request(
    url: str,
    method: str,
    headers: dict[str, str],
    timeout_seconds: int,
    query: dict[str, str] | None = None,
    body: Any = None,
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

    content_type = next((v for k, v in headers.items() if k.casefold() == "content-type"), None)
    data = _encode_body(body, content_type)
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
    if data is not None and content_type is None:
        req.add_header("Content-Type", "application/json")

    try:
        with urllib.request.urlopen(req, timeout=timeout_seconds) as resp:
            body_text = resp.read().decode("utf-8", errors="replace")
            return HttpResponse(
                status_code=getattr(resp, "status", 200),
                headers=dict(resp.headers.items()),
                body=body_text,
            )
    except Exception as exc:  # pragma: no cover
        raise RequestError(f"request_failed:{exc}") from exc

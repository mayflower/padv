from __future__ import annotations

import http.cookies
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any


class RequestError(RuntimeError):
    pass


@dataclass(slots=True)
class HttpResponse:
    status_code: int
    headers: dict[str, str]
    body: str


_TOKEN_PLACEHOLDER_RE = re.compile(r"\{\{token:([A-Za-z0-9_.-]+)\}\}")


def _normalize_cookie_jar(cookie_jar: dict[str, str] | None) -> dict[str, str]:
    if not isinstance(cookie_jar, dict):
        return {}
    return {
        str(key).strip(): str(value)
        for key, value in cookie_jar.items()
        if str(key).strip()
    }


def _normalize_token_cache(tokens: dict[str, str] | None) -> dict[str, str]:
    if not isinstance(tokens, dict):
        return {}
    return {
        str(key).strip(): str(value)
        for key, value in tokens.items()
        if str(key).strip()
    }


def _iter_set_cookie_headers(headers: Any) -> list[str]:
    if headers is None:
        return []
    get_all = getattr(headers, "get_all", None)
    if callable(get_all):
        values = get_all("Set-Cookie")
        if values:
            return [str(value) for value in values if str(value).strip()]
    if isinstance(headers, dict):
        for key, value in headers.items():
            if str(key).casefold() != "set-cookie":
                continue
            if isinstance(value, (list, tuple)):
                return [str(item) for item in value if str(item).strip()]
            if str(value).strip():
                return [str(value)]
    return []


def _parse_set_cookie(header_value: str) -> dict[str, str]:
    parsed = http.cookies.SimpleCookie()
    try:
        parsed.load(header_value)
    except http.cookies.CookieError:
        parsed = http.cookies.SimpleCookie()
    cookies = {
        morsel.key.strip(): morsel.value
        for morsel in parsed.values()
        if morsel.key.strip()
    }
    if cookies:
        return cookies
    first_segment = str(header_value).split(";", 1)[0]
    if "=" not in first_segment:
        return {}
    key, value = first_segment.split("=", 1)
    key = key.strip()
    if not key:
        return {}
    return {key: value.strip()}


@dataclass(slots=True)
class HttpSession:
    cookies: dict[str, str] = field(default_factory=dict)
    tokens: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.cookies = _normalize_cookie_jar(self.cookies)
        self.tokens = _normalize_token_cache(self.tokens)

    @classmethod
    def from_cookie_jar(cls, cookie_jar: dict[str, str] | None) -> HttpSession:
        return cls(cookies=_normalize_cookie_jar(cookie_jar))

    def request_cookies(self, cookie_jar: dict[str, str] | None = None) -> dict[str, str]:
        merged = dict(self.cookies)
        merged.update(_normalize_cookie_jar(cookie_jar))
        return merged

    def learn_from_headers(self, headers: Any) -> None:
        for header_value in _iter_set_cookie_headers(headers):
            self.cookies.update(_parse_set_cookie(header_value))

    def _resolve_string(self, value: str) -> str:
        def replace(match: re.Match[str]) -> str:
            key = str(match.group(1)).strip()
            return self.tokens.get(key, match.group(0))

        return _TOKEN_PLACEHOLDER_RE.sub(replace, value)

    def resolve_value(self, value: Any) -> Any:
        if isinstance(value, str):
            return self._resolve_string(value)
        if isinstance(value, dict):
            return {
                str(key): self.resolve_value(item)
                for key, item in value.items()
            }
        if isinstance(value, list):
            return [self.resolve_value(item) for item in value]
        if isinstance(value, tuple):
            return [self.resolve_value(item) for item in value]
        return value

    def _learn_json_tokens(self, body: str) -> None:
        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            return
        if not isinstance(payload, dict):
            return
        for key, value in payload.items():
            normalized_key = str(key).strip()
            if not normalized_key or isinstance(value, (dict, list, tuple)):
                continue
            self.tokens[normalized_key] = str(value)

    def learn_from_response(self, headers: Any, body: str) -> None:
        self.learn_from_headers(headers)
        self._learn_json_tokens(body)


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
    session: HttpSession | None = None,
) -> HttpResponse:
    full_url = url
    resolved_headers = (
        session.resolve_value(headers) if session is not None else dict(headers)
    )
    resolved_query = session.resolve_value(query) if session is not None else query
    resolved_body = session.resolve_value(body) if session is not None else body
    resolved_cookie_jar = session.resolve_value(cookie_jar) if session is not None else cookie_jar
    if query:
        parsed = urllib.parse.urlsplit(url)
        existing = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        for key, value in (resolved_query or {}).items():
            existing[key] = [value]
        new_query = urllib.parse.urlencode(existing, doseq=True)
        full_url = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, new_query, parsed.fragment))

    content_type = next((v for k, v in resolved_headers.items() if k.casefold() == "content-type"), None)
    data = _encode_body(resolved_body, content_type)
    req = urllib.request.Request(full_url, method=method.upper(), data=data)
    for key, value in resolved_headers.items():
        req.add_header(key, value)
    request_cookies = (
        session.request_cookies(resolved_cookie_jar)
        if session is not None
        else _normalize_cookie_jar(resolved_cookie_jar)
    )
    if request_cookies:
        cookie_value = "; ".join(
            f"{str(k).strip()}={str(v)}"
            for k, v in request_cookies.items()
            if str(k).strip()
        )
        if cookie_value:
            req.add_header("Cookie", cookie_value)
    if data is not None and content_type is None:
        req.add_header("Content-Type", "application/json")

    try:
        with urllib.request.urlopen(req, timeout=timeout_seconds) as resp:
            body_text = resp.read().decode("utf-8", errors="replace")
            if session is not None:
                session.learn_from_response(resp.headers, body_text)
            return HttpResponse(
                status_code=getattr(resp, "status", 200),
                headers=dict(resp.headers.items()),
                body=body_text,
            )
    except urllib.error.HTTPError as exc:
        body_text = exc.read().decode("utf-8", errors="replace")
        if session is not None:
            session.learn_from_response(exc.headers, body_text)
        return HttpResponse(
            status_code=int(exc.code),
            headers=dict(exc.headers.items()),
            body=body_text,
        )
    except Exception as exc:  # pragma: no cover
        raise RequestError(f"request_failed:{exc}") from exc

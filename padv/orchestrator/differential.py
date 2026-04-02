from __future__ import annotations

from copy import deepcopy
from typing import Any

from padv.config.schema import PadvConfig
from padv.models import DifferentialPair, RuntimeEvidence


AUTHZ_VULN_CLASSES = frozenset(
    {
        "broken_access_control",
        "idor_invariant_missing",
        "auth_and_session_failures",
    }
)

_AUTH_COOKIE_HINTS = ("auth", "token", "sess", "php")


def needs_differential(vuln_class: str) -> bool:
    return vuln_class.strip().casefold() in AUTHZ_VULN_CLASSES


def resolve_auth_state_for_level(auth_state: dict[str, Any] | None, level: str) -> dict[str, Any] | None:
    normalized_level = level.strip().casefold()
    if not normalized_level:
        return None

    if normalized_level in {"anonymous", "anon", "none"}:
        return {"auth_context": "anonymous", "cookies": {}, "headers": {}}

    if not isinstance(auth_state, dict):
        return None

    # Preferred source for multi-level auth contexts.
    levels = auth_state.get("auth_levels")
    if isinstance(levels, dict):
        for key in (normalized_level, level):
            value = levels.get(key)
            if isinstance(value, dict):
                merged = dict(auth_state)
                merged["lower_privilege"] = value
                merged["auth_context"] = normalized_level
                return merged

    # Fallback: allow direct level keys in auth_state.
    for key in (normalized_level, level):
        value = auth_state.get(key)
        if isinstance(value, dict):
            merged = dict(auth_state)
            merged["lower_privilege"] = value
            merged["auth_context"] = normalized_level
            return merged

    return None


def _auth_cookie_names(auth_state: dict[str, Any] | None) -> set[str]:
    names: set[str] = {"phpsessid", "session", "sessionid", "auth", "token"}
    if not isinstance(auth_state, dict):
        return names
    cookies = auth_state.get("cookies")
    if isinstance(cookies, dict):
        names.update(str(k).strip().casefold() for k in cookies.keys() if str(k).strip())
    return names


def _extract_lower_privilege(auth_state: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(auth_state, dict):
        return {}

    for key in ("lower_privilege", "unprivileged", "anonymous"):
        value = auth_state.get(key)
        if isinstance(value, dict):
            return value

    levels = auth_state.get("auth_levels")
    if isinstance(levels, dict):
        for preferred in ("anonymous", "user", "unprivileged"):
            value = levels.get(preferred)
            if isinstance(value, dict):
                return value
        for value in levels.values():
            if isinstance(value, dict):
                return value
    return {}


def _strip_auth_headers(request: dict[str, Any]) -> None:
    headers = request.get("headers")
    if not isinstance(headers, dict):
        return
    request["headers"] = {
        str(key): value
        for key, value in headers.items()
        if str(key).casefold() != "authorization"
    }


def _strip_auth_cookies(request: dict[str, Any], auth_state: dict[str, Any] | None) -> None:
    cookies = request.get("cookies")
    if not isinstance(cookies, dict):
        return
    cookie_names = _auth_cookie_names(auth_state)
    stripped: dict[str, Any] = {}
    for key, value in cookies.items():
        norm = str(key).casefold()
        if norm in cookie_names:
            continue
        if any(hint in norm for hint in _AUTH_COOKIE_HINTS):
            continue
        stripped[str(key)] = value
    request["cookies"] = stripped


def _apply_lower_privilege(request: dict[str, Any], auth_state: dict[str, Any] | None) -> None:
    lower_priv = _extract_lower_privilege(auth_state)
    if not lower_priv:
        return

    lower_headers = lower_priv.get("headers")
    if isinstance(lower_headers, dict):
        current = request.get("headers")
        merged = dict(current) if isinstance(current, dict) else {}
        merged.update({str(k): v for k, v in lower_headers.items()})
        request["headers"] = merged

    lower_cookies = lower_priv.get("cookies")
    if isinstance(lower_cookies, dict):
        current = request.get("cookies")
        merged = dict(current) if isinstance(current, dict) else {}
        merged.update({str(k): v for k, v in lower_cookies.items()})
        request["cookies"] = merged


def build_unprivileged_request(
    privileged_request: dict[str, Any],
    auth_state: dict[str, Any] | None,
) -> dict[str, Any]:
    request = deepcopy(privileged_request)
    _strip_auth_headers(request)
    _strip_auth_cookies(request, auth_state)
    _apply_lower_privilege(request, auth_state)
    return request


def _determine_auth_diff(priv: RuntimeEvidence, unpriv: RuntimeEvidence) -> str:
    priv_ctx = str(priv.aux.get("auth_context", "authenticated")).strip().casefold()
    unpriv_ctx = str(unpriv.aux.get("auth_context", "anonymous")).strip().casefold()
    if not priv_ctx:
        priv_ctx = "authenticated"
    if not unpriv_ctx:
        unpriv_ctx = "anonymous"
    return f"{priv_ctx}_vs_{unpriv_ctx}"


def compare_responses(
    privileged: RuntimeEvidence,
    unprivileged: RuntimeEvidence,
    config: PadvConfig,
) -> DifferentialPair:
    signals: list[str] = []

    if privileged.http_status == unprivileged.http_status:
        signals.append("same_http_status")

    if privileged.call_count == unprivileged.call_count:
        signals.append("same_morcilla_calls")

    priv_len = len(privileged.body_excerpt or "")
    unpriv_len = len(unprivileged.body_excerpt or "")
    if priv_len == 0 and unpriv_len == 0:
        signals.append("same_body_length")
    elif priv_len > 0:
        tolerance = config.differential.body_length_tolerance
        ratio = abs(priv_len - unpriv_len) / float(priv_len)
        if ratio <= tolerance:
            signals.append("same_body_length")

    return DifferentialPair(
        privileged_run=privileged,
        unprivileged_run=unprivileged,
        auth_diff=_determine_auth_diff(privileged, unprivileged),
        response_equivalent=len(signals) >= 3,
        equivalence_signals=signals,
    )

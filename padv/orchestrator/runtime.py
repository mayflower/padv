from __future__ import annotations

import html
import urllib.parse
import uuid
from time import monotonic
from typing import Any

from padv.config.schema import PadvConfig
from padv.dynamic.http.runner import RequestError, send_request
from padv.dynamic.sandbox import adapter as sandbox_adapter
from padv.gates.engine import evaluate_candidate
from padv.models import Candidate, DifferentialPair, EvidenceBundle, RuntimeEvidence, StaticEvidence, ValidationPlan, utc_now_iso
from padv.oracle.morcilla import parse_response_headers, sanitized_runtime_evidence
from padv.orchestrator.differential import (
    build_unprivileged_request,
    compare_responses,
    needs_differential,
    resolve_auth_state_for_level,
)
from padv.store.evidence_store import EvidenceStore


_HTTP_SIGNAL_CLASSES = {
    "xss_output_boundary",
    "debug_output_leak",
    "information_disclosure",
    "broken_access_control",
    "csrf_invariant_missing",
    "idor_invariant_missing",
    "session_fixation_invariant",
    "auth_and_session_failures",
}

_AUTHZ_PROBE_CLASSES = {
    "broken_access_control",
    "csrf_invariant_missing",
    "idor_invariant_missing",
    "auth_and_session_failures",
}

_ERROR_MARKERS = ("warning:", "notice:", "fatal error", "stack trace", "uncaught exception")
_LOGIN_MARKERS = ("login", "sign in", "signin", "anmelden", "auth", "passwort", "password")


def new_run_id(prefix: str = "run") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


def new_request_id(candidate_id: str, phase: str, idx: int) -> str:
    return f"{candidate_id}-{phase}-{idx:02d}-{uuid.uuid4().hex[:6]}"


def _validation_headers(config: PadvConfig, intercepts: list[str], correlation: str) -> dict[str, str]:
    return {
        config.oracle.request_key_header: config.oracle.api_key,
        config.oracle.request_intercept_header: ", ".join(intercepts),
        config.oracle.request_correlation_header: correlation,
    }


def _target_url(base_url: str, request_spec: dict[str, Any]) -> str:
    path = request_spec.get("path")
    if not isinstance(path, str) or not path.strip():
        return base_url
    parsed = urllib.parse.urlsplit(base_url)
    merged_path = path if path.startswith("/") else f"/{path}"
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, merged_path, parsed.query, parsed.fragment))


def _status_ok(status_code: int) -> bool:
    return 200 <= status_code < 400


def _request_has_token(request_spec: dict[str, Any]) -> bool:
    keys: list[str] = []
    for key in ("query", "body"):
        value = request_spec.get(key)
        if isinstance(value, dict):
            keys.extend(str(k).casefold() for k in value.keys())
    return any(("csrf" in key) or ("token" in key) or ("xsrf" in key) for key in keys)


def _request_has_id(request_spec: dict[str, Any]) -> bool:
    query = request_spec.get("query")
    if not isinstance(query, dict):
        return False
    for key in query.keys():
        norm = str(key).strip().casefold()
        if norm == "id" or norm.endswith("_id") or norm.endswith("id"):
            return True
    return False


def _extract_set_cookie(headers: dict[str, str]) -> str:
    for key, value in headers.items():
        if key.casefold() == "set-cookie":
            return value
    return ""


def _looks_like_login(response: Any) -> bool:
    location = str(response.headers.get("Location", "") or response.headers.get("location", "")).casefold()
    body = (response.body or "").casefold()
    if "login" in location or "signin" in location or "auth" in location:
        return True
    return any(marker in body for marker in _LOGIN_MARKERS)


def _annotate_runtime_evidence(
    runtime: RuntimeEvidence,
    response: Any,
    candidate: Candidate,
    plan: ValidationPlan,
    request_spec: dict[str, Any],
    cookie_jar: dict[str, str],
    anonymous_probe: Any | None = None,
) -> RuntimeEvidence:
    runtime.http_status = int(response.status_code)
    runtime.location = str(response.headers.get("Location", "") or response.headers.get("location", ""))
    runtime.body_excerpt = (response.body or "")[:2000]

    flags = {x for x in runtime.analysis_flags if isinstance(x, str) and x}
    body = response.body or ""
    body_lower = body.casefold()
    canary = plan.canary
    escaped = html.escape(canary, quote=True)

    has_raw_canary = canary in body
    has_escaped_canary = escaped in body if escaped != canary else False

    if has_raw_canary:
        flags.add("body_canary")
    if has_raw_canary and not has_escaped_canary:
        flags.add("xss_raw_canary")

    if ("phpinfo()" in body_lower) or ("<title>phpinfo()" in body_lower) or ("php version" in body_lower):
        flags.add("phpinfo_marker")

    if any(marker in body_lower for marker in _ERROR_MARKERS):
        if has_raw_canary:
            flags.add("verbose_error_leak")
        flags.add("debug_leak")

    header_keys = {k.casefold() for k in response.headers.keys()}
    if "x-powered-by" in header_keys or "server" in header_keys:
        flags.add("info_disclosure_header")

    if candidate.vuln_class in _AUTHZ_PROBE_CLASSES and anonymous_probe is not None:
        flags.add("authz_pair_observed")
        auth_login_like = _looks_like_login(response)
        anon_login_like = _looks_like_login(anonymous_probe)
        if (
            _status_ok(int(response.status_code))
            and _status_ok(int(anonymous_probe.status_code))
            and not auth_login_like
            and not anon_login_like
        ):
            flags.add("authz_bypass_status")
        if candidate.vuln_class == "auth_and_session_failures" and _status_ok(int(anonymous_probe.status_code)):
            if not anon_login_like:
                flags.add("auth_bypass")
        if candidate.vuln_class == "idor_invariant_missing":
            if _request_has_id(request_spec) and _status_ok(int(response.status_code)) and _status_ok(int(anonymous_probe.status_code)):
                if (response.body or "") != (anonymous_probe.body or ""):
                    flags.add("idor_bypass")
        if candidate.vuln_class == "csrf_invariant_missing":
            method = str(request_spec.get("method", "GET")).upper()
            if method in {"POST", "PUT", "PATCH", "DELETE"} and not _request_has_token(request_spec):
                if _status_ok(int(response.status_code)):
                    flags.add("csrf_missing_token_acceptance")

    if candidate.vuln_class == "session_fixation_invariant":
        set_cookie = _extract_set_cookie(response.headers)
        if cookie_jar and set_cookie:
            for key, value in cookie_jar.items():
                key_norm = str(key).casefold()
                if "sess" not in key_norm and "php" not in key_norm:
                    continue
                if f"{key}={value}" in set_cookie:
                    flags.add("session_id_not_rotated")
        elif cookie_jar and not set_cookie:
            flags.add("session_cookie_not_rotated")

    runtime.analysis_flags = sorted(flags)
    runtime.aux = dict(runtime.aux)
    if anonymous_probe is not None:
        runtime.aux["anonymous_status"] = int(anonymous_probe.status_code)
        runtime.aux["anonymous_body_excerpt"] = (anonymous_probe.body or "")[:500]

    if candidate.vuln_class in _HTTP_SIGNAL_CLASSES and runtime.status in {"inactive", "missing_intercept"}:
        runtime.status = "http_observed"
    return runtime


def validate_candidates_runtime(
    config: PadvConfig,
    store: EvidenceStore,
    static_evidence: list[StaticEvidence],
    candidates: list[Candidate],
    run_id: str,
    plans_by_candidate: dict[str, ValidationPlan] | None = None,
    planner_trace: dict[str, Any] | None = None,
    discovery_trace: dict[str, Any] | None = None,
    artifact_refs: list[str] | None = None,
    auth_state: dict[str, Any] | None = None,
) -> tuple[list[EvidenceBundle], dict[str, int]]:
    plans_by_candidate = plans_by_candidate or {}
    planner_trace = planner_trace or {}
    discovery_trace = discovery_trace or {}
    artifact_refs = artifact_refs or []
    auth_state = auth_state or {}
    cookie_jar_raw = auth_state.get("cookies", {}) if isinstance(auth_state, dict) else {}
    cookie_jar = (
        {str(k): str(v) for k, v in cookie_jar_raw.items() if str(k).strip()}
        if isinstance(cookie_jar_raw, dict)
        else {}
    )

    static_by_candidate: dict[str, list[StaticEvidence]] = {}
    for item in static_evidence:
        static_by_candidate.setdefault(item.candidate_id, []).append(item)

    decisions: dict[str, int] = {"VALIDATED": 0, "DROPPED": 0, "NEEDS_HUMAN_SETUP": 0}
    bundles: list[EvidenceBundle] = []
    request_budget_remaining = config.budgets.max_requests
    run_deadline = monotonic() + float(config.budgets.max_run_seconds)

    if config.sandbox.reset_cmd:
        sandbox_adapter.reset(config.sandbox)

    for candidate in candidates:
        if monotonic() >= run_deadline:
            break

        plan = plans_by_candidate.get(candidate.candidate_id)
        if plan is None:
            raise RuntimeError(f"missing agent-generated validation plan for candidate: {candidate.candidate_id}")
        positive_runs = []
        negative_runs = []
        differential_pairs: list[DifferentialPair] = []
        repro_ids: list[str] = []
        candidate_deadline = min(
            run_deadline,
            monotonic() + float(config.budgets.max_seconds_per_candidate),
        )

        for idx, request in enumerate(plan.positive_requests[:3]):
            if request_budget_remaining <= 0:
                break
            if monotonic() >= candidate_deadline:
                break
            req_id = new_request_id(candidate.candidate_id, "pos", idx)
            headers = _validation_headers(config, plan.intercepts, req_id)
            try:
                response = send_request(
                    url=_target_url(config.target.base_url, request),
                    method=request.get("method", "GET"),
                    headers=headers,
                    timeout_seconds=config.target.request_timeout_seconds,
                    query=request.get("query"),
                    body=request.get("body"),
                    cookie_jar=cookie_jar,
                )
                runtime = parse_response_headers(req_id, response.headers, config.oracle)
                anonymous_probe = None
                if (
                    candidate.vuln_class in _AUTHZ_PROBE_CLASSES
                    and cookie_jar
                    and request_budget_remaining > 1
                    and monotonic() < candidate_deadline
                ):
                    try:
                        anonymous_probe = send_request(
                            url=_target_url(config.target.base_url, request),
                            method=request.get("method", "GET"),
                            headers={},
                            timeout_seconds=config.target.request_timeout_seconds,
                            query=request.get("query"),
                            body=request.get("body"),
                            cookie_jar={},
                        )
                        request_budget_remaining -= 1
                    except RequestError:
                        anonymous_probe = None
                runtime = _annotate_runtime_evidence(
                    runtime=runtime,
                    response=response,
                    candidate=candidate,
                    plan=plan,
                    request_spec=request,
                    cookie_jar=cookie_jar,
                    anonymous_probe=anonymous_probe,
                )
                runtime.aux = dict(runtime.aux)
                runtime.aux.setdefault("auth_context", "authenticated" if cookie_jar else "anonymous")
            except RequestError as exc:
                runtime = RuntimeEvidence(
                    request_id=req_id,
                    status="request_failed",
                    call_count=0,
                    overflow=False,
                    arg_truncated=False,
                    result_truncated=False,
                    correlation=None,
                    calls=[],
                    raw_headers={"error": str(exc)},
                    aux={"auth_context": "authenticated" if cookie_jar else "anonymous"},
                )
            positive_runs.append(runtime)
            repro_ids.append(req_id)
            request_budget_remaining -= 1
            if config.sandbox.reset_cmd:
                sandbox_adapter.reset(config.sandbox)

        for idx, request in enumerate(plan.negative_requests):
            if request_budget_remaining <= 0:
                break
            if monotonic() >= candidate_deadline:
                break
            req_id = new_request_id(candidate.candidate_id, "neg", idx)
            headers = _validation_headers(config, plan.intercepts, req_id)
            try:
                response = send_request(
                    url=_target_url(config.target.base_url, request),
                    method=request.get("method", "GET"),
                    headers=headers,
                    timeout_seconds=config.target.request_timeout_seconds,
                    query=request.get("query"),
                    body=request.get("body"),
                    cookie_jar=cookie_jar,
                )
                runtime = parse_response_headers(req_id, response.headers, config.oracle)
                runtime = _annotate_runtime_evidence(
                    runtime=runtime,
                    response=response,
                    candidate=candidate,
                    plan=plan,
                    request_spec=request,
                    cookie_jar=cookie_jar,
                    anonymous_probe=None,
                )
            except RequestError as exc:
                runtime = RuntimeEvidence(
                    request_id=req_id,
                    status="request_failed",
                    call_count=0,
                    overflow=False,
                    arg_truncated=False,
                    result_truncated=False,
                    correlation=None,
                    calls=[],
                    raw_headers={"error": str(exc)},
                )
            negative_runs.append(runtime)
            request_budget_remaining -= 1

        if (
            config.differential.enabled
            and needs_differential(candidate.vuln_class)
            and positive_runs
            and plan.positive_requests
        ):
            base_request = plan.positive_requests[0]
            levels = [x.strip() for x in config.differential.auth_levels if isinstance(x, str) and x.strip()]
            if not levels:
                levels = ["anonymous"]
            levels = list(dict.fromkeys(levels))
            for diff_idx, level in enumerate(levels):
                if request_budget_remaining <= 0 or monotonic() >= candidate_deadline:
                    break
                level_state = resolve_auth_state_for_level(auth_state, level)
                if level_state is None:
                    continue
                unpriv_request = build_unprivileged_request(base_request, level_state)
                req_id = new_request_id(candidate.candidate_id, "diff", diff_idx)
                headers = _validation_headers(config, plan.intercepts, req_id)
                override_headers = unpriv_request.get("headers")
                if isinstance(override_headers, dict):
                    for key, value in override_headers.items():
                        if str(key).strip() and value is not None:
                            headers[str(key)] = str(value)
                unpriv_cookie_jar: dict[str, str] = {}
                request_cookies = unpriv_request.get("cookies")
                if isinstance(request_cookies, dict):
                    unpriv_cookie_jar = {str(k): str(v) for k, v in request_cookies.items() if str(k).strip()}
                try:
                    response = send_request(
                        url=_target_url(config.target.base_url, unpriv_request),
                        method=unpriv_request.get("method", "GET"),
                        headers=headers,
                        timeout_seconds=config.target.request_timeout_seconds,
                        query=unpriv_request.get("query"),
                        body=unpriv_request.get("body"),
                        cookie_jar=unpriv_cookie_jar,
                    )
                    unpriv_runtime = parse_response_headers(req_id, response.headers, config.oracle)
                    unpriv_runtime = _annotate_runtime_evidence(
                        runtime=unpriv_runtime,
                        response=response,
                        candidate=candidate,
                        plan=plan,
                        request_spec=unpriv_request,
                        cookie_jar=unpriv_cookie_jar,
                        anonymous_probe=None,
                    )
                    unpriv_runtime.aux = dict(unpriv_runtime.aux)
                    context = str(level_state.get("auth_context", "")).strip().casefold()
                    if not context:
                        context = "anonymous" if not unpriv_cookie_jar else "unprivileged"
                    unpriv_runtime.aux["auth_context"] = context
                    differential_pairs.append(compare_responses(positive_runs[0], unpriv_runtime, config))
                except RequestError:
                    pass
                request_budget_remaining -= 1
                if config.sandbox.reset_cmd:
                    sandbox_adapter.reset(config.sandbox)

        candidate_static = static_by_candidate.get(candidate.candidate_id, [])
        query_signals = {
            item.query_id.split("::", 1)[0].strip().lower()
            for item in candidate_static
            if isinstance(item.query_id, str) and item.query_id.strip()
        }
        candidate_signals = {x.strip().lower() for x in candidate.provenance if isinstance(x, str) and x.strip()}
        if candidate.web_path_hints:
            candidate_signals.add("web")
        evidence_signals = sorted(query_signals | candidate_signals)

        gate_result = evaluate_candidate(
            config=config,
            static_evidence=candidate_static,
            positive_runs=positive_runs,
            negative_runs=negative_runs,
            intercepts=plan.intercepts,
            canary=plan.canary,
            preconditions=candidate.preconditions,
            evidence_signals=evidence_signals,
            vuln_class=candidate.vuln_class,
            differential_pairs=differential_pairs,
        )
        decisions[gate_result.decision] = decisions.get(gate_result.decision, 0) + 1

        limitations: list[str] = []
        if gate_result.decision != "VALIDATED":
            limitations.append(gate_result.reason)

        if config.store.store_raw_reports:
            positive_export = positive_runs
            negative_export = negative_runs
            differential_export = differential_pairs
        else:
            positive_export = [sanitized_runtime_evidence(r) for r in positive_runs]
            negative_export = [sanitized_runtime_evidence(r) for r in negative_runs]
            differential_export = [
                DifferentialPair(
                    privileged_run=sanitized_runtime_evidence(pair.privileged_run),
                    unprivileged_run=sanitized_runtime_evidence(pair.unprivileged_run),
                    auth_diff=pair.auth_diff,
                    response_equivalent=pair.response_equivalent,
                    equivalence_signals=list(pair.equivalence_signals),
                )
                for pair in differential_pairs
            ]

        bundle = EvidenceBundle(
            bundle_id=f"bundle-{run_id}-{candidate.candidate_id}",
            created_at=utc_now_iso(),
            candidate=candidate,
            static_evidence=candidate_static,
            positive_runtime=positive_export,
            negative_runtime=negative_export,
            repro_run_ids=repro_ids,
            gate_result=gate_result,
            limitations=limitations,
            differential_pairs=differential_export,
            artifact_refs=artifact_refs,
            discovery_trace=discovery_trace,
            planner_trace=planner_trace.get(candidate.candidate_id, {}),
        )
        store.save_bundle(bundle)
        bundles.append(bundle)

    return bundles, decisions

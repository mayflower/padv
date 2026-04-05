from __future__ import annotations

import html
import urllib.parse
import uuid
from time import monotonic
from typing import Any

from dataclasses import dataclass

from padv.config.schema import PadvConfig
from padv.dynamic.http.runner import RequestError, send_request
from padv.dynamic.sandbox import adapter as sandbox_adapter
from padv.gates.engine import evaluate_candidate
from padv.models import (
    Candidate,
    DifferentialPair,
    EnvironmentFacts,
    EvidenceBundle,
    GateResult,
    OracleEvidence,
    RequestEvidence,
    ResponseEvidence,
    RuntimeCall,
    RuntimeEvidence,
    StaticEvidence,
    ValidationPlan,
    WitnessEvidence,
    utc_now_iso,
)
from padv.oracle.morcilla import parse_response_headers, sanitized_runtime_evidence
from padv.orchestrator.differential import (
    build_unprivileged_request,
    compare_responses,
    needs_differential,
    resolve_auth_state_for_level,
)
from padv.orchestrator.evidence_linking import group_static_evidence_by_candidate
from padv.store.evidence_store import EvidenceStore
from padv.taxonomy import (
    CLASS_ORACLE_WITNESS_FLAGS,
    SQL_ERROR_MARKERS,
    canonicalize_vuln_class,
    contains_canary,
)
from padv.validation.contracts import apply_validation_profile, is_runtime_validatable, profile_for_vuln_class


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
_SQL_ERROR_MARKERS = SQL_ERROR_MARKERS
_NONBLOCKING_PRECONDITION_EXACT = {
    "runtime-oracle-not-applicable",
    "auth-state-known",
}
_NONBLOCKING_PRECONDITION_PREFIXES = (
    "content-type:",
    "http post request",
    "http get request",
    "soapaction:",
    "common payloads:",
    "for level 0:",
    "for level 1:",
    "stage 1 -",
    "stage 2 -",
    "stage 3 -",
    "optional:",
    "post to ",
    "get to ",
    "get/post to ",
    "response includes",
    "response must",
    "response should",
    "base query returns",
    "valid soap",
    "valid json",
    "shell metacharacters",
    "sql injection in ",
    "post request",
    "get request",
    "post or get request",
    "request with ",
    "request to ",
)
_NONBLOCKING_PRECONDITION_SUBSTRINGS = (
    "security_level",
    "security-level",
    "security level",
    "must be at security level",
    "default security level",
    "security level must be",
    "$lprotectagainst",
    "$lusesafejsonparser",
    "gusesafejsonparser",
    "public endpoint accessibility",
    "no session uid validation",
    "no authentication check",
    "no session validation",
    "mysql connection active",
    "database must be accessible",
    "error reporting must be enabled",
    "direct endpoint access via post or get",
    "post or get request with ",
    "none - unauthenticated access allowed",
    "none - endpoint accessible without authentication",
    "active php session",
    "session_start()",
    "php session must be initiated",
    "php session initialized",
    "valid php session",
    "php shell_exec() function must be enabled",
    "shell_exec() enabled",
    "shell_exec() function enabled",
    "no jwt token required",
    "no special permissions",
    "no username/password required",
    "server must accept post requests",
    "soapaction header",
    "soap request must be well-formed xml",
    "parameter in soap body",
    "parameter with payload",
    "json body with ",
    "multipart/form-data",
    "valid json format",
    "get or post request with ",
    "query must return ",
    "satisfying precondition",
    "for union-based:",
    "for boolean-blind:",
    "for error-based:",
    "for special uuid:",
    "for time-based:",
    "unix/linux system with /etc/passwd readable by web server",
    "apache/nginx serves .php files",
    "apache web server with allowoverride",
    "allowoverride all",
    "allowoverride fileinfo",
    "mod_mime enabled in apache",
    "syntax varies for other databases",
    "mysql database backend",
    "response returned as json",
    "must not equal special uuid",
    "matching 5 columns",
    "webroot path known",
    "write permissions to webroot",
    "writable by www-data",
    "uid cookie",
    "upload_directory hidden field",
    "extract permanent file path",
    "uploaded_file_path",
    "query string (?cmd=",
    "file_exists() check",
    "require_once() executes php code",
)
_AUTH_PRECONDITION_HINTS = (
    "login",
    "logged in",
    "authenticated",
    "session required",
    "admin session",
    "admin role",
    "privileged",
)

_CLASS_ORACLE_WITNESS_FLAGS = CLASS_ORACLE_WITNESS_FLAGS


def new_run_id(prefix: str = "run") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


def new_request_id(candidate_id: str, phase: str, idx: int) -> str:
    return f"{candidate_id}-{phase}-{idx:02d}-{uuid.uuid4().hex[:6]}"


def _validation_headers(config: PadvConfig, oracle_functions: list[str], correlation: str) -> dict[str, str]:
    return {
        config.oracle.request_key_header: config.oracle.api_key,
        config.oracle.request_intercept_header: ", ".join(oracle_functions),
        config.oracle.request_correlation_header: correlation,
    }


def _oracle_functions(plan: ValidationPlan) -> list[str]:
    values = plan.oracle_functions or plan.intercepts
    return [str(x).strip() for x in values if str(x).strip()]


def _request_transport(request_spec: dict[str, Any]) -> str:
    headers = request_spec.get("headers")
    content_type = ""
    if isinstance(headers, dict):
        content_type = str(headers.get("Content-Type") or headers.get("content-type") or "").casefold()
    if "multipart/form-data" in content_type:
        return "multipart"
    if "application/json" in content_type:
        return "json"
    if "xml" in content_type or (isinstance(request_spec.get("body_text"), str) and str(request_spec.get("body_text", "")).lstrip().startswith("<")):
        return "xml"
    if isinstance(request_spec.get("body"), dict):
        return "form"
    if isinstance(request_spec.get("query"), dict):
        return "query"
    return "query"


def _request_evidence(request_id: str, request_spec: dict[str, Any], auth_context: str) -> RequestEvidence:
    query = request_spec.get("query") if isinstance(request_spec.get("query"), dict) else {}
    body = request_spec.get("body") if isinstance(request_spec.get("body"), dict) else {}
    headers = request_spec.get("headers") if isinstance(request_spec.get("headers"), dict) else {}
    placements: list[str] = []
    if query:
        placements.append("query")
    if body:
        placements.append("body")
    if isinstance(request_spec.get("body_text"), str) and str(request_spec.get("body_text", "")).strip():
        placements.append("body_text")
    if headers:
        placements.append("headers")
    return RequestEvidence(
        request_id=request_id,
        method=str(request_spec.get("method", "GET")).upper(),
        path=str(request_spec.get("path", "")),
        transport=_request_transport(request_spec),
        auth_context=auth_context,
        query_keys=sorted(str(k) for k in query.keys()),
        body_keys=sorted(str(k) for k in body.keys()),
        header_keys=sorted(str(k) for k in headers.keys()),
        payload_placements=placements,
        request_summary=_request_summary(request_spec),
    )


def _display_arg(arg: str) -> str:
    if len(arg) <= 64:
        return arg
    return arg[:24] + "..." + arg[-12:]


def _oracle_evidence(runtime: RuntimeEvidence, plan: ValidationPlan, config: PadvConfig) -> list[OracleEvidence]:
    intercepts = {x.strip().casefold() for x in _oracle_functions(plan)}
    out: list[OracleEvidence] = []
    for call in runtime.calls:
        function = str(call.function or "").strip()
        if intercepts and function.casefold() not in intercepts:
            continue
        full_args = [str(arg) for arg in call.args]
        out.append(
            OracleEvidence(
                correlation_id=str(runtime.correlation or runtime.request_id),
                function=function,
                file=str(call.file or ""),
                line=int(call.line or 0),
                full_args=full_args,
                display_args=[_display_arg(arg) for arg in full_args],
                matched_canary=any(_contains_canary(arg, plan.canary, config) for arg in full_args),
            )
        )
    return out


def _response_evidence(response: Any, body_excerpt: str, elapsed_ms: int | None) -> ResponseEvidence:
    headers = getattr(response, "headers", {}) or {}
    content_type = ""
    if isinstance(headers, dict):
        content_type = str(headers.get("Content-Type") or headers.get("content-type") or "")
    features: dict[str, Any] = {
        "contains_json_object": body_excerpt.lstrip().startswith("{"),
        "contains_xml": body_excerpt.lstrip().startswith("<"),
    }
    return ResponseEvidence(
        status_code=int(getattr(response, "status_code", 0)) if getattr(response, "status_code", None) is not None else None,
        location=str(headers.get("Location") or headers.get("location") or ""),
        body_excerpt=body_excerpt,
        content_type=content_type,
        elapsed_ms=elapsed_ms,
        parsed_features=features,
    )


def _witness_evidence(
    *,
    candidate: Candidate,
    runtime: RuntimeEvidence,
) -> WitnessEvidence:
    flags = sorted({str(x).strip() for x in runtime.analysis_flags if str(x).strip()})
    data: dict[str, Any] = {}
    oracle_items = runtime.oracle_evidence
    if candidate.canonical_class == "sql_injection_boundary":
        data["sql_sink_hit"] = any(item.matched_canary for item in oracle_items)
        data["sql_canary_arg_match"] = any(item.matched_canary for item in oracle_items)
        body = runtime.body_excerpt.casefold()
        data["sql_error_diff_candidate"] = any(marker in body for marker in _SQL_ERROR_MARKERS)
    elif candidate.canonical_class == "command_injection_boundary":
        data["command_sink_hit"] = any(item.matched_canary for item in oracle_items)
        data["command_canary_arg_match"] = any(item.matched_canary for item in oracle_items)
    elif candidate.canonical_class == "xss_output_boundary":
        data["dom_execution"] = "xss_dom_witness" in {flag.casefold() for flag in flags}
    elif candidate.canonical_class in {"ssrf", "outbound_request_influence"}:
        data["outbound_url_arg_match"] = any(
            "http://" in " ".join(item.full_args).casefold()
            or "https://" in " ".join(item.full_args).casefold()
            for item in oracle_items
        )
    elif candidate.canonical_class == "xxe_influence":
        data["xxe_entity_witness"] = any("<!entity" in " ".join(item.full_args).casefold() for item in oracle_items)
    return WitnessEvidence(class_name=candidate.canonical_class or candidate.vuln_class, witness_flags=flags, witness_data=data)


def _extract_identities(auth_state: dict[str, Any]) -> list[str]:
    identities: list[str] = []
    if not isinstance(auth_state, dict):
        return identities
    for key in ("username", "user", "identity", "role"):
        value = auth_state.get(key)
        if isinstance(value, str) and value.strip():
            identities.append(value.strip())
    return identities


def _extract_security_level(auth_state: dict[str, Any]) -> str:
    if not isinstance(auth_state, dict):
        return ""
    for key in ("security_level", "security-level"):
        value = auth_state.get(key)
        if value is not None:
            return str(value).strip()
    return ""


def _environment_facts(
    candidate: Candidate,
    auth_state: dict[str, Any],
    plan: ValidationPlan,
) -> EnvironmentFacts:
    cookies = auth_state.get("cookies", {}) if isinstance(auth_state, dict) else {}
    reachable_paths = list(dict.fromkeys(str(x).strip() for x in candidate.web_path_hints if str(x).strip()))
    return EnvironmentFacts(
        security_level=_extract_security_level(auth_state),
        session_state="observed-session" if isinstance(cookies, dict) and cookies else "anonymous",
        authenticated_identities=_extract_identities(auth_state),
        database_initialized=None,
        known_seed_data=[],
        reachable_app_paths=reachable_paths,
        role_prerequisites=list(plan.environment_requirements),
        provenance={"auth_state_keys": sorted(str(k) for k in auth_state.keys())} if isinstance(auth_state, dict) else {},
    )


def _bundle_type_for_decision(decision: str) -> str:
    mapping = {
        "VALIDATED": "validated_exploit",
        "CONFIRMED_ANALYSIS_FINDING": "confirmed_analysis_finding",
        "DROPPED": "dropped",
        "NEEDS_HUMAN_SETUP": "needs_human_setup",
    }
    return mapping.get(str(decision).strip(), "dropped")


def _deserialize_runtime_evidence(item: dict[str, Any]) -> RuntimeEvidence:
    calls = [RuntimeCall(**call) for call in item.get("calls", []) if isinstance(call, dict)]
    oracle_evidence = [OracleEvidence(**entry) for entry in item.get("oracle_evidence", []) if isinstance(entry, dict)]
    request_evidence = RequestEvidence(**item["request_evidence"]) if isinstance(item.get("request_evidence"), dict) else None
    response_evidence = ResponseEvidence(**item["response_evidence"]) if isinstance(item.get("response_evidence"), dict) else None
    witness_evidence = WitnessEvidence(**item["witness_evidence"]) if isinstance(item.get("witness_evidence"), dict) else None
    return RuntimeEvidence(
        request_id=str(item.get("request_id", "")),
        status=str(item.get("status", "")),
        call_count=int(item.get("call_count", 0)),
        overflow=bool(item.get("overflow")),
        arg_truncated=bool(item.get("arg_truncated")),
        result_truncated=bool(item.get("result_truncated")),
        correlation=item.get("correlation"),
        calls=calls,
        raw_headers=dict(item.get("raw_headers", {})) if isinstance(item.get("raw_headers"), dict) else {},
        http_status=item.get("http_status"),
        body_excerpt=str(item.get("body_excerpt", "")),
        location=str(item.get("location", "")),
        analysis_flags=[str(x) for x in item.get("analysis_flags", []) if str(x).strip()],
        aux=dict(item.get("aux", {})) if isinstance(item.get("aux"), dict) else {},
        oracle_evidence=oracle_evidence,
        request_evidence=request_evidence,
        response_evidence=response_evidence,
        witness_evidence=witness_evidence,
    )


def _deserialize_differential_pairs(payload: dict[str, Any]) -> list[DifferentialPair]:
    pairs: list[DifferentialPair] = []
    for item in payload.get("differential_pairs", []):
        if not isinstance(item, dict):
            continue
        priv = item.get("privileged_run")
        unpriv = item.get("unprivileged_run")
        if not isinstance(priv, dict) or not isinstance(unpriv, dict):
            continue
        pairs.append(
            DifferentialPair(
                privileged_run=_deserialize_runtime_evidence(priv),
                unprivileged_run=_deserialize_runtime_evidence(unpriv),
                auth_diff=str(item.get("auth_diff", "")),
                response_equivalent=bool(item.get("response_equivalent")),
                equivalence_signals=[str(x) for x in item.get("equivalence_signals", []) if str(x).strip()],
            )
        )
    return pairs


def _load_existing_bundle(store: EvidenceStore, run_id: str, candidate_id: str) -> EvidenceBundle | None:
    payload = store.load_bundle(f"bundle-{run_id}-{candidate_id}")
    if not isinstance(payload, dict):
        return None
    try:
        candidate = Candidate(**payload["candidate"])
        static_evidence = [StaticEvidence(**item) for item in payload.get("static_evidence", []) if isinstance(item, dict)]
        positive_runtime = [_deserialize_runtime_evidence(item) for item in payload.get("positive_runtime", []) if isinstance(item, dict)]
        negative_runtime = [_deserialize_runtime_evidence(item) for item in payload.get("negative_runtime", []) if isinstance(item, dict)]
        gate_result = GateResult(**payload["gate_result"])
        environment_facts = EnvironmentFacts(**payload["environment_facts"]) if isinstance(payload.get("environment_facts"), dict) else None
        return EvidenceBundle(
            bundle_id=str(payload.get("bundle_id", "")),
            created_at=str(payload.get("created_at", "")),
            candidate=candidate,
            static_evidence=static_evidence,
            positive_runtime=positive_runtime,
            negative_runtime=negative_runtime,
            repro_run_ids=[str(x) for x in payload.get("repro_run_ids", []) if str(x).strip()],
            gate_result=gate_result,
            limitations=[str(x) for x in payload.get("limitations", []) if str(x).strip()],
            differential_pairs=_deserialize_differential_pairs(payload),
            artifact_refs=[str(x) for x in payload.get("artifact_refs", []) if str(x).strip()],
            discovery_trace=dict(payload.get("discovery_trace", {})) if isinstance(payload.get("discovery_trace"), dict) else {},
            planner_trace=dict(payload.get("planner_trace", {})) if isinstance(payload.get("planner_trace"), dict) else {},
            bundle_type=str(payload.get("bundle_type", "validated_exploit")),
            validation_contract=dict(payload.get("validation_contract", {})) if isinstance(payload.get("validation_contract"), dict) else {},
            environment_facts=environment_facts,
        )
    except Exception:
        return None


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


def _is_nonblocking_precondition(lowered: str, cookie_jar: dict[str, str], config: PadvConfig) -> bool:
    if lowered in _NONBLOCKING_PRECONDITION_EXACT:
        return True
    if any(lowered.startswith(prefix) for prefix in _NONBLOCKING_PRECONDITION_PREFIXES):
        return True
    if any(fragment in lowered for fragment in _NONBLOCKING_PRECONDITION_SUBSTRINGS):
        return True
    if "web server" in lowered and "running" in lowered:
        return True
    if cookie_jar and any(hint in lowered for hint in _AUTH_PRECONDITION_HINTS):
        return True
    if not config.auth.enabled and ("anonymous" in lowered or "no auth" in lowered):
        return True
    return False


def _normalize_gate_preconditions(
    candidate: Candidate,
    cookie_jar: dict[str, str],
    config: PadvConfig,
) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    raw_values = list(candidate.preconditions)
    if candidate.auth_requirements and not cookie_jar:
        raw_values.extend(candidate.auth_requirements)

    for raw in raw_values:
        value = str(raw).strip()
        if not value:
            continue
        if _is_nonblocking_precondition(value.casefold(), cookie_jar, config):
            continue
        if value in seen:
            continue
        seen.add(value)
        out.append(value)
    return out


def _contains_canary(arg: str, canary: str, config: PadvConfig) -> bool:
    return contains_canary(
        arg,
        canary,
        allow_casefold=config.canary.allow_casefold,
        allow_url_decode=config.canary.allow_url_decode,
    )


def _has_class_oracle_witness(
    runtime: RuntimeEvidence,
    candidate: Candidate,
    plan: ValidationPlan,
    config: PadvConfig,
) -> bool:
    witness_flag = _CLASS_ORACLE_WITNESS_FLAGS.get(canonicalize_vuln_class(candidate.vuln_class))
    if not witness_flag:
        return False
    intercepts = {x.strip().casefold() for x in _oracle_functions(plan)}
    for call in runtime.calls:
        function = str(call.function or "").strip().casefold()
        if intercepts and function not in intercepts:
            continue
        for arg in call.args:
            if _contains_canary(str(arg), plan.canary, config):
                return True
    return False


def _derive_body_canary_flags(body: str, canary: str) -> tuple[set[str], bool]:
    flags: set[str] = set()
    escaped = html.escape(canary, quote=True)
    has_raw_canary = canary in body
    has_escaped_canary = escaped in body if escaped != canary else False

    if has_raw_canary:
        flags.add("body_canary")
    if has_raw_canary and not has_escaped_canary:
        flags.add("xss_raw_canary")
        body_lower = body.casefold()
        if "<script" in body_lower or "onerror=" in body_lower or "onload=" in body_lower:
            flags.add("xss_dom_witness")
    return flags, has_raw_canary


def _derive_body_marker_flags(body_lower: str, has_raw_canary: bool) -> set[str]:
    flags: set[str] = set()
    if ("phpinfo()" in body_lower) or ("<title>phpinfo()" in body_lower) or ("php version" in body_lower):
        flags.add("phpinfo_marker")
    if any(marker in body_lower for marker in _ERROR_MARKERS):
        if has_raw_canary:
            flags.add("verbose_error_leak")
        flags.add("debug_leak")
    if any(marker in body_lower for marker in _SQL_ERROR_MARKERS):
        flags.add("sql_error_witness")
    return flags


def _derive_header_flags(response: Any) -> set[str]:
    header_keys = {k.casefold() for k in response.headers.keys()}
    if "x-powered-by" in header_keys or "server" in header_keys:
        return {"info_disclosure_header"}
    return set()


def _check_authz_bypass_status(response: Any, anonymous_probe: Any) -> bool:
    return (
        _status_ok(int(response.status_code))
        and _status_ok(int(anonymous_probe.status_code))
        and not _looks_like_login(response)
        and not _looks_like_login(anonymous_probe)
    )


def _check_idor_bypass(response: Any, anonymous_probe: Any, request_spec: dict[str, Any]) -> bool:
    if not _request_has_id(request_spec):
        return False
    if not _status_ok(int(response.status_code)) or not _status_ok(int(anonymous_probe.status_code)):
        return False
    return (response.body or "") != (anonymous_probe.body or "")


def _check_csrf_missing_token(response: Any, request_spec: dict[str, Any]) -> bool:
    method = str(request_spec.get("method", "GET")).upper()
    if method not in {"POST", "PUT", "PATCH", "DELETE"}:
        return False
    return not _request_has_token(request_spec) and _status_ok(int(response.status_code))


def _derive_authz_probe_flags(
    candidate: Candidate,
    response: Any,
    anonymous_probe: Any,
    request_spec: dict[str, Any],
) -> set[str]:
    flags: set[str] = {"authz_pair_observed"}

    if _check_authz_bypass_status(response, anonymous_probe):
        flags.add("authz_bypass_status")

    if candidate.vuln_class == "auth_and_session_failures":
        if _status_ok(int(anonymous_probe.status_code)) and not _looks_like_login(anonymous_probe):
            flags.add("auth_bypass")

    if candidate.vuln_class == "idor_invariant_missing" and _check_idor_bypass(response, anonymous_probe, request_spec):
        flags.add("idor_bypass")

    if candidate.vuln_class == "csrf_invariant_missing" and _check_csrf_missing_token(response, request_spec):
        flags.add("csrf_missing_token_acceptance")

    return flags


def _derive_session_fixation_flags(response: Any, cookie_jar: dict[str, str]) -> set[str]:
    flags: set[str] = set()
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
    return flags


def _collect_analysis_flags(
    runtime: RuntimeEvidence,
    response: Any,
    candidate: Candidate,
    plan: ValidationPlan,
    config: PadvConfig,
    request_spec: dict[str, Any],
    cookie_jar: dict[str, str],
    anonymous_probe: Any | None,
) -> set[str]:
    flags = {x for x in runtime.analysis_flags if isinstance(x, str) and x}
    body = response.body or ""

    canary_flags, has_raw_canary = _derive_body_canary_flags(body, plan.canary)
    flags |= canary_flags
    flags |= _derive_body_marker_flags(body.casefold(), has_raw_canary)
    flags |= _derive_header_flags(response)

    witness_flag = _CLASS_ORACLE_WITNESS_FLAGS.get(candidate.canonical_class or candidate.vuln_class)
    if witness_flag and _has_class_oracle_witness(runtime, candidate, plan, config):
        flags.add(witness_flag)

    if candidate.vuln_class in _AUTHZ_PROBE_CLASSES and anonymous_probe is not None:
        flags |= _derive_authz_probe_flags(candidate, response, anonymous_probe, request_spec)

    if candidate.vuln_class == "session_fixation_invariant":
        flags |= _derive_session_fixation_flags(response, cookie_jar)

    return flags


def _annotate_runtime_evidence(
    runtime: RuntimeEvidence,
    response: Any,
    candidate: Candidate,
    plan: ValidationPlan,
    config: PadvConfig,
    request_spec: dict[str, Any],
    cookie_jar: dict[str, str],
    elapsed_ms: int | None,
    anonymous_probe: Any | None = None,
) -> RuntimeEvidence:
    runtime.http_status = int(response.status_code)
    runtime.location = str(response.headers.get("Location", "") or response.headers.get("location", ""))
    runtime.body_excerpt = (response.body or "")[:2000]

    flags = _collect_analysis_flags(runtime, response, candidate, plan, config, request_spec, cookie_jar, anonymous_probe)
    runtime.analysis_flags = sorted(flags)

    runtime.aux = dict(runtime.aux)
    if anonymous_probe is not None:
        runtime.aux["anonymous_status"] = int(anonymous_probe.status_code)
        runtime.aux["anonymous_body_excerpt"] = (anonymous_probe.body or "")[:500]

    if (candidate.canonical_class or candidate.vuln_class) in _HTTP_SIGNAL_CLASSES and runtime.status in {"inactive", "missing_intercept"}:
        runtime.status = "http_observed"
    auth_context = "authenticated" if cookie_jar else "anonymous"
    runtime.request_evidence = _request_evidence(runtime.request_id, request_spec, auth_context)
    runtime.response_evidence = _response_evidence(response, runtime.body_excerpt, elapsed_ms)
    runtime.oracle_evidence = _oracle_evidence(runtime, plan, config)
    runtime.witness_evidence = _witness_evidence(
        candidate=candidate,
        runtime=runtime,
    )
    return runtime


def _candidate_hypotheses(planner_trace: dict[str, Any], candidate_id: str) -> list[dict[str, Any]]:
    proposer = planner_trace.get("proposer")
    if not isinstance(proposer, dict):
        return []
    hypotheses = proposer.get("hypotheses")
    if not isinstance(hypotheses, list):
        return []
    out: list[dict[str, Any]] = []
    for item in hypotheses:
        if not isinstance(item, dict):
            continue
        cid = str(item.get("candidate_id", "")).strip()
        if cid != candidate_id:
            continue
        out.append(
            {
                "candidate_id": cid,
                "rationale": str(item.get("rationale", "")).strip(),
            }
        )
    return out


def _request_summary(request_spec: dict[str, Any]) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "method": str(request_spec.get("method", "GET")).upper(),
        "path": str(request_spec.get("path", "")),
    }
    query = request_spec.get("query")
    if isinstance(query, dict):
        summary["query_keys"] = sorted(str(k) for k in query.keys())
    body = request_spec.get("body")
    if isinstance(body, dict):
        summary["body_keys"] = sorted(str(k) for k in body.keys())
    elif isinstance(request_spec.get("body_text"), str):
        summary["body_mode"] = "text"
    headers = request_spec.get("headers")
    if isinstance(headers, dict):
        summary["header_keys"] = sorted(str(k) for k in headers.keys())
    return summary


def _record_attempt(
    attempts: list[dict[str, Any]],
    seen_flags: set[str],
    *,
    phase: str,
    idx: int,
    request_spec: dict[str, Any],
    runtime: RuntimeEvidence,
    elapsed_ms: int,
) -> None:
    current_flags = {x for x in runtime.analysis_flags if isinstance(x, str) and x.strip()}
    new_flags = sorted(current_flags - seen_flags)
    seen_flags.update(current_flags)
    attempts.append(
        {
            "phase": phase,
            "index": idx,
            "request_id": runtime.request_id,
            "request": _request_summary(request_spec),
            "runtime_status": runtime.status,
            "http_status": runtime.http_status,
            "call_count": runtime.call_count,
            "analysis_flags": sorted(current_flags),
            "new_flags": new_flags,
            "elapsed_ms": elapsed_ms,
            "auth_context": (
                str(runtime.aux.get("auth_context", ""))
                if isinstance(runtime.aux, dict)
                else ""
            ),
        }
    )


def _merge_request_headers(headers: dict[str, str], request_spec: dict[str, Any]) -> None:
    request_headers = request_spec.get("headers")
    if isinstance(request_headers, dict):
        headers.update({str(k): str(v) for k, v in request_headers.items() if str(k).strip()})


def _make_failed_runtime(req_id: str, exc: RequestError, cookie_jar: dict[str, str] | None = None) -> RuntimeEvidence:
    aux: dict[str, Any] = {"error": str(exc)}
    if cookie_jar is not None:
        aux["auth_context"] = "authenticated" if cookie_jar else "anonymous"
    return RuntimeEvidence(
        request_id=req_id, status="request_failed", call_count=0, overflow=False,
        arg_truncated=False, result_truncated=False, correlation=None, calls=[],
        raw_headers={"error": str(exc)}, aux=aux,
    )


def _try_anonymous_probe(
    config: PadvConfig, request_spec: dict[str, Any], candidate: Candidate,
    cookie_jar: dict[str, str], request_budget_remaining: int, candidate_deadline: float,
) -> tuple[Any | None, int]:
    if candidate.vuln_class not in _AUTHZ_PROBE_CLASSES:
        return None, 0
    if not cookie_jar or request_budget_remaining <= 1 or monotonic() >= candidate_deadline:
        return None, 0
    try:
        probe = send_request(
            url=_target_url(config.target.base_url, request_spec),
            method=request_spec.get("method", "GET"), headers={},
            timeout_seconds=config.target.request_timeout_seconds,
            query=request_spec.get("query"),
            body=request_spec.get("body", request_spec.get("body_text")), cookie_jar={},
        )
        return probe, 1
    except RequestError:
        return None, 0


def _run_positive_phase(
    ctx: _ValidationContext, candidate: Candidate, plan: ValidationPlan,
    request_budget_remaining: int, candidate_deadline: float,
    attempts: list[dict[str, Any]], seen_flags: set[str],
) -> tuple[list[RuntimeEvidence], list[str], int]:
    config = ctx.config
    cookie_jar = ctx.cookie_jar
    positive_runs: list[RuntimeEvidence] = []
    repro_ids: list[str] = []
    budget = request_budget_remaining
    for idx, request_spec in enumerate(plan.positive_requests[:3]):
        if budget <= 0 or monotonic() >= candidate_deadline:
            break
        req_id = new_request_id(candidate.candidate_id, "pos", idx)
        headers = _validation_headers(config, _oracle_functions(plan), req_id)
        _merge_request_headers(headers, request_spec)
        req_started = monotonic()
        try:
            response = send_request(
                url=_target_url(config.target.base_url, request_spec),
                method=request_spec.get("method", "GET"), headers=headers,
                timeout_seconds=config.target.request_timeout_seconds,
                query=request_spec.get("query"),
                body=request_spec.get("body", request_spec.get("body_text")), cookie_jar=cookie_jar,
            )
            runtime = parse_response_headers(req_id, response.headers, config.oracle)
            anonymous_probe, probe_cost = _try_anonymous_probe(config, request_spec, candidate, cookie_jar, budget, candidate_deadline)
            budget -= probe_cost
            runtime = _annotate_runtime_evidence(
                runtime=runtime, response=response, candidate=candidate, plan=plan,
                config=config, request_spec=request_spec, cookie_jar=cookie_jar,
                elapsed_ms=int((monotonic() - req_started) * 1000), anonymous_probe=anonymous_probe,
            )
            runtime.aux = dict(runtime.aux)
            runtime.aux.setdefault("auth_context", "authenticated" if cookie_jar else "anonymous")
        except RequestError as exc:
            runtime = _make_failed_runtime(req_id, exc, cookie_jar)
        elapsed_ms = int((monotonic() - req_started) * 1000)
        positive_runs.append(runtime)
        _record_attempt(attempts, seen_flags, phase="positive", idx=idx, request_spec=request_spec, runtime=runtime, elapsed_ms=elapsed_ms)
        repro_ids.append(req_id)
        budget -= 1
        if config.sandbox.reset_cmd:
            sandbox_adapter.reset(config.sandbox)
    return positive_runs, repro_ids, request_budget_remaining - budget


def _run_negative_phase(
    ctx: _ValidationContext, candidate: Candidate, plan: ValidationPlan,
    request_budget_remaining: int, candidate_deadline: float,
    attempts: list[dict[str, Any]], seen_flags: set[str],
) -> tuple[list[RuntimeEvidence], int]:
    config = ctx.config
    cookie_jar = ctx.cookie_jar
    negative_runs: list[RuntimeEvidence] = []
    budget = request_budget_remaining
    for idx, request_spec in enumerate(plan.negative_requests):
        if budget <= 0 or monotonic() >= candidate_deadline:
            break
        req_id = new_request_id(candidate.candidate_id, "neg", idx)
        headers = _validation_headers(config, _oracle_functions(plan), req_id)
        _merge_request_headers(headers, request_spec)
        req_started = monotonic()
        try:
            response = send_request(
                url=_target_url(config.target.base_url, request_spec),
                method=request_spec.get("method", "GET"), headers=headers,
                timeout_seconds=config.target.request_timeout_seconds,
                query=request_spec.get("query"),
                body=request_spec.get("body", request_spec.get("body_text")), cookie_jar=cookie_jar,
            )
            runtime = parse_response_headers(req_id, response.headers, config.oracle)
            runtime = _annotate_runtime_evidence(
                runtime=runtime, response=response, candidate=candidate, plan=plan,
                config=config, request_spec=request_spec, cookie_jar=cookie_jar,
                elapsed_ms=int((monotonic() - req_started) * 1000), anonymous_probe=None,
            )
        except RequestError as exc:
            runtime = _make_failed_runtime(req_id, exc)
        elapsed_ms = int((monotonic() - req_started) * 1000)
        negative_runs.append(runtime)
        _record_attempt(attempts, seen_flags, phase="negative", idx=idx, request_spec=request_spec, runtime=runtime, elapsed_ms=elapsed_ms)
        budget -= 1
    return negative_runs, request_budget_remaining - budget


def _normalize_cookie_dict(raw: Any) -> dict[str, str]:
    if isinstance(raw, dict):
        return {str(k): str(v) for k, v in raw.items() if str(k).strip()}
    return {}


def _extract_cookie_jar(request_spec: dict[str, Any]) -> dict[str, str]:
    return _normalize_cookie_dict(request_spec.get("cookies"))


def _execute_differential_request(
    config: PadvConfig, candidate: Candidate, plan: ValidationPlan,
    level_state: dict[str, Any], base_request: dict[str, Any], diff_idx: int,
    positive_runs: list[RuntimeEvidence],
    attempts: list[dict[str, Any]], seen_flags: set[str],
) -> DifferentialPair | None:
    unpriv_request = build_unprivileged_request(base_request, level_state)
    req_id = new_request_id(candidate.candidate_id, "diff", diff_idx)
    headers = _validation_headers(config, _oracle_functions(plan), req_id)
    _merge_request_headers(headers, unpriv_request)
    unpriv_cookie_jar = _extract_cookie_jar(unpriv_request)
    try:
        req_started = monotonic()
        response = send_request(
            url=_target_url(config.target.base_url, unpriv_request),
            method=unpriv_request.get("method", "GET"), headers=headers,
            timeout_seconds=config.target.request_timeout_seconds,
            query=unpriv_request.get("query"),
            body=unpriv_request.get("body", unpriv_request.get("body_text")), cookie_jar=unpriv_cookie_jar,
        )
        unpriv_runtime = parse_response_headers(req_id, response.headers, config.oracle)
        unpriv_runtime = _annotate_runtime_evidence(
            runtime=unpriv_runtime, response=response, candidate=candidate, plan=plan,
            config=config, request_spec=unpriv_request, cookie_jar=unpriv_cookie_jar,
            elapsed_ms=int((monotonic() - req_started) * 1000), anonymous_probe=None,
        )
        unpriv_runtime.aux = dict(unpriv_runtime.aux)
        context = str(level_state.get("auth_context", "")).strip().casefold()
        if not context:
            context = "anonymous" if not unpriv_cookie_jar else "unprivileged"
        unpriv_runtime.aux["auth_context"] = context
        elapsed_ms = int((monotonic() - req_started) * 1000)
        _record_attempt(attempts, seen_flags, phase="differential", idx=diff_idx, request_spec=unpriv_request, runtime=unpriv_runtime, elapsed_ms=elapsed_ms)
        if not positive_runs:
            return None
        return compare_responses(positive_runs[0], unpriv_runtime, config)
    except RequestError:
        return None


def _resolve_differential_levels(config: PadvConfig) -> list[str]:
    levels = [x.strip() for x in config.differential.auth_levels if isinstance(x, str) and x.strip()]
    if not levels:
        levels = ["anonymous"]
    return list(dict.fromkeys(levels))


def _run_differential_phase(
    ctx: _ValidationContext, candidate: Candidate, plan: ValidationPlan,
    positive_runs: list[RuntimeEvidence],
    request_budget_remaining: int, candidate_deadline: float,
    attempts: list[dict[str, Any]], seen_flags: set[str],
) -> tuple[list[DifferentialPair], int]:
    config = ctx.config
    auth_state = ctx.auth_state
    pairs: list[DifferentialPair] = []
    budget = request_budget_remaining
    if not config.differential.enabled or not needs_differential(candidate.vuln_class):
        return pairs, 0
    if not positive_runs or not plan.positive_requests:
        return pairs, 0
    base_request = plan.positive_requests[0]
    levels = _resolve_differential_levels(config)
    for diff_idx, level in enumerate(levels):
        if budget <= 0 or monotonic() >= candidate_deadline:
            break
        level_state = resolve_auth_state_for_level(auth_state, level)
        if level_state is None:
            continue
        pair = _execute_differential_request(
            config, candidate, plan, level_state, base_request, diff_idx,
            positive_runs, attempts, seen_flags,
        )
        if pair is not None:
            pairs.append(pair)
        budget -= 1
        if config.sandbox.reset_cmd:
            sandbox_adapter.reset(config.sandbox)
    return pairs, request_budget_remaining - budget


def _collect_evidence_signals(candidate_static: list[StaticEvidence], candidate: Candidate) -> list[str]:
    query_signals = {
        item.query_id.split("::", 1)[0].strip().lower()
        for item in candidate_static
        if isinstance(item.query_id, str) and item.query_id.strip()
    }
    candidate_signals = {x.strip().lower() for x in candidate.provenance if isinstance(x, str) and x.strip()}
    if candidate.web_path_hints:
        candidate_signals.add("web")
    return sorted(query_signals | candidate_signals)


def _build_analysis_only_bundle(
    run_id: str, candidate: Candidate, candidate_static: list[StaticEvidence],
    evidence_signals: list[str], artifact_refs: list[str], discovery_trace: dict[str, Any],
    auth_state: dict[str, Any], profile: Any,
) -> EvidenceBundle:
    gate_result = GateResult(
        "CONFIRMED_ANALYSIS_FINDING", ["A0"], None,
        "analysis-only candidate confirmed by static and research evidence",
    )
    return EvidenceBundle(
        bundle_id=f"bundle-{run_id}-{candidate.candidate_id}",
        created_at=utc_now_iso(), candidate=candidate, static_evidence=candidate_static,
        positive_runtime=[], negative_runtime=[], repro_run_ids=[], gate_result=gate_result,
        limitations=[], differential_pairs=[], artifact_refs=artifact_refs,
        discovery_trace=discovery_trace,
        planner_trace={"analysis_only": True, "evidence_signals": evidence_signals, "validation_mode": candidate.validation_mode},
        bundle_type=_bundle_type_for_decision(gate_result.decision),
        validation_contract={"profile": profile.to_dict(), "class_contract_id": profile.class_contract_id, "validation_mode": profile.validation_mode},
        environment_facts=_environment_facts(candidate, auth_state, ValidationPlan(candidate.candidate_id, [], [], [], "")),
    )


def _sanitize_exports(
    config: PadvConfig, positive_runs: list[RuntimeEvidence],
    negative_runs: list[RuntimeEvidence], differential_pairs: list[DifferentialPair],
) -> tuple[list[RuntimeEvidence], list[RuntimeEvidence], list[DifferentialPair]]:
    if config.store.store_raw_reports:
        return positive_runs, negative_runs, differential_pairs
    return (
        [sanitized_runtime_evidence(r) for r in positive_runs],
        [sanitized_runtime_evidence(r) for r in negative_runs],
        [
            DifferentialPair(
                privileged_run=sanitized_runtime_evidence(pair.privileged_run),
                unprivileged_run=sanitized_runtime_evidence(pair.unprivileged_run),
                auth_diff=pair.auth_diff, response_equivalent=pair.response_equivalent,
                equivalence_signals=list(pair.equivalence_signals),
            )
            for pair in differential_pairs
        ],
    )


def _build_planner_trace(
    candidate_hypotheses: list[dict[str, Any]], plan: ValidationPlan, attempts: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "hypotheses": candidate_hypotheses,
        "validation_plan": {
            "candidate_id": plan.candidate_id, "validation_mode": plan.validation_mode,
            "canonical_class": plan.canonical_class, "class_contract_id": plan.class_contract_id,
            "oracle_functions": list(_oracle_functions(plan)),
            "request_expectations": list(plan.request_expectations),
            "response_witnesses": list(plan.response_witnesses), "intercepts": list(plan.intercepts),
            "environment_requirements": list(plan.environment_requirements),
            "requests": list(plan.requests or plan.positive_requests),
            "negative_controls": list(plan.negative_controls or plan.negative_requests),
            "strategy": plan.strategy, "negative_control_strategy": plan.negative_control_strategy,
            "positive_request_count": len(plan.positive_requests),
            "negative_request_count": len(plan.negative_requests), "plan_notes": list(plan.plan_notes),
        },
        "attempts": attempts,
    }


@dataclass
class _ValidationContext:
    """Shared context for single-candidate runtime validation."""
    config: PadvConfig
    store: EvidenceStore
    run_id: str
    cookie_jar: dict[str, str]
    auth_state: dict[str, Any]
    planner_trace: dict[str, Any]
    discovery_trace: dict[str, Any]
    artifact_refs: list[str]


@dataclass(frozen=True)
class _PreparedValidationTarget:
    candidate: Candidate
    profile: Any
    plan: ValidationPlan | None
    static_evidence: list[StaticEvidence]
    evidence_signals: list[str]
    preconditions: list[str]


def _validate_single_candidate_runtime(
    ctx: _ValidationContext,
    target: _PreparedValidationTarget,
    request_budget_remaining: int, run_deadline: float,
) -> tuple[EvidenceBundle, int]:
    attempts: list[dict[str, Any]] = []
    seen_flags: set[str] = set()
    config = ctx.config
    candidate = target.candidate
    plan = target.plan
    profile = target.profile
    candidate_static = target.static_evidence
    evidence_signals = target.evidence_signals
    if plan is None:
        raise RuntimeError(f"missing agent-generated validation plan for candidate: {candidate.candidate_id}")
    candidate_deadline = min(run_deadline, monotonic() + float(config.budgets.max_seconds_per_candidate))
    total_cost = 0

    positive_runs, repro_ids, pos_cost = _run_positive_phase(
        ctx, candidate, plan, request_budget_remaining, candidate_deadline, attempts, seen_flags,
    )
    total_cost += pos_cost

    negative_runs, neg_cost = _run_negative_phase(
        ctx, candidate, plan, request_budget_remaining - total_cost, candidate_deadline, attempts, seen_flags,
    )
    total_cost += neg_cost

    differential_pairs, diff_cost = _run_differential_phase(
        ctx, candidate, plan, positive_runs, request_budget_remaining - total_cost, candidate_deadline, attempts, seen_flags,
    )
    total_cost += diff_cost

    gate_result = evaluate_candidate(
        config=config, candidate=candidate, static_evidence=candidate_static,
        positive_runs=positive_runs, negative_runs=negative_runs,
        intercepts=_oracle_functions(plan), canary=plan.canary,
        preconditions=target.preconditions,
        evidence_signals=evidence_signals, vuln_class=candidate.vuln_class,
        differential_pairs=differential_pairs,
    )

    positive_export, negative_export, differential_export = _sanitize_exports(config, positive_runs, negative_runs, differential_pairs)

    bundle = EvidenceBundle(
        bundle_id=f"bundle-{ctx.run_id}-{candidate.candidate_id}",
        created_at=utc_now_iso(), candidate=candidate, static_evidence=candidate_static,
        positive_runtime=positive_export, negative_runtime=negative_export, repro_run_ids=repro_ids,
        gate_result=gate_result,
        limitations=[gate_result.reason] if gate_result.decision != "VALIDATED" else [],
        differential_pairs=differential_export, artifact_refs=ctx.artifact_refs, discovery_trace=ctx.discovery_trace,
        planner_trace=_build_planner_trace(_candidate_hypotheses(ctx.planner_trace, candidate.candidate_id), plan, attempts),
        bundle_type=_bundle_type_for_decision(gate_result.decision),
        validation_contract={
            "profile": profile.to_dict(), "class_contract_id": plan.class_contract_id,
            "validation_mode": plan.validation_mode,
            "required_request_shape": list(profile.required_request_shape),
            "required_witnesses": list(profile.required_witnesses),
            "required_negative_controls": list(profile.required_negative_controls),
        },
        environment_facts=_environment_facts(candidate, ctx.auth_state, plan),
    )
    ctx.store.save_bundle(bundle)
    return bundle, total_cost


def _extract_auth_cookie_jar(auth_state: dict[str, Any]) -> dict[str, str]:
    raw = auth_state.get("cookies", {}) if isinstance(auth_state, dict) else {}
    return _normalize_cookie_dict(raw)


def _prepare_validation_target(
    ctx: _ValidationContext,
    candidate: Candidate,
    plans_by_candidate: dict[str, ValidationPlan],
    static_by_candidate: dict[str, list[StaticEvidence]],
) -> _PreparedValidationTarget:
    prepared = apply_validation_profile(candidate)
    candidate_static = static_by_candidate.get(prepared.candidate_id, [])
    return _PreparedValidationTarget(
        candidate=prepared,
        profile=profile_for_vuln_class(prepared.canonical_class or prepared.vuln_class),
        plan=plans_by_candidate.get(prepared.candidate_id),
        static_evidence=candidate_static,
        evidence_signals=_collect_evidence_signals(candidate_static, prepared),
        preconditions=_normalize_gate_preconditions(prepared, ctx.cookie_jar, ctx.config),
    )


def _process_candidate(
    ctx: _ValidationContext,
    target: _PreparedValidationTarget,
    request_budget_remaining: int,
    run_deadline: float,
) -> tuple[EvidenceBundle, int]:
    candidate = target.candidate

    existing_bundle = _load_existing_bundle(ctx.store, ctx.run_id, candidate.candidate_id)
    if existing_bundle is not None:
        return existing_bundle, 0

    if not is_runtime_validatable(candidate):
        bundle = _build_analysis_only_bundle(
            ctx.run_id, candidate, target.static_evidence, target.evidence_signals,
            ctx.artifact_refs, ctx.discovery_trace, ctx.auth_state, target.profile,
        )
        ctx.store.save_bundle(bundle)
        return bundle, 0

    return _validate_single_candidate_runtime(
        ctx, target,
        request_budget_remaining, run_deadline,
    )


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
    cookie_jar = _extract_auth_cookie_jar(auth_state)

    decisions: dict[str, int] = dict.fromkeys(("VALIDATED", "DROPPED", "NEEDS_HUMAN_SETUP", "CONFIRMED_ANALYSIS_FINDING"), 0)
    bundles: list[EvidenceBundle] = []
    request_budget_remaining = config.budgets.max_requests
    run_deadline = monotonic() + float(config.budgets.max_run_seconds)

    if config.sandbox.reset_cmd:
        sandbox_adapter.reset(config.sandbox)

    ctx = _ValidationContext(
        config=config, store=store, run_id=run_id,
        cookie_jar=cookie_jar, auth_state=auth_state,
        planner_trace=planner_trace, discovery_trace=discovery_trace,
        artifact_refs=artifact_refs,
    )

    static_by_candidate = group_static_evidence_by_candidate(candidates, static_evidence)
    targets = [
        _prepare_validation_target(ctx, candidate, plans_by_candidate, static_by_candidate)
        for candidate in candidates
    ]

    for target in targets:
        if monotonic() >= run_deadline:
            break
        if request_budget_remaining <= 0:
            break
        bundle, cost = _process_candidate(
            ctx, target,
            request_budget_remaining, run_deadline,
        )
        request_budget_remaining -= cost
        decisions[bundle.gate_result.decision] = decisions.get(bundle.gate_result.decision, 0) + 1
        bundles.append(bundle)

    return bundles, decisions

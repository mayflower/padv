from __future__ import annotations

import urllib.parse

from padv.config.schema import PadvConfig
from padv.models import DifferentialPair, GateResult, RuntimeEvidence, StaticEvidence
from padv.static.joern.query_sets import VULN_CLASS_SPECS


REQUIRED_GATES = ["V0", "V1", "V2", "V3", "V4", "V5", "V6"]
AUTHZ_VULN_CLASSES = frozenset(
    {
        "broken_access_control",
        "idor_invariant_missing",
        "auth_and_session_failures",
    }
)

_RUNTIME_VALIDATABLE_CLASSES = frozenset(
    spec.vuln_class.casefold()
    for spec in VULN_CLASS_SPECS
    if spec.runtime_validatable
)

_CLASS_ORACLE_WITNESS_FLAGS: dict[str, str] = {
    "sql_injection_boundary": "sql_sink_oracle_witness",
    "command_injection_boundary": "command_sink_oracle_witness",
    "code_injection_boundary": "code_sink_oracle_witness",
    "ldap_injection_boundary": "ldap_sink_oracle_witness",
    "xpath_injection_boundary": "xpath_sink_oracle_witness",
    "file_boundary_influence": "file_sink_oracle_witness",
    "file_upload_influence": "upload_sink_oracle_witness",
    "outbound_request_influence": "ssrf_sink_oracle_witness",
    "ssrf": "ssrf_sink_oracle_witness",
    "xxe_influence": "xxe_sink_oracle_witness",
    "deserialization_influence": "deserialization_sink_oracle_witness",
    "php_object_gadget_surface": "gadget_sink_oracle_witness",
    "header_injection_boundary": "header_sink_oracle_witness",
    "regex_dos_boundary": "regex_sink_oracle_witness",
    "xml_dos_boundary": "xml_sink_oracle_witness",
    "security_misconfiguration": "misconfiguration_sink_oracle_witness",
}

_CLASS_WITNESS_RULES: dict[str, dict[str, object]] = {
    "sql_injection_boundary": {
        "required_all": {"sql_sink_oracle_witness"},
        "required_any": {"sql_status_diff_witness", "sql_body_diff_witness", "sql_error_witness"},
        "enforce_negative_clean": True,
    },
    "command_injection_boundary": {"required_all": {"command_sink_oracle_witness"}, "required_any": set(), "enforce_negative_clean": True},
    "code_injection_boundary": {"required_all": {"code_sink_oracle_witness"}, "required_any": set(), "enforce_negative_clean": True},
    "ldap_injection_boundary": {"required_all": {"ldap_sink_oracle_witness"}, "required_any": set(), "enforce_negative_clean": True},
    "xpath_injection_boundary": {"required_all": {"xpath_sink_oracle_witness"}, "required_any": set(), "enforce_negative_clean": True},
    "file_boundary_influence": {"required_all": {"file_sink_oracle_witness"}, "required_any": set(), "enforce_negative_clean": True},
    "file_upload_influence": {"required_all": {"upload_sink_oracle_witness"}, "required_any": set(), "enforce_negative_clean": True},
    "xss_output_boundary": {"required_all": {"xss_dom_witness"}, "required_any": set(), "enforce_negative_clean": True},
    "debug_output_leak": {"required_all": set(), "required_any": {"debug_leak", "verbose_error_leak", "phpinfo_marker"}, "enforce_negative_clean": True},
    "information_disclosure": {"required_all": set(), "required_any": {"info_disclosure_header", "verbose_error_leak", "phpinfo_marker"}, "enforce_negative_clean": True},
    "outbound_request_influence": {"required_all": {"ssrf_sink_oracle_witness", "ssrf_url_arg_witness"}, "required_any": set(), "enforce_negative_clean": True},
    "ssrf": {"required_all": {"ssrf_sink_oracle_witness", "ssrf_url_arg_witness"}, "required_any": set(), "enforce_negative_clean": True},
    "xxe_influence": {"required_all": {"xxe_sink_oracle_witness", "xxe_entity_witness"}, "required_any": set(), "enforce_negative_clean": True},
    "deserialization_influence": {"required_all": {"deserialization_sink_oracle_witness"}, "required_any": set(), "enforce_negative_clean": True},
    "php_object_gadget_surface": {"required_all": {"gadget_sink_oracle_witness"}, "required_any": set(), "enforce_negative_clean": True},
    "header_injection_boundary": {"required_all": {"header_sink_oracle_witness"}, "required_any": set(), "enforce_negative_clean": True},
    "regex_dos_boundary": {"required_all": {"regex_sink_oracle_witness"}, "required_any": set(), "enforce_negative_clean": True},
    "xml_dos_boundary": {"required_all": {"xml_sink_oracle_witness"}, "required_any": set(), "enforce_negative_clean": True},
    "broken_access_control": {"required_all": {"authz_bypass_status", "authz_pair_observed"}, "required_any": set(), "enforce_negative_clean": True},
    "csrf_invariant_missing": {"required_all": {"csrf_missing_token_acceptance"}, "required_any": set(), "enforce_negative_clean": True},
    "idor_invariant_missing": {"required_all": {"idor_bypass", "authz_bypass_status", "authz_pair_observed"}, "required_any": set(), "enforce_negative_clean": True},
    "session_fixation_invariant": {"required_all": set(), "required_any": {"session_id_not_rotated", "session_cookie_not_rotated"}, "enforce_negative_clean": True},
    "security_misconfiguration": {"required_all": {"misconfiguration_sink_oracle_witness"}, "required_any": set(), "enforce_negative_clean": True},
    "auth_and_session_failures": {"required_all": {"auth_bypass", "authz_bypass_status", "authz_pair_observed"}, "required_any": set(), "enforce_negative_clean": True},
}

_SQL_ERROR_MARKERS = (
    "sql syntax",
    "mysql",
    "mysqli",
    "pdoexception",
    "syntax error near",
    "sqlite",
    "postgresql",
    "pg_query",
    "ora-",
)


def _contains_canary(arg: str, canary: str, allow_casefold: bool, allow_url_decode: bool) -> bool:
    candidates = [arg]
    if allow_url_decode:
        candidates.append(urllib.parse.unquote(arg))

    if allow_casefold:
        folded = canary.casefold()
        return any(folded in c.casefold() for c in candidates)
    return any(canary in c for c in candidates)


def _has_oracle_hit(
    evidence: RuntimeEvidence,
    intercepts: set[str],
    canary: str,
    config: PadvConfig,
) -> bool:
    intercepts_lower = {i.lower() for i in intercepts}
    for call in evidence.calls:
        if intercepts_lower and call.function.lower() not in intercepts_lower:
            continue
        for arg in call.args:
            if _contains_canary(
                arg,
                canary,
                allow_casefold=config.canary.allow_casefold,
                allow_url_decode=config.canary.allow_url_decode,
            ):
                return True
    return False


def _flag_set(runs: list[RuntimeEvidence]) -> set[str]:
    out: set[str] = set()
    for run in runs:
        for flag in run.analysis_flags:
            if isinstance(flag, str) and flag.strip():
                out.add(flag.strip().casefold())
    return out


def _oracle_hit_count(
    runs: list[RuntimeEvidence],
    intercepts: set[str],
    canary: str,
    config: PadvConfig,
) -> int:
    return sum(1 for run in runs if _has_oracle_hit(run, intercepts, canary, config))


def _has_status_diff(positive_runs: list[RuntimeEvidence], negative_runs: list[RuntimeEvidence]) -> bool:
    pair_count = min(len(positive_runs), len(negative_runs))
    for idx in range(pair_count):
        pos = positive_runs[idx].http_status
        neg = negative_runs[idx].http_status
        if pos is None or neg is None:
            continue
        if int(pos) != int(neg):
            return True
    return False


def _has_body_diff(positive_runs: list[RuntimeEvidence], negative_runs: list[RuntimeEvidence]) -> bool:
    pair_count = min(len(positive_runs), len(negative_runs))
    for idx in range(pair_count):
        pos_body = (positive_runs[idx].body_excerpt or "").strip()
        neg_body = (negative_runs[idx].body_excerpt or "").strip()
        if not pos_body or not neg_body:
            continue
        if pos_body != neg_body:
            return True
    return False


def _has_sql_error_witness(positive_runs: list[RuntimeEvidence], negative_runs: list[RuntimeEvidence]) -> bool:
    positive_hit = any(
        any(marker in (run.body_excerpt or "").casefold() for marker in _SQL_ERROR_MARKERS)
        for run in positive_runs
    )
    if not positive_hit:
        return False
    negative_hit = any(
        any(marker in (run.body_excerpt or "").casefold() for marker in _SQL_ERROR_MARKERS)
        for run in negative_runs
    )
    return not negative_hit


def _call_args(runs: list[RuntimeEvidence], intercepts: set[str]) -> list[str]:
    values: list[str] = []
    lowered_intercepts = {x.casefold() for x in intercepts if isinstance(x, str) and x.strip()}
    for run in runs:
        for call in run.calls:
            function = str(call.function or "").strip().casefold()
            if lowered_intercepts and function not in lowered_intercepts:
                continue
            for arg in call.args:
                values.append(str(arg))
    return values


def _has_ssrf_url_arg_witness(runs: list[RuntimeEvidence], intercepts: set[str]) -> bool:
    args = _call_args(runs, intercepts)
    for raw in args:
        value = raw.casefold()
        if "http://" not in value and "https://" not in value and "gopher://" not in value and "file://" not in value:
            continue
        if "127.0.0.1" in value or "localhost" in value or "169.254." in value or "::1" in value:
            return True
        if "padv" in value or "canary" in value:
            return True
    return False


def _has_xxe_entity_witness(runs: list[RuntimeEvidence], intercepts: set[str]) -> bool:
    args = _call_args(runs, intercepts)
    for raw in args:
        value = raw.casefold()
        if "<!doctype" in value and ("<!entity" in value or " system " in value):
            return True
    return False


def _derived_class_flags(
    class_key: str,
    positive_runs: list[RuntimeEvidence],
    negative_runs: list[RuntimeEvidence],
    intercept_set: set[str],
    canary: str,
    config: PadvConfig,
) -> tuple[set[str], set[str]]:
    positive_flags: set[str] = set()
    negative_flags: set[str] = set()

    oracle_witness = _CLASS_ORACLE_WITNESS_FLAGS.get(class_key)
    if oracle_witness:
        min_positive_hits = min(2, len(positive_runs)) if positive_runs else 0
        pos_hits = _oracle_hit_count(positive_runs, intercept_set, canary, config)
        neg_hits = _oracle_hit_count(negative_runs, intercept_set, canary, config)
        if min_positive_hits > 0 and pos_hits >= min_positive_hits:
            positive_flags.add(oracle_witness)
        if neg_hits > 0:
            negative_flags.add(oracle_witness)

    if class_key == "sql_injection_boundary":
        if _has_status_diff(positive_runs, negative_runs):
            positive_flags.add("sql_status_diff_witness")
        if _has_body_diff(positive_runs, negative_runs):
            positive_flags.add("sql_body_diff_witness")
        if _has_sql_error_witness(positive_runs, negative_runs):
            positive_flags.add("sql_error_witness")
    elif class_key in {"ssrf", "outbound_request_influence"}:
        if _has_ssrf_url_arg_witness(positive_runs, intercept_set):
            positive_flags.add("ssrf_url_arg_witness")
        if _has_ssrf_url_arg_witness(negative_runs, intercept_set):
            negative_flags.add("ssrf_url_arg_witness")
    elif class_key == "xxe_influence":
        if _has_xxe_entity_witness(positive_runs, intercept_set):
            positive_flags.add("xxe_entity_witness")
        if _has_xxe_entity_witness(negative_runs, intercept_set):
            negative_flags.add("xxe_entity_witness")

    return positive_flags, negative_flags


def evaluate_candidate(
    config: PadvConfig,
    static_evidence: list[StaticEvidence],
    positive_runs: list[RuntimeEvidence],
    negative_runs: list[RuntimeEvidence],
    intercepts: list[str],
    canary: str,
    preconditions: list[str],
    evidence_signals: list[str] | None = None,
    vuln_class: str | None = None,
    differential_pairs: list[DifferentialPair] | None = None,
) -> GateResult:
    passed: list[str] = []

    if any(run.status in {"auth_failed", "missing_key", "missing_intercept", "inactive", "request_failed"} for run in positive_runs):
        return GateResult("DROPPED", passed, "V0", "runtime not in valid scope")
    passed.append("V0")

    if preconditions:
        return GateResult("NEEDS_HUMAN_SETUP", passed, "V1", "preconditions unresolved")
    passed.append("V1")

    if not static_evidence:
        return GateResult("DROPPED", passed, "V2", "missing static evidence")
    if not positive_runs:
        return GateResult("DROPPED", passed, "V2", "missing runtime evidence")
    signal_set = {s.strip().lower() for s in (evidence_signals or []) if isinstance(s, str) and s.strip()}
    if len(signal_set) < 2:
        return GateResult("DROPPED", passed, "V2", "insufficient multi-evidence corroboration")
    passed.append("V2")

    class_key = (vuln_class or "").strip().casefold()
    intercept_set = set(intercepts)
    positive_flags = _flag_set(positive_runs)
    negative_flags = _flag_set(negative_runs)
    if class_key in AUTHZ_VULN_CLASSES and differential_pairs:
        if any(pair.response_equivalent for pair in differential_pairs):
            positive_flags.add("authz_bypass_status")
            positive_flags.add("authz_pair_observed")

    derived_positive, derived_negative = _derived_class_flags(
        class_key,
        positive_runs=positive_runs,
        negative_runs=negative_runs,
        intercept_set=intercept_set,
        canary=canary,
        config=config,
    )
    positive_flags |= derived_positive
    negative_flags |= derived_negative

    if class_key in _RUNTIME_VALIDATABLE_CLASSES:
        rule = _CLASS_WITNESS_RULES.get(class_key)
        if rule is None:
            return GateResult("DROPPED", passed, "V3", "runtime witness rule missing for class")
        required_all = {
            str(x).strip().casefold()
            for x in rule.get("required_all", set())
            if str(x).strip()
        }
        required_any = {
            str(x).strip().casefold()
            for x in rule.get("required_any", set())
            if str(x).strip()
        }

        if required_all and not required_all.issubset(positive_flags):
            return GateResult("DROPPED", passed, "V3", "runtime class witness missing")
        if required_any and not (positive_flags & required_any):
            return GateResult("DROPPED", passed, "V3", "runtime class witness missing")
        passed.append("V3")

        enforce_negative_clean = bool(rule.get("enforce_negative_clean", True))
        witness_flags = required_all | required_any
        if enforce_negative_clean and witness_flags and (negative_flags & witness_flags):
            return GateResult("DROPPED", passed, "V4", "negative control matched class witness")
        passed.append("V4")
    else:
        # Legacy fallback for non-runtime classes and unknown classes only.
        positive_hits = [
            _has_oracle_hit(run, intercept_set, canary, config)
            for run in positive_runs
        ]
        if not all(positive_hits):
            return GateResult("DROPPED", passed, "V3", "canary boundary proof missing")
        passed.append("V3")

        negative_hits = [
            _has_oracle_hit(run, intercept_set, canary, config)
            for run in negative_runs
        ]
        if any(negative_hits):
            return GateResult("DROPPED", passed, "V4", "negative control hit canary")
        passed.append("V4")

    if len(positive_runs) < 3 or len(negative_runs) < 1:
        return GateResult("DROPPED", passed, "V5", "insufficient repro runs")
    if any(run.overflow or run.result_truncated for run in positive_runs + negative_runs):
        return GateResult("DROPPED", passed, "V5", "runtime evidence truncated")
    passed.append("V5")

    passed.append("V6")
    return GateResult("VALIDATED", passed, None, "all required gates passed")

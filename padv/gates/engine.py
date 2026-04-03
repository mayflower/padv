from __future__ import annotations

from padv.config.schema import PadvConfig
from padv.models import Candidate, DifferentialPair, GateResult, RuntimeEvidence, StaticEvidence
from padv.taxonomy import (
    AUTHZ_VULN_CLASSES,
    CLASS_ORACLE_WITNESS_FLAGS,
    SQL_ERROR_MARKERS,
    canonicalize_vuln_class,
    contains_canary,
    runtime_validatable_classes,
)


REQUIRED_GATES = ["V0", "V1", "V2", "V3", "V4", "V5", "V6"]

_RUNTIME_VALIDATABLE_CLASSES = runtime_validatable_classes()

_CLASS_ORACLE_WITNESS_FLAGS = CLASS_ORACLE_WITNESS_FLAGS

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

_SQL_ERROR_MARKERS = SQL_ERROR_MARKERS


def _contains_canary(arg: str, canary: str, allow_casefold: bool, allow_url_decode: bool) -> bool:
    return contains_canary(arg, canary, allow_casefold, allow_url_decode)


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
        witness = getattr(run, "witness_evidence", None)
        witness_flags = getattr(witness, "witness_flags", []) if witness is not None else []
        for flag in witness_flags:
            if isinstance(flag, str) and flag.strip():
                out.add(flag.strip().casefold())
        witness_data = getattr(witness, "witness_data", {}) or {}
        for key, value in witness_data.items():
            if value:
                out.add(key.strip().casefold())
    return out


def _oracle_hit_count(
    runs: list[RuntimeEvidence],
    intercepts: set[str],
    canary: str,
    config: PadvConfig,
) -> int:
    return sum(1 for run in runs if _has_oracle_hit(run, intercepts, canary, config))


def _typed_oracle_hit_count(runs: list[RuntimeEvidence], intercepts: set[str]) -> int:
    normalized = {x.casefold() for x in intercepts if isinstance(x, str) and x.strip()}
    count = 0
    for run in runs:
        evidence = getattr(run, "oracle_evidence", []) or []
        matched = False
        for item in evidence:
            function = str(getattr(item, "function", "")).strip().casefold()
            if normalized and function not in normalized:
                continue
            if bool(getattr(item, "matched_canary", False)):
                matched = True
                break
        if matched:
            count += 1
    return count


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


def _derive_oracle_witness_flags(
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
    if not oracle_witness:
        return positive_flags, negative_flags
    min_positive_hits = min(2, len(positive_runs)) if positive_runs else 0
    pos_hits = _typed_oracle_hit_count(positive_runs, intercept_set) or _oracle_hit_count(positive_runs, intercept_set, canary, config)
    neg_hits = _typed_oracle_hit_count(negative_runs, intercept_set) or _oracle_hit_count(negative_runs, intercept_set, canary, config)
    if min_positive_hits > 0 and pos_hits >= min_positive_hits:
        positive_flags.add(oracle_witness)
    if neg_hits > 0:
        negative_flags.add(oracle_witness)
    return positive_flags, negative_flags


def _derive_sql_injection_flags(
    positive_runs: list[RuntimeEvidence],
    negative_runs: list[RuntimeEvidence],
) -> set[str]:
    flags: set[str] = set()
    if _has_status_diff(positive_runs, negative_runs):
        flags.add("sql_status_diff_witness")
    if _has_body_diff(positive_runs, negative_runs):
        flags.add("sql_body_diff_witness")
    if _has_sql_error_witness(positive_runs, negative_runs):
        flags.add("sql_error_witness")
    return flags


def _derive_ssrf_flags(
    positive_runs: list[RuntimeEvidence],
    negative_runs: list[RuntimeEvidence],
    intercept_set: set[str],
) -> tuple[set[str], set[str]]:
    positive_flags: set[str] = set()
    negative_flags: set[str] = set()
    if _has_ssrf_url_arg_witness(positive_runs, intercept_set):
        positive_flags.add("ssrf_url_arg_witness")
    if _has_ssrf_url_arg_witness(negative_runs, intercept_set):
        negative_flags.add("ssrf_url_arg_witness")
    return positive_flags, negative_flags


def _derive_xxe_flags(
    positive_runs: list[RuntimeEvidence],
    negative_runs: list[RuntimeEvidence],
    intercept_set: set[str],
) -> tuple[set[str], set[str]]:
    positive_flags: set[str] = set()
    negative_flags: set[str] = set()
    if _has_xxe_entity_witness(positive_runs, intercept_set):
        positive_flags.add("xxe_entity_witness")
    if _has_xxe_entity_witness(negative_runs, intercept_set):
        negative_flags.add("xxe_entity_witness")
    return positive_flags, negative_flags


def _derived_class_flags(
    class_key: str,
    positive_runs: list[RuntimeEvidence],
    negative_runs: list[RuntimeEvidence],
    intercept_set: set[str],
    canary: str,
    config: PadvConfig,
) -> tuple[set[str], set[str]]:
    positive_flags, negative_flags = _derive_oracle_witness_flags(
        class_key, positive_runs, negative_runs, intercept_set, canary, config,
    )

    if class_key == "sql_injection_boundary":
        positive_flags |= _derive_sql_injection_flags(positive_runs, negative_runs)
    elif class_key in {"ssrf", "outbound_request_influence"}:
        extra_pos, extra_neg = _derive_ssrf_flags(positive_runs, negative_runs, intercept_set)
        positive_flags |= extra_pos
        negative_flags |= extra_neg
    elif class_key == "xxe_influence":
        extra_pos, extra_neg = _derive_xxe_flags(positive_runs, negative_runs, intercept_set)
        positive_flags |= extra_pos
        negative_flags |= extra_neg

    return positive_flags, negative_flags


def _evaluate_v0_scope(
    positive_runs: list[RuntimeEvidence],
    negative_runs: list[RuntimeEvidence],
) -> tuple[list[RuntimeEvidence], list[RuntimeEvidence], GateResult | None]:
    hard_scope_failures = {"auth_failed", "missing_key", "missing_intercept", "inactive"}
    if any(run.status in hard_scope_failures for run in positive_runs):
        return [], [], GateResult("DROPPED", [], "V0", "runtime not in valid scope")
    in_scope_positive = [run for run in positive_runs if run.status != "request_failed"]
    in_scope_negative = [run for run in negative_runs if run.status != "request_failed"]
    if not in_scope_positive or not in_scope_negative:
        return [], [], GateResult("DROPPED", [], "V0", "runtime not in valid scope")
    return in_scope_positive, in_scope_negative, None


def _evaluate_v2_corroboration(
    static_evidence: list[StaticEvidence],
    in_scope_positive_runs: list[RuntimeEvidence],
    evidence_signals: list[str] | None,
    passed: list[str],
) -> GateResult | None:
    if not static_evidence:
        return GateResult("DROPPED", passed, "V2", "missing static evidence")
    if not in_scope_positive_runs:
        return GateResult("DROPPED", passed, "V2", "missing runtime evidence")
    signal_set = {s.strip().lower() for s in (evidence_signals or []) if isinstance(s, str) and s.strip()}
    if len(signal_set) < 2:
        return GateResult("DROPPED", passed, "V2", "insufficient multi-evidence corroboration")
    return None


def _evaluate_v3v4_runtime_class(
    rule: dict[str, object],
    positive_flags: set[str],
    negative_flags: set[str],
    passed: list[str],
) -> GateResult | None:
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
    return None


def _run_has_canary_hit(run: RuntimeEvidence, intercept_set: set[str], canary: str, config: PadvConfig) -> bool:
    typed_hit = any(bool(getattr(item, "matched_canary", False)) for item in getattr(run, "oracle_evidence", []) or [])
    return typed_hit or _has_oracle_hit(run, intercept_set, canary, config)


def _evaluate_v3v4_legacy(
    in_scope_positive_runs: list[RuntimeEvidence],
    in_scope_negative_runs: list[RuntimeEvidence],
    intercept_set: set[str],
    canary: str,
    config: PadvConfig,
    passed: list[str],
) -> GateResult | None:
    if not all(_run_has_canary_hit(run, intercept_set, canary, config) for run in in_scope_positive_runs):
        return GateResult("DROPPED", passed, "V3", "canary boundary proof missing")
    passed.append("V3")

    if any(_run_has_canary_hit(run, intercept_set, canary, config) for run in in_scope_negative_runs):
        return GateResult("DROPPED", passed, "V4", "negative control hit canary")
    passed.append("V4")
    return None


def _prepare_class_flags(
    class_key: str,
    positive_runs: list[RuntimeEvidence],
    negative_runs: list[RuntimeEvidence],
    in_scope_positive_runs: list[RuntimeEvidence],
    in_scope_negative_runs: list[RuntimeEvidence],
    intercept_set: set[str],
    canary: str,
    config: PadvConfig,
    differential_pairs: list[DifferentialPair] | None,
) -> tuple[set[str], set[str]]:
    positive_flags = _flag_set(positive_runs)
    negative_flags = _flag_set(negative_runs)
    if class_key in AUTHZ_VULN_CLASSES and differential_pairs:
        if any(pair.response_equivalent for pair in differential_pairs):
            positive_flags.add("authz_bypass_status")
            positive_flags.add("authz_pair_observed")

    derived_positive, derived_negative = _derived_class_flags(
        class_key,
        positive_runs=in_scope_positive_runs,
        negative_runs=in_scope_negative_runs,
        intercept_set=intercept_set,
        canary=canary,
        config=config,
    )
    positive_flags |= derived_positive
    negative_flags |= derived_negative
    return positive_flags, negative_flags


def _evaluate_v3v4(
    class_key: str,
    positive_flags: set[str],
    negative_flags: set[str],
    in_scope_positive_runs: list[RuntimeEvidence],
    in_scope_negative_runs: list[RuntimeEvidence],
    intercept_set: set[str],
    canary: str,
    config: PadvConfig,
    passed: list[str],
) -> GateResult | None:
    if class_key in _RUNTIME_VALIDATABLE_CLASSES:
        rule = _CLASS_WITNESS_RULES.get(class_key)
        if rule is None:
            return GateResult("DROPPED", passed, "V3", "runtime witness rule missing for class")
        return _evaluate_v3v4_runtime_class(rule, positive_flags, negative_flags, passed)
    return _evaluate_v3v4_legacy(
        in_scope_positive_runs, in_scope_negative_runs, intercept_set, canary, config, passed,
    )


def _evaluate_v5(
    in_scope_positive_runs: list[RuntimeEvidence],
    in_scope_negative_runs: list[RuntimeEvidence],
    passed: list[str],
) -> GateResult | None:
    if len(in_scope_positive_runs) < 2 or len(in_scope_negative_runs) < 1:
        return GateResult("DROPPED", passed, "V5", "insufficient repro runs")
    if any(run.overflow or run.result_truncated for run in in_scope_positive_runs + in_scope_negative_runs):
        return GateResult("DROPPED", passed, "V5", "runtime evidence truncated")
    return None


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
    candidate: Candidate | None = None,
) -> GateResult:
    passed: list[str] = []
    if candidate is not None and str(getattr(candidate, "validation_mode", "")).strip() == "analysis_only":
        return GateResult("CONFIRMED_ANALYSIS_FINDING", ["A0"], None, "analysis-only candidate confirmed by static and research evidence")

    in_scope_positive_runs, in_scope_negative_runs, v0_fail = _evaluate_v0_scope(positive_runs, negative_runs)
    if v0_fail is not None:
        return v0_fail
    passed.append("V0")

    if preconditions:
        return GateResult("NEEDS_HUMAN_SETUP", passed, "V1", "preconditions unresolved")
    passed.append("V1")

    v2_fail = _evaluate_v2_corroboration(static_evidence, in_scope_positive_runs, evidence_signals, passed)
    if v2_fail is not None:
        return v2_fail
    passed.append("V2")

    class_key = canonicalize_vuln_class(
        getattr(candidate, "canonical_class", "") or vuln_class or getattr(candidate, "vuln_class", "")
    )
    intercept_set = set(intercepts)
    positive_flags, negative_flags = _prepare_class_flags(
        class_key, positive_runs, negative_runs,
        in_scope_positive_runs, in_scope_negative_runs,
        intercept_set, canary, config, differential_pairs,
    )

    v3v4_fail = _evaluate_v3v4(
        class_key, positive_flags, negative_flags,
        in_scope_positive_runs, in_scope_negative_runs,
        intercept_set, canary, config, passed,
    )
    if v3v4_fail is not None:
        return v3v4_fail

    v5_fail = _evaluate_v5(in_scope_positive_runs, in_scope_negative_runs, passed)
    if v5_fail is not None:
        return v5_fail
    passed.append("V5")

    passed.append("V6")
    return GateResult("VALIDATED", passed, None, "all required gates passed")

from __future__ import annotations

import hashlib
from dataclasses import replace
from typing import cast

from padv.config.schema import PadvConfig
from padv.models import Candidate, DifferentialPair, RuntimeEvidence, ValidationClassProfile, Witness, WitnessContract
from padv.static.joern.query_sets import VULN_CLASS_SPECS
from padv.taxonomy import (
    AUTHZ_VULN_CLASSES,
    CLASS_ORACLE_WITNESS_FLAGS,
    SQL_ERROR_MARKERS,
    canonicalize_vuln_class,
    contains_canary,
    runtime_validatable_classes,
)

_RUNTIME_VALIDATABLE = {
    canonicalize_vuln_class(spec.vuln_class): bool(spec.runtime_validatable)
    for spec in VULN_CLASS_SPECS
}

_ANALYSIS_ONLY_CLASSES = {
    "security_misconfiguration",
    "logging_monitoring_failures",
    "crypto_failures",
    "debug_output_leak",
    "information_disclosure",
}

_RUNTIME_VALIDATABLE_CLASSES = runtime_validatable_classes()

_CLASS_ORACLE_WITNESS_FLAGS = CLASS_ORACLE_WITNESS_FLAGS

_SQL_ERROR_MARKERS = SQL_ERROR_MARKERS

_WITNESS_CONTRACT_OVERRIDES: dict[str, dict[str, object]] = {
    "sql_injection_boundary": {
        "required_all": ["sql_sink_oracle_witness"],
        "required_any": ["sql_status_diff_witness", "sql_body_diff_witness", "sql_error_witness"],
    },
    "command_injection_boundary": {"required_all": ["command_sink_oracle_witness"], "required_any": []},
    "code_injection_boundary": {"required_all": ["code_sink_oracle_witness"], "required_any": []},
    "ldap_injection_boundary": {"required_all": ["ldap_sink_oracle_witness"], "required_any": []},
    "xpath_injection_boundary": {"required_all": ["xpath_sink_oracle_witness"], "required_any": []},
    "file_boundary_influence": {"required_all": ["file_sink_oracle_witness"], "required_any": []},
    "file_upload_influence": {"required_all": ["upload_sink_oracle_witness"], "required_any": []},
    "xss_output_boundary": {"required_all": ["xss_dom_witness"], "required_any": []},
    "debug_output_leak": {"required_all": [], "required_any": ["debug_leak", "verbose_error_leak", "phpinfo_marker"]},
    "information_disclosure": {"required_all": [], "required_any": ["info_disclosure_header", "verbose_error_leak", "phpinfo_marker"]},
    "outbound_request_influence": {"required_all": ["ssrf_sink_oracle_witness", "ssrf_url_arg_witness"], "required_any": []},
    "ssrf": {"required_all": ["ssrf_sink_oracle_witness", "ssrf_url_arg_witness"], "required_any": []},
    "xxe_influence": {"required_all": ["xxe_sink_oracle_witness", "xxe_entity_witness"], "required_any": []},
    "deserialization_influence": {"required_all": ["deserialization_sink_oracle_witness"], "required_any": []},
    "php_object_gadget_surface": {"required_all": ["gadget_sink_oracle_witness"], "required_any": []},
    "header_injection_boundary": {"required_all": ["header_sink_oracle_witness"], "required_any": []},
    "regex_dos_boundary": {"required_all": ["regex_sink_oracle_witness"], "required_any": []},
    "xml_dos_boundary": {"required_all": ["xml_sink_oracle_witness"], "required_any": []},
    "broken_access_control": {"required_all": ["authz_bypass_status", "authz_pair_observed"], "required_any": []},
    "csrf_invariant_missing": {"required_all": ["csrf_missing_token_acceptance"], "required_any": []},
    "idor_invariant_missing": {"required_all": ["idor_bypass", "authz_bypass_status", "authz_pair_observed"], "required_any": []},
    "session_fixation_invariant": {"required_all": [], "required_any": ["session_id_not_rotated", "session_cookie_not_rotated"]},
    "security_misconfiguration": {"required_all": ["misconfiguration_sink_oracle_witness"], "required_any": []},
    "auth_and_session_failures": {"required_all": ["auth_bypass", "authz_bypass_status", "authz_pair_observed"], "required_any": []},
}

_PROFILE_OVERRIDES: dict[str, dict[str, object]] = {
    "sql_injection_boundary": {
        "allowed_transports": ["query", "form", "json", "xml", "path"],
        "required_request_shape": ["endpoint", "content_type", "parameter_binding"],
        "required_negative_controls": ["same_endpoint_benign_literal", "same_structure_non_injecting_control"],
        "auth_handling": "reuse_or_observe_session",
        "min_positive_requests": 2,
        "min_negative_controls": 2,
    },
    "command_injection_boundary": {
        "allowed_transports": ["query", "form", "json", "xml", "path"],
        "required_request_shape": ["endpoint", "parameter_binding"],
        "required_negative_controls": ["same_structure_no_metacharacters"],
        "auth_handling": "reuse_or_observe_session",
        "min_positive_requests": 2,
        "min_negative_controls": 1,
    },
    "xss_output_boundary": {
        "allowed_transports": ["query", "form", "json", "path", "headers", "cookies"],
        "required_request_shape": ["endpoint", "reflection_path"],
        "required_negative_controls": ["same_sink_inert_marker", "same_sink_encoded_marker"],
        "auth_handling": "reuse_or_observe_session",
        "min_positive_requests": 2,
        "min_negative_controls": 2,
    },
    "outbound_request_influence": {
        "allowed_transports": ["query", "form", "json", "xml", "path"],
        "required_request_shape": ["endpoint", "url_parameter"],
        "required_negative_controls": ["same_route_local_non_callback_target"],
        "auth_handling": "reuse_or_observe_session",
        "min_positive_requests": 2,
        "min_negative_controls": 1,
    },
    "ssrf": {
        "allowed_transports": ["query", "form", "json", "xml", "path"],
        "required_request_shape": ["endpoint", "url_parameter"],
        "required_negative_controls": ["same_route_local_non_callback_target"],
        "auth_handling": "reuse_or_observe_session",
        "min_positive_requests": 2,
        "min_negative_controls": 1,
    },
    "xxe_influence": {
        "allowed_transports": ["xml", "form", "json"],
        "required_request_shape": ["endpoint", "xml_body"],
        "required_negative_controls": ["same_structure_without_external_entity"],
        "auth_handling": "reuse_or_observe_session",
        "min_positive_requests": 2,
        "min_negative_controls": 1,
    },
    "file_boundary_influence": {
        "allowed_transports": ["query", "form", "json", "path"],
        "required_request_shape": ["endpoint", "path_parameter"],
        "required_negative_controls": ["same_route_benign_local_file"],
        "auth_handling": "reuse_or_observe_session",
        "min_positive_requests": 2,
        "min_negative_controls": 1,
    },
    "file_upload_influence": {
        "allowed_transports": ["multipart", "form"],
        "required_request_shape": ["endpoint", "multipart_file_part"],
        "required_negative_controls": ["same_route_inert_file"],
        "auth_handling": "reuse_or_observe_session",
        "min_positive_requests": 2,
        "min_negative_controls": 1,
    },
    "deserialization_influence": {
        "allowed_transports": ["query", "form", "json", "cookies", "headers"],
        "required_request_shape": ["endpoint", "serialized_payload_binding"],
        "required_negative_controls": ["same_structure_non_gadget_payload"],
        "auth_handling": "reuse_or_observe_session",
        "min_positive_requests": 2,
        "min_negative_controls": 1,
    },
    "php_object_gadget_surface": {
        "allowed_transports": ["query", "form", "json", "cookies", "headers"],
        "required_request_shape": ["endpoint", "serialized_payload_binding"],
        "required_negative_controls": ["same_structure_non_gadget_payload"],
        "auth_handling": "reuse_or_observe_session",
        "min_positive_requests": 2,
        "min_negative_controls": 1,
    },
    "broken_access_control": {
        "allowed_transports": ["query", "form", "json", "path"],
        "required_request_shape": ["endpoint", "target_object", "auth_state_transition"],
        "required_negative_controls": ["same_target_unprivileged_control"],
        "auth_handling": "differential_auth_required",
        "min_positive_requests": 1,
        "min_negative_controls": 1,
    },
    "idor_invariant_missing": {
        "allowed_transports": ["query", "form", "json", "path"],
        "required_request_shape": ["endpoint", "target_object", "auth_state_transition"],
        "required_negative_controls": ["same_target_unprivileged_control"],
        "auth_handling": "differential_auth_required",
        "min_positive_requests": 1,
        "min_negative_controls": 1,
    },
    "csrf_invariant_missing": {
        "allowed_transports": ["form", "json", "query"],
        "required_request_shape": ["state_change", "auth_state_transition"],
        "required_negative_controls": ["same_action_with_token"],
        "auth_handling": "differential_auth_required",
        "min_positive_requests": 1,
        "min_negative_controls": 1,
    },
    "session_fixation_invariant": {
        "allowed_transports": ["query", "form", "headers", "cookies"],
        "required_request_shape": ["session_transition"],
        "required_negative_controls": ["fresh_session_control"],
        "auth_handling": "differential_auth_required",
        "min_positive_requests": 1,
        "min_negative_controls": 1,
    },
    "auth_and_session_failures": {
        "allowed_transports": ["query", "form", "json", "path"],
        "required_request_shape": ["endpoint", "auth_state_transition"],
        "required_negative_controls": ["same_route_unprivileged_control"],
        "auth_handling": "differential_auth_required",
        "min_positive_requests": 1,
        "min_negative_controls": 1,
    },
}

_ANALYSIS_ONLY_DEFAULT = {
    "allowed_transports": [],
    "required_request_shape": [],
    "required_witnesses": [],
    "required_negative_controls": [],
    "auth_handling": "none",
    "min_positive_requests": 0,
    "min_negative_controls": 0,
}


def runtime_witness_contracts() -> dict[str, WitnessContract]:
    return {
        canonical: witness_contract_for_vuln_class(canonical)
        for canonical in _WITNESS_CONTRACT_OVERRIDES
    }


def witness_contract_for_vuln_class(vuln_class: str | None) -> WitnessContract:
    canonical = canonicalize_vuln_class(vuln_class)
    override = _WITNESS_CONTRACT_OVERRIDES.get(canonical, {})
    required_all = [str(x).strip() for x in override.get("required_all", []) if str(x).strip()]
    required_any = [str(x).strip() for x in override.get("required_any", []) if str(x).strip()]
    enforce_negative_clean = bool(override.get("enforce_negative_clean", True))
    negative_must_not_include = [str(x).strip() for x in override.get("negative_must_not_include", []) if str(x).strip()]
    if enforce_negative_clean and not negative_must_not_include:
        negative_must_not_include = [*required_all, *required_any]
    return WitnessContract(
        canonical_class=canonical,
        required_all=required_all,
        required_any=required_any,
        negative_must_not_include=negative_must_not_include,
        enforce_negative_clean=enforce_negative_clean,
    )


def _profile_required_witnesses(contract: WitnessContract) -> list[str]:
    required = list(contract.required_all)
    if contract.required_any:
        required.append("|".join(contract.required_any))
    return required


def _contains_canary(arg: str, canary: str, config: PadvConfig) -> bool:
    return contains_canary(
        arg,
        canary,
        allow_casefold=config.canary.allow_casefold,
        allow_url_decode=config.canary.allow_url_decode,
    )


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
            if _contains_canary(arg, canary, config):
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


def build_runtime_witness(
    *,
    config: PadvConfig,
    vuln_class: str | None,
    positive_runs: list[RuntimeEvidence],
    negative_runs: list[RuntimeEvidence],
    intercepts: list[str],
    canary: str,
    differential_pairs: list[DifferentialPair] | None = None,
) -> Witness:
    class_key = canonicalize_vuln_class(vuln_class)
    intercept_set = {str(x).strip() for x in intercepts if str(x).strip()}
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
    return Witness(
        canonical_class=class_key,
        positive_flags=sorted(positive_flags),
        negative_flags=sorted(negative_flags),
    )


def profile_for_vuln_class(vuln_class: str | None) -> ValidationClassProfile:
    canonical = canonicalize_vuln_class(vuln_class)
    contract = witness_contract_for_vuln_class(canonical)
    runtime_validatable = bool(_RUNTIME_VALIDATABLE.get(canonical, False)) and canonical not in _ANALYSIS_ONLY_CLASSES
    validation_mode = "runtime" if runtime_validatable else "analysis_only"
    base = _ANALYSIS_ONLY_DEFAULT.copy()
    if runtime_validatable:
        base.update(
            {
                "allowed_transports": ["query", "form", "json", "xml", "headers", "cookies", "path"],
                "required_request_shape": ["endpoint"],
                "required_witnesses": _profile_required_witnesses(contract),
                "required_negative_controls": ["same_route_control"],
                "auth_handling": "reuse_or_observe_session",
                "min_positive_requests": 2,
                "min_negative_controls": 1,
            }
        )
    base.update(_PROFILE_OVERRIDES.get(canonical, {}))
    base["required_witnesses"] = _profile_required_witnesses(contract)
    return ValidationClassProfile(
        canonical_class=canonical,
        validation_mode=validation_mode,
        class_contract_id=f"{validation_mode}:{canonical or 'unknown'}",
        required_request_shape=list(base["required_request_shape"]),
        required_witnesses=list(base["required_witnesses"]),
        required_negative_controls=list(base["required_negative_controls"]),
        allowed_transports=list(base["allowed_transports"]),
        auth_handling=str(base["auth_handling"]),
        min_positive_requests=int(base["min_positive_requests"]),
        min_negative_controls=int(base["min_negative_controls"]),
    )


def canonical_issue_id(candidate: Candidate) -> str:
    canonical = canonicalize_vuln_class(candidate.canonical_class or candidate.vuln_class)
    payload = "|".join(
        [
            canonical,
            str(candidate.file_path or ""),
            str(candidate.line or 0),
            str(candidate.sink or ""),
            str(candidate.entrypoint_hint or ""),
        ]
    )
    return hashlib.sha1(payload.encode("utf-8")).hexdigest()[:16]


def apply_validation_profile(candidate: Candidate) -> Candidate:
    profile = profile_for_vuln_class(candidate.canonical_class or candidate.vuln_class)
    updated = cast(Candidate, replace(candidate))
    updated.canonical_class = profile.canonical_class
    updated.validation_mode = profile.validation_mode
    if not updated.canonical_issue_id:
        updated.canonical_issue_id = canonical_issue_id(updated)
    return updated


def is_runtime_validatable(candidate: Candidate | str | None) -> bool:
    if isinstance(candidate, Candidate):
        key = candidate.canonical_class or candidate.vuln_class
    else:
        key = str(candidate or "")
    return profile_for_vuln_class(key).validation_mode == "runtime"

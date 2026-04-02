from __future__ import annotations

import hashlib
from dataclasses import replace
from typing import cast

from padv.models import Candidate, ValidationClassProfile
from padv.static.joern.query_sets import VULN_CLASS_SPECS
from padv.taxonomy import canonicalize_vuln_class

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

_PROFILE_OVERRIDES: dict[str, dict[str, object]] = {
    "sql_injection_boundary": {
        "allowed_transports": ["query", "form", "json", "xml", "path"],
        "required_request_shape": ["endpoint", "content_type", "parameter_binding"],
        "required_witnesses": ["sql_sink_oracle_witness", "sql_error_witness|sql_status_diff_witness|sql_body_diff_witness", "sql_canary_arg_match"],
        "required_negative_controls": ["same_endpoint_benign_literal", "same_structure_non_injecting_control"],
        "auth_handling": "reuse_or_observe_session",
        "min_positive_requests": 2,
        "min_negative_controls": 2,
    },
    "command_injection_boundary": {
        "allowed_transports": ["query", "form", "json", "xml", "path"],
        "required_request_shape": ["endpoint", "parameter_binding"],
        "required_witnesses": ["command_sink_oracle_witness", "command_canary_arg_match"],
        "required_negative_controls": ["same_structure_no_metacharacters"],
        "auth_handling": "reuse_or_observe_session",
        "min_positive_requests": 2,
        "min_negative_controls": 1,
    },
    "xss_output_boundary": {
        "allowed_transports": ["query", "form", "json", "path", "headers", "cookies"],
        "required_request_shape": ["endpoint", "reflection_path"],
        "required_witnesses": ["xss_dom_witness"],
        "required_negative_controls": ["same_sink_inert_marker", "same_sink_encoded_marker"],
        "auth_handling": "reuse_or_observe_session",
        "min_positive_requests": 2,
        "min_negative_controls": 2,
    },
    "outbound_request_influence": {
        "allowed_transports": ["query", "form", "json", "xml", "path"],
        "required_request_shape": ["endpoint", "url_parameter"],
        "required_witnesses": ["ssrf_sink_oracle_witness", "ssrf_url_arg_witness"],
        "required_negative_controls": ["same_route_local_non_callback_target"],
        "auth_handling": "reuse_or_observe_session",
        "min_positive_requests": 2,
        "min_negative_controls": 1,
    },
    "ssrf": {
        "allowed_transports": ["query", "form", "json", "xml", "path"],
        "required_request_shape": ["endpoint", "url_parameter"],
        "required_witnesses": ["ssrf_sink_oracle_witness", "ssrf_url_arg_witness"],
        "required_negative_controls": ["same_route_local_non_callback_target"],
        "auth_handling": "reuse_or_observe_session",
        "min_positive_requests": 2,
        "min_negative_controls": 1,
    },
    "xxe_influence": {
        "allowed_transports": ["xml", "form", "json"],
        "required_request_shape": ["endpoint", "xml_body"],
        "required_witnesses": ["xxe_sink_oracle_witness", "xxe_entity_witness"],
        "required_negative_controls": ["same_structure_without_external_entity"],
        "auth_handling": "reuse_or_observe_session",
        "min_positive_requests": 2,
        "min_negative_controls": 1,
    },
    "file_boundary_influence": {
        "allowed_transports": ["query", "form", "json", "path"],
        "required_request_shape": ["endpoint", "path_parameter"],
        "required_witnesses": ["file_sink_oracle_witness"],
        "required_negative_controls": ["same_route_benign_local_file"],
        "auth_handling": "reuse_or_observe_session",
        "min_positive_requests": 2,
        "min_negative_controls": 1,
    },
    "file_upload_influence": {
        "allowed_transports": ["multipart", "form"],
        "required_request_shape": ["endpoint", "multipart_file_part"],
        "required_witnesses": ["upload_sink_oracle_witness"],
        "required_negative_controls": ["same_route_inert_file"],
        "auth_handling": "reuse_or_observe_session",
        "min_positive_requests": 2,
        "min_negative_controls": 1,
    },
    "deserialization_influence": {
        "allowed_transports": ["query", "form", "json", "cookies", "headers"],
        "required_request_shape": ["endpoint", "serialized_payload_binding"],
        "required_witnesses": ["deserialization_sink_oracle_witness"],
        "required_negative_controls": ["same_structure_non_gadget_payload"],
        "auth_handling": "reuse_or_observe_session",
        "min_positive_requests": 2,
        "min_negative_controls": 1,
    },
    "php_object_gadget_surface": {
        "allowed_transports": ["query", "form", "json", "cookies", "headers"],
        "required_request_shape": ["endpoint", "serialized_payload_binding"],
        "required_witnesses": ["gadget_sink_oracle_witness"],
        "required_negative_controls": ["same_structure_non_gadget_payload"],
        "auth_handling": "reuse_or_observe_session",
        "min_positive_requests": 2,
        "min_negative_controls": 1,
    },
    "broken_access_control": {
        "allowed_transports": ["query", "form", "json", "path"],
        "required_request_shape": ["endpoint", "target_object", "auth_state_transition"],
        "required_witnesses": ["authz_bypass_status", "authz_pair_observed"],
        "required_negative_controls": ["same_target_unprivileged_control"],
        "auth_handling": "differential_auth_required",
        "min_positive_requests": 1,
        "min_negative_controls": 1,
    },
    "idor_invariant_missing": {
        "allowed_transports": ["query", "form", "json", "path"],
        "required_request_shape": ["endpoint", "target_object", "auth_state_transition"],
        "required_witnesses": ["idor_bypass", "authz_pair_observed"],
        "required_negative_controls": ["same_target_unprivileged_control"],
        "auth_handling": "differential_auth_required",
        "min_positive_requests": 1,
        "min_negative_controls": 1,
    },
    "csrf_invariant_missing": {
        "allowed_transports": ["form", "json", "query"],
        "required_request_shape": ["state_change", "auth_state_transition"],
        "required_witnesses": ["csrf_missing_token_acceptance"],
        "required_negative_controls": ["same_action_with_token"],
        "auth_handling": "differential_auth_required",
        "min_positive_requests": 1,
        "min_negative_controls": 1,
    },
    "session_fixation_invariant": {
        "allowed_transports": ["query", "form", "headers", "cookies"],
        "required_request_shape": ["session_transition"],
        "required_witnesses": ["session_id_not_rotated|session_cookie_not_rotated"],
        "required_negative_controls": ["fresh_session_control"],
        "auth_handling": "differential_auth_required",
        "min_positive_requests": 1,
        "min_negative_controls": 1,
    },
    "auth_and_session_failures": {
        "allowed_transports": ["query", "form", "json", "path"],
        "required_request_shape": ["endpoint", "auth_state_transition"],
        "required_witnesses": ["auth_bypass", "authz_pair_observed"],
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


def profile_for_vuln_class(vuln_class: str | None) -> ValidationClassProfile:
    canonical = canonicalize_vuln_class(vuln_class)
    runtime_validatable = bool(_RUNTIME_VALIDATABLE.get(canonical, False)) and canonical not in _ANALYSIS_ONLY_CLASSES
    validation_mode = "runtime" if runtime_validatable else "analysis_only"
    base = _ANALYSIS_ONLY_DEFAULT.copy()
    if runtime_validatable:
        base.update(
            {
                "allowed_transports": ["query", "form", "json", "xml", "headers", "cookies", "path"],
                "required_request_shape": ["endpoint"],
                "required_witnesses": [],
                "required_negative_controls": ["same_route_control"],
                "auth_handling": "reuse_or_observe_session",
                "min_positive_requests": 2,
                "min_negative_controls": 1,
            }
        )
    base.update(_PROFILE_OVERRIDES.get(canonical, {}))
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

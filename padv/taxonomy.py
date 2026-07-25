from __future__ import annotations

import urllib.parse


_VULN_CLASS_ALIASES: dict[str, str] = {
    "sql_injection": "sql_injection_boundary",
    "command_injection": "command_injection_boundary",
    "code_injection": "code_injection_boundary",
    "ldap_injection": "ldap_injection_boundary",
    "xpath_injection": "xpath_injection_boundary",
    "cross_site_scripting": "xss_output_boundary",
    "file_inclusion_path_traversal": "file_boundary_influence",
    "unrestricted_file_upload": "file_upload_influence",
    "information_disclosure_misconfiguration": "information_disclosure",
    "xxe_xml_injection": "xxe_influence",
    "deserialization": "deserialization_influence",
    "header_cookie_manipulation": "header_injection_boundary",
    "regex_xml_dos": "regex_dos_boundary",
    "authn_authz_failures": "auth_and_session_failures",
}


def canonicalize_vuln_class(value: str | None) -> str:
    key = str(value or "").strip().casefold()
    if not key:
        return ""
    return _VULN_CLASS_ALIASES.get(key, key)


# ---------------------------------------------------------------------------
# Shared constants: single-source-of-truth for vuln-class-related data
# used by gates/engine.py, orchestrator/runtime.py, orchestrator/graphs.py,
# and orchestrator/differential.py.
# ---------------------------------------------------------------------------

CLASS_ORACLE_WITNESS_FLAGS: dict[str, str] = {
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

# Every witness flag the runtime can actually produce. A contract that requires
# something outside this set can never be satisfied, so the gate treats it as an
# experiment it cannot run rather than as a refutation. Kept in sync with the
# derivers by tests/test_witness_contract_vocabulary.py.
KNOWN_WITNESS_FLAGS: frozenset[str] = frozenset(
    {
        # sink oracle witnesses, one per class (see CLASS_ORACLE_WITNESS_FLAGS)
        "code_sink_oracle_witness",
        "command_sink_oracle_witness",
        "deserialization_sink_oracle_witness",
        "file_sink_oracle_witness",
        "gadget_sink_oracle_witness",
        "header_sink_oracle_witness",
        "ldap_sink_oracle_witness",
        "misconfiguration_sink_oracle_witness",
        "regex_sink_oracle_witness",
        "sql_sink_oracle_witness",
        "ssrf_sink_oracle_witness",
        "upload_sink_oracle_witness",
        "xml_sink_oracle_witness",
        "xpath_sink_oracle_witness",
        "xxe_sink_oracle_witness",
        # sink argument shape
        "ssrf_url_arg_witness",
        "xxe_entity_witness",
        # response differentials
        "sql_body_diff_witness",
        "sql_status_diff_witness",
        # reflection and execution context
        "body_canary",
        "xss_raw_canary",
        "xss_dom_witness",
        # authz, session and auth invariants
        "auth_bypass",
        "authz_bypass_status",
        "authz_pair_observed",
        "session_cookie_not_rotated",
        "session_id_not_rotated",
        # diagnostics: reported, never sufficient on their own
        "diagnostic_debug_leak",
        "diagnostic_phpinfo_marker",
        "diagnostic_sql_error",
        "diagnostic_verbose_error_leak",
        "info_disclosure_header",
    }
)

AUTHZ_VULN_CLASSES: frozenset[str] = frozenset(
    {
        "broken_access_control",
        "idor_invariant_missing",
        "auth_and_session_failures",
        "csrf_invariant_missing",
        "session_fixation_invariant",
    }
)

SQL_ERROR_MARKERS: tuple[str, ...] = (
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


def contains_canary(arg: str, canary: str, allow_casefold: bool, allow_url_decode: bool) -> bool:
    """Check whether *canary* appears inside *arg*, with optional case-folding
    and URL-decoding.  This is the single canonical implementation used by both
    the gate engine and the runtime validator."""
    candidates = [arg]
    if allow_url_decode:
        candidates.append(urllib.parse.unquote(arg))

    if allow_casefold:
        folded = canary.casefold()
        return any(folded in c.casefold() for c in candidates)
    return any(canary in c for c in candidates)


def runtime_validatable_classes() -> frozenset[str]:
    """Return the casefolded set of vuln classes that support runtime validation.

    Lazily imports ``VULN_CLASS_SPECS`` to avoid circular imports at module
    level (the Joern query_sets module is heavy)."""
    from padv.static.joern.query_sets import VULN_CLASS_SPECS

    return frozenset(
        spec.vuln_class.casefold()
        for spec in VULN_CLASS_SPECS
        if spec.runtime_validatable
    )

from __future__ import annotations


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

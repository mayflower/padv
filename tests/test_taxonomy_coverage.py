from __future__ import annotations

from pathlib import Path

from padv.static.joern.query_sets import VULN_CLASS_SPECS


def _normalized_patterns() -> list[str]:
    out: list[str] = []
    for spec in VULN_CLASS_SPECS:
        for pattern in spec.sink_patterns:
            out.append(pattern.casefold())
    return out


def test_requested_security_classes_exist() -> None:
    classes = {spec.vuln_class for spec in VULN_CLASS_SPECS}
    expected = {
        "command_injection_boundary",   # 1
        "code_injection_boundary",      # 1
        "sql_injection_boundary",       # 2
        "ldap_injection_boundary",      # 2
        "xpath_injection_boundary",     # 2
        "xss_output_boundary",          # 3
        "file_boundary_influence",      # 4
        "file_upload_influence",        # 4
        "xxe_influence",                # 5
        "ssrf",                         # 5
        "deserialization_influence",    # 6
        "header_injection_boundary",    # 7
        "regex_dos_boundary",           # 10
        "xml_dos_boundary",             # 10
        "csrf_invariant_missing",       # 11
        "idor_invariant_missing",       # 11
        "session_fixation_invariant",   # 11
        "information_disclosure",       # 12
    }
    assert expected.issubset(classes)


def test_requested_function_markers_are_covered() -> None:
    patterns = _normalized_patterns()
    required_markers = [
        # 1
        "exec(", "system(", "shell_exec(", "passthru(", "popen(", "proc_open(", "pcntl_exec(", "`", "eval(", "assert(",
        "preg_replace(", "create_function(",
        # 2
        "pdo::query", "pdo::exec", "mysqli_query", "mysqli_real_query", "mysqli::query", "mysqli_multi_query",
        "pg_query", "ldap_search(", "ldap_list(", "ldap_read(", "ldap_add(", "ldap_modify(",
        "domxpath::query", "domxpath::evaluate", "simplexmlelement::xpath",
        # 3
        "echo ", "print ", "printf(", "vprintf(", "die(", "exit(", "print_r(", "var_dump(", "var_export(",
        # 4
        "include(", "include_once(", "require(", "require_once(", "file_get_contents(", "fopen(", "readfile(",
        "file(", "show_source(", "highlight_file(", "move_uploaded_file(",
        # 5
        "domdocument::load(", "domdocument::loadxml(", "simplexml_load_file(", "simplexml_load_string(", "xml_parse(",
        "curl_exec", "curl_setopt", "curlopt_url", "fsockopen(", "pfsockopen(",
        # 6
        "unserialize(", "__wakeup(", "__destruct(", "__tostring(", "__call(", "__get(", "__set(",
        # 7
        "header(", "mail(", "mb_send_mail(",
        # 10
        "preg_match(", "preg_match_all(", "max_input_vars",
        # 11
        "$_session", "hash_equals(", "csrf_token", "$_get['id']", "session_regenerate_id(",
        # 12
        "phpinfo(", "display_errors",
    ]
    missing = [marker for marker in required_markers if not any(marker in pattern for pattern in patterns)]
    assert not missing, f"missing taxonomy markers: {missing}"


def test_phase1_fixes_are_runtime_validatable() -> None:
    runtime_map = {spec.vuln_class: spec.runtime_validatable for spec in VULN_CLASS_SPECS}
    for cls in (
        "php_object_gadget_surface",
        "regex_dos_boundary",
        "xml_dos_boundary",
        "security_misconfiguration",
    ):
        assert runtime_map.get(cls) is True, f"{cls} must be runtime_validatable"


def test_joern_script_covers_echo_for_xss() -> None:
    script = (
        Path(__file__).resolve().parents[1] / "padv" / "static" / "joern" / "queries" / "owasp_php.sc"
    ).read_text(encoding="utf-8")
    assert "xss_output_boundary" in script
    assert "echo" in script.casefold()

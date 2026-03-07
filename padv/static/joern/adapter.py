from __future__ import annotations

import hashlib
import json
import re
import shlex
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from urllib import error, request

from padv.config.schema import PadvConfig
from padv.models import Candidate, StaticEvidence
from padv.path_scope import is_app_candidate_path, normalize_repo_path
from padv.static.joern.query_sets import VULN_CLASS_SPECS, VulnClassSpec, intercepts_for_class


class JoernExecutionError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class JoernFinding:
    vuln_class: str
    query_id: str
    file_path: str
    line: int
    sink: str
    snippet: str


@dataclass(slots=True)
class JoernDiscoveryMeta:
    joern_findings: int = 0
    joern_app_findings: int = 0
    joern_candidate_count: int = 0
    manifest_candidates: int = 0


_SPEC_BY_CLASS = {spec.vuln_class: spec for spec in VULN_CLASS_SPECS}
_ANSI_RE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
_RESULT_MARKER = re.compile(r"<padv_result>\s*(\[.*\])\s*</padv_result>", re.DOTALL)


def _hash_for(file_path: str, line: int, text: str) -> str:
    payload = f"{file_path}:{line}:{text}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()[:16]


def _preconditions_for_spec(spec: VulnClassSpec, config: PadvConfig) -> list[str]:
    return (
        (["auth-state-known"] if config.auth.enabled else [])
        + ([] if spec.runtime_validatable else ["runtime-oracle-not-applicable"])
    )


def _make_candidate_and_evidence(
    candidate_id: str,
    spec: VulnClassSpec,
    file_path: str,
    line: int,
    sink: str,
    snippet: str,
    query_profile: str,
    query_id: str,
    notes: str,
    config: PadvConfig,
) -> tuple[Candidate, StaticEvidence]:
    evidence_ref = f"{query_id}:{file_path}:{line}"
    candidate = Candidate(
        candidate_id=candidate_id,
        vuln_class=spec.vuln_class,
        title=f"{spec.owasp_id} {spec.description}",
        file_path=file_path,
        line=line,
        sink=sink,
        expected_intercepts=intercepts_for_class(spec.vuln_class),
        entrypoint_hint=None,
        preconditions=_preconditions_for_spec(spec, config),
        notes=notes,
        provenance=(["manifest"] if query_id.startswith("manifest::") else ["joern"]),
        evidence_refs=[evidence_ref],
        confidence=(0.55 if query_id.startswith("manifest::") else 0.6),
        auth_requirements=(["login"] if config.auth.enabled else []),
        web_path_hints=[],
    )
    evidence = StaticEvidence(
        candidate_id=candidate_id,
        query_profile=query_profile,
        query_id=query_id,
        file_path=file_path,
        line=line,
        snippet=snippet[:240],
        hash=_hash_for(file_path, line, snippet),
    )
    return candidate, evidence


def _default_joern_script_path() -> Path:
    return Path(__file__).resolve().parent / "queries" / "owasp_php.sc"


def _parse_joern_items(items: list[object]) -> list[JoernFinding]:
    findings: list[JoernFinding] = []
    for item in items:
        if not isinstance(item, dict):
            continue

        vuln_class = str(item.get("vuln_class", "")).strip()
        query_id = str(item.get("query_id", "")).strip()
        file_path = str(item.get("file_path", "")).strip()
        sink = str(item.get("sink", "")).strip()
        snippet = str(item.get("snippet", "")).strip()
        line_value = item.get("line", 0)
        try:
            line_no = int(line_value)
        except Exception:
            line_no = 0

        if not vuln_class or not file_path or line_no <= 0:
            continue

        findings.append(
            JoernFinding(
                vuln_class=vuln_class,
                query_id=query_id or f"joern::{vuln_class}",
                file_path=file_path,
                line=line_no,
                sink=sink or "unknown",
                snippet=snippet,
            )
        )
    return findings


def _parse_joern_jsonl(path: Path) -> list[JoernFinding]:
    if not path.exists():
        return []

    items: list[object] = []
    for raw_line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            items.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return _parse_joern_items(items)


def _escape_scala_string(value: str) -> str:
    return (
        value.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")
    )


def _joern_http_query_with_import(import_statement: str) -> str:
    query = """
workspace.reset
__IMPORT_STATEMENT__
import io.shiftleft.semanticcpg.language._

case class Rule(vulnClass: String, queryId: String, regex: scala.util.matching.Regex)
val rules = List(
  Rule("sql_injection_boundary", "joern::sql_boundary", "(?i)(mysqli_query|mysqli_real_query|mysqli::query|mysqli_multi_query|pdo::query|pdo::prepare|pdo::exec|pg_query)".r),
  Rule("command_injection_boundary", "joern::cmd_boundary", "(?i)(exec|shell_exec|system|passthru|popen|proc_open|pcntl_exec|`)".r),
  Rule("code_injection_boundary", "joern::code_boundary", "(?i)(eval|assert|preg_replace|create_function)".r),
  Rule("ldap_injection_boundary", "joern::ldap_boundary", "(?i)(ldap_search|ldap_list|ldap_read|ldap_add|ldap_modify)".r),
  Rule("xpath_injection_boundary", "joern::xpath_boundary", "(?i)(domxpath::query|domxpath::evaluate|simplexmlelement::xpath)".r),
  Rule("file_boundary_influence", "joern::file_boundary", "(?i)(file_put_contents|file_get_contents|fopen|include_once|include|require_once|require|readfile|show_source|highlight_file)".r),
  Rule("file_upload_influence", "joern::upload_boundary", "(?i)(move_uploaded_file|finfo_file|mime_content_type)".r),
  Rule("xss_output_boundary", "joern::xss_boundary", "(?i)(\\becho\\b|printf|vprintf|die|exit|\\bprint\\b)".r),
  Rule("debug_output_leak", "joern::debug_output", "(?i)(print_r|var_dump|var_export|phpinfo)".r),
  Rule("outbound_request_influence", "joern::outbound_boundary", "(?i)(curl_exec|curl_setopt|curlopt_url|file_get_contents|fopen|fsockopen|pfsockopen)".r),
  Rule("xxe_influence", "joern::xxe_boundary", "(?i)(domdocument::loadxml|domdocument::load|simplexml_load_file|simplexml_load_string|xml_parse)".r),
  Rule("deserialization_influence", "joern::deser_boundary", "(?i)(unserialize|json_decode)".r),
  Rule("php_object_gadget_surface", "joern::gadget_surface", "(?i)(__wakeup|__destruct|__tostring|__call|__get|__set)".r),
  Rule("header_injection_boundary", "joern::header_boundary", "(?i)(header|mail|mb_send_mail)".r),
  Rule("regex_dos_boundary", "joern::regex_dos", "(?i)(preg_match|preg_match_all|preg_replace|max_input_vars)".r),
  Rule("xml_dos_boundary", "joern::xml_dos", "(?i)(domdocument::loadxml|simplexml_load_string|xml_parse)".r),
  Rule("broken_access_control", "joern::access_control", "(?i)(authorize|is_admin|role|permission)".r),
  Rule("csrf_invariant_missing", "joern::csrf_invariant", "(?i)(hash_equals|csrf|csrf_token|token)".r),
  Rule("idor_invariant_missing", "joern::idor_invariant", "(?i)(findbyid|getbyid|loadbyid)".r),
  Rule("session_fixation_invariant", "joern::session_fixation", "(?i)(session_start|session_regenerate_id)".r),
  Rule("crypto_failures", "joern::crypto", "(?i)(md5|sha1|openssl_encrypt|openssl_decrypt|crypt|rand|mt_rand|uniqid|shuffle|array_rand)".r),
  Rule("security_misconfiguration", "joern::misconfig", "(?i)(ini_set|display_errors|error_reporting)".r),
  Rule("insecure_design", "joern::insecure_design", "(?i)(allow_all_access|bypass_auth|skip_authorization|trust_client_role)".r),
  Rule("auth_and_session_failures", "joern::auth_session", "(?i)(session_start|password_verify|setcookie)".r),
  Rule("software_data_integrity", "joern::integrity", "(?i)(eval|assert|include|require)".r),
  Rule("logging_monitoring_failures", "joern::logging", "(?i)(error_log|logger|audit)".r),
  Rule("ssrf", "joern::ssrf", "(?i)(curl_exec|curl_setopt|curlopt_url|file_get_contents|fopen|fsockopen|pfsockopen)".r),
  Rule("information_disclosure", "joern::info_disclosure", "(?i)(phpinfo|display_errors|print_r|var_dump|var_export)".r)
)

def esc(value: String): String =
  value.replace("\\\\", "\\\\\\\\").replace("\"", "\\\\\"").replace("\\n", "\\\\n").replace("\\r", "\\\\r").replace("\\t", "\\\\t")

val rows = cpg.call.l.flatMap { call =>
  val name = Option(call.name).getOrElse("")
  val code = Option(call.code).getOrElse("")
  rules.collect {
    case rule if rule.regex.findFirstIn(name).nonEmpty || rule.regex.findFirstIn(code).nonEmpty =>
      val filePath = call.file.name.headOption.getOrElse("")
      val line = call.lineNumber.getOrElse(0)
      val sink = if (name.nonEmpty) name else "unknown"
      val snippet = code.take(240)
      "{\\\"vuln_class\\\":\\\"" + esc(rule.vulnClass) +
      "\\\",\\\"query_id\\\":\\\"" + esc(rule.queryId) +
      "\\\",\\\"file_path\\\":\\\"" + esc(filePath) +
      "\\\",\\\"line\\\":" + line +
      ",\\\"sink\\\":\\\"" + esc(sink) +
      "\\\",\\\"snippet\\\":\\\"" + esc(snippet) +
      "\\\"}"
  }
}
println("<padv_result>[" + rows.mkString(",") + "]</padv_result>")
"""
    return query.replace("__IMPORT_STATEMENT__", import_statement)


def _joern_http_query_for_php(cpg_path: Path) -> str:
    cpg = _escape_scala_string(str(cpg_path))
    return _joern_http_query_with_import(f'importCpg("{cpg}")')


def _joern_http_query_for_repo(repo_root: Path) -> str:
    source_root = _escape_scala_string(str(repo_root))
    return _joern_http_query_with_import(f'importCode("{source_root}")')


def _strip_ansi(value: str) -> str:
    return _ANSI_RE.sub("", value)


def _parse_joern_stdout_json(stdout: str) -> list[JoernFinding]:
    cleaned = _strip_ansi(stdout)
    marker_match = _RESULT_MARKER.search(cleaned)
    if marker_match:
        try:
            data = json.loads(marker_match.group(1))
        except json.JSONDecodeError:
            data = []
        if isinstance(data, list):
            return _parse_joern_items(data)

    tmp_items: list[object] = []
    for raw_line in cleaned.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            tmp_items.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return _parse_joern_items(tmp_items)


def _run_joern_parse(repo_root: Path, cpg_path: Path, config: PadvConfig) -> None:
    cmd = shlex.split(config.joern.parse_command) + [
        str(repo_root),
        "--language",
        config.joern.parse_language,
        "--output",
        str(cpg_path),
    ]
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            check=False,
            timeout=config.joern.timeout_seconds,
        )
    except OSError as exc:
        raise JoernExecutionError(f"unable to execute joern parse command: {exc}") from exc

    if proc.returncode != 0:
        stderr = (proc.stderr or "").strip()
        stdout = (proc.stdout or "").strip()
        msg = stderr or stdout or "joern parse command failed"
        raise JoernExecutionError(f"joern-parse failed ({proc.returncode}): {msg}")

    if not cpg_path.exists():
        raise JoernExecutionError(f"joern-parse did not produce CPG artifact: {cpg_path}")


def _post_joern_http_query(query: str, config: PadvConfig) -> str:
    endpoint = f"{config.joern.server_url.rstrip('/')}/query-sync"
    payload = json.dumps({"query": query}).encode("utf-8")
    req = request.Request(
        endpoint,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with request.urlopen(req, timeout=config.joern.timeout_seconds) as response:
            body = response.read().decode("utf-8", errors="ignore")
    except error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="ignore") if hasattr(exc, "read") else ""
        msg = detail.strip() or str(exc)
        raise JoernExecutionError(f"joern http query failed ({exc.code}): {msg}") from exc
    except OSError as exc:
        raise JoernExecutionError(f"unable to call joern server: {exc}") from exc

    try:
        data = json.loads(body)
    except json.JSONDecodeError as exc:
        raise JoernExecutionError("joern http response was not valid JSON") from exc

    if not isinstance(data, dict):
        raise JoernExecutionError("joern http response must be a JSON object")

    success = bool(data.get("success"))
    stdout = str(data.get("stdout", ""))
    stderr = str(data.get("stderr", ""))

    if not success:
        msg = stderr.strip() or stdout.strip() or "joern query returned unsuccessful result"
        raise JoernExecutionError(msg)

    return stdout


def _run_joern_findings_http(repo_root: Path, config: PadvConfig) -> list[JoernFinding]:
    parse_command = config.joern.parse_command.strip()
    if not parse_command:
        query = _joern_http_query_for_repo(repo_root)
        stdout = _post_joern_http_query(query=query, config=config)
        return _parse_joern_stdout_json(stdout)

    with tempfile.TemporaryDirectory(prefix="padv-joern-http-") as temp_dir:
        cpg_path = Path(temp_dir) / "repo.cpg.bin"
        _run_joern_parse(repo_root=repo_root, cpg_path=cpg_path, config=config)

        query = _joern_http_query_for_php(cpg_path)
        stdout = _post_joern_http_query(query=query, config=config)
        return _parse_joern_stdout_json(stdout)


def _run_joern_findings_script(repo_root: Path, config: PadvConfig) -> list[JoernFinding]:
    script_path = Path(config.joern.script_path) if config.joern.script_path else _default_joern_script_path()
    if not script_path.exists():
        raise JoernExecutionError(f"joern script not found: {script_path}")

    with tempfile.TemporaryDirectory(prefix="padv-joern-") as temp_dir:
        out_path = Path(temp_dir) / "findings.jsonl"
        cmd = shlex.split(config.joern.command) + [
            "--script",
            str(script_path),
            "--params",
            f"inputPath={repo_root},outputPath={out_path}",
        ]

        try:
            proc = subprocess.run(
                cmd,
                cwd=str(repo_root),
                capture_output=True,
                text=True,
                check=False,
                timeout=config.joern.timeout_seconds,
            )
        except OSError as exc:
            raise JoernExecutionError(f"unable to execute joern command: {exc}") from exc

        if proc.returncode != 0:
            stderr = (proc.stderr or "").strip()
            stdout = (proc.stdout or "").strip()
            msg = stderr or stdout or "joern command failed"
            raise JoernExecutionError(f"joern failed ({proc.returncode}): {msg}")

        findings = _parse_joern_jsonl(out_path)
        if findings:
            return findings

        return _parse_joern_stdout_json(proc.stdout or "")


def _run_joern_findings(repo_root: Path, config: PadvConfig) -> list[JoernFinding]:
    if config.joern.use_http_api:
        return _run_joern_findings_http(repo_root, config)
    return _run_joern_findings_script(repo_root, config)


def _discover_with_joern(
    repo_root: Path, config: PadvConfig
) -> tuple[list[Candidate], list[StaticEvidence], JoernDiscoveryMeta]:
    findings = _run_joern_findings(repo_root, config)

    unique_findings: list[JoernFinding] = []
    seen: set[tuple[str, str, int, str, str]] = set()
    for finding in findings:
        key = (finding.vuln_class, finding.file_path, finding.line, finding.sink, finding.query_id)
        if key in seen:
            continue
        seen.add(key)
        unique_findings.append(finding)

    meta = JoernDiscoveryMeta(joern_findings=len(unique_findings))
    candidates: list[Candidate] = []
    evidence: list[StaticEvidence] = []
    detector_note = "joern http detector" if config.joern.use_http_api else "joern script detector"
    for finding in unique_findings:
        spec = _SPEC_BY_CLASS.get(finding.vuln_class)
        if spec is None:
            continue
        rel_path = normalize_repo_path(finding.file_path, repo_root=repo_root)
        if not rel_path or not is_app_candidate_path(rel_path):
            continue
        meta.joern_app_findings += 1
        if len(candidates) >= config.budgets.max_candidates:
            continue
        candidate_id = f"cand-{len(candidates)+1:05d}"
        candidate, static = _make_candidate_and_evidence(
            candidate_id=candidate_id,
            spec=spec,
            file_path=rel_path,
            line=finding.line,
            sink=finding.sink,
            snippet=finding.snippet,
            query_profile=config.joern.query_profile,
            query_id=finding.query_id,
            notes=detector_note,
            config=config,
        )
        candidates.append(candidate)
        evidence.append(static)

    meta.joern_candidate_count = len(candidates)
    return candidates, evidence, meta


def _discover_manifest_candidates(
    root: Path,
    config: PadvConfig,
    candidates: list[Candidate],
    evidence: list[StaticEvidence],
) -> int:
    spec = _SPEC_BY_CLASS.get("vulnerable_components")
    if spec is None:
        return 0

    manifest_paths = [root / "composer.json", root / "composer.lock"]
    added = 0
    for manifest in manifest_paths:
        if len(candidates) >= config.budgets.max_candidates:
            break
        if not manifest.exists() or not manifest.is_file():
            continue

        try:
            raw_text = manifest.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        snippet = "composer manifest detected"
        try:
            payload = json.loads(raw_text)
            names: list[str] = []
            if isinstance(payload, dict):
                for field in ("require", "require-dev"):
                    deps = payload.get(field)
                    if isinstance(deps, dict):
                        names.extend(str(k) for k in deps.keys())
                packages = payload.get("packages")
                if isinstance(packages, list):
                    for package in packages:
                        if isinstance(package, dict) and package.get("name"):
                            names.append(str(package.get("name")))
            if names:
                snippet = "dependencies: " + ", ".join(names[:5])
        except json.JSONDecodeError:
            if raw_text.strip():
                snippet = raw_text.strip().replace("\n", " ")[:240]

        rel_path = str(manifest.relative_to(root))
        candidate_id = f"cand-{len(candidates)+1:05d}"
        candidate, static = _make_candidate_and_evidence(
            candidate_id=candidate_id,
            spec=spec,
            file_path=rel_path,
            line=1,
            sink="composer_dependency",
            snippet=snippet,
            query_profile=config.joern.query_profile,
            query_id="manifest::vulnerable_components",
            notes="dependency manifest detector",
            config=config,
        )
        candidates.append(candidate)
        evidence.append(static)
        added += 1
    return added


def discover_candidates_with_meta(
    repo_root: str, config: PadvConfig
) -> tuple[list[Candidate], list[StaticEvidence], JoernDiscoveryMeta]:
    root = Path(repo_root)
    if not root.exists():
        raise FileNotFoundError(f"repo root does not exist: {repo_root}")
    if not config.joern.enabled:
        raise JoernExecutionError("joern.enabled must remain true")
    joern_candidates, joern_evidence, meta = _discover_with_joern(root, config)
    meta.manifest_candidates = _discover_manifest_candidates(root, config, joern_candidates, joern_evidence)
    return joern_candidates, joern_evidence, meta


def discover_candidates(repo_root: str, config: PadvConfig) -> tuple[list[Candidate], list[StaticEvidence]]:
    candidates, evidence, _meta = discover_candidates_with_meta(repo_root, config)
    return candidates, evidence

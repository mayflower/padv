from __future__ import annotations

import os
import hashlib
import json
import base64
import re
import shlex
import shutil
import subprocess
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from urllib import error, request

from padv.config.schema import PadvConfig
from padv.discovery.budgeting import select_fair_share
from padv.models import Candidate, StaticEvidence
from padv.path_scope import is_app_candidate_path, normalize_repo_path
from padv.static.joern.query_sets import VULN_CLASS_SPECS, VulnClassSpec, intercepts_for_class
from padv.taxonomy import canonicalize_vuln_class


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
_REPL_B64_STRING_RE = re.compile(r'"([A-Za-z0-9+/=]+)"')
_REPL_LIST_BLOCK_RE = re.compile(r"val\s+res\d+:\s+List\[String\]\s*=\s*List\((.*)\)\s*$", re.DOTALL)
_JOERN_SHARED_DIR_ENV = "PADV_JOERN_SHARED_DIR"


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
    candidate.canonical_class = canonicalize_vuln_class(spec.vuln_class)
    evidence = StaticEvidence(
        candidate_id=candidate_id,
        query_profile=query_profile,
        query_id=query_id,
        file_path=file_path,
        line=line,
        snippet=snippet[:240],
        hash=_hash_for(file_path, line, snippet),
        candidate_uid=candidate.candidate_uid,
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
    query = r"""
workspace.reset
__IMPORT_STATEMENT__
import io.shiftleft.semanticcpg.language._
import java.nio.charset.StandardCharsets
import java.util.Base64

case class Rule(vulnClass: String, queryId: String, regex: scala.util.matching.Regex)
val rules = List(
  Rule("sql_injection_boundary", "joern::sql_boundary", "(?i)(mysqli_query|mysqli_real_query|mysqli::query|mysqli_multi_query|pdo::query|pdo::prepare|pdo::exec|pg_query|sqlsrv_query|\\bquery\\b|\\bprepare\\b|\\bexec\\b)".r),
  Rule("command_injection_boundary", "joern::cmd_boundary", "(?i)(exec|shell_exec|system|passthru|popen|proc_open|pcntl_exec|`)".r),
  Rule("code_injection_boundary", "joern::code_boundary", "(?i)(eval|assert|preg_replace|create_function)".r),
  Rule("ldap_injection_boundary", "joern::ldap_boundary", "(?i)(ldap_search|ldap_list|ldap_read|ldap_add|ldap_modify)".r),
  Rule("xpath_injection_boundary", "joern::xpath_boundary", "(?i)(domxpath::query|domxpath::evaluate|simplexmlelement::xpath|\\bxpath\\b|\\bevaluate\\b)".r),
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
  value.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")

val rows = cpg.call.l.flatMap { call =>
  val name = Option(call.name).getOrElse("")
  val code = Option(call.code).getOrElse("")
  rules.collect {
    case rule if rule.regex.findFirstIn(name).nonEmpty || rule.regex.findFirstIn(code).nonEmpty =>
      val filePath = call.file.name.headOption.getOrElse("")
      val line = call.lineNumber.getOrElse(0)
      val sink = if (name.nonEmpty) name else "unknown"
      val snippet = code.take(240)
      Base64.getEncoder.encodeToString(
        ("{\"vuln_class\":\"" + esc(rule.vulnClass) +
        "\",\"query_id\":\"" + esc(rule.queryId) +
        "\",\"file_path\":\"" + esc(filePath) +
        "\",\"line\":" + line +
        ",\"sink\":\"" + esc(sink) +
        "\",\"snippet\":\"" + esc(snippet) +
        "\"}").getBytes(StandardCharsets.UTF_8)
      )
  }
}
rows
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


def _load_composer_vendor_dir(repo_root: Path) -> str | None:
    payload = _load_composer_payload(repo_root)
    if not isinstance(payload, dict):
        return None
    if not isinstance(payload, dict):
        return None
    config = payload.get("config")
    if not isinstance(config, dict):
        return None
    vendor_dir = config.get("vendor-dir")
    if not isinstance(vendor_dir, str):
        return None
    normalized = vendor_dir.replace("\\", "/").strip().strip("/")
    return normalized or None


def _load_composer_payload(repo_root: Path) -> dict[str, object] | None:
    composer_json = repo_root / "composer.json"
    if not composer_json.exists():
        return None
    try:
        payload = json.loads(composer_json.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    return payload


def _normalize_autoload_path(raw: str) -> str | None:
    normalized = normalize_repo_path(raw, repo_root=None)
    normalized = normalized.removeprefix("./").strip("/")
    return normalized or None


def _extract_psr_paths(mapping: dict[str, object]) -> set[str]:
    paths: set[str] = set()
    for value in mapping.values():
        items = value if isinstance(value, list) else [value]
        for item in items:
            if not isinstance(item, str):
                continue
            path = _normalize_autoload_path(item)
            if path:
                paths.add(path)
    return paths


def _collect_psr_roots(autoload: dict[str, object]) -> set[str]:
    roots: set[str] = set()
    for field in ("psr-4", "psr-0"):
        mapping = autoload.get(field)
        if isinstance(mapping, dict):
            roots |= _extract_psr_paths(mapping)
    return roots


def _collect_classmap_roots(autoload: dict[str, object]) -> set[str]:
    roots: set[str] = set()
    classmap = autoload.get("classmap")
    if not isinstance(classmap, list):
        return roots
    for item in classmap:
        if isinstance(item, str):
            path = _normalize_autoload_path(item)
            if path:
                roots.add(path)
    return roots


def _load_composer_autoload_roots(repo_root: Path) -> list[str]:
    payload = _load_composer_payload(repo_root)
    if not isinstance(payload, dict):
        return []
    autoload = payload.get("autoload")
    if not isinstance(autoload, dict):
        return []

    roots = _collect_psr_roots(autoload) | _collect_classmap_roots(autoload)
    return sorted(roots)


def _is_php_source_file(path: Path) -> bool:
    return path.suffix.casefold() in {".php", ".phtml", ".inc", ".phpt"}


def _path_is_within(rel_path: str, scope_root: str) -> bool:
    path_parts = PurePosixPath(rel_path).parts
    root_parts = PurePosixPath(scope_root).parts
    return len(path_parts) >= len(root_parts) and path_parts[: len(root_parts)] == root_parts


def _entrypoint_dirs_for_base(repo_root: Path, app_base: PurePosixPath) -> set[str]:
    base_path = repo_root / app_base.as_posix()
    if not base_path.exists():
        return set()
    dirs: set[str] = set()
    base_parts = app_base.parts
    for index_file in base_path.rglob("index.php"):
        try:
            rel_path = index_file.relative_to(repo_root).as_posix()
        except ValueError:
            continue
        if not is_app_candidate_path(rel_path):
            continue
        if len(PurePosixPath(rel_path).parts) - len(base_parts) > 2:
            continue
        dirs.add(PurePosixPath(rel_path).parent.as_posix())
    return dirs


def _discover_entrypoint_dirs(repo_root: Path, autoload_roots: list[str]) -> set[str]:
    entrypoint_dirs: set[str] = set()
    for root in autoload_roots:
        app_base = PurePosixPath(root).parent.parent
        if not app_base.parts:
            continue
        entrypoint_dirs |= _entrypoint_dirs_for_base(repo_root, app_base)
    return entrypoint_dirs


def _path_matches_autoload_root(rel_path: str, root: str, entrypoint_dirs: set[str]) -> bool:
    if _path_is_within(rel_path, root):
        return True
    path_parts = PurePosixPath(rel_path).parts
    root_path = PurePosixPath(root)
    source_parent = root_path.parent
    if source_parent.parts and path_parts[:-1] == source_parent.parts:
        return True
    app_base = source_parent.parent
    if app_base.parts and path_parts[:-1] == app_base.parts:
        return True
    if PurePosixPath(rel_path).parent.as_posix() in entrypoint_dirs:
        return True
    return False


def _include_path_via_autoload_roots(
    rel_path: str, autoload_roots: list[str], entrypoint_dirs: set[str]
) -> bool:
    if not autoload_roots:
        return True
    return any(_path_matches_autoload_root(rel_path, root, entrypoint_dirs) for root in autoload_roots)


def _is_within_staging(source: Path, staging_resolved: Path) -> bool:
    try:
        source.resolve().relative_to(staging_resolved)
        return True
    except ValueError:
        return False


def _should_include_source(
    source: Path, repo_root: Path, staging_resolved: Path,
    vendor_dir: str | None, autoload_roots: list[str], entrypoint_dirs: set[str],
) -> bool:
    if not source.is_file():
        return False
    if _is_within_staging(source, staging_resolved):
        return False
    if not _is_php_source_file(source):
        return False
    rel_path = source.relative_to(repo_root).as_posix()
    if vendor_dir and (rel_path == vendor_dir or rel_path.startswith(f"{vendor_dir}/")):
        return False
    if not is_app_candidate_path(rel_path):
        return False
    return _include_path_via_autoload_roots(rel_path, autoload_roots, entrypoint_dirs)


def _build_joern_parse_scope(repo_root: Path, staging_root: Path) -> Path:
    scoped_root = staging_root / "source"
    scoped_root.mkdir(parents=True, exist_ok=True)

    vendor_dir = _load_composer_vendor_dir(repo_root)
    autoload_roots = _load_composer_autoload_roots(repo_root)
    entrypoint_dirs = _discover_entrypoint_dirs(repo_root, autoload_roots)
    staging_resolved = staging_root.resolve()
    copied = 0
    for source in repo_root.rglob("*"):
        if not _should_include_source(source, repo_root, staging_resolved, vendor_dir, autoload_roots, entrypoint_dirs):
            continue
        rel_path = source.relative_to(repo_root).as_posix()
        destination = scoped_root / rel_path
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
        copied += 1

    if copied == 0:
        raise JoernExecutionError(f"no parseable PHP application files found under: {repo_root}")

    return scoped_root


def _remap_findings_to_repo_root(
    findings: list[JoernFinding], parse_root: Path, repo_root: Path
) -> list[JoernFinding]:
    remapped: list[JoernFinding] = []
    parse_root_resolved = parse_root.resolve()
    repo_root_resolved = repo_root.resolve()
    for finding in findings:
        file_path = finding.file_path
        if file_path:
            path_obj = Path(file_path)
            if path_obj.is_absolute():
                try:
                    relative = path_obj.resolve().relative_to(parse_root_resolved)
                except ValueError:
                    relative = None
                if relative is not None:
                    file_path = str((repo_root_resolved / relative).as_posix())
        remapped.append(
            JoernFinding(
                vuln_class=finding.vuln_class,
                query_id=finding.query_id,
                file_path=file_path,
                line=finding.line,
                sink=finding.sink,
                snippet=finding.snippet,
            )
        )
    return remapped


def _try_parse_marker_json(cleaned: str) -> list[JoernFinding] | None:
    marker_match = _RESULT_MARKER.search(cleaned)
    if not marker_match:
        return None
    try:
        data = json.loads(marker_match.group(1))
    except json.JSONDecodeError:
        return None
    if isinstance(data, list):
        return _parse_joern_items(data)
    return None


def _decode_b64_items(candidate_region: str) -> list[object]:
    items: list[object] = []
    for encoded in _REPL_B64_STRING_RE.findall(candidate_region):
        try:
            payload = base64.b64decode(encoded).decode("utf-8")
            items.append(json.loads(payload))
        except Exception:
            continue
    return items


def _parse_jsonl_items(text: str) -> list[object]:
    items: list[object] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            items.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return items


def _parse_joern_stdout_json(stdout: str) -> list[JoernFinding]:
    cleaned = _strip_ansi(stdout)

    marker_result = _try_parse_marker_json(cleaned)
    if marker_result is not None:
        return marker_result

    block_matches = list(_REPL_LIST_BLOCK_RE.finditer(cleaned))
    if block_matches:
        candidate_region = block_matches[-1].group(1)
    else:
        list_idx = cleaned.rfind("List(")
        candidate_region = cleaned[list_idx:] if list_idx != -1 else cleaned

    decoded_items = _decode_b64_items(candidate_region)
    if decoded_items:
        return _parse_joern_items(decoded_items)

    jsonl_items = _parse_jsonl_items(cleaned)
    if jsonl_items:
        return _parse_joern_items(jsonl_items)

    return _parse_joern_items(decoded_items)


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
    except subprocess.TimeoutExpired as exc:
        raise JoernExecutionError(
            f"joern parse command timed out ({config.joern.timeout_seconds}s)"
        ) from exc
    except OSError as exc:
        raise JoernExecutionError(f"unable to execute joern parse command: {exc}") from exc

    if proc.returncode != 0:
        stderr = (proc.stderr or "").strip()
        stdout = (proc.stdout or "").strip()
        msg = stderr or stdout or "joern parse command failed"
        raise JoernExecutionError(f"joern-parse failed ({proc.returncode}): {msg}")

    if not cpg_path.exists():
        raise JoernExecutionError(f"joern-parse did not produce CPG artifact: {cpg_path}")


@contextmanager
def _joern_http_workspace():
    shared_dir = os.environ.get(_JOERN_SHARED_DIR_ENV, "").strip()
    if shared_dir:
        shared_path = Path(shared_dir)
        shared_path.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="padv-joern-http-", dir=str(shared_path)) as temp_dir:
            yield Path(temp_dir)
        return
    with tempfile.TemporaryDirectory(prefix="padv-joern-http-") as temp_dir:
        yield Path(temp_dir)


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

    with _joern_http_workspace() as temp_dir:
        parse_root = _build_joern_parse_scope(repo_root=repo_root, staging_root=temp_dir)
        cpg_path = temp_dir / "repo.cpg.bin"
        _run_joern_parse(repo_root=parse_root, cpg_path=cpg_path, config=config)

        query = _joern_http_query_for_php(cpg_path)
        stdout = _post_joern_http_query(query=query, config=config)
        findings = _parse_joern_stdout_json(stdout)
        return _remap_findings_to_repo_root(findings=findings, parse_root=parse_root, repo_root=repo_root)


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
        except subprocess.TimeoutExpired as exc:
            raise JoernExecutionError(
                f"joern script command timed out ({config.joern.timeout_seconds}s)"
            ) from exc
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
    eligible_findings: list[tuple[JoernFinding, VulnClassSpec, str]] = []
    seen_app: set[tuple[str, str, int, str, str]] = set()
    for finding in unique_findings:
        spec = _SPEC_BY_CLASS.get(finding.vuln_class)
        if spec is None:
            continue
        rel_path = normalize_repo_path(finding.file_path, repo_root=repo_root)
        if not rel_path or not is_app_candidate_path(rel_path):
            continue
        app_key = (finding.vuln_class, rel_path, finding.line, finding.sink, finding.query_id)
        if app_key in seen_app:
            continue
        seen_app.add(app_key)
        meta.joern_app_findings += 1
        eligible_findings.append((finding, spec, rel_path))

    selected_findings = select_fair_share(
        eligible_findings,
        key_fn=lambda item: item[0].vuln_class,
        limit=config.budgets.max_candidates,
    )

    candidates: list[Candidate] = []
    evidence: list[StaticEvidence] = []
    detector_note = "joern http detector" if config.joern.use_http_api else "joern script detector"
    for idx, (finding, spec, rel_path) in enumerate(selected_findings, start=1):
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


def _extract_dependency_names(payload: object) -> list[str]:
    if not isinstance(payload, dict):
        return []
    names: list[str] = []
    for field in ("require", "require-dev"):
        deps = payload.get(field)
        if isinstance(deps, dict):
            names.extend(str(k) for k in deps.keys())
    packages = payload.get("packages")
    if isinstance(packages, list):
        for package in packages:
            if isinstance(package, dict) and package.get("name"):
                names.append(str(package.get("name")))
    return names


def _manifest_snippet(raw_text: str) -> str:
    try:
        payload = json.loads(raw_text)
        names = _extract_dependency_names(payload)
        if names:
            return "dependencies: " + ", ".join(names[:5])
    except json.JSONDecodeError:
        if raw_text.strip():
            return raw_text.strip().replace("\n", " ")[:240]
    return "composer manifest detected"


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

        rel_path = str(manifest.relative_to(root))
        candidate_id = f"cand-{len(candidates)+1:05d}"
        candidate, static = _make_candidate_and_evidence(
            candidate_id=candidate_id,
            spec=spec,
            file_path=rel_path,
            line=1,
            sink="composer_dependency",
            snippet=_manifest_snippet(raw_text),
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

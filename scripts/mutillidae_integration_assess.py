#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from padv.eval.integration_assessment import RequirementResult, classify_failure, matrix_to_gap_list
from padv.models import default_candidate_outcomes, explicit_candidate_outcome_for_decision
from padv.store.evidence_store import EvidenceStore
from padv.taxonomy import canonicalize_vuln_class

PADV_STORE = ROOT_DIR / ".padv"
APP_COMPOSE_FILE = ROOT_DIR / "docker-compose.mutillidae.yml"
SCANNER_COMPOSE_FILE = ROOT_DIR / "docker-compose.yml"
APP_PROJECT = "mutillidae-e2e"
SCANNER_PROJECT = "haxor-scan"
STRICT_CONFIG_PATH = "/workspace/haxor/padv.mutillidae.strict.toml"
STRICT_REPO_ROOT = "/workspace/targets/mutillidae"
GAP_CATALOG_PATH = ROOT_DIR / "tests" / "fixtures" / "mutillidae-gap-catalog.json"
LDAP_BIND_DN = "cn=admin,dc=mutillidae,dc=localhost"
# Default credentials for Mutillidae (deliberately vulnerable test application)
LDAP_BIND_PASSWORD = "mutillidae"
LDAP_BASE_DN = "dc=mutillidae,dc=localhost"


@dataclass(slots=True)
class CmdResult:
    name: str
    cmd: list[str]
    returncode: int
    stdout: str
    stderr: str
    started_at: str
    ended_at: str
    duration_seconds: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "cmd": self.cmd,
            "returncode": self.returncode,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "duration_seconds": round(self.duration_seconds, 3),
        }


def _now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def _run(name: str, cmd: list[str], timeout_seconds: int = 3600) -> CmdResult:
    started = _now_iso()
    t0 = time.monotonic()
    try:
        completed = subprocess.run(
            cmd,
            cwd=str(ROOT_DIR),
            text=True,
            capture_output=True,
            timeout=timeout_seconds,
            check=False,
        )
        return CmdResult(
            name=name,
            cmd=cmd,
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
            started_at=started,
            ended_at=_now_iso(),
            duration_seconds=time.monotonic() - t0,
        )
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout if isinstance(exc.stdout, str) else ""
        stderr = exc.stderr if isinstance(exc.stderr, str) else ""
        stderr = f"{stderr}\ncommand timed out after {timeout_seconds}s".strip()
        return CmdResult(
            name=name,
            cmd=cmd,
            returncode=124,
            stdout=stdout,
            stderr=stderr,
            started_at=started,
            ended_at=_now_iso(),
            duration_seconds=time.monotonic() - t0,
        )


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=True), encoding="utf-8")


def _safe_json_parse(text: str) -> dict[str, Any] | None:
    raw = text.strip()
    if not raw:
        return None
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, dict):
            return parsed
    except json.JSONDecodeError:
        pass
    first = raw.find("{")
    last = raw.rfind("}")
    if first >= 0 and last > first:
        try:
            parsed = json.loads(raw[first : last + 1])
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            return None
    return None


_GRAPH_STAGE_RE = re.compile(r"^(?P<index>\d+)-(?P<stage>[^.]+)\.json$")
_REASON_TOKEN_RE = re.compile(r"[^a-z0-9]+")

_ASSESSMENT_CATEGORY_BY_CANONICAL_CLASS: dict[str, str] = {
    "sql_injection_boundary": "sql_injection",
    "xss_output_boundary": "cross_site_scripting",
    "command_injection_boundary": "command_injection",
    "broken_access_control": "authn_authz_failures",
    "idor_invariant_missing": "authn_authz_failures",
    "auth_and_session_failures": "authn_authz_failures",
    "session_misuse": "session_misuse",
    "session_fixation_invariant": "session_misuse",
    "csrf": "csrf",
    "csrf_invariant": "csrf",
    "csrf_invariant_missing": "csrf",
    "file_boundary_influence": "file_inclusion_path_traversal",
    "ldap_injection_boundary": "ldap_injection",
    "xxe_influence": "xxe_xml_injection",
    "xml_dos_boundary": "xxe_xml_injection",
    "file_upload_influence": "unrestricted_file_upload",
    "header_injection_boundary": "open_redirect_header_cookie_manipulation",
    "header_cookie_manipulation": "open_redirect_header_cookie_manipulation",
    "information_disclosure": "information_disclosure_misconfiguration",
    "security_misconfiguration": "information_disclosure_misconfiguration",
    "debug_output_leak": "information_disclosure_misconfiguration",
}


def _latest_graph_progress(prefix: str) -> dict[str, Any] | None:
    root = PADV_STORE / "langgraph"
    if not root.exists():
        return None

    candidates = [path for path in root.iterdir() if path.is_dir() and path.name.startswith(f"{prefix}-")]
    if not candidates:
        return None

    def _latest_snapshot(path: Path) -> tuple[float, Path | None]:
        latest_ts = path.stat().st_mtime
        latest_path: Path | None = None
        for child in path.iterdir():
            if not child.is_file():
                continue
            match = _GRAPH_STAGE_RE.match(child.name)
            if match is None:
                continue
            if child.stat().st_mtime >= latest_ts:
                latest_ts = child.stat().st_mtime
                latest_path = child
        return latest_ts, latest_path

    latest_dir = max(candidates, key=lambda item: _latest_snapshot(item)[0])
    snapshots: list[tuple[int, str, Path]] = []
    for child in latest_dir.iterdir():
        if not child.is_file():
            continue
        match = _GRAPH_STAGE_RE.match(child.name)
        if match is None:
            continue
        snapshots.append((int(match.group("index")), match.group("stage"), child))
    if not snapshots:
        return None

    snapshots.sort()
    _, latest_stage, latest_path = snapshots[-1]
    payload = _load_json(latest_path, {})
    counts = payload.get("counts", {}) if isinstance(payload, dict) else {}
    decisions = payload.get("decisions", {}) if isinstance(payload, dict) else {}
    frontier = payload.get("frontier", {}) if isinstance(payload, dict) else {}
    run_id = str(payload.get("run_id", "")).strip() if isinstance(payload, dict) else ""
    if not run_id:
        run_id = latest_dir.name
    return {
        "run_id": run_id,
        "latest_stage": latest_stage,
        "latest_stage_file": str(latest_path),
        "completed": any(stage == "persist" for _, stage, _ in snapshots),
        "candidates": int(counts.get("candidates", 0) or 0),
        "static_evidence": int(counts.get("static_evidence", 0) or 0),
        "bundle_count": int(counts.get("all_bundles", counts.get("bundles", 0)) or 0),
        "counts": counts,
        "decisions": decisions,
        "frontier": frontier,
    }


def _graph_progress_for_run(run_id: str) -> dict[str, Any] | None:
    run_id = str(run_id).strip()
    if not run_id:
        return None

    candidate_roots = [PADV_STORE / "langgraph" / run_id, PADV_STORE / "runs" / run_id / "stages"]
    snapshots: list[tuple[int, str, Path]] = []
    for root in candidate_roots:
        if not root.exists():
            continue
        for child in root.iterdir():
            if not child.is_file():
                continue
            match = _GRAPH_STAGE_RE.match(child.name)
            if match is None:
                continue
            snapshots.append((int(match.group("index")), match.group("stage"), child))
    if not snapshots:
        return None

    snapshots.sort()
    _, latest_stage, latest_path = snapshots[-1]
    payload = _load_json(latest_path, {})
    counts = payload.get("counts", {}) if isinstance(payload, dict) else {}
    decisions = payload.get("decisions", {}) if isinstance(payload, dict) else {}
    frontier = payload.get("frontier", {}) if isinstance(payload, dict) else {}
    return {
        "run_id": str(payload.get("run_id", "")).strip() or run_id,
        "latest_stage": latest_stage,
        "latest_stage_file": str(latest_path),
        "completed": any(stage == "persist" for _, stage, _ in snapshots),
        "candidates": int(counts.get("candidates", 0) or 0),
        "static_evidence": int(counts.get("static_evidence", 0) or 0),
        "bundle_count": int(counts.get("all_bundles", counts.get("bundles", 0)) or 0),
        "counts": counts,
        "decisions": decisions,
        "frontier": frontier,
    }


def _attempt_failure_class(result: CmdResult) -> str:
    if result.returncode == 124:
        return "timeout"
    return classify_failure(f"{result.stdout}\n{result.stderr}")


def _scanner_padv_cmd(*args: str) -> list[str]:
    return [
        "docker",
        "compose",
        "-f",
        str(SCANNER_COMPOSE_FILE),
        "--project-name",
        SCANNER_PROJECT,
        "run",
        "--rm",
        "padv",
        *args,
    ]


def _app_compose_cmd(*args: str) -> list[str]:
    return [
        "docker",
        "compose",
        "-f",
        str(APP_COMPOSE_FILE),
        "--project-name",
        APP_PROJECT,
        *args,
    ]


def run_preflight(output_dir: Path) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []

    def add_check(name: str, result: CmdResult, pass_predicate: bool, blocker: str) -> None:
        checks.append(
            {
                "name": name,
                "pass": bool(pass_predicate),
                "blocker": "" if pass_predicate else blocker,
                "command": result.to_dict(),
            }
        )

    services = _run("mutillidae_services", _app_compose_cmd("ps", "--status", "running", "www", "database", "directory"), 120)
    services_ok = services.returncode == 0 and all(name in services.stdout for name in ("www", "database", "directory"))
    add_check("docker_services_mutillidae", services, services_ok, "www/database/directory not running")

    joern = _run("scanner_service", ["docker", "compose", "-f", str(SCANNER_COMPOSE_FILE), "--project-name", SCANNER_PROJECT, "ps", "--status", "running", "joern"], 120)
    joern_ok = joern.returncode == 0 and "joern" in joern.stdout
    add_check("docker_service_joern", joern, joern_ok, "joern service not running")

    http = _run("http_mutillidae", ["curl", "-fsS", "http://127.0.0.1:18080/"], 60)
    http_ok = http.returncode == 0 and "Mutillidae" in http.stdout
    add_check("mutillidae_http_reachable", http, http_ok, "Mutillidae not reachable on :18080")

    db = _run(
        "database_initialized",
        _app_compose_cmd(
            "exec",
            "-T",
            "database",
            "mariadb",
            "-uroot",
            "-pmutillidae",
            "-e",
            "SELECT COUNT(*) AS table_count FROM information_schema.tables WHERE table_schema='mutillidae';",
        ),
        120,
    )
    db_ok = db.returncode == 0 and re.search(r"\b[1-9][0-9]*\b", db.stdout or "") is not None
    add_check("database_initialized", db, db_ok, "Mutillidae database not initialized")

    ldap = _run(
        "ldap_seeded",
        _app_compose_cmd(
            "exec",
            "-T",
            "directory",
            "ldapsearch",
            "-x",
            "-H",
            "ldap://127.0.0.1:389",
            "-D",
            LDAP_BIND_DN,
            "-w",
            LDAP_BIND_PASSWORD,
            "-b",
            LDAP_BASE_DN,
            "(uid=fred)",
            "dn",
        ),
        120,
    )
    ldap_ok = ldap.returncode == 0 and "dn: cn=fred" in ldap.stdout
    add_check("ldap_seeded", ldap, ldap_ok, "Mutillidae LDAP directory not seeded")

    morcilla_mod = _run("morcilla_module", _app_compose_cmd("exec", "-T", "www", "php", "-m"), 120)
    mod_ok = morcilla_mod.returncode == 0 and re.search(r"(?im)^morcilla$", morcilla_mod.stdout or "") is not None
    add_check("morcilla_module_loaded", morcilla_mod, mod_ok, "morcilla module not loaded in www container")

    morcilla_headers = _run(
        "morcilla_headers",
        [
            "curl",
            "-fsS",
            "-D",
            "-",
            "-o",
            "/dev/null",
            "-H",
            "Morcilla-Key: test-key",
            "-H",
            "Morcilla-Intercept: mysqli_query",
            "-H",
            "Morcilla-Correlation: preflight-1",
            "http://127.0.0.1:18080/",
        ],
        60,
    )
    hdr_ok = morcilla_headers.returncode == 0 and re.search(r"(?im)^X-Morcilla-Status:", morcilla_headers.stdout or "")
    add_check("morcilla_headers_visible", morcilla_headers, bool(hdr_ok), "missing X-Morcilla-Status response header")

    passed = sum(1 for item in checks if item["pass"])
    result = {
        "phase": "A1",
        "generated_at": _now_iso(),
        "checks": checks,
        "summary": {"passed": passed, "total": len(checks), "all_passed": passed == len(checks)},
    }
    _write_json(output_dir / "a1-preflight.json", result)
    return result


def run_analyze_stabilization(output_dir: Path, max_attempts: int, analyze_timeout: int) -> dict[str, Any]:
    attempts: list[dict[str, Any]] = []
    success = False
    final_payload: dict[str, Any] | None = None
    for idx in range(1, max_attempts + 1):
        requested_run_id = f"analyze-mutillidae-{idx:02d}"
        res = _run(
            f"analyze_attempt_{idx}",
            _scanner_padv_cmd("analyze", "--config", STRICT_CONFIG_PATH, "--repo-root", STRICT_REPO_ROOT, "--mode", "variant", "--run-id", requested_run_id),
            timeout_seconds=analyze_timeout,
        )
        parsed = _safe_json_parse(res.stdout)
        recovered = _graph_progress_for_run(requested_run_id)
        observed = parsed if isinstance(parsed, dict) else recovered
        has_counts = isinstance(observed, dict) and int(observed.get("candidates", 0)) > 0 and int(observed.get("static_evidence", 0)) > 0
        completed = isinstance(recovered, dict) and bool(recovered.get("completed"))
        ok = (
            res.returncode == 0
            and isinstance(parsed, dict)
            and "error" not in parsed
            and has_counts
        ) or (
            completed
            and isinstance(observed, dict)
            and "error" not in observed
            and has_counts
        )
        if observed:
            final_payload = observed
        attempts.append(
            {
                "attempt": idx,
                "ok": ok,
                "failure_class": "" if ok else _attempt_failure_class(res),
                "result": res.to_dict(),
                "parsed_output": observed or {},
            }
        )
        if ok:
            success = True
            break
    output = {"phase": "A2", "generated_at": _now_iso(), "attempts": attempts, "success": success, "final_output": final_payload or {}}
    _write_json(output_dir / "a2-analyze-stabilization.json", output)
    return output


def run_strict_run_stabilization(output_dir: Path, max_attempts: int, run_timeout: int) -> dict[str, Any]:
    attempts: list[dict[str, Any]] = []
    success = False
    final_payload: dict[str, Any] | None = None
    for idx in range(1, max_attempts + 1):
        requested_run_id = f"run-mutillidae-{idx:02d}"
        res = _run(
            f"run_attempt_{idx}",
            _scanner_padv_cmd("run", "--config", STRICT_CONFIG_PATH, "--repo-root", STRICT_REPO_ROOT, "--mode", "variant", "--run-id", requested_run_id),
            timeout_seconds=run_timeout,
        )
        parsed = _safe_json_parse(res.stdout)
        recovered = _graph_progress_for_run(requested_run_id)
        observed = parsed if isinstance(parsed, dict) else recovered
        has_run = isinstance(observed, dict) and str(observed.get("run_id", "")).strip() != ""
        completed = isinstance(recovered, dict) and bool(recovered.get("completed"))
        ok = (
            res.returncode == 0
            and isinstance(parsed, dict)
            and "error" not in parsed
            and has_run
        ) or (
            completed
            and isinstance(observed, dict)
            and "error" not in observed
            and has_run
        )
        if observed:
            final_payload = observed
        attempts.append(
            {
                "attempt": idx,
                "ok": ok,
                "failure_class": "" if ok else _attempt_failure_class(res),
                "result": res.to_dict(),
                "parsed_output": observed or {},
            }
        )
        if ok:
            success = True
            break
    output = {"phase": "A3", "generated_at": _now_iso(), "attempts": attempts, "success": success, "final_output": final_payload or {}}
    _write_json(output_dir / "a3-run-stabilization.json", output)
    return output


def _load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return default


def _assessment_category(vuln_class: str) -> str:
    canonical = canonicalize_vuln_class(vuln_class)
    return _ASSESSMENT_CATEGORY_BY_CANONICAL_CLASS.get(canonical, "")


def _category_match(category: str, vuln_class: str) -> bool:
    return str(category).strip() == _assessment_category(vuln_class)


def _load_gap_rows() -> list[dict[str, Any]]:
    return _load_json(GAP_CATALOG_PATH, [])


def _store() -> EvidenceStore:
    return EvidenceStore(PADV_STORE)


def _require_run_id(run_id: str) -> str:
    normalized = str(run_id).strip()
    if not normalized:
        raise ValueError("run_id is required")
    return normalized


def _load_candidates(run_id: str) -> list[dict[str, Any]]:
    run_store = _store().for_run(_require_run_id(run_id))
    payload = run_store.load_json_artifact("candidates.json")
    if not isinstance(payload, list):
        return []
    return [item for item in payload if isinstance(item, dict)]


def _load_bundles(run_id: str) -> list[dict[str, Any]]:
    run_store = _store().for_run(_require_run_id(run_id))
    bundles: list[dict[str, Any]] = []
    for bundle_id in run_store.list_bundle_ids():
        payload = run_store.load_bundle(bundle_id)
        if isinstance(payload, dict):
            bundles.append(payload)
    return bundles


def _bundle_candidate_outcome(bundle: dict[str, Any]) -> str:
    explicit = str(bundle.get("candidate_outcome", "")).strip().upper()
    if explicit:
        return explicit
    decision = str((bundle.get("gate_result") or {}).get("decision", "")).strip().upper()
    return explicit_candidate_outcome_for_decision(decision)


def _bundle_refutation_has_strong_witness(bundle: dict[str, Any]) -> bool:
    contract = (bundle.get("validation_contract") or {}).get("witness_contract", {})
    witness = (bundle.get("validation_contract") or {}).get("witness", {})
    if not isinstance(contract, dict) or not isinstance(witness, dict):
        return False
    positive_flags = {
        str(item).strip().casefold()
        for item in witness.get("positive_flags", [])
        if str(item).strip()
    }
    negative_flags = {
        str(item).strip().casefold()
        for item in witness.get("negative_flags", [])
        if str(item).strip()
    }
    required_all = {
        str(item).strip().casefold()
        for item in contract.get("required_all", [])
        if str(item).strip()
    }
    required_any = {
        str(item).strip().casefold()
        for item in contract.get("required_any", [])
        if str(item).strip()
    }
    forbidden_negative = {
        str(item).strip().casefold()
        for item in contract.get("negative_must_not_include", [])
        if str(item).strip()
    }
    enforce_negative_clean = bool(contract.get("enforce_negative_clean", True))
    if required_all and not required_all.issubset(positive_flags):
        return False
    if required_any and not (positive_flags & required_any):
        return False
    if enforce_negative_clean and forbidden_negative and (negative_flags & forbidden_negative):
        return False
    return bool(required_all or required_any)


def _bundle_coverage_outcome(bundle: dict[str, Any]) -> str:
    outcome = _bundle_candidate_outcome(bundle)
    if outcome == "VALIDATED":
        return "VALIDATED"
    if outcome == "REFUTED":
        return "REFUTED"
    if outcome in {"SKIPPED_BUDGET", "SKIPPED_PRECONDITION"}:
        return "SKIPPED"
    if outcome == "ERROR":
        return "ERROR"
    return "ERROR"


def _normalize_reason_token(value: str, default: str) -> str:
    normalized = _REASON_TOKEN_RE.sub("_", str(value).strip().casefold()).strip("_")
    return normalized or default


def _bundle_outcome_reason(bundle: dict[str, Any]) -> str:
    outcome = _bundle_candidate_outcome(bundle)
    default_reason = {
        "VALIDATED": "validated",
        "REFUTED": "refuted",
        "SKIPPED_BUDGET": "skipped_budget",
        "SKIPPED_PRECONDITION": "skipped_precondition",
        "ERROR": "error",
    }.get(outcome, "error")
    gate_result = bundle.get("gate_result")
    if isinstance(gate_result, dict):
        reason = str(gate_result.get("reason", "")).strip()
        if reason:
            return _normalize_reason_token(reason, default_reason)
    return default_reason


def _count_bundle_outcomes(bundles: list[dict[str, Any]]) -> dict[str, int]:
    counts = default_candidate_outcomes()
    for bundle in bundles:
        outcome = _bundle_candidate_outcome(bundle)
        counts[outcome] = counts.get(outcome, 0) + 1
    return counts


def _count_bundle_outcome_reasons(bundles: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
    reasons = {key: {} for key in default_candidate_outcomes()}
    for bundle in bundles:
        outcome = _bundle_candidate_outcome(bundle)
        reason = _bundle_outcome_reason(bundle)
        outcome_reasons = reasons.setdefault(outcome, {})
        outcome_reasons[reason] = outcome_reasons.get(reason, 0) + 1
    return reasons


def run_phase_b(output_dir: Path, run_id: str, phase_a: dict[str, Any]) -> dict[str, Any]:
    run_id = _require_run_id(run_id)
    matrix: list[dict[str, Any]] = []
    gaps = []

    a1_ok = bool(phase_a.get("a1", {}).get("summary", {}).get("all_passed"))
    a2_ok = bool(phase_a.get("a2", {}).get("success"))
    a3_ok = bool(phase_a.get("a3", {}).get("success"))

    matrix.append(
        RequirementResult("CORE-INFRA", "Mutillidae stack preflight", "preflight completed", str(output_dir / "a1-preflight.json"), "FULL" if a1_ok else "FAIL", "" if a1_ok else "preflight failed", "fix Docker/runtime preflight blockers").to_dict()
    )
    matrix.append(
        RequirementResult("CORE-ANALYZE", "strict analyze on Mutillidae", "analyze completed", str(output_dir / "a2-analyze-stabilization.json"), "FULL" if a2_ok else "FAIL", "" if a2_ok else "analyze did not finish successfully", "stabilize semantic discovery and agent path").to_dict()
    )
    matrix.append(
        RequirementResult("CORE-RUN", "strict run on Mutillidae", "run completed", str(output_dir / "a3-run-stabilization.json"), "FULL" if a3_ok else "FAIL", "" if a3_ok else "strict run did not finish successfully", "stabilize runtime validation path").to_dict()
    )

    candidates = _load_candidates(run_id)
    bundles = _load_bundles(run_id)
    candidate_outcomes = _count_bundle_outcomes(bundles)
    outcome_reasons = _count_bundle_outcome_reasons(bundles)
    run_summary = _store().load_run_summary(run_id)
    for gap in _load_gap_rows():
        category = str(gap.get("category", ""))
        matched_candidates = [
            item
            for item in candidates
            if _category_match(category, str(item.get("canonical_class", "") or item.get("vuln_class", "")))
        ]
        matched_bundles = [
            item
            for item in bundles
            if _category_match(category, str(((item.get("candidate") or {}).get("canonical_class", "") or (item.get("candidate") or {}).get("vuln_class", ""))))
        ]
        found_by_static = any(set(item.get("provenance", [])) & {"source", "joern", "scip"} for item in matched_candidates)
        found_by_web = any("web" in item.get("provenance", []) or item.get("web_path_hints") for item in matched_candidates)
        runtime_attempted = bool(matched_bundles)
        runtime_outcomes = [_bundle_coverage_outcome(item) for item in matched_bundles]
        matched_outcome_counts = _count_bundle_outcomes(matched_bundles)
        matched_outcome_reasons = _count_bundle_outcome_reasons(matched_bundles)
        strong_refutation_count = sum(
            1
            for item, outcome in zip(matched_bundles, runtime_outcomes, strict=False)
            if outcome == "REFUTED" and _bundle_refutation_has_strong_witness(item)
        )
        runtime_full = any(outcome == "VALIDATED" for outcome in runtime_outcomes) or strong_refutation_count > 0

        if not gap.get("runtime_validatable"):
            status = "FULL" if matched_candidates else "NONE"
        elif runtime_full:
            status = "FULL"
        elif runtime_attempted:
            status = "PARTIAL"
        else:
            status = "NONE"

        evidence_path = str(_store().for_run(run_id).root / "candidates.json") if matched_candidates else str(GAP_CATALOG_PATH)
        observed = json.dumps(
            {
                "found_by_static": found_by_static,
                "found_by_web": found_by_web,
                "runtime_attempted": runtime_attempted,
                "runtime_outcomes": runtime_outcomes,
                "outcome_counts": matched_outcome_counts,
                "outcome_reasons": matched_outcome_reasons,
                "strong_refutation_count": strong_refutation_count,
            },
            ensure_ascii=True,
        )
        root_cause = "" if status == "FULL" else "category not fully exercised by current Mutillidae run"
        next_fix = "improve discovery/runtime coverage for this documented Mutillidae category" if status != "FULL" else ""
        matrix.append(
            RequirementResult(gap["gap_id"], f"Mutillidae documented gap: {category}", observed, evidence_path, status, root_cause, next_fix).to_dict()
        )

    gaps = matrix_to_gap_list(matrix)
    output = {
        "phase": "B",
        "generated_at": _now_iso(),
        "run_id": run_id,
        "matrix": matrix,
        "gaps": gaps,
        "candidate_outcomes": candidate_outcomes,
        "outcome_reasons": outcome_reasons,
        "stop_rule": str((run_summary or {}).get("stop_rule", "")),
        "stop_reason": str((run_summary or {}).get("stop_reason", "")),
    }
    _write_json(output_dir / "phase-b-matrix.json", output)
    return output


def _write_report_markdown(output_dir: Path, phase_a: dict[str, Any], phase_b: dict[str, Any] | None) -> None:
    lines = ["# Mutillidae Integration Assessment", "", "## Phase A", ""]
    for phase_name in ("a1", "a2", "a3"):
        payload = phase_a.get(phase_name, {})
        lines.append(f"- `{phase_name.upper()}`: `{json.dumps(payload.get('summary', payload.get('success', {})), ensure_ascii=True)}`")
    if phase_b is not None:
        lines.extend(["", "## Phase B", ""])
        for row in phase_b.get("matrix", []):
            lines.append(f"- `{row['requirement_id']}` `{row['status']}` {row['scenario']}")
        lines.extend(["", "## Gaps", ""])
        for gap in phase_b.get("gaps", []):
            lines.append(f"- `{gap['priority']}` `{gap['requirement_id']}` {gap['status']} {gap['root_cause']}")
    (output_dir / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Stabilize strict Mutillidae integration run and produce requirement assessment.")
    parser.add_argument("--phase", choices=["a", "b", "full"], default="full")
    parser.add_argument("--run-id", default="")
    parser.add_argument("--max-attempts", type=int, default=2)
    parser.add_argument("--analyze-timeout", type=int, default=3600)
    parser.add_argument("--run-timeout", type=int, default=3600)
    args = parser.parse_args()
    if args.phase == "b" and not str(args.run_id).strip():
        parser.error("--run-id is required when --phase b")

    timestamp = datetime.now(tz=timezone.utc).strftime("%Y%m%d-%H%M%S")
    output_dir = PADV_STORE / "assessments" / f"mutillidae-{timestamp}"
    output_dir.mkdir(parents=True, exist_ok=True)

    phase_a: dict[str, Any] = {}
    phase_b: dict[str, Any] | None = None

    if args.phase in {"a", "full"}:
        phase_a["a1"] = run_preflight(output_dir)
        phase_a["a2"] = run_analyze_stabilization(output_dir, args.max_attempts, args.analyze_timeout)
        phase_a["a3"] = run_strict_run_stabilization(output_dir, args.max_attempts, args.run_timeout)
    else:
        phase_a = {"a1": {"summary": {"all_passed": True}}, "a2": {"success": True}, "a3": {"success": True, "final_output": {}}}

    phase_a_success = bool(phase_a.get("a1", {}).get("summary", {}).get("all_passed")) and bool(phase_a.get("a2", {}).get("success")) and bool(phase_a.get("a3", {}).get("success"))
    run_id = _require_run_id(args.run_id) if args.phase == "b" else str((phase_a.get("a3", {}).get("final_output", {}) or {}).get("run_id", "")).strip()

    if args.phase in {"b", "full"}:
        phase_b = run_phase_b(output_dir, run_id=run_id, phase_a=phase_a)

    _write_json(output_dir / "phase-a-summary.json", phase_a)
    _write_report_markdown(output_dir, phase_a, phase_b)
    print(json.dumps({"ok": phase_a_success, "phase": args.phase, "output_dir": str(output_dir), "run_id": run_id}, indent=2, ensure_ascii=True))
    return 0 if phase_a_success or args.phase == "b" else 1


if __name__ == "__main__":
    raise SystemExit(main())

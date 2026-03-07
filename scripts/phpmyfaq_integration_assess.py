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

from padv.eval.integration_assessment import (
    RequirementResult,
    classify_failure,
    matrix_to_gap_list,
)


PADV_STORE = ROOT_DIR / ".padv"
PMF_COMPOSE_FILE = ROOT_DIR / "docker-compose.phpmyfaq.yml"
SCANNER_COMPOSE_FILE = ROOT_DIR / "docker-compose.yml"
PMF_PROJECT = "phpmyfaq-e2e"
SCANNER_PROJECT = "haxor-scan"
STRICT_CONFIG_PATH = "/workspace/haxor/padv.phpmyfaq.strict.toml"
STRICT_REPO_ROOT = "/workspace/targets/phpMyFAQ"


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
    started_dt = datetime.now(tz=timezone.utc)
    started = started_dt.isoformat()
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
        ended = datetime.now(tz=timezone.utc).isoformat()
        duration = time.monotonic() - t0
        return CmdResult(
            name=name,
            cmd=cmd,
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
            started_at=started,
            ended_at=ended,
            duration_seconds=duration,
        )
    except subprocess.TimeoutExpired as exc:
        ended = datetime.now(tz=timezone.utc).isoformat()
        duration = time.monotonic() - t0
        stdout = exc.stdout if isinstance(exc.stdout, str) else ""
        stderr = exc.stderr if isinstance(exc.stderr, str) else ""
        timeout_msg = f"command timed out after {timeout_seconds}s"
        stderr = f"{stderr}\n{timeout_msg}".strip()
        return CmdResult(
            name=name,
            cmd=cmd,
            returncode=124,
            stdout=stdout,
            stderr=stderr,
            started_at=started,
            ended_at=ended,
            duration_seconds=duration,
        )


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


def _pmf_compose_cmd(*args: str) -> list[str]:
    return [
        "docker",
        "compose",
        "-f",
        str(PMF_COMPOSE_FILE),
        "--project-name",
        PMF_PROJECT,
        *args,
    ]


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
        snippet = raw[first : last + 1]
        try:
            parsed = json.loads(snippet)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            return None
    return None


def _detect_last_stage(stderr: str) -> str:
    matches = re.findall(r"\]\s+([a-z_]+)\s+(?:start|done|error|failed|info)\b", stderr or "")
    if not matches:
        return ""
    return matches[-1]


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=True), encoding="utf-8")


def _read_json(path: Path) -> Any:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


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

    # Docker services running
    pmf_ps = _run("pmf_services", _pmf_compose_cmd("ps", "--status", "running", "apache", "mariadb"), 120)
    pmf_ok = pmf_ps.returncode == 0 and "apache" in pmf_ps.stdout and "mariadb" in pmf_ps.stdout
    add_check("docker_services_phpmyfaq", pmf_ps, pmf_ok, "apache/mariadb not running")

    scan_ps = _run("scanner_service", ["docker", "compose", "-f", str(SCANNER_COMPOSE_FILE), "--project-name", SCANNER_PROJECT, "ps", "--status", "running", "joern"], 120)
    scan_ok = scan_ps.returncode == 0 and "joern" in scan_ps.stdout
    add_check("docker_service_joern", scan_ps, scan_ok, "joern service not running")

    # Reachability
    app_http = _run("http_phpmyfaq", ["curl", "-fsS", "http://127.0.0.1:18080/index.php"], 60)
    add_check("phpmyfaq_http_reachable", app_http, app_http.returncode == 0, "phpMyFAQ not reachable on :18080")

    joern_http = _run(
        "http_joern",
        ["curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}", "http://127.0.0.1:8080/"],
        30,
    )
    joern_code = joern_http.stdout.strip()
    joern_ok = joern_http.returncode == 0 and joern_code not in {"", "000"}
    add_check("joern_http_reachable", joern_http, joern_ok, "joern not reachable on :8080")

    # Morcilla checks
    morcilla_mod = _run("morcilla_module", _pmf_compose_cmd("exec", "-T", "apache", "php", "-m"), 120)
    mod_ok = morcilla_mod.returncode == 0 and re.search(r"(?im)^morcilla$", morcilla_mod.stdout or "") is not None
    add_check("morcilla_module_loaded", morcilla_mod, mod_ok, "morcilla module not loaded in apache container")

    morcilla_headers = _run(
        "morcilla_headers",
        [
            "curl",
            "-fsSI",
            "-H",
            "Morcilla-Key: test-key",
            "-H",
            "Morcilla-Intercept: mysqli_query",
            "-H",
            "Morcilla-Correlation: preflight-1",
            "http://127.0.0.1:18080/index.php",
        ],
        60,
    )
    hdr_ok = morcilla_headers.returncode == 0 and re.search(
        r"(?im)^X-Morcilla-Status:",
        morcilla_headers.stdout or "",
    )
    add_check("morcilla_headers_visible", morcilla_headers, bool(hdr_ok), "missing X-Morcilla-Status response header")

    passed = sum(1 for c in checks if c["pass"])
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
        res = _run(
            f"analyze_attempt_{idx}",
            _scanner_padv_cmd(
                "analyze",
                "--config",
                STRICT_CONFIG_PATH,
                "--repo-root",
                STRICT_REPO_ROOT,
                "--mode",
                "variant",
            ),
            timeout_seconds=analyze_timeout,
        )
        parsed = _safe_json_parse(res.stdout)
        has_counts = isinstance(parsed, dict) and int(parsed.get("candidates", 0)) > 0 and int(parsed.get("static_evidence", 0)) > 0
        ok = res.returncode == 0 and isinstance(parsed, dict) and "error" not in parsed and has_counts
        attempt = {
            "attempt": idx,
            "ok": ok,
            "failure_class": "" if ok else classify_failure(f"{res.stdout}\n{res.stderr}"),
            "result": res.to_dict(),
            "parsed_output": parsed,
        }
        attempts.append(attempt)
        if ok:
            success = True
            final_payload = parsed
            break

    output = {
        "phase": "A2",
        "generated_at": _now_iso(),
        "max_attempts": max_attempts,
        "attempts": attempts,
        "success": success,
        "final_output": final_payload or {},
    }
    _write_json(output_dir / "a2-analyze-stabilization.json", output)
    return output


def run_strict_run_stabilization(
    output_dir: Path,
    max_attempts: int,
    run_timeout: int,
    validate_timeout: int,
) -> dict[str, Any]:
    attempts: list[dict[str, Any]] = []
    success = False
    final_payload: dict[str, Any] | None = None

    for idx in range(1, max_attempts + 1):
        res = _run(
            f"run_attempt_{idx}",
            _scanner_padv_cmd(
                "run",
                "--config",
                STRICT_CONFIG_PATH,
                "--repo-root",
                STRICT_REPO_ROOT,
                "--mode",
                "variant",
            ),
            timeout_seconds=run_timeout,
        )
        parsed = _safe_json_parse(res.stdout)
        has_bundles = isinstance(parsed, dict) and len(parsed.get("bundle_ids", []) or []) > 0
        ok = res.returncode == 0 and isinstance(parsed, dict) and "error" not in parsed and has_bundles
        stage = _detect_last_stage(res.stderr)
        retest: dict[str, Any] | None = None
        if not ok and stage in {"validation_plan", "runtime_validate", "deterministic_gates"}:
            ret = _run(
                f"targeted_validate_attempt_{idx}",
                _scanner_padv_cmd(
                    "validate",
                    "--config",
                    STRICT_CONFIG_PATH,
                    "--repo-root",
                    STRICT_REPO_ROOT,
                    "--mode",
                    "variant",
                ),
                timeout_seconds=validate_timeout,
            )
            retest = {
                "stage": stage,
                "result": ret.to_dict(),
                "parsed_output": _safe_json_parse(ret.stdout),
            }

        attempt = {
            "attempt": idx,
            "ok": ok,
            "failure_class": "" if ok else classify_failure(f"{res.stdout}\n{res.stderr}"),
            "failed_stage": stage,
            "result": res.to_dict(),
            "parsed_output": parsed,
            "targeted_retest": retest or {},
        }
        attempts.append(attempt)
        if ok:
            success = True
            final_payload = parsed
            break

    output = {
        "phase": "A3",
        "generated_at": _now_iso(),
        "max_attempts": max_attempts,
        "attempts": attempts,
        "success": success,
        "final_output": final_payload or {},
    }
    _write_json(output_dir / "a3-run-stabilization.json", output)
    return output


def _load_run_summary(run_id: str) -> dict[str, Any] | None:
    return _read_json(PADV_STORE / "runs" / f"{run_id}.json")


def _load_bundle(bundle_id: str) -> dict[str, Any] | None:
    return _read_json(PADV_STORE / "bundles" / f"{bundle_id}.json")


def _has_stage_snapshots(run_id: str, expected_stages: list[str]) -> tuple[bool, list[str], list[str], str]:
    stage_dir = PADV_STORE / "runs" / run_id / "stages"
    if not stage_dir.exists():
        return False, [], expected_stages, str(stage_dir)
    names = [p.stem.split("-", 1)[-1] for p in sorted(stage_dir.glob("*.json"))]
    missing = [s for s in expected_stages if s not in names]
    return len(missing) == 0, names, missing, str(stage_dir)


def _run_cli_evidence(bundle_ids: list[str], run_id: str, output_dir: Path) -> tuple[bool, list[dict[str, Any]]]:
    cmds: list[tuple[str, list[str]]] = [
        ("list_bundles", _scanner_padv_cmd("list", "--config", STRICT_CONFIG_PATH, "bundles")),
        ("list_runs", _scanner_padv_cmd("list", "--config", STRICT_CONFIG_PATH, "runs")),
        ("show_run", _scanner_padv_cmd("show", "--config", STRICT_CONFIG_PATH, "--run-id", run_id)),
    ]
    if bundle_ids:
        cmds.append(("show_bundle", _scanner_padv_cmd("show", "--config", STRICT_CONFIG_PATH, "--bundle-id", bundle_ids[0])))
        export_path = f"/workspace/haxor/.padv/integration-assessment-exports/{bundle_ids[0]}.json"
        cmds.append(
            (
                "export_bundle",
                _scanner_padv_cmd(
                    "export",
                    "--config",
                    STRICT_CONFIG_PATH,
                    "--bundle-id",
                    bundle_ids[0],
                    "--output",
                    export_path,
                ),
            )
        )

    results: list[dict[str, Any]] = []
    all_ok = True
    for name, cmd in cmds:
        res = _run(name, cmd, timeout_seconds=1200)
        ok = res.returncode == 0
        all_ok = all_ok and ok
        results.append({"name": name, "ok": ok, "result": res.to_dict(), "parsed_output": _safe_json_parse(res.stdout)})
    _write_json(output_dir / "b1-cli-evidence.json", {"commands": results, "all_ok": all_ok})
    return all_ok, results


def _evaluate_enhancement_rows(
    run_summary: dict[str, Any],
    bundles: list[dict[str, Any]],
    output_dir: Path,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    artifacts_dir = PADV_STORE / "artifacts"
    failure_artifacts = sorted(str(p) for p in artifacts_dir.glob("failure-analysis-*.json")) if artifacts_dir.exists() else []
    analyze_failures_cmd = _run(
        "analyze_failures",
        _scanner_padv_cmd("analyze-failures", "--config", STRICT_CONFIG_PATH, "--format", "json"),
        timeout_seconds=1200,
    )
    analyze_failures_ok = analyze_failures_cmd.returncode == 0 and _safe_json_parse(analyze_failures_cmd.stdout) is not None
    _write_json(
        output_dir / "b1-analyze-failures.json",
        {"result": analyze_failures_cmd.to_dict(), "parsed_output": _safe_json_parse(analyze_failures_cmd.stdout)},
    )

    checks = [
        ("E1", ROOT_DIR / "padv/discovery/taint_spec.py", "LLM-Based Taint Specification Inference"),
        ("E2", ROOT_DIR / "padv/static/joern/slicer.py", "CPG-Slice → LLM Refinement Pipeline"),
        ("E3", ROOT_DIR / "padv/discovery/web_state.py", "State-Graph-Aware Web Discovery"),
        ("E4", ROOT_DIR / "tests/test_input_state.py", "Morcilla Input-to-State Feedback"),
        ("E5", ROOT_DIR / "padv/orchestrator/mutations.py", "Morcilla-Guided Mutation Loop"),
    ]
    for rid, path, title in checks:
        exists = path.exists()
        rows.append(
            RequirementResult(
                requirement_id=rid,
                scenario=title,
                observed_result=f"implementation_artifact_exists={exists}",
                evidence_path=str(path),
                status="FULL" if exists else "FAIL",
                root_cause="" if exists else "implementation artifact missing",
                next_fix="" if exists else f"implement {rid} module and integration hooks per PRD-enhancements",
            ).to_dict()
        )

    # E6 differential
    has_differential_key = all("differential_pairs" in b for b in bundles) if bundles else False
    non_empty_pairs = any((b.get("differential_pairs") or []) for b in bundles) if bundles else False
    e6_status = "FULL" if has_differential_key and non_empty_pairs else ("PARTIAL" if has_differential_key else "FAIL")
    e6_cause = ""
    e6_fix = ""
    if e6_status == "PARTIAL":
        e6_cause = "differential feature integrated, but no runtime differential pair observed in this run"
        e6_fix = "add authz-targeted candidate scenario/auth state to force differential evidence generation"
    if e6_status == "FAIL":
        e6_cause = "differential_pairs missing from runtime bundles"
        e6_fix = "wire differential validation output into EvidenceBundle persistence"
    rows.append(
        RequirementResult(
            requirement_id="E6",
            scenario="Differential Validation for AuthZ Classes",
            observed_result=f"has_bundle_field={has_differential_key}, non_empty_pairs={non_empty_pairs}",
            evidence_path=str(PADV_STORE / "bundles"),
            status=e6_status,
            root_cause=e6_cause,
            next_fix=e6_fix,
        ).to_dict()
    )

    # E7 failure learning
    e7_status = "FULL" if failure_artifacts and analyze_failures_ok else ("PARTIAL" if failure_artifacts or analyze_failures_ok else "FAIL")
    e7_cause = ""
    e7_fix = ""
    if e7_status == "PARTIAL":
        e7_cause = "failure analysis only partially integrated (artifact or command missing)"
        e7_fix = "ensure init node persists failure-analysis artifacts and CLI analyze-failures remains functional"
    if e7_status == "FAIL":
        e7_cause = "no failure-analysis artifact and analyze-failures command not functional"
        e7_fix = "implement E7 analytics pipeline and CLI wiring"
    rows.append(
        RequirementResult(
            requirement_id="E7",
            scenario="Failure-Pattern Learning",
            observed_result=f"failure_artifacts={len(failure_artifacts)}, analyze_failures_ok={analyze_failures_ok}",
            evidence_path=";".join(failure_artifacts[:5]) if failure_artifacts else str(PADV_STORE / "artifacts"),
            status=e7_status,
            root_cause=e7_cause,
            next_fix=e7_fix,
        ).to_dict()
    )

    return rows


def run_phase_b(output_dir: Path, run_id: str, phase_a: dict[str, Any], run_timeout: int) -> dict[str, Any]:
    summary = _load_run_summary(run_id) or {}
    bundle_ids = [str(x) for x in summary.get("bundle_ids", []) if str(x).strip()]
    bundles = [b for b in (_load_bundle(bid) for bid in bundle_ids) if isinstance(b, dict)]
    candidates = _read_json(PADV_STORE / "candidates.json") or []
    static_ev = _read_json(PADV_STORE / "static_evidence.json") or []

    matrix: list[dict[str, Any]] = []

    # Core Infra / Analyze / Run from phase A
    a1 = phase_a.get("a1", {})
    a2 = phase_a.get("a2", {})
    a3 = phase_a.get("a3", {})
    preflight_ok = bool((a1.get("summary") or {}).get("all_passed"))
    analyze_ok = bool(a2.get("success"))
    run_ok = bool(a3.get("success"))

    matrix.append(
        RequirementResult(
            requirement_id="CORE-INFRA",
            scenario="A1 Preflight",
            observed_result=f"passed={(a1.get('summary') or {}).get('passed', 0)}/{(a1.get('summary') or {}).get('total', 0)}",
            evidence_path=str(output_dir / "a1-preflight.json"),
            status="FULL" if preflight_ok else "FAIL",
            root_cause="" if preflight_ok else "infrastructure prerequisites not met",
            next_fix="" if preflight_ok else "resolve failing preflight checks before strict analyze/run",
        ).to_dict()
    )
    matrix.append(
        RequirementResult(
            requirement_id="CORE-ANALYZE",
            scenario="A2 Analyze stabilization",
            observed_result=json.dumps(a2.get("final_output", {}), ensure_ascii=True),
            evidence_path=str(output_dir / "a2-analyze-stabilization.json"),
            status="FULL" if analyze_ok else "FAIL",
            root_cause="" if analyze_ok else "analyze flow still unstable under strict config",
            next_fix="" if analyze_ok else "triage by failure_class and fix blocking channel",
        ).to_dict()
    )
    matrix.append(
        RequirementResult(
            requirement_id="CORE-RUN",
            scenario="A3 Run stabilization",
            observed_result=json.dumps(a3.get("final_output", {}), ensure_ascii=True),
            evidence_path=str(output_dir / "a3-run-stabilization.json"),
            status="FULL" if run_ok else "FAIL",
            root_cause="" if run_ok else "strict run flow still unstable or no bundles produced",
            next_fix="" if run_ok else "fix stage-specific failures and re-run strict run",
        ).to_dict()
    )

    cli_ok, _cli_results = _run_cli_evidence(bundle_ids, run_id, output_dir)
    matrix.append(
        RequirementResult(
            requirement_id="CORE-CLI",
            scenario="CLI integration (list/show/export)",
            observed_result=f"all_ok={cli_ok}",
            evidence_path=str(output_dir / "b1-cli-evidence.json"),
            status="FULL" if cli_ok else "PARTIAL",
            root_cause="" if cli_ok else "one or more artifact CLI commands failed",
            next_fix="" if cli_ok else "fix command/runtime path resolution for failed CLI subcommands",
        ).to_dict()
    )

    expected_stages = [
        "init",
        "static_discovery",
        "web_discovery",
        "auth_setup",
        "candidate_synthesis",
        "skeptic_refine",
        "objective_schedule",
        "frontier_update",
        "validation_plan",
        "runtime_validate",
        "deterministic_gates",
        "dedup_topk",
        "persist",
    ]
    stage_ok, stage_names, stage_missing, stage_path = _has_stage_snapshots(run_id, expected_stages)
    matrix.append(
        RequirementResult(
            requirement_id="CORE-GRAPH-FLOW",
            scenario="Expected LangGraph stage snapshots",
            observed_result=f"stages_seen={len(stage_names)}, missing={stage_missing}",
            evidence_path=stage_path,
            status="FULL" if stage_ok else ("PARTIAL" if stage_names else "FAIL"),
            root_cause="" if stage_ok else "missing required stage snapshot(s)",
            next_fix="" if stage_ok else "ensure stage execution writes snapshots for every required node",
        ).to_dict()
    )

    channels: set[str] = set()
    for cand in candidates:
        if not isinstance(cand, dict):
            continue
        provenance = cand.get("provenance", [])
        if isinstance(provenance, list):
            for item in provenance:
                if isinstance(item, str) and item.strip():
                    channels.add(item.strip().lower())
    required_channels = {"source", "joern", "scip", "web"}
    present_count = len(required_channels & channels)
    discovery_status = "FULL" if present_count == 4 else ("PARTIAL" if present_count >= 2 else "FAIL")
    matrix.append(
        RequirementResult(
            requirement_id="CORE-DISCOVERY",
            scenario="Source+Joern+SCIP+Web candidate evidence",
            observed_result=f"channels_present={sorted(channels)}",
            evidence_path=str(PADV_STORE / "candidates.json"),
            status=discovery_status,
            root_cause="" if discovery_status == "FULL" else "not all discovery channels produced candidate evidence",
            next_fix="" if discovery_status == "FULL" else "inspect failing channel(s) and recover strict signal path",
        ).to_dict()
    )

    bundles_ok = bool(bundles)
    runtime_shape_ok = bundles_ok and all(
        isinstance(b.get("gate_result"), dict)
        and len(b.get("positive_runtime", []) or []) >= 3
        and len(b.get("negative_runtime", []) or []) >= 1
        for b in bundles
    )
    matrix.append(
        RequirementResult(
            requirement_id="CORE-RUNTIME-GATES",
            scenario="Validation runtime + deterministic gates + bundles",
            observed_result=f"bundle_count={len(bundles)}, runtime_shape_ok={runtime_shape_ok}",
            evidence_path=str(PADV_STORE / "bundles"),
            status="FULL" if runtime_shape_ok else ("PARTIAL" if bundles_ok else "FAIL"),
            root_cause="" if runtime_shape_ok else "missing bundle runtime/gate evidence shape",
            next_fix="" if runtime_shape_ok else "ensure runtime_validate emits full positive/negative evidence and gate_result",
        ).to_dict()
    )

    evidence_paths = [
        PADV_STORE / "candidates.json",
        PADV_STORE / "static_evidence.json",
        PADV_STORE / "runs" / f"{run_id}.json",
        PADV_STORE / "bundles",
        PADV_STORE / "runs" / run_id / "stages",
    ]
    existing = [p for p in evidence_paths if p.exists()]
    store_status = "FULL" if len(existing) == len(evidence_paths) else ("PARTIAL" if existing else "FAIL")
    matrix.append(
        RequirementResult(
            requirement_id="CORE-EVIDENCE-STORE",
            scenario="Evidence persistence completeness",
            observed_result=f"existing={len(existing)}/{len(evidence_paths)}",
            evidence_path=";".join(str(p) for p in evidence_paths),
            status=store_status,
            root_cause="" if store_status == "FULL" else "required evidence artifacts missing",
            next_fix="" if store_status == "FULL" else "fix persistence path and stage artifact writes",
        ).to_dict()
    )

    determinism_res = _run(
        "determinism_second_run",
        _scanner_padv_cmd("run", "--config", STRICT_CONFIG_PATH, "--repo-root", STRICT_REPO_ROOT, "--mode", "variant"),
        timeout_seconds=run_timeout,
    )
    determinism_parsed = _safe_json_parse(determinism_res.stdout) or {}
    _write_json(
        output_dir / "b1-determinism-second-run.json",
        {"result": determinism_res.to_dict(), "parsed_output": determinism_parsed},
    )
    decisions_1 = summary.get("decisions", {})
    decisions_2 = determinism_parsed.get("decisions", {})
    det_status = "FAIL"
    det_cause = "second strict run failed"
    det_fix = "stabilize runtime nondeterminism and stage failures before determinism check"
    if determinism_res.returncode == 0 and isinstance(decisions_2, dict):
        if decisions_1 == decisions_2:
            det_status = "FULL"
            det_cause = ""
            det_fix = ""
        else:
            det_status = "PARTIAL"
            det_cause = "second run succeeded but decisions differ"
            det_fix = "investigate non-deterministic discovery/planning/runtime influences"
    matrix.append(
        RequirementResult(
            requirement_id="CORE-DETERMINISM",
            scenario="Two strict runs produce consistent gate decisions",
            observed_result=f"run1_decisions={decisions_1}, run2_decisions={decisions_2}",
            evidence_path=str(output_dir / "b1-determinism-second-run.json"),
            status=det_status,
            root_cause=det_cause,
            next_fix=det_fix,
        ).to_dict()
    )

    matrix.extend(_evaluate_enhancement_rows(summary, bundles, output_dir))
    gap_list = matrix_to_gap_list(matrix)

    output = {
        "phase": "B",
        "generated_at": _now_iso(),
        "run_id": run_id,
        "matrix": matrix,
        "gaps": gap_list,
    }
    _write_json(output_dir / "b1-b2-assessment.json", output)
    return output


def _write_report_markdown(output_dir: Path, phase_a: dict[str, Any], phase_b: dict[str, Any] | None) -> None:
    lines: list[str] = []
    lines.append("# phpMyFAQ Integration Assessment")
    lines.append("")
    lines.append(f"- Generated: {_now_iso()}")
    lines.append(f"- Output dir: `{output_dir}`")
    lines.append("")

    a1 = phase_a.get("a1", {})
    a2 = phase_a.get("a2", {})
    a3 = phase_a.get("a3", {})
    lines.append("## Phase A")
    lines.append("")
    lines.append(f"- A1 preflight: `{(a1.get('summary') or {}).get('passed', 0)}/{(a1.get('summary') or {}).get('total', 0)}` checks passed")
    lines.append(f"- A2 analyze success: `{bool(a2.get('success'))}`")
    lines.append(f"- A3 run success: `{bool(a3.get('success'))}`")
    lines.append("")

    if phase_b is not None:
        lines.append("## Phase B Matrix")
        lines.append("")
        lines.append("| requirement_id | status | root_cause | next_fix |")
        lines.append("|---|---|---|---|")
        for row in phase_b.get("matrix", []):
            rid = str(row.get("requirement_id", ""))
            status = str(row.get("status", ""))
            cause = str(row.get("root_cause", "")).replace("|", "/")
            fix = str(row.get("next_fix", "")).replace("|", "/")
            lines.append(f"| {rid} | {status} | {cause} | {fix} |")
        lines.append("")
        lines.append("## Gap Prioritization")
        lines.append("")
        lines.append("| priority | requirement_id | status | root_cause | next_fix |")
        lines.append("|---|---|---|---|---|")
        for gap in phase_b.get("gaps", []):
            prio = str(gap.get("priority", ""))
            rid = str(gap.get("requirement_id", ""))
            status = str(gap.get("status", ""))
            cause = str(gap.get("root_cause", "")).replace("|", "/")
            fix = str(gap.get("next_fix", "")).replace("|", "/")
            lines.append(f"| {prio} | {rid} | {status} | {cause} | {fix} |")

    (output_dir / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Stabilize strict phpMyFAQ integration run and produce requirement assessment.")
    parser.add_argument("--phase", choices=["a", "b", "full"], default="full")
    parser.add_argument("--max-attempts", type=int, default=2, help="Max attempts for analyze/run stabilization in phase A.")
    parser.add_argument("--output-dir", default="", help="Optional output directory path.")
    parser.add_argument("--analyze-timeout", type=int, default=1800, help="Timeout in seconds for each analyze attempt.")
    parser.add_argument("--run-timeout", type=int, default=2400, help="Timeout in seconds for each run attempt.")
    parser.add_argument("--validate-timeout", type=int, default=1800, help="Timeout in seconds for targeted validate retries.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    max_attempts = max(1, int(args.max_attempts))
    analyze_timeout = max(60, int(args.analyze_timeout))
    run_timeout = max(60, int(args.run_timeout))
    validate_timeout = max(60, int(args.validate_timeout))
    if args.output_dir.strip():
        output_dir = Path(args.output_dir).expanduser().resolve()
    else:
        ts = datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        output_dir = PADV_STORE / f"integration-assessment-{ts}"
    output_dir.mkdir(parents=True, exist_ok=True)

    phase_a: dict[str, Any] = {}
    phase_b: dict[str, Any] | None = None

    if args.phase in {"a", "full"}:
        phase_a["a1"] = run_preflight(output_dir)
        phase_a["a2"] = run_analyze_stabilization(
            output_dir,
            max_attempts=max_attempts,
            analyze_timeout=analyze_timeout,
        )
        phase_a["a3"] = run_strict_run_stabilization(
            output_dir,
            max_attempts=max_attempts,
            run_timeout=run_timeout,
            validate_timeout=validate_timeout,
        )
    else:
        # For phase B-only, infer latest run summary.
        phase_a = {"a1": {"summary": {"all_passed": True}}, "a2": {"success": True}, "a3": {"success": True}}

    phase_a_success = bool(phase_a.get("a1", {}).get("summary", {}).get("all_passed")) and bool(phase_a.get("a2", {}).get("success")) and bool(phase_a.get("a3", {}).get("success"))

    run_id = ""
    if "a3" in phase_a:
        run_id = str((phase_a.get("a3", {}).get("final_output", {}) or {}).get("run_id", "")).strip()
    if not run_id:
        run_ids = sorted((PADV_STORE / "runs").glob("*.json")) if (PADV_STORE / "runs").exists() else []
        if run_ids:
            run_id = run_ids[-1].stem

    if args.phase in {"b", "full"}:
        if not run_id:
            _write_json(
                output_dir / "b1-b2-assessment.json",
                {
                    "phase": "B",
                    "generated_at": _now_iso(),
                    "error": "no run_id available for phase B",
                    "matrix": [],
                    "gaps": [],
                },
            )
            _write_report_markdown(output_dir, phase_a, None)
            print(json.dumps({"ok": False, "reason": "no run_id available for phase B", "output_dir": str(output_dir)}, indent=2, ensure_ascii=True))
            return 1
        if args.phase == "full" and not phase_a_success:
            _write_json(
                output_dir / "b1-b2-assessment.json",
                {
                    "phase": "B",
                    "generated_at": _now_iso(),
                    "run_id": run_id,
                    "skipped": True,
                    "reason": "phase A did not reach strict success criteria",
                    "matrix": [],
                    "gaps": [],
                },
            )
        else:
            phase_b = run_phase_b(output_dir, run_id=run_id, phase_a=phase_a, run_timeout=run_timeout)

    _write_json(output_dir / "phase-a-summary.json", phase_a)
    _write_report_markdown(output_dir, phase_a, phase_b)

    response: dict[str, Any] = {
        "ok": True,
        "output_dir": str(output_dir),
        "phase": args.phase,
        "phase_a_success": phase_a_success,
        "run_id": run_id,
    }
    if phase_b is not None:
        response["gap_counts"] = {
            "P1": len([g for g in phase_b.get("gaps", []) if g.get("priority") == "P1"]),
            "P2": len([g for g in phase_b.get("gaps", []) if g.get("priority") == "P2"]),
            "P3": len([g for g in phase_b.get("gaps", []) if g.get("priority") == "P3"]),
        }

    print(json.dumps(response, indent=2, ensure_ascii=True))
    if args.phase in {"a", "full"} and not phase_a_success:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

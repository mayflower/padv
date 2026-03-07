from __future__ import annotations

import json
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, TypedDict
from urllib.parse import urlsplit, urlunsplit

from padv.analytics.failure_patterns import analyze_failures
from padv.agents.deepagents_harness import (
    ensure_agent_session,
    make_validation_plans_with_deepagents,
    rank_candidates_with_deepagents,
    schedule_actions_with_deepagents,
    skeptic_refine_with_deepagents,
)
from padv.config.schema import PadvConfig
from padv.discovery import (
    discover_scip_candidates_safe_with_meta,
    discover_web_hints,
    establish_auth_state,
    fuse_candidates_with_meta,
)
from padv.dynamic.sandbox import adapter as sandbox_adapter
from padv.models import Candidate, FailureAnalysis, RunSummary, StaticEvidence
from padv.orchestrator.runtime import new_run_id, validate_candidates_runtime
from padv.static.joern.adapter import discover_candidates_with_meta
from padv.store.evidence_store import EvidenceStore


class GraphState(TypedDict, total=False):
    config: PadvConfig
    repo_root: str
    store: EvidenceStore
    mode: str
    run_id: str
    started_at: str
    run_validation: bool
    selected_candidates: list[Candidate]
    selected_static: list[StaticEvidence]
    candidates: list[Candidate]
    static_evidence: list[StaticEvidence]
    web_hints: dict[str, list[str]]
    web_error: str | None
    discovery_trace: dict[str, Any]
    planner_trace: dict[str, Any]
    plans_by_candidate: dict[str, Any]
    artifact_refs: list[str]
    bundles: list[Any]
    all_bundles: list[Any]
    iteration_bundles: list[Any]
    decisions: dict[str, int]
    skip_discovery: bool
    had_semantic_candidates: bool
    frontier_state: dict[str, Any]
    objective_scores: dict[str, float]
    schedule_all_candidates: list[Candidate]
    resume_filtered_candidates: list[str]
    loop_continue: bool
    agent_session: Any
    auth_state: dict[str, Any]
    failure_analysis: FailureAnalysis | None
    progress_callback: Callable[[dict[str, Any]], None]
    stage_seq: int


def _safe_copy_candidate(candidate: Candidate) -> Candidate:
    return replace(candidate)


def _now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def _candidate_signature(candidate: Candidate) -> str:
    return f"{candidate.vuln_class}|{candidate.file_path}|{candidate.line}|{candidate.sink}"


def _attempts_are_clean(attempts: list[dict[str, Any]]) -> bool:
    if not attempts:
        return False
    for item in attempts:
        status = str(item.get("runtime_status", "")).strip().lower()
        if status in {"request_failed", "missing_intercept", "inactive"}:
            return False
    return True


def _extract_bundle_attempts(bundle: Any) -> list[dict[str, Any]]:
    trace = getattr(bundle, "planner_trace", {})
    if not isinstance(trace, dict):
        return []
    attempts = trace.get("attempts", [])
    if not isinstance(attempts, list):
        return []
    return [x for x in attempts if isinstance(x, dict)]


def _emit_progress(state: GraphState, step: str, status: str, detail: str | None = None) -> None:
    callback = state.get("progress_callback")
    if callback is None:
        return
    payload: dict[str, Any] = {"ts": _now_iso(), "step": step, "status": status}
    if detail:
        payload["detail"] = detail
    try:
        callback(payload)
    except Exception:
        # Progress callbacks are observational only and must not affect the run.
        return


def _invariant_error(stage: str, detail: str) -> RuntimeError:
    return RuntimeError(f"{stage} invariant failed: {detail}")


def _assert_stage_invariants(state: GraphState, stage: str) -> None:
    def _expect_list(key: str) -> list[Any]:
        value = state.get(key)
        if not isinstance(value, list):
            raise _invariant_error(stage, f"{key} must be a list")
        return value

    def _expect_dict(key: str) -> dict[str, Any]:
        value = state.get(key)
        if not isinstance(value, dict):
            raise _invariant_error(stage, f"{key} must be a dict")
        return value

    if stage == "init":
        _expect_dict("discovery_trace")
        _expect_dict("planner_trace")
        _expect_list("candidates")
        _expect_list("static_evidence")
        _expect_list("artifact_refs")
        _expect_list("all_bundles")
        _expect_list("iteration_bundles")
        _expect_dict("decisions")
        _expect_dict("auth_state")
        analysis = state.get("failure_analysis")
        if analysis is not None and not isinstance(analysis, FailureAnalysis):
            raise _invariant_error(stage, "failure_analysis must be FailureAnalysis or None")
        return

    if stage == "static_discovery":
        _expect_list("candidates")
        _expect_list("static_evidence")
        return

    if stage == "web_discovery":
        web_hints = state.get("web_hints")
        if not isinstance(web_hints, dict):
            raise _invariant_error(stage, "web_hints must be a dict")
        web_error = state.get("web_error")
        if web_error is not None and not isinstance(web_error, str):
            raise _invariant_error(stage, "web_error must be a string or null")
        return

    if stage == "auth_setup":
        _expect_dict("auth_state")
        return

    if stage == "candidate_synthesis":
        _expect_list("candidates")
        proposer = _expect_dict("planner_trace").get("proposer")
        if proposer is not None and not isinstance(proposer, dict):
            raise _invariant_error(stage, "planner_trace.proposer must be a dict")
        return

    if stage == "skeptic_refine":
        _expect_list("candidates")
        skeptic = _expect_dict("planner_trace").get("skeptic")
        if skeptic is not None and not isinstance(skeptic, dict):
            raise _invariant_error(stage, "planner_trace.skeptic must be a dict")
        return

    if stage == "objective_schedule":
        selected = _expect_list("selected_candidates")
        _expect_list("selected_static")
        _expect_dict("objective_scores")
        if any(not hasattr(c, "candidate_id") for c in selected):
            raise _invariant_error(stage, "selected_candidates entries must be Candidate-like")
        return

    if stage == "frontier_update":
        frontier = _expect_dict("frontier_state")
        if not isinstance(frontier.get("coverage"), dict):
            raise _invariant_error(stage, "frontier_state.coverage must be a dict")
        if not isinstance(frontier.get("history"), list):
            raise _invariant_error(stage, "frontier_state.history must be a list")
        if not isinstance(frontier.get("candidate_resume", {}), dict):
            raise _invariant_error(stage, "frontier_state.candidate_resume must be a dict")
        return

    if stage == "validation_plan":
        plans = _expect_dict("plans_by_candidate")
        if state.get("run_validation"):
            selected = state.get("selected_candidates") or state.get("candidates") or []
            selected_ids = {
                c.candidate_id
                for c in selected
                if hasattr(c, "candidate_id")
            }
            missing = [cid for cid in selected_ids if cid not in plans]
            if missing:
                raise _invariant_error(stage, f"missing plans for candidates: {sorted(missing)}")
        return

    if stage in {"runtime_validate", "dedup_topk"}:
        _expect_list("bundles")
        _expect_dict("decisions")
        return

    if stage == "persist":
        _expect_list("candidates")
        _expect_list("static_evidence")
        return


def _stage_snapshot_payload(state: GraphState, stage: str) -> dict[str, Any]:
    frontier = state.get("frontier_state", {})
    coverage = frontier.get("coverage", {}) if isinstance(frontier, dict) else {}
    return {
        "ts": _now_iso(),
        "stage": stage,
        "mode": state.get("mode"),
        "run_id": state.get("run_id"),
        "run_validation": bool(state.get("run_validation")),
        "loop_continue": bool(state.get("loop_continue")),
        "counts": {
            "candidates": len(state.get("candidates", [])),
            "static_evidence": len(state.get("static_evidence", [])),
            "selected_candidates": len(state.get("selected_candidates", [])),
            "selected_static": len(state.get("selected_static", [])),
            "bundles": len(state.get("bundles", [])),
            "all_bundles": len(state.get("all_bundles", [])),
            "iteration_bundles": len(state.get("iteration_bundles", [])),
            "artifact_refs": len(state.get("artifact_refs", [])),
        },
        "frontier": {
            "iteration": frontier.get("iteration") if isinstance(frontier, dict) else None,
            "stagnation_rounds": frontier.get("stagnation_rounds") if isinstance(frontier, dict) else None,
            "attempt_history": len(frontier.get("attempt_history", [])) if isinstance(frontier, dict) else 0,
            "candidate_resume": len(frontier.get("candidate_resume", {})) if isinstance(frontier, dict) else 0,
            "coverage_counts": {
                "files": len(coverage.get("files", [])) if isinstance(coverage, dict) else 0,
                "classes": len(coverage.get("classes", [])) if isinstance(coverage, dict) else 0,
                "signals": len(coverage.get("signals", [])) if isinstance(coverage, dict) else 0,
                "sinks": len(coverage.get("sinks", [])) if isinstance(coverage, dict) else 0,
                "web_paths": len(coverage.get("web_paths", [])) if isinstance(coverage, dict) else 0,
            },
        },
        "web_error": state.get("web_error"),
        "decisions": dict(state.get("decisions", {})),
        "selected_candidate_ids": [
            c.candidate_id
            for c in state.get("selected_candidates", [])
            if hasattr(c, "candidate_id")
        ][:50],
    }


def _persist_stage_snapshot(state: GraphState, stage: str) -> None:
    store = state.get("store")
    if store is None:
        return
    store.ensure()
    run_id = str(state.get("run_id") or "unknown-run")
    stage_seq = int(state.get("stage_seq", 0)) + 1
    state["stage_seq"] = stage_seq

    stage_dir = store.runs_dir / run_id / "stages"
    stage_dir.mkdir(parents=True, exist_ok=True)
    path = stage_dir / f"{stage_seq:03d}-{stage}.json"
    path.write_text(json.dumps(_stage_snapshot_payload(state, stage), indent=2, ensure_ascii=True))


def _finalize_stage(state: GraphState, stage: str, detail: str | None = None) -> GraphState:
    _assert_stage_invariants(state, stage)
    _persist_stage_snapshot(state, stage)
    _emit_progress(state, stage, "done", detail)
    return state


def _default_frontier_state() -> dict[str, Any]:
    return {
        "version": 1,
        "updated_at": _now_iso(),
        "iteration": 0,
        "stagnation_rounds": 0,
        "hypotheses": [],
        "failed_paths": [],
        "coverage": {
            "files": [],
            "classes": [],
            "signals": [],
            "sinks": [],
            "web_paths": [],
        },
        "history": [],
        "attempt_history": [],
        "candidate_resume": {},
        "runtime_coverage": {
            "flags": [],
            "classes": [],
        },
    }


def _merge_unique(existing: list[str], incoming: list[str]) -> list[str]:
    seen = set(existing)
    out = list(existing)
    for item in incoming:
        if item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def _candidate_signal_set(candidate: Candidate) -> set[str]:
    signals = {x.strip().lower() for x in candidate.provenance if isinstance(x, str) and x.strip()}
    if candidate.web_path_hints:
        signals.add("web")
    return signals


def _coverage_snapshot(candidates: list[Candidate], web_hints: dict[str, list[str]]) -> dict[str, list[str]]:
    files = sorted({c.file_path for c in candidates if c.file_path})
    classes = sorted({c.vuln_class for c in candidates if c.vuln_class})
    sinks = sorted({c.sink for c in candidates if c.sink})
    signals = sorted({sig for c in candidates for sig in _candidate_signal_set(c)})
    web_paths = sorted(web_hints.keys())
    return {
        "files": files,
        "classes": classes,
        "signals": signals,
        "sinks": sinks,
        "web_paths": web_paths,
    }


def _coverage_delta(old: dict[str, list[str]], new: dict[str, list[str]]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for key in ("files", "classes", "signals", "sinks", "web_paths"):
        out[f"new_{key}"] = sorted(set(new.get(key, [])) - set(old.get(key, [])))
    return out


def _runtime_feedback_from_bundles(bundles: list[Any], iteration: int) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    attempts: list[dict[str, Any]] = []
    flags: set[str] = set()
    classes: set[str] = set()
    decisions: dict[str, int] = {}
    for bundle in bundles:
        candidate = getattr(bundle, "candidate", None)
        candidate_id = getattr(candidate, "candidate_id", "")
        vuln_class = getattr(candidate, "vuln_class", "")
        if isinstance(vuln_class, str) and vuln_class.strip():
            classes.add(vuln_class.strip())
        gate = getattr(bundle, "gate_result", None)
        decision = getattr(gate, "decision", "")
        if isinstance(decision, str) and decision:
            decisions[decision] = decisions.get(decision, 0) + 1

        trace = getattr(bundle, "planner_trace", {})
        trace_attempts = trace.get("attempts", []) if isinstance(trace, dict) else []
        if not isinstance(trace_attempts, list):
            continue
        for item in trace_attempts:
            if not isinstance(item, dict):
                continue
            copied = dict(item)
            copied["candidate_id"] = str(candidate_id)
            copied["vuln_class"] = str(vuln_class)
            copied["iteration"] = iteration
            attempts.append(copied)
            analysis_flags = item.get("analysis_flags", [])
            if isinstance(analysis_flags, list):
                for flag in analysis_flags:
                    if isinstance(flag, str) and flag.strip():
                        flags.add(flag.strip())
    summary = {
        "attempt_count": len(attempts),
        "flags": sorted(flags),
        "classes": sorted(classes),
        "decisions": decisions,
    }
    return attempts, summary


def _normalize_seed_url(raw: str, base_url: str) -> str | None:
    value = raw.strip()
    if not value:
        return None
    parsed = urlsplit(value)
    if parsed.scheme in {"http", "https"} and parsed.netloc:
        return value
    if value.startswith("/"):
        base = urlsplit(base_url)
        if base.scheme and base.netloc:
            return urlunsplit((base.scheme, base.netloc, value, "", ""))
    return None


def _seed_urls_from_frontier(frontier_state: dict[str, Any], max_urls: int, base_url: str) -> list[str]:
    seed_urls: list[str] = []
    failed_paths = frontier_state.get("failed_paths", [])
    if not isinstance(failed_paths, list):
        return seed_urls
    for item in failed_paths[-max_urls:]:
        if isinstance(item, str):
            normalized = _normalize_seed_url(item, base_url)
            if normalized:
                seed_urls.append(normalized)
        elif isinstance(item, dict):
            path = item.get("path")
            if isinstance(path, str):
                normalized = _normalize_seed_url(path, base_url)
                if normalized:
                    seed_urls.append(normalized)
    # preserve order while deduplicating
    return list(dict.fromkeys(seed_urls))


def _persist_web_artifact(state: GraphState, seed_urls: list[str], hints: dict[str, list[str]], err: str | None) -> None:
    store = state["store"]
    store.ensure()
    artifact_dir = store.root / "artifacts"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    artifact_path = artifact_dir / f"web-discovery-{new_run_id('disc')}.json"
    payload = {
        "generated_at": _now_iso(),
        "seed_urls": seed_urls,
        "hints": hints,
        "error": err,
    }
    artifact_path.write_text(json.dumps(payload, indent=2, ensure_ascii=True))
    artifact_refs = state.setdefault("artifact_refs", [])
    artifact_refs.append(str(Path(artifact_path)))


def _persist_semantic_discovery_artifact(state: GraphState, payload: dict[str, Any]) -> None:
    store = state["store"]
    store.ensure()
    artifact_dir = store.root / "artifacts"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    artifact_path = artifact_dir / f"semantic-discovery-{new_run_id('disc')}.json"
    full_payload = {"generated_at": _now_iso(), **payload}
    artifact_path.write_text(json.dumps(full_payload, indent=2, ensure_ascii=True))
    state.setdefault("artifact_refs", []).append(str(Path(artifact_path)))


def _persist_fusion_artifact(state: GraphState, meta: dict[str, Any]) -> None:
    store = state["store"]
    store.ensure()
    artifact_dir = store.root / "artifacts"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    artifact_path = artifact_dir / f"semantic-fusion-{new_run_id('disc')}.json"
    payload = {"generated_at": _now_iso(), **meta}
    artifact_path.write_text(json.dumps(payload, indent=2, ensure_ascii=True))
    state.setdefault("artifact_refs", []).append(str(Path(artifact_path)))


def _persist_auth_artifact(state: GraphState, auth_state: dict[str, Any]) -> None:
    store = state["store"]
    store.ensure()
    artifact_dir = store.root / "artifacts"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    artifact_path = artifact_dir / f"auth-state-{new_run_id('disc')}.json"
    safe_payload = {
        "generated_at": _now_iso(),
        "auth_enabled": bool(auth_state.get("auth_enabled")),
        "login_url": auth_state.get("login_url"),
        "username": auth_state.get("username"),
        "cookie_names": sorted((auth_state.get("cookies") or {}).keys()) if isinstance(auth_state.get("cookies"), dict) else [],
        "cookie_count": len(auth_state.get("cookies", {})) if isinstance(auth_state.get("cookies"), dict) else 0,
        "summary": auth_state.get("summary", ""),
    }
    artifact_path.write_text(json.dumps(safe_payload, indent=2, ensure_ascii=True))
    state.setdefault("artifact_refs", []).append(str(Path(artifact_path)))


def _persist_failure_analysis_artifact(state: GraphState, analysis: FailureAnalysis) -> None:
    store = state["store"]
    store.ensure()
    artifact_dir = store.root / "artifacts"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    run_id = str(state.get("run_id", "run-unknown"))
    artifact_path = artifact_dir / f"failure-analysis-{run_id}.json"
    artifact_path.write_text(json.dumps(analysis.to_dict(), indent=2, ensure_ascii=True))
    state.setdefault("artifact_refs", []).append(str(Path(artifact_path)))


def _persist_runtime_liveness_artifact(state: GraphState, payload: dict[str, Any]) -> None:
    store = state["store"]
    store.ensure()
    artifact_dir = store.root / "artifacts"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    run_id = str(state.get("run_id", "run-unknown"))
    artifact_path = artifact_dir / f"runtime-liveness-{run_id}-{new_run_id('diag')}.json"
    artifact_path.write_text(
        json.dumps({"generated_at": _now_iso(), **payload}, indent=2, ensure_ascii=True)
    )
    state.setdefault("artifact_refs", []).append(str(Path(artifact_path)))


def _persist_candidate_run_mapping(state: GraphState, records: list[dict[str, Any]]) -> None:
    if not records:
        return
    store = state["store"]
    store.ensure()
    run_id = str(state.get("run_id") or "unknown-run")
    run_dir = store.runs_dir / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    path = run_dir / "candidate_run_map.jsonl"
    with path.open("a", encoding="utf-8") as fh:
        for record in records:
            fh.write(json.dumps(record, ensure_ascii=True))
            fh.write("\n")


def _triage_reason_for_candidate(trace: dict[str, Any], candidate_id: str) -> str:
    triage_by_candidate = trace.get("triage_by_candidate", {})
    if not isinstance(triage_by_candidate, dict):
        return ""
    raw = triage_by_candidate.get(candidate_id)
    if not isinstance(raw, dict):
        return ""
    parts: list[str] = []
    for key in ("reproducibility_gap", "legitimacy_gap", "impact_gap", "missing_witness"):
        value = str(raw.get(key, "")).strip()
        if value:
            parts.append(f"{key}={value}")
    return "; ".join(parts)


def _update_candidate_resume_state(frontier: dict[str, Any], bundles: list[Any], iteration: int) -> None:
    resume = frontier.get("candidate_resume", {})
    if not isinstance(resume, dict):
        resume = {}

    for bundle in bundles:
        candidate = getattr(bundle, "candidate", None)
        if not isinstance(candidate, Candidate):
            continue
        signature = _candidate_signature(candidate)
        attempts = _extract_bundle_attempts(bundle)
        gate_result = getattr(bundle, "gate_result", None)
        decision = str(getattr(gate_result, "decision", "")).strip()
        resume[signature] = {
            "candidate_id": candidate.candidate_id,
            "signature": signature,
            "completed_clean": _attempts_are_clean(attempts),
            "last_iteration": iteration,
            "last_decision": decision,
            "last_bundle_id": str(getattr(bundle, "bundle_id", "")),
            "last_attempt_count": len(attempts),
            "updated_at": _now_iso(),
        }

    frontier["candidate_resume"] = resume


def _resolve_auth_preconditions(candidates: list[Candidate], auth_known: bool) -> None:
    if not auth_known:
        return
    for candidate in candidates:
        if not candidate.preconditions:
            continue
        candidate.preconditions = [p for p in candidate.preconditions if p != "auth-state-known"]


def _node_init(state: GraphState) -> GraphState:
    _emit_progress(state, "init", "start")
    if not state.get("run_id"):
        state["run_id"] = new_run_id("analyze")
    state["stage_seq"] = 0
    state["discovery_trace"] = {}
    state["planner_trace"] = {}
    state["plans_by_candidate"] = {}
    state["artifact_refs"] = []
    state["web_hints"] = {}
    state["web_error"] = None
    state["bundles"] = []
    state["all_bundles"] = []
    state["iteration_bundles"] = []
    state["objective_scores"] = {}
    state["schedule_all_candidates"] = []
    state["resume_filtered_candidates"] = []
    state["had_semantic_candidates"] = False
    state["loop_continue"] = False
    state["decisions"] = {"VALIDATED": 0, "DROPPED": 0, "NEEDS_HUMAN_SETUP": 0}
    state["auth_state"] = {}
    state["failure_analysis"] = None
    state["candidates"] = list(state.get("candidates", []))
    state["static_evidence"] = list(state.get("static_evidence", []))
    state["selected_candidates"] = list(state.get("selected_candidates", []))
    state["selected_static"] = list(state.get("selected_static", []))

    if state.get("skip_discovery"):
        analysis = analyze_failures(state["store"])
        state["failure_analysis"] = analysis
        _persist_failure_analysis_artifact(state, analysis)
        state["discovery_trace"]["failure_patterns"] = len(analysis.patterns)
        state["frontier_state"] = _default_frontier_state()
        state["had_semantic_candidates"] = bool(state.get("selected_candidates"))
        state["agent_session"] = ensure_agent_session(
            state["config"],
            frontier_state=state["frontier_state"],
            repo_root=state.get("repo_root"),
            session=state.get("agent_session"),
        )
        return _finalize_stage(state, "init", "validate-only state initialized")

    persisted = state["store"].load_frontier_state() or _default_frontier_state()
    if not isinstance(persisted, dict):
        persisted = _default_frontier_state()
    persisted.setdefault("coverage", _default_frontier_state()["coverage"])
    persisted.setdefault("history", [])
    persisted.setdefault("hypotheses", [])
    persisted.setdefault("failed_paths", [])
    persisted.setdefault("iteration", 0)
    persisted.setdefault("stagnation_rounds", 0)
    persisted.setdefault("attempt_history", [])
    persisted.setdefault("candidate_resume", {})
    persisted.setdefault("runtime_coverage", {"flags": [], "classes": []})
    state["frontier_state"] = persisted
    analysis = analyze_failures(state["store"])
    state["failure_analysis"] = analysis
    _persist_failure_analysis_artifact(state, analysis)
    state["discovery_trace"]["failure_patterns"] = len(analysis.patterns)
    state["agent_session"] = ensure_agent_session(
        state["config"],
        frontier_state=state["frontier_state"],
        repo_root=state.get("repo_root"),
        session=state.get("agent_session"),
    )
    return _finalize_stage(state, "init", "frontier and agent session ready")


def _node_static_discovery(state: GraphState) -> GraphState:
    _emit_progress(state, "static_discovery", "start")
    if state.get("skip_discovery"):
        state.setdefault("discovery_trace", {})["mode"] = "validate-only"
        return _finalize_stage(state, "static_discovery", "skipped (validate-only)")

    # Static discoveries are deterministic for a fixed repo/config. Reuse after first pass.
    if state.get("candidates") and state.get("static_evidence"):
        state["discovery_trace"]["static_reused"] = True
        state["had_semantic_candidates"] = True
        return _finalize_stage(state, "static_discovery", "reused prior static results")

    config = state["config"]
    repo_root = state["repo_root"]

    scip_candidates, scip_evidence, scip_refs, scip_meta, scip_error = discover_scip_candidates_safe_with_meta(
        repo_root, config
    )
    joern_candidates, joern_evidence, joern_meta = discover_candidates_with_meta(repo_root=repo_root, config=config)
    joern_semantic_ids = {c.candidate_id for c in joern_candidates if "joern" in c.provenance}
    joern_semantic_candidates = [c for c in joern_candidates if c.candidate_id in joern_semantic_ids]
    joern_semantic_evidence = [e for e in joern_evidence if e.candidate_id in joern_semantic_ids]
    dropped_nonsemantic = max(0, len(joern_candidates) - len(joern_semantic_candidates))

    semantic_candidates = scip_candidates + joern_semantic_candidates
    semantic_evidence = scip_evidence + joern_semantic_evidence
    if not semantic_candidates:
        raise RuntimeError("semantic discovery produced zero candidates (joern+scip)")

    state["artifact_refs"].extend(scip_refs)
    _persist_semantic_discovery_artifact(
        state,
        {
            "raw_scip_hits": scip_meta.raw_scip_hits,
            "mapped_scip_sinks": scip_meta.mapped_scip_sinks,
            "scip_app_scoped_sinks": scip_meta.app_scoped_sinks,
            "scip_dropped_non_app_sinks": scip_meta.dropped_non_app_sinks,
            "scip_candidates": len(scip_candidates),
            "joern_findings": joern_meta.joern_findings,
            "joern_app_findings": joern_meta.joern_app_findings,
            "joern_candidates": len(joern_semantic_candidates),
            "manifest_candidates": joern_meta.manifest_candidates,
            "joern_dropped_nonsemantic": dropped_nonsemantic,
            "semantic_candidates": len(semantic_candidates),
        },
    )
    state["candidates"] = semantic_candidates
    state["static_evidence"] = semantic_evidence
    state["had_semantic_candidates"] = True
    state["discovery_trace"] = {
        "source_count": 0,
        "raw_scip_hits": scip_meta.raw_scip_hits,
        "mapped_scip_sinks": scip_meta.mapped_scip_sinks,
        "joern_count": len(joern_semantic_candidates),
        "joern_findings": joern_meta.joern_findings,
        "joern_dropped_nonsemantic": dropped_nonsemantic,
        "scip_count": len(scip_candidates),
        "semantic_count": len(semantic_candidates),
        "fused_candidates": len(semantic_candidates),
        "scip_error": scip_error,
    }
    return _finalize_stage(
        state,
        "static_discovery",
        f"semantic={len(semantic_candidates)} joern={len(joern_semantic_candidates)} scip={len(scip_candidates)}",
    )


def _node_web_discovery(state: GraphState) -> GraphState:
    _emit_progress(state, "web_discovery", "start")
    if state.get("skip_discovery"):
        return _finalize_stage(state, "web_discovery", "skipped (validate-only)")

    config = state["config"]
    seed_urls = _seed_urls_from_frontier(
        state.get("frontier_state", {}),
        max_urls=config.web.max_pages,
        base_url=config.target.base_url,
    )
    hints, err = discover_web_hints(config, seed_urls=seed_urls)
    _persist_web_artifact(state, seed_urls, hints, err)

    merged_hints: dict[str, list[str]] = dict(state.get("web_hints", {}))
    for path, params in hints.items():
        merged_hints[path] = sorted(set(merged_hints.get(path, []) + params))
    state["web_hints"] = merged_hints
    state["web_error"] = err

    if merged_hints:
        paths = list(merged_hints.keys())
        for candidate in state.get("candidates", []):
            candidate.web_path_hints = sorted(set(candidate.web_path_hints + paths))

    state["discovery_trace"]["web_paths"] = len(merged_hints)
    if err:
        raise RuntimeError(f"web discovery failed: {err}")
    return _finalize_stage(state, "web_discovery", f"paths={len(merged_hints)}")


def _node_auth_setup(state: GraphState) -> GraphState:
    _emit_progress(state, "auth_setup", "start")
    config = state["config"]
    if not config.auth.enabled:
        state["auth_state"] = {"auth_enabled": False, "cookies": {}}
        state.setdefault("discovery_trace", {})["auth"] = {"enabled": False, "resolved": True, "cookies": 0}
        return _finalize_stage(state, "auth_setup", "auth disabled")

    auth_state = establish_auth_state(config)
    state["auth_state"] = auth_state
    _persist_auth_artifact(state, auth_state)
    cookie_count = len(auth_state.get("cookies", {})) if isinstance(auth_state.get("cookies"), dict) else 0
    state.setdefault("discovery_trace", {})["auth"] = {
        "enabled": True,
        "resolved": cookie_count > 0,
        "cookies": cookie_count,
        "login_url": config.auth.login_url,
    }
    _resolve_auth_preconditions(state.get("candidates", []), auth_known=cookie_count > 0)
    _resolve_auth_preconditions(state.get("selected_candidates", []), auth_known=cookie_count > 0)
    return _finalize_stage(state, "auth_setup", f"cookies={cookie_count}")


def _node_candidate_synthesis(state: GraphState) -> GraphState:
    _emit_progress(state, "candidate_synthesis", "start")
    config = state["config"]
    frontier_state = state.get("frontier_state", {})

    if state.get("skip_discovery"):
        ranked, proposer_trace = rank_candidates_with_deepagents(
            state.get("selected_candidates", []),
            state["mode"],
            config,
            frontier_state=frontier_state,
            repo_root=state.get("repo_root"),
            session=state.get("agent_session"),
        )
        state["candidates"] = ranked
        state["planner_trace"]["proposer"] = proposer_trace
        return _finalize_stage(state, "candidate_synthesis", f"ranked={len(ranked)} (validate-only)")

    candidates, static_evidence, fusion_meta = fuse_candidates_with_meta(
        candidates=[_safe_copy_candidate(c) for c in state.get("candidates", [])],
        static_evidence=state.get("static_evidence", []),
        config=config,
    )
    ranked, proposer_trace = rank_candidates_with_deepagents(
        candidates,
        state["mode"],
        config,
        frontier_state=frontier_state,
        repo_root=state.get("repo_root"),
        session=state.get("agent_session"),
    )
    state["candidates"] = ranked[: config.budgets.max_candidates]
    state["static_evidence"] = static_evidence
    state["discovery_trace"]["fusion_count"] = len(candidates)
    state["discovery_trace"]["fused_candidates"] = len(candidates)
    state["discovery_trace"]["fusion_dual_signal"] = fusion_meta.dual_signal_candidates
    state["discovery_trace"]["fusion_dropped_nonsemantic"] = fusion_meta.dropped_nonsemantic_candidates
    _persist_fusion_artifact(
        state,
        {
            "input_candidates": fusion_meta.input_candidates,
            "fused_candidates": fusion_meta.fused_candidates,
            "dual_signal_candidates": fusion_meta.dual_signal_candidates,
            "dropped_nonsemantic_candidates": fusion_meta.dropped_nonsemantic_candidates,
            "evidence_graph": fusion_meta.evidence_graph,
        },
    )
    state["planner_trace"]["proposer"] = proposer_trace
    return _finalize_stage(state, "candidate_synthesis", f"fused={len(candidates)} selected={len(state['candidates'])}")


def _node_skeptic_refine(state: GraphState) -> GraphState:
    _emit_progress(state, "skeptic_refine", "start")
    rounds = max(1, state["config"].agent.skeptic_rounds)
    current = state.get("candidates", [])
    skeptic_round_traces: list[dict[str, Any]] = []
    for _ in range(rounds):
        refined, skeptic_trace = skeptic_refine_with_deepagents(
            current,
            state["config"],
            frontier_state=state.get("frontier_state", {}),
            repo_root=state.get("repo_root"),
            session=state.get("agent_session"),
            failure_analysis=state.get("failure_analysis"),
        )
        if isinstance(skeptic_trace, dict):
            skeptic_round_traces.append(skeptic_trace)
        current = refined
        if not current:
            break

    out: list[Candidate] = []
    for candidate in current:
        clone = _safe_copy_candidate(candidate)
        if clone.expected_intercepts:
            clone.expected_intercepts = sorted(set(clone.expected_intercepts))
        elif clone.sink:
            clone.expected_intercepts = [clone.sink.replace("(", "").replace("->", "::")]
        out.append(clone)

    aggregated_failed: list[str] = []
    for trace in skeptic_round_traces:
        raw_failed = trace.get("failed_paths")
        if isinstance(raw_failed, list):
            for item in raw_failed:
                if isinstance(item, str) and item.strip():
                    aggregated_failed.append(item.strip())

    final_trace: dict[str, Any]
    if skeptic_round_traces:
        final_trace = dict(skeptic_round_traces[-1])
        final_trace["rounds"] = [dict(item) for item in skeptic_round_traces]
    else:
        final_trace = {"engine": "deepagents", "rounds": []}
    if aggregated_failed:
        final_trace["failed_paths"] = sorted(set(aggregated_failed))

    state["candidates"] = out
    state.setdefault("planner_trace", {})["skeptic"] = final_trace
    return _finalize_stage(state, "skeptic_refine", f"remaining={len(out)}")


def _node_objective_schedule(state: GraphState) -> GraphState:
    _emit_progress(state, "objective_schedule", "start")
    candidates = list(state.get("candidates", []))
    state["schedule_all_candidates"] = list(candidates)
    state["resume_filtered_candidates"] = []
    if not candidates:
        state["selected_candidates"] = []
        state["selected_static"] = []
        state["objective_scores"] = {}
        return _finalize_stage(state, "objective_schedule", "no candidates")

    scheduler_input = list(candidates)
    frontier_state = state.get("frontier_state", {})
    if state.get("run_validation"):
        resume_map = frontier_state.get("candidate_resume", {}) if isinstance(frontier_state, dict) else {}
        if isinstance(resume_map, dict):
            filtered: list[Candidate] = []
            filtered_ids: list[str] = []
            for candidate in candidates:
                entry = resume_map.get(_candidate_signature(candidate))
                if isinstance(entry, dict) and bool(entry.get("completed_clean")):
                    filtered_ids.append(candidate.candidate_id)
                    continue
                filtered.append(candidate)
            if filtered:
                scheduler_input = filtered
            elif state.get("had_semantic_candidates"):
                # Deterministic fallback: never starve runtime selection when semantic candidates exist.
                scheduler_input = [candidates[0]]
            else:
                scheduler_input = []
            state["resume_filtered_candidates"] = sorted(set(filtered_ids))

    selected, scores, scheduler_trace = schedule_actions_with_deepagents(
        scheduler_input,
        state["config"],
        max_candidates=state["config"].budgets.max_candidates,
        frontier_state=frontier_state,
        repo_root=state.get("repo_root"),
        session=state.get("agent_session"),
    )
    if not selected and scheduler_input and state.get("run_validation") and state.get("had_semantic_candidates"):
        fallback = scheduler_input[0]
        selected = [fallback]
        scores = {fallback.candidate_id: max(0.0, float(fallback.confidence))}
        scheduler_trace = dict(scheduler_trace) if isinstance(scheduler_trace, dict) else {"engine": "deepagents"}
        scheduler_trace["reason"] = "deterministic-fallback-selection"
        scheduler_trace["fallback_selected"] = [fallback.candidate_id]
    scheduler_trace = dict(scheduler_trace) if isinstance(scheduler_trace, dict) else {"engine": "deepagents"}
    scheduler_trace["schedule_pool_size"] = len(scheduler_input)
    scheduler_trace["resume_filtered_candidates"] = list(state.get("resume_filtered_candidates", []))

    selected_ids = {c.candidate_id for c in selected}
    selected_static = [
        item for item in state.get("static_evidence", []) if item.candidate_id in selected_ids
    ]

    state["objective_scores"] = scores
    state["selected_candidates"] = selected
    state["selected_static"] = selected_static
    state["candidates"] = selected
    state["static_evidence"] = selected_static

    state.setdefault("planner_trace", {})["scheduler"] = scheduler_trace
    return _finalize_stage(state, "objective_schedule", f"selected={len(selected)}")


def _node_frontier_update(state: GraphState) -> GraphState:
    _emit_progress(state, "frontier_update", "start")
    if state.get("skip_discovery"):
        state["loop_continue"] = False
        return _finalize_stage(state, "frontier_update", "skipped (validate-only)")

    frontier = state.get("frontier_state") or _default_frontier_state()
    iteration = int(frontier.get("iteration", 0)) + 1
    old_cov = frontier.get("coverage", _default_frontier_state()["coverage"])
    new_cov = _coverage_snapshot(state.get("candidates", []), state.get("web_hints", {}))
    delta = _coverage_delta(old_cov, new_cov)

    frontier["coverage"] = {
        "files": _merge_unique(old_cov.get("files", []), new_cov.get("files", [])),
        "classes": _merge_unique(old_cov.get("classes", []), new_cov.get("classes", [])),
        "signals": _merge_unique(old_cov.get("signals", []), new_cov.get("signals", [])),
        "sinks": _merge_unique(old_cov.get("sinks", []), new_cov.get("sinks", [])),
        "web_paths": _merge_unique(old_cov.get("web_paths", []), new_cov.get("web_paths", [])),
    }

    proposer_trace = state.get("planner_trace", {}).get("proposer", {})
    hypotheses = proposer_trace.get("hypotheses", []) if isinstance(proposer_trace, dict) else []
    if isinstance(hypotheses, list):
        for item in hypotheses[:100]:
            if not isinstance(item, dict):
                continue
            cid = item.get("candidate_id")
            if not isinstance(cid, str) or not cid.strip():
                continue
            frontier.setdefault("hypotheses", []).append(
                {
                    "candidate_id": cid,
                    "rationale": str(item.get("rationale", "")).strip(),
                    "score": state.get("objective_scores", {}).get(cid, 0.0),
                    "iteration": iteration,
                }
            )

    if state.get("web_error"):
        frontier.setdefault("failed_paths", []).append(
            {
                "path": state["config"].target.base_url,
                "reason": str(state["web_error"]),
                "iteration": iteration,
            }
        )

    skeptic_trace = state.get("planner_trace", {}).get("skeptic", {})
    failed_paths = skeptic_trace.get("failed_paths", []) if isinstance(skeptic_trace, dict) else []
    if isinstance(failed_paths, list):
        for item in failed_paths[:100]:
            if isinstance(item, str) and item.strip():
                frontier.setdefault("failed_paths", []).append(
                    {
                        "path": item.strip(),
                        "reason": "skeptic-refute",
                        "iteration": iteration,
                    }
                )

    runtime_attempts, runtime_summary = _runtime_feedback_from_bundles(
        state.get("iteration_bundles", []),
        iteration=iteration,
    )
    runtime_cov = frontier.get("runtime_coverage", {"flags": [], "classes": []})
    old_runtime_flags = set(runtime_cov.get("flags", [])) if isinstance(runtime_cov, dict) else set()
    old_runtime_classes = set(runtime_cov.get("classes", [])) if isinstance(runtime_cov, dict) else set()
    new_runtime_flags = set(runtime_summary.get("flags", []))
    new_runtime_classes = set(runtime_summary.get("classes", []))
    runtime_delta = {
        "new_flags": sorted(new_runtime_flags - old_runtime_flags),
        "new_classes": sorted(new_runtime_classes - old_runtime_classes),
        "attempt_count": int(runtime_summary.get("attempt_count", 0)),
        "decisions": dict(runtime_summary.get("decisions", {})),
    }
    frontier["runtime_coverage"] = {
        "flags": sorted(old_runtime_flags | new_runtime_flags),
        "classes": sorted(old_runtime_classes | new_runtime_classes),
    }
    frontier.setdefault("attempt_history", [])
    frontier["attempt_history"].extend(runtime_attempts)
    _update_candidate_resume_state(frontier, state.get("iteration_bundles", []), iteration)

    frontier["history"] = list(frontier.get("history", []))[-200:]
    frontier["history"].append(
        {
            "iteration": iteration,
            "selected": [c.candidate_id for c in state.get("selected_candidates", [])],
            "delta": delta,
            "runtime_delta": runtime_delta,
            "web_error": state.get("web_error"),
        }
    )

    has_discovery_delta = any(delta.get(key) for key in delta)
    has_runtime_delta = bool(runtime_delta["new_flags"] or runtime_delta["new_classes"])
    has_delta = has_discovery_delta or has_runtime_delta
    stagnation = int(frontier.get("stagnation_rounds", 0))
    frontier["stagnation_rounds"] = 0 if has_delta else stagnation + 1
    frontier["iteration"] = iteration
    frontier["updated_at"] = _now_iso()
    frontier["hypotheses"] = list(frontier.get("hypotheses", []))[-1000:]
    frontier["failed_paths"] = list(frontier.get("failed_paths", []))[-1000:]
    frontier["attempt_history"] = list(frontier.get("attempt_history", []))[-5000:]

    state["frontier_state"] = frontier
    state["discovery_trace"]["frontier_delta"] = delta
    state["discovery_trace"]["runtime_delta"] = runtime_delta
    state["discovery_trace"]["frontier_iteration"] = frontier["iteration"]
    state["iteration_bundles"] = []

    max_iterations = max(1, state["config"].agent.max_iterations)
    patience = max(0, state["config"].agent.improvement_patience)
    state["loop_continue"] = (
        frontier["iteration"] < max_iterations
        and frontier["stagnation_rounds"] <= patience
    )

    state["store"].save_frontier_state(frontier)
    return _finalize_stage(
        state,
        "frontier_update",
        f"iteration={frontier['iteration']} loop_continue={state['loop_continue']}",
    )


def _node_validation_plan(state: GraphState) -> GraphState:
    _emit_progress(state, "validation_plan", "start")
    if not state.get("run_validation"):
        return _finalize_stage(state, "validation_plan", "skipped (analysis-only)")

    selected_candidates = state.get("selected_candidates") or state.get("candidates", [])
    planner_trace: dict[str, Any] = dict(state.get("planner_trace", {}))
    plans_by_candidate, validation_trace = make_validation_plans_with_deepagents(
        selected_candidates,
        state["config"],
        repo_root=state.get("repo_root"),
        session=state.get("agent_session"),
    )
    planner_trace["validation_plan"] = validation_trace
    state["plans_by_candidate"] = plans_by_candidate
    state["planner_trace"] = planner_trace
    return _finalize_stage(state, "validation_plan", f"planned={len(plans_by_candidate)}")


def _node_runtime_validate(state: GraphState) -> GraphState:
    _emit_progress(state, "runtime_validate", "start")
    if not state.get("run_validation"):
        return _finalize_stage(state, "runtime_validate", "skipped (analysis-only)")
    candidates = list(state.get("selected_candidates") or state.get("candidates", []))
    schedule_all = list(state.get("schedule_all_candidates") or candidates)
    resume_filtered = {str(x) for x in state.get("resume_filtered_candidates", []) if str(x).strip()}
    iteration = int((state.get("frontier_state") or {}).get("iteration", 0)) + 1
    if state.get("had_semantic_candidates") and not candidates:
        payload = {
            "run_id": state.get("run_id"),
            "iteration": iteration,
            "reason": "no-selected-candidates",
            "had_semantic_candidates": True,
            "schedule_all_candidate_ids": [c.candidate_id for c in schedule_all],
            "resume_filtered_candidates": sorted(resume_filtered),
            "scheduler_trace": state.get("planner_trace", {}).get("scheduler", {}),
        }
        _persist_runtime_liveness_artifact(state, payload)
        raise RuntimeError("runtime validation invariant failed: semantic candidates present but none selected")
    static_evidence = state.get("selected_static") or state.get("static_evidence", [])
    bundles, decisions = validate_candidates_runtime(
        config=state["config"],
        store=state["store"],
        static_evidence=static_evidence,
        candidates=candidates,
        run_id=state["run_id"],
        plans_by_candidate=state.get("plans_by_candidate"),
        planner_trace=state.get("planner_trace"),
        discovery_trace=state.get("discovery_trace"),
        artifact_refs=state.get("artifact_refs", []),
        auth_state=state.get("auth_state"),
    )
    if candidates and not bundles:
        payload = {
            "run_id": state.get("run_id"),
            "iteration": iteration,
            "reason": "zero-bundles-for-selected-candidates",
            "selected_candidate_ids": [c.candidate_id for c in candidates],
            "schedule_all_candidate_ids": [c.candidate_id for c in schedule_all],
            "resume_filtered_candidates": sorted(resume_filtered),
            "plans_present": sorted((state.get("plans_by_candidate") or {}).keys()),
            "scheduler_trace": state.get("planner_trace", {}).get("scheduler", {}),
            "discovery_trace": state.get("discovery_trace", {}),
        }
        _persist_runtime_liveness_artifact(state, payload)
        raise RuntimeError("runtime validation invariant failed: selected candidates produced zero bundles")

    selected_ids = {c.candidate_id for c in candidates}
    plans_by_candidate = state.get("plans_by_candidate", {})
    scheduler_trace = state.get("planner_trace", {}).get("scheduler", {})
    bundles_by_candidate = {
        str(getattr(getattr(bundle, "candidate", None), "candidate_id", "")): bundle
        for bundle in bundles
    }
    mapping_records: list[dict[str, Any]] = []
    for candidate in schedule_all:
        candidate_id = candidate.candidate_id
        bundle = bundles_by_candidate.get(candidate_id)
        attempts = _extract_bundle_attempts(bundle) if bundle is not None else []
        decision = ""
        bundle_id = ""
        reason_if_skipped = ""
        if bundle is not None:
            gate_result = getattr(bundle, "gate_result", None)
            decision = str(getattr(gate_result, "decision", "")).strip()
            bundle_id = str(getattr(bundle, "bundle_id", "")).strip()
        else:
            if candidate_id in resume_filtered and candidate_id not in selected_ids:
                reason_if_skipped = "resume-clean-completed"
            elif candidate_id in selected_ids:
                reason_if_skipped = "selected-not-executed"
            else:
                reason_if_skipped = "scheduler-not-selected"
            triage_reason = _triage_reason_for_candidate(
                scheduler_trace if isinstance(scheduler_trace, dict) else {},
                candidate_id,
            )
            if triage_reason:
                reason_if_skipped = f"{reason_if_skipped}; {triage_reason}"

        mapping_records.append(
            {
                "ts": _now_iso(),
                "iteration": iteration,
                "candidate_id": candidate_id,
                "candidate_signature": _candidate_signature(candidate),
                "plan_present": bool(candidate_id in plans_by_candidate),
                "attempt_count": len(attempts),
                "bundle_id": bundle_id,
                "decision": decision,
                "reason_if_skipped": reason_if_skipped,
            }
        )
    _persist_candidate_run_mapping(state, mapping_records)

    state["iteration_bundles"] = list(bundles)
    all_bundles = list(state.get("all_bundles", []))
    all_bundles.extend(bundles)
    state["all_bundles"] = all_bundles
    state["bundles"] = all_bundles
    state["decisions"] = decisions
    return _finalize_stage(
        state,
        "runtime_validate",
        f"iteration_bundles={len(bundles)} total_bundles={len(all_bundles)}",
    )


def _node_deterministic_gates(state: GraphState) -> GraphState:
    # Gate evaluation is executed inside validate_candidates_runtime.
    return _finalize_stage(state, "deterministic_gates", "evaluated in runtime_validate")


def _node_dedup_topk(state: GraphState) -> GraphState:
    _emit_progress(state, "dedup_topk", "start")
    if state.get("all_bundles"):
        state["bundles"] = list(state.get("all_bundles", []))
    bundles = state.get("bundles", [])
    if not bundles:
        return _finalize_stage(state, "dedup_topk", "no bundles")
    seen: set[tuple[str, str, int, str]] = set()
    deduped = []
    for bundle in bundles:
        key = (
            bundle.candidate.vuln_class,
            bundle.candidate.file_path,
            bundle.candidate.line,
            bundle.candidate.sink,
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(bundle)
    state["bundles"] = deduped[: state["config"].budgets.max_candidates]
    decisions = {"VALIDATED": 0, "DROPPED": 0, "NEEDS_HUMAN_SETUP": 0}
    for bundle in state["bundles"]:
        decisions[bundle.gate_result.decision] = decisions.get(bundle.gate_result.decision, 0) + 1
    state["decisions"] = decisions
    return _finalize_stage(state, "dedup_topk", f"bundles={len(state['bundles'])}")


def _node_persist(state: GraphState) -> GraphState:
    _emit_progress(state, "persist", "start")
    store = state["store"]
    store.save_candidates(state.get("candidates", []))
    store.save_static_evidence(state.get("static_evidence", []))
    if state.get("frontier_state"):
        store.save_frontier_state(state["frontier_state"])
    return _finalize_stage(state, "persist", "evidence persisted")


def _run_nodes(state: GraphState, include_validation: bool) -> GraphState:
    _emit_progress(state, "run", "start", f"include_validation={include_validation}")
    state = _node_init(state)

    while True:
        state = _node_static_discovery(state)
        state = _node_web_discovery(state)
        state = _node_auth_setup(state)
        state = _node_candidate_synthesis(state)
        state = _node_skeptic_refine(state)
        state = _node_objective_schedule(state)
        if include_validation:
            state = _node_validation_plan(state)
            state = _node_runtime_validate(state)
            state = _node_deterministic_gates(state)
        state = _node_frontier_update(state)
        if state.get("skip_discovery") or not state.get("loop_continue"):
            break

    if include_validation:
        state["bundles"] = list(state.get("all_bundles", []))
        state = _node_dedup_topk(state)
    state = _node_persist(state)
    _emit_progress(state, "run", "done", "node runner complete")
    return state


def _run_langgraph(state: GraphState, include_validation: bool) -> GraphState:
    try:
        from langgraph.graph import END, START, StateGraph  # type: ignore[import-not-found]
    except Exception as exc:
        raise RuntimeError(f"langgraph import failed: {exc}") from exc

    def _after_frontier_route(current: GraphState) -> str:
        if current.get("skip_discovery") or not current.get("loop_continue"):
            return "done"
        return "again"

    builder = StateGraph(GraphState)
    builder.add_node("init", _node_init)
    builder.add_node("static_discovery", _node_static_discovery)
    builder.add_node("web_discovery", _node_web_discovery)
    builder.add_node("auth_setup", _node_auth_setup)
    builder.add_node("candidate_synthesis", _node_candidate_synthesis)
    builder.add_node("skeptic_refine", _node_skeptic_refine)
    builder.add_node("objective_schedule", _node_objective_schedule)
    builder.add_node("frontier_update", _node_frontier_update)
    builder.add_node("validation_plan", _node_validation_plan)
    builder.add_node("runtime_validate", _node_runtime_validate)
    builder.add_node("deterministic_gates", _node_deterministic_gates)
    builder.add_node("dedup_topk", _node_dedup_topk)
    builder.add_node("persist", _node_persist)

    builder.add_edge(START, "init")
    builder.add_edge("init", "static_discovery")
    builder.add_edge("static_discovery", "web_discovery")
    builder.add_edge("web_discovery", "auth_setup")
    builder.add_edge("auth_setup", "candidate_synthesis")
    builder.add_edge("candidate_synthesis", "skeptic_refine")
    builder.add_edge("skeptic_refine", "objective_schedule")
    if include_validation:
        builder.add_edge("objective_schedule", "validation_plan")
        builder.add_edge("validation_plan", "runtime_validate")
        builder.add_edge("runtime_validate", "deterministic_gates")
        builder.add_edge("deterministic_gates", "frontier_update")
    else:
        builder.add_edge("objective_schedule", "frontier_update")

    builder.add_conditional_edges(
        "frontier_update",
        _after_frontier_route,
        {
            "again": "static_discovery",
            "done": "dedup_topk" if include_validation else "persist",
        },
    )

    if include_validation:
        builder.add_edge("dedup_topk", "persist")
    builder.add_edge("persist", END)

    graph = builder.compile()
    _emit_progress(state, "graph", "start", f"include_validation={include_validation}")
    result = graph.invoke(state)
    _emit_progress(result if isinstance(result, dict) else state, "graph", "done", "langgraph complete")
    return result


def analyze_with_graph(
    config: PadvConfig,
    repo_root: str,
    store: EvidenceStore,
    mode: str,
    progress_callback: Callable[[dict[str, Any]], None] | None = None,
) -> tuple[list[Candidate], list[StaticEvidence], dict[str, Any]]:
    state: GraphState = {
        "config": config,
        "repo_root": repo_root,
        "store": store,
        "mode": mode,
        "run_validation": False,
        "progress_callback": progress_callback,
    }
    result = _run_langgraph(state, include_validation=False)
    return result.get("candidates", []), result.get("static_evidence", []), result.get("discovery_trace", {})


def run_with_graph(
    config: PadvConfig,
    repo_root: str,
    store: EvidenceStore,
    mode: str,
    progress_callback: Callable[[dict[str, Any]], None] | None = None,
) -> RunSummary:
    run_id = new_run_id("run")
    started = datetime.now(tz=timezone.utc).isoformat()

    if config.sandbox.deploy_cmd:
        sandbox_adapter.deploy(config.sandbox)

    state: GraphState = {
        "config": config,
        "repo_root": repo_root,
        "store": store,
        "mode": mode,
        "run_id": run_id,
        "started_at": started,
        "run_validation": True,
        "progress_callback": progress_callback,
    }
    result = _run_langgraph(state, include_validation=True)
    completed = datetime.now(tz=timezone.utc).isoformat()

    bundles = result.get("bundles", [])
    decisions = result.get("decisions", {"VALIDATED": 0, "DROPPED": 0, "NEEDS_HUMAN_SETUP": 0})
    summary = RunSummary(
        run_id=run_id,
        mode=mode,
        started_at=started,
        completed_at=completed,
        total_candidates=len(result.get("candidates", [])),
        decisions=decisions,
        bundle_ids=[b.bundle_id for b in bundles],
        discovery_trace=result.get("discovery_trace", {}),
        planner_trace=result.get("planner_trace", {}),
        frontier_state=result.get("frontier_state", {}),
    )
    store.save_run_summary(summary)
    return summary


def validate_with_graph(
    config: PadvConfig,
    store: EvidenceStore,
    static_evidence: list[StaticEvidence],
    candidates: list[Candidate],
    run_id: str,
    repo_root: str | None = None,
    progress_callback: Callable[[dict[str, Any]], None] | None = None,
) -> tuple[list[Any], dict[str, int]]:
    state: GraphState = {
        "config": config,
        "repo_root": repo_root or ".",
        "store": store,
        "mode": "variant",
        "run_id": run_id,
        "run_validation": True,
        "candidates": candidates,
        "static_evidence": static_evidence,
        "selected_candidates": candidates,
        "selected_static": static_evidence,
        "discovery_trace": {"mode": "validate-only"},
        "skip_discovery": True,
        "progress_callback": progress_callback,
    }
    result = _run_langgraph(state, include_validation=True)
    return result.get("bundles", []), result.get("decisions", {})

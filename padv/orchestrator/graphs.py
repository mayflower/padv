from __future__ import annotations

import json
import hashlib
from dataclasses import asdict, is_dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, TypedDict, cast
from urllib.parse import urlsplit, urlunsplit

from padv.analytics.failure_patterns import analyze_failures
from padv.agents.checkpoints import FileBackedMemorySaver
from padv.agents.deepagents_harness import (
    AgentExecutionError,
    AgentSoftYield,
    challenge_hypotheses_with_subagent,
    clone_runtime_for_parallel_role,
    decide_continue_with_root_agent,
    ensure_agent_runtime,
    finalize_parallel_role_runtime,
    make_validation_plans_with_deepagents,
    merge_agent_runtime_context_delta,
    orient_root_agent,
    rank_candidates_with_deepagents,
    plan_experiments_with_subagent,
    run_research_subagent,
    schedule_actions_with_deepagents,
    select_objective_with_root_agent,
    skeptic_refine_with_deepagents,
    synthesize_hypotheses_with_subagent,
    update_agent_runtime_context,
)
from padv.config.schema import PadvConfig
from padv.discovery import (
    discover_scip_candidates_safe_with_meta,
    discover_web_inventory,
    establish_auth_state,
    fuse_candidates_with_meta,
)
from padv.dynamic.sandbox import adapter as sandbox_adapter
from padv.models import (
    Candidate,
    ExperimentAttempt,
    FailureAnalysis,
    Hypothesis,
    ObjectiveScore,
    Refutation,
    ResearchFinding,
    ResearchTask,
    RunSummary,
    StaticEvidence,
    WitnessBundle,
    utc_now_iso as _now_iso,
)
from padv.orchestrator.runtime import new_run_id, validate_candidates_runtime
from padv.static.joern.adapter import discover_candidates_with_meta
from padv.static.joern.query_sets import VULN_CLASS_SPECS
from padv.store.evidence_store import EvidenceStore
from padv.taxonomy import runtime_validatable_classes

_DECISION_KEYS = ("VALIDATED", "DROPPED", "NEEDS_HUMAN_SETUP", "CONFIRMED_ANALYSIS_FINDING")


def _default_decisions() -> dict[str, int]:
    return dict.fromkeys(_DECISION_KEYS, 0)


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
    web_artifacts: dict[str, Any]
    anonymous_web_hints: dict[str, list[str]]
    anonymous_web_artifacts: dict[str, Any]
    authenticated_web_hints: dict[str, list[str]]
    authenticated_web_artifacts: dict[str, Any]
    discovery_summary: dict[str, Any]
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
    auth_state: dict[str, Any]
    failure_analysis: FailureAnalysis | None
    stage_seq: int
    graph_thread_id: str
    graph_checkpoint_id: str
    resume_mode: bool
    resume_requested_run_id: str
    objective_queue: list[ObjectiveScore]
    active_objective: ObjectiveScore | None
    research_tasks: list[ResearchTask]
    research_findings: list[ResearchFinding]
    source_findings: list[ResearchFinding]
    graph_findings: list[ResearchFinding]
    web_findings: list[ResearchFinding]
    source_tasks: list[ResearchTask]
    graph_tasks: list[ResearchTask]
    web_tasks: list[ResearchTask]
    source_trace: dict[str, Any]
    graph_trace: dict[str, Any]
    web_trace: dict[str, Any]
    source_context_delta: dict[str, Any]
    graph_context_delta: dict[str, Any]
    web_context_delta: dict[str, Any]
    research_branch_errors: dict[str, dict[str, Any]]
    hypothesis_board: list[Hypothesis]
    refutations: list[Refutation]
    experiment_board: list[ExperimentAttempt]
    runtime_history: list[dict[str, Any]]
    witness_bundles: list[WitnessBundle]
    gate_history: list[dict[str, Any]]
    auth_contexts: dict[str, Any]
    artifact_index: dict[str, str]
    continue_reason: str
    run_iteration: int
    detection_board: dict[str, Any]
    research_board: dict[str, Any]
    validation_board: dict[str, Any]
    execution_board: dict[str, Any]
    gate_board: dict[str, Any]


_PROGRESS_CALLBACKS: dict[str, Callable[[dict[str, Any]], None]] = {}
_AGENT_RUNTIMES: dict[str, Any] = {}
# Dirty-tracking for _state_runtime sync: set of run_ids that need re-sync.
# A run_id is added here by _finalize_stage after persisting a stage snapshot,
# and removed by _state_runtime after a successful sync.  When a run_id is
# absent (i.e. clean) AND the runtime is already cached, _state_runtime skips
# the expensive _sync_runtime_from_state call.  First-time creation and
# injected runtimes always sync unconditionally.
_RUNTIME_SYNC_DIRTY: set[str] = set()
_SKIPPED_VALIDATE_ONLY = "skipped (validate-only)"


def _safe_copy_candidate(candidate: Candidate) -> Candidate:
    return cast(Candidate, replace(candidate))



def _stable_serialize(value: Any) -> Any:
    if is_dataclass(value):
        return _stable_serialize(asdict(value))
    if isinstance(value, dict):
        return {str(key): _stable_serialize(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_stable_serialize(item) for item in value]
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def _set_progress_callback(run_id: str, callback: Callable[[dict[str, Any]], None] | None) -> None:
    if callback is None:
        _PROGRESS_CALLBACKS.pop(run_id, None)
        return
    _PROGRESS_CALLBACKS[run_id] = callback


def _get_progress_callback(state: GraphState) -> Callable[[dict[str, Any]], None] | None:
    run_id = str(state.get("run_id") or "").strip()
    if not run_id:
        return None
    return _PROGRESS_CALLBACKS.get(run_id)


def _state_runtime(state: GraphState) -> Any:
    run_id = str(state.get("run_id") or "").strip()
    if not run_id:
        raise RuntimeError("agent runtime requires run_id")
    injected_runtime = state.get("agent_runtime")
    if injected_runtime is not None:
        _AGENT_RUNTIMES[run_id] = injected_runtime
        _sync_runtime_from_state(injected_runtime, state)
        _RUNTIME_SYNC_DIRTY.discard(run_id)
        return injected_runtime
    runtime = _AGENT_RUNTIMES.get(run_id)
    if runtime is not None:
        if run_id in _RUNTIME_SYNC_DIRTY:
            _sync_runtime_from_state(runtime, state)
            _RUNTIME_SYNC_DIRTY.discard(run_id)
        return runtime
    checkpoint_dir = _agent_checkpoint_dir(state)
    runtime = ensure_agent_runtime(
        state["config"],
        frontier_state=state.get("frontier_state", {}),
        repo_root=state.get("repo_root"),
        checkpoint_dir=checkpoint_dir,
        runtime=None,
    )
    _AGENT_RUNTIMES[run_id] = runtime
    _sync_runtime_from_state(runtime, state)
    _RUNTIME_SYNC_DIRTY.discard(run_id)
    return runtime


def _clear_state_runtime(run_id: str | None) -> None:
    if run_id:
        _AGENT_RUNTIMES.pop(str(run_id), None)
        _RUNTIME_SYNC_DIRTY.discard(str(run_id))


def _serialize_runtime_context_items(items: list[Any] | tuple[Any, ...]) -> list[Any]:
    return [_stable_serialize(item) for item in items]


def _collect_serialized_state_fields(state: GraphState) -> dict[str, Any]:
    """Extract and serialize graph state fields into a runtime context payload."""
    payload: dict[str, Any] = {}
    _SERIALIZED_LIST_FIELDS: tuple[tuple[str, str], ...] = (
        ("objective_queue", "objective_queue"),
        ("research_findings", "research_findings"),
        ("hypothesis_board", "hypotheses"),
        ("refutations", "refutations"),
        ("experiment_board", "experiment_board"),
        ("candidates", "candidate_seeds"),
        ("static_evidence", "static_evidence"),
        ("witness_bundles", "witness_bundles"),
    )
    for state_key, payload_key in _SERIALIZED_LIST_FIELDS:
        value = state.get(state_key)
        if value is not None:
            payload[payload_key] = _serialize_runtime_context_items(value)

    _STABLE_SERIALIZE_LIST_FIELDS: tuple[str, ...] = ("gate_history", "runtime_history")
    for key in _STABLE_SERIALIZE_LIST_FIELDS:
        value = state.get(key)
        if value is not None:
            payload[key] = _stable_serialize(value)

    for key in ("auth_contexts", "web_hints", "web_artifacts", "artifact_index"):
        if key in state:
            payload[key] = _stable_serialize(state.get(key))
    return payload


def _sync_runtime_from_state(runtime: Any, state: GraphState) -> None:
    if runtime is None or not hasattr(runtime, "shared_context"):
        return
    payload: dict[str, Any] = {}
    payload["__progress_callback__"] = _get_progress_callback(state)
    frontier_state = state.get("frontier_state")
    if isinstance(frontier_state, dict):
        payload["frontier_state"] = _sanitize_frontier_for_persistence(frontier_state)
    payload.update(_collect_serialized_state_fields(state))
    if payload:
        update_agent_runtime_context(runtime, **payload)


def _target_signature_for(repo_root: str, base_url: str) -> str:
    return hashlib.sha256(f"{Path(repo_root).resolve()}\n{base_url.strip()}".encode("utf-8")).hexdigest()[:16]


def _config_signature(config: PadvConfig, mode: str, run_validation: bool) -> str:
    payload = _stable_serialize(
        {
            "mode": mode,
            "run_validation": run_validation,
            "target": config.target,
            "oracle": config.oracle,
            "budgets": config.budgets,
            "agent": config.agent,
            "web": config.web,
            "auth": config.auth,
            "scip": config.scip,
            "differential": config.differential,
            "canary": config.canary,
        }
    )
    return hashlib.sha256(json.dumps(payload, sort_keys=True, ensure_ascii=True).encode("utf-8")).hexdigest()[:16]


def _graph_thread_id(state: GraphState) -> str:
    existing = str(state.get("graph_thread_id") or "").strip()
    if existing:
        return existing
    run_id = str(state.get("run_id") or "").strip()
    if not run_id:
        run_id = new_run_id("graph")
        state["run_id"] = run_id
    thread_id = f"graph-{run_id}"
    state["graph_thread_id"] = thread_id
    return thread_id


def _graph_checkpointer_path(store: EvidenceStore, thread_id: str) -> Path:
    path = store.langgraph_dir / "threads" / f"{thread_id}.pkl"
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def _graph_resume_payload(
    state: GraphState,
    *,
    thread_id: str,
    checkpoint_id: str = "",
    status: str,
    next_nodes: list[str] | tuple[str, ...] | None = None,
    error: str = "",
) -> dict[str, Any]:
    repo_root = str(Path(str(state.get("repo_root") or ".")).resolve())
    base_url = str(state["config"].target.base_url or "").strip()
    payload = {
        "run_id": str(state.get("run_id") or ""),
        "thread_id": thread_id,
        "checkpoint_id": checkpoint_id,
        "status": status,
        "mode": str(state.get("mode") or ""),
        "run_validation": bool(state.get("run_validation")),
        "repo_root": repo_root,
        "base_url": base_url,
        "target_signature": _target_signature_for(repo_root, base_url),
        "config_signature": _config_signature(state["config"], str(state.get("mode") or ""), bool(state.get("run_validation"))),
        "started_at": str(state.get("started_at") or ""),
        "updated_at": _now_iso(),
        "next_nodes": list(next_nodes or []),
        "error": error,
    }
    soft_yield = state.get("soft_yield")
    if isinstance(soft_yield, dict) and soft_yield:
        payload["soft_yield"] = dict(soft_yield)
    return payload


def _latest_checkpoint_info(graph: Any, config: dict[str, Any]) -> tuple[str, list[str]]:
    try:
        snapshot = graph.get_state(config)
    except Exception:
        return "", []
    checkpoint_id = str(getattr(snapshot, "config", {}).get("configurable", {}).get("checkpoint_id", "") or "")
    next_nodes = list(getattr(snapshot, "next", ()) or ())
    return checkpoint_id, [str(item) for item in next_nodes if str(item).strip()]


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
    callback = _get_progress_callback(state)
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


class _InvariantChecker:
    """Helper to validate stage invariants without deep nesting."""

    def __init__(self, state: GraphState, stage: str) -> None:
        self.state = state
        self._stage = stage

    def expect_list(self, key: str) -> list[Any]:
        value = self.state.get(key)
        if not isinstance(value, list):
            raise _invariant_error(self._stage, f"{key} must be a list")
        return value

    def expect_dict(self, key: str) -> dict[str, Any]:
        value = self.state.get(key)
        if not isinstance(value, dict):
            raise _invariant_error(self._stage, f"{key} must be a dict")
        return value


def _assert_init_invariants(chk: _InvariantChecker, state: GraphState, stage: str) -> None:
    chk.expect_dict("discovery_trace")
    chk.expect_dict("planner_trace")
    chk.expect_list("candidates")
    chk.expect_list("static_evidence")
    chk.expect_list("artifact_refs")
    chk.expect_list("all_bundles")
    chk.expect_list("iteration_bundles")
    chk.expect_dict("decisions")
    chk.expect_dict("auth_state")
    analysis = state.get("failure_analysis")
    if analysis is not None and not isinstance(analysis, FailureAnalysis):
        raise _invariant_error(stage, "failure_analysis must be FailureAnalysis or None")


def _assert_web_discovery_invariants(chk: _InvariantChecker, state: GraphState, stage: str) -> None:
    chk.expect_dict("web_hints")
    web_error = state.get("web_error")
    if web_error is not None and not isinstance(web_error, str):
        raise _invariant_error(stage, "web_error must be a string or null")


def _assert_candidate_synthesis_invariants(chk: _InvariantChecker, stage: str) -> None:
    chk.expect_list("candidates")
    proposer = chk.expect_dict("planner_trace").get("proposer")
    if proposer is not None and not isinstance(proposer, dict):
        raise _invariant_error(stage, "planner_trace.proposer must be a dict")


def _assert_skeptic_refine_invariants(chk: _InvariantChecker, stage: str) -> None:
    chk.expect_list("candidates")
    skeptic = chk.expect_dict("planner_trace").get("skeptic")
    if skeptic is not None and not isinstance(skeptic, dict):
        raise _invariant_error(stage, "planner_trace.skeptic must be a dict")


def _assert_objective_schedule_invariants(chk: _InvariantChecker, stage: str) -> None:
    selected = chk.expect_list("selected_candidates")
    chk.expect_list("selected_static")
    chk.expect_dict("objective_scores")
    if any(not hasattr(c, "candidate_id") for c in selected):
        raise _invariant_error(stage, "selected_candidates entries must be Candidate-like")


def _assert_frontier_update_invariants(chk: _InvariantChecker, stage: str) -> None:
    frontier = chk.expect_dict("frontier_state")
    if not isinstance(frontier.get("coverage"), dict):
        raise _invariant_error(stage, "frontier_state.coverage must be a dict")
    if not isinstance(frontier.get("history"), list):
        raise _invariant_error(stage, "frontier_state.history must be a list")
    if not isinstance(frontier.get("candidate_resume", {}), dict):
        raise _invariant_error(stage, "frontier_state.candidate_resume must be a dict")


def _assert_validation_plan_invariants(chk: _InvariantChecker, state: GraphState, stage: str) -> None:
    plans = chk.expect_dict("plans_by_candidate")
    if not state.get("run_validation"):
        return
    selected = state.get("selected_candidates") or state.get("candidates") or []
    selected_ids = {
        c.candidate_id
        for c in selected
        if hasattr(c, "candidate_id")
    }
    missing = [cid for cid in selected_ids if cid not in plans]
    if missing:
        raise _invariant_error(stage, f"missing plans for candidates: {sorted(missing)}")


def _assert_static_discovery_invariants(chk: _InvariantChecker, _stage: str) -> None:
    chk.expect_list("candidates")
    chk.expect_list("static_evidence")


def _assert_auth_setup_invariants(chk: _InvariantChecker, _stage: str) -> None:
    chk.expect_dict("auth_state")


def _assert_discovery_summary_invariants(chk: _InvariantChecker, _stage: str) -> None:
    chk.expect_dict("discovery_summary")


def _assert_orient_invariants(chk: _InvariantChecker, _stage: str) -> None:
    chk.expect_list("objective_queue")


def _assert_select_objective_invariants(chk: _InvariantChecker, stage: str) -> None:
    if chk.state.get("active_objective") is None:
        raise _invariant_error(stage, "active_objective must be set")


def _assert_reduce_research_invariants(chk: _InvariantChecker, _stage: str) -> None:
    chk.expect_list("research_tasks")
    chk.expect_list("research_findings")


def _assert_hypothesis_board_update_invariants(chk: _InvariantChecker, _stage: str) -> None:
    chk.expect_list("hypothesis_board")
    chk.expect_list("candidates")


def _assert_skeptic_challenge_invariants(chk: _InvariantChecker, _stage: str) -> None:
    chk.expect_list("refutations")


def _assert_experiment_plan_invariants(chk: _InvariantChecker, _stage: str) -> None:
    chk.expect_dict("plans_by_candidate")


def _assert_runtime_execute_invariants(chk: _InvariantChecker, _stage: str) -> None:
    chk.expect_list("bundles")


def _assert_evidence_reduce_invariants(chk: _InvariantChecker, _stage: str) -> None:
    chk.expect_list("witness_bundles")


def _assert_deterministic_gate_invariants(chk: _InvariantChecker, _stage: str) -> None:
    chk.expect_list("gate_history")


def _assert_runtime_validate_invariants(chk: _InvariantChecker, _stage: str) -> None:
    chk.expect_list("bundles")
    chk.expect_dict("decisions")


def _assert_persist_invariants(chk: _InvariantChecker, _stage: str) -> None:
    chk.expect_list("candidates")
    chk.expect_list("static_evidence")


def _noop_invariants(_chk: _InvariantChecker, _stage: str) -> None:
    """No invariants to check for this stage (e.g. init, continue_or_stop)."""


_STAGE_INVARIANT_DISPATCH: dict[str, Callable[[_InvariantChecker, str], None]] = {
    "static_discovery": _assert_static_discovery_invariants,
    "auth_setup": _assert_auth_setup_invariants,
    "discovery_summary": _assert_discovery_summary_invariants,
    "orient": _assert_orient_invariants,
    "select_objective": _assert_select_objective_invariants,
    "reduce_research": _assert_reduce_research_invariants,
    "hypothesis_board_update": _assert_hypothesis_board_update_invariants,
    "skeptic_challenge": _assert_skeptic_challenge_invariants,
    "experiment_plan": _assert_experiment_plan_invariants,
    "runtime_execute": _assert_runtime_execute_invariants,
    "evidence_reduce": _assert_evidence_reduce_invariants,
    "deterministic_gate": _assert_deterministic_gate_invariants,
    "candidate_synthesis": _assert_candidate_synthesis_invariants,
    "skeptic_refine": _assert_skeptic_refine_invariants,
    "objective_schedule": _assert_objective_schedule_invariants,
    "frontier_update": _assert_frontier_update_invariants,
    "runtime_validate": _assert_runtime_validate_invariants,
    "dedup_topk": _assert_runtime_validate_invariants,
    "persist": _assert_persist_invariants,
    "source_research": _noop_invariants,
    "graph_research": _noop_invariants,
    "web_research": _noop_invariants,
    "continue_or_stop": _noop_invariants,
}


def _assert_stage_invariants(state: GraphState, stage: str) -> None:
    chk = _InvariantChecker(state, stage)

    if stage == "init":
        _assert_init_invariants(chk, state, stage)
        return

    if stage in {"web_discovery", "authenticated_web_discovery"}:
        _assert_web_discovery_invariants(chk, state, stage)
        return

    if stage == "validation_plan":
        _assert_validation_plan_invariants(chk, state, stage)
        return

    handler = _STAGE_INVARIANT_DISPATCH.get(stage)
    if handler is not None:
        handler(chk, stage)


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
            "objectives": len(state.get("objective_queue", [])),
            "research_tasks": len(state.get("research_tasks", [])),
            "research_findings": len(state.get("research_findings", [])),
            "hypotheses": len(state.get("hypothesis_board", [])),
            "refutations": len(state.get("refutations", [])),
            "experiment_attempts": len(state.get("experiment_board", [])),
            "witness_bundles": len(state.get("witness_bundles", [])),
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
    payload = _stage_snapshot_payload(state, stage)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=True))
    checkpoint_dir = store.langgraph_dir / run_id
    checkpoint_dir.mkdir(parents=True, exist_ok=True)
    (checkpoint_dir / f"{stage_seq:03d}-{stage}.json").write_text(json.dumps(payload, indent=2, ensure_ascii=True))


def _finalize_stage(state: GraphState, stage: str, detail: str | None = None) -> GraphState:
    _assert_stage_invariants(state, stage)
    _persist_stage_snapshot(state, stage)
    run_id = str(state.get("run_id") or "").strip()
    if run_id:
        _RUNTIME_SYNC_DIRTY.add(run_id)
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


def _current_target_scope(state: GraphState) -> dict[str, str]:
    repo_root = str(Path(str(state.get("repo_root") or ".")).resolve())
    base_url = str(state["config"].target.base_url or "").strip()
    fingerprint = hashlib.sha256(f"{repo_root}\n{base_url}".encode("utf-8")).hexdigest()[:16]
    return {
        "repo_root": repo_root,
        "base_url": base_url,
        "fingerprint": fingerprint,
    }


_RUNTIME_VALIDATABLE_CLASSES = runtime_validatable_classes()

_OBJECTIVE_FAMILY_KEYWORDS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("sql_injection", ("sql", "sqli")),
    ("cross_site_scripting", ("xss", "cross site scripting", "cross-site scripting")),
    ("command_injection", ("command", "cmdi", "shell", "dns lookup", "echo")),
    ("code_injection", ("code injection", "eval", "assert", "preg_replace", "create_function")),
    ("ldap_injection", ("ldap",)),
    ("xpath_injection", ("xpath",)),
    ("file_inclusion_path_traversal", ("file inclusion", "include", "traversal", "lfi", "rfi", "file read")),
    ("unrestricted_file_upload", ("upload",)),
    ("information_disclosure_misconfiguration", ("phpinfo", "error", "debug", "information disclosure", "misconfig")),
    ("ssrf", ("ssrf", "outbound request", "server-side request forgery")),
    ("xxe_xml_injection", ("xxe", "xml external", "xml injection")),
    ("deserialization", ("deserial", "unserialize", "object injection")),
    ("header_cookie_manipulation", ("header", "cookie", "redirect", "mail header")),
    ("regex_xml_dos", ("regex dos", "redos", "xml dos", "billion laughs")),
    ("authn_authz_failures", ("auth", "authorization", "access control", "idor", "privilege")),
    ("csrf", ("csrf",)),
    ("session_misuse", ("session", "fixation")),
    ("crypto_failures", ("crypto", "hash", "random", "md5", "sha1")),
    ("software_data_integrity", ("integrity", "signature", "supply chain")),
    ("logging_monitoring_failures", ("logging", "monitoring")),
)


_VULN_CLASS_EXACT_MAP: dict[str, str] = {
    "file_boundary_influence": "file_inclusion_path_traversal",
    "debug_output_leak": "information_disclosure_misconfiguration",
    "information_disclosure": "information_disclosure_misconfiguration",
    "security_misconfiguration": "information_disclosure_misconfiguration",
    "broken_access_control": "authn_authz_failures",
    "idor_invariant_missing": "authn_authz_failures",
    "auth_and_session_failures": "authn_authz_failures",
}

_VULN_CLASS_SUBSTRING_MAP: tuple[tuple[tuple[str, ...], str], ...] = (
    (("sql",), "sql_injection"),
    (("xss",), "cross_site_scripting"),
    (("command",), "command_injection"),
    (("code_injection",), "code_injection"),
    (("ldap",), "ldap_injection"),
    (("xpath",), "xpath_injection"),
    (("file_upload",), "unrestricted_file_upload"),
    (("ssrf", "outbound_request"), "ssrf"),
    (("xxe", "xml_dos"), "xxe_xml_injection"),
    (("deserialization", "gadget"), "deserialization"),
    (("header",), "header_cookie_manipulation"),
    (("regex_dos",), "regex_xml_dos"),
    (("csrf",), "csrf"),
    (("session",), "session_misuse"),
    (("crypto",), "crypto_failures"),
    (("software_data_integrity",), "software_data_integrity"),
    (("logging_monitoring",), "logging_monitoring_failures"),
)


def _objective_family_from_vuln_class(vuln_class: str) -> str:
    key = str(vuln_class or "").strip().lower()
    if not key:
        return "unknown"
    exact = _VULN_CLASS_EXACT_MAP.get(key)
    if exact is not None:
        return exact
    for substrings, family in _VULN_CLASS_SUBSTRING_MAP:
        if any(s in key for s in substrings):
            return family
    return key


def _objective_family_from_text(*parts: str) -> str | None:
    text = " ".join(str(part or "").strip().lower() for part in parts if str(part or "").strip())
    if not text:
        return None
    for family, keywords in _OBJECTIVE_FAMILY_KEYWORDS:
        if any(keyword in text for keyword in keywords):
            return family
    return None


def _objective_family_title(family: str) -> str:
    return family.replace("_", " ").title()


def _build_family_buckets(candidates: list[Candidate]) -> dict[str, dict[str, Any]]:
    """Group candidates into vuln-class family buckets."""
    family_buckets: dict[str, dict[str, Any]] = {}
    for candidate in candidates:
        family = _objective_family_from_vuln_class(candidate.vuln_class)
        bucket = family_buckets.setdefault(
            family,
            {
                "candidate_ids": [],
                "file_paths": set(),
                "sample_titles": [],
                "max_confidence": 0.0,
                "runtime_validatable": False,
            },
        )
        bucket["candidate_ids"].append(candidate.candidate_id)
        bucket["file_paths"].add(candidate.file_path)
        if len(bucket["sample_titles"]) < 3 and candidate.title not in bucket["sample_titles"]:
            bucket["sample_titles"].append(candidate.title)
        bucket["max_confidence"] = max(float(bucket["max_confidence"]), float(candidate.confidence))
        if candidate.vuln_class in _RUNTIME_VALIDATABLE_CLASSES:
            bucket["runtime_validatable"] = True
    return family_buckets


def _make_backfill_objective(
    family: str,
    data: dict[str, Any],
    existing_ids: set[str],
) -> ObjectiveScore:
    """Create a single backfill ObjectiveScore for a vuln-class family."""
    objective_id = f"obj-auto-{family}"
    suffix = 1
    while objective_id in existing_ids:
        suffix += 1
        objective_id = f"obj-auto-{family}-{suffix}"
    candidate_count = len(data["candidate_ids"])
    file_count = len(data["file_paths"])
    max_confidence = float(data["max_confidence"])
    runtime_bonus = 0.1 if data["runtime_validatable"] else 0.0
    priority = min(0.99, 0.45 + min(candidate_count, 8) * 0.05 + runtime_bonus + min(max_confidence, 1.0) * 0.1)
    return ObjectiveScore(
        objective_id=objective_id,
        title=f"Investigate {_objective_family_title(family)}",
        rationale=(
            f"Deterministic coverage backfill for {family} based on {candidate_count} candidate seeds "
            f"across {file_count} files; sample leads: {', '.join(data['sample_titles']) or family}."
        ),
        expected_info_gain=priority,
        priority=priority,
        channels=["source", "graph", "web"],
        related_hypothesis_ids=[],
    )


def _supplement_objectives_with_candidate_coverage(
    state: GraphState,
    objectives: list[ObjectiveScore],
) -> tuple[list[ObjectiveScore], dict[str, Any]]:
    candidates = [item for item in state.get("candidates", []) if isinstance(item, Candidate)]
    if not candidates:
        return objectives, {"added": [], "families": {}}

    represented: set[str] = set()
    for item in objectives:
        family = _objective_family_from_text(item.objective_id, item.title, item.rationale)
        if family:
            represented.add(family)

    family_buckets = _build_family_buckets(candidates)

    # Keep enough headroom to preserve coverage across the full Mutillidae family
    # set instead of truncating lower-signal runtime-validatable classes like LDAP.
    max_objectives = max(12, min(max(state["config"].agent.max_iterations * 3, 12), 24))
    ranked_families = sorted(
        family_buckets.items(),
        key=lambda item: (
            -int(bool(item[1]["runtime_validatable"])),
            -len(item[1]["candidate_ids"]),
            -float(item[1]["max_confidence"]),
            item[0],
        ),
    )

    supplemented = list(objectives)
    existing_ids = {item.objective_id for item in objectives}
    added: list[str] = []
    for family, data in ranked_families:
        if len(supplemented) >= max_objectives:
            break
        if family in represented:
            continue
        obj = _make_backfill_objective(family, data, existing_ids)
        supplemented.append(obj)
        represented.add(family)
        existing_ids.add(obj.objective_id)
        added.append(obj.objective_id)

    summary = {
        family: {
            "candidate_count": len(data["candidate_ids"]),
            "runtime_validatable": bool(data["runtime_validatable"]),
        }
        for family, data in ranked_families
    }
    return supplemented, {"added": added, "families": summary}


def _frontier_matches_target_scope(frontier: dict[str, Any], state: GraphState) -> bool:
    target_scope = frontier.get("target_scope")
    if not isinstance(target_scope, dict):
        return False
    expected = _current_target_scope(state)
    return (
        str(target_scope.get("fingerprint", "")).strip() == expected["fingerprint"]
        and str(target_scope.get("repo_root", "")).strip() == expected["repo_root"]
        and str(target_scope.get("base_url", "")).strip() == expected["base_url"]
    )


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


def _extract_bundle_decision(bundle: Any) -> tuple[str, str, str]:
    """Return (candidate_id, vuln_class, decision) from a bundle."""
    candidate = getattr(bundle, "candidate", None)
    candidate_id = str(getattr(candidate, "candidate_id", ""))
    vuln_class = str(getattr(candidate, "vuln_class", ""))
    gate = getattr(bundle, "gate_result", None)
    decision = str(getattr(gate, "decision", ""))
    return candidate_id, vuln_class, decision


def _collect_attempt_flags(item: dict[str, Any], flags: set[str]) -> None:
    """Extract analysis flags from a single attempt dict into the flags set."""
    analysis_flags = item.get("analysis_flags", [])
    if not isinstance(analysis_flags, list):
        return
    for flag in analysis_flags:
        if isinstance(flag, str) and flag.strip():
            flags.add(flag.strip())


def _runtime_feedback_from_bundles(bundles: list[Any], iteration: int) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    attempts: list[dict[str, Any]] = []
    flags: set[str] = set()
    classes: set[str] = set()
    decisions: dict[str, int] = {}
    for bundle in bundles:
        candidate_id, vuln_class, decision = _extract_bundle_decision(bundle)
        if vuln_class.strip():
            classes.add(vuln_class.strip())
        if decision:
            decisions[decision] = decisions.get(decision, 0) + 1

        trace = getattr(bundle, "planner_trace", {})
        trace_attempts = trace.get("attempts", []) if isinstance(trace, dict) else []
        if not isinstance(trace_attempts, list):
            continue
        for item in trace_attempts:
            if not isinstance(item, dict):
                continue
            copied = dict(item)
            copied["candidate_id"] = candidate_id
            copied["vuln_class"] = vuln_class
            copied["iteration"] = iteration
            attempts.append(copied)
            _collect_attempt_flags(item, flags)
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


def _write_artifact(
    state: GraphState,
    filename: str,
    payload: dict[str, Any],
    *,
    index_key: str | None = None,
) -> str:
    """Write a JSON artifact to the store artifacts directory.

    1. Gets the store from state, ensures directories exist.
    2. Writes ``{"generated_at": <now>, **payload}`` as indented JSON.
    3. Appends the path to ``state["artifact_refs"]``.
    4. Optionally sets ``state["artifact_index"][index_key]``.
    5. Returns the artifact path string.
    """
    store = state["store"]
    store.ensure()
    artifact_dir = store.root / "artifacts"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    artifact_path = artifact_dir / filename
    artifact_path.write_text(
        json.dumps({"generated_at": _now_iso(), **payload}, indent=2, ensure_ascii=True)
    )
    ref = str(Path(artifact_path))
    state.setdefault("artifact_refs", []).append(ref)
    if index_key is not None:
        state.setdefault("artifact_index", {})[index_key] = ref
    return ref


def _persist_web_artifact(
    state: GraphState,
    seed_urls: list[str],
    hints: dict[str, list[str]],
    artifacts: dict[str, Any],
    err: str | None,
    *,
    artifact_key: str = "web_discovery",
    artifact_prefix: str = "web-discovery",
    scope: str = "anonymous",
) -> None:
    _write_artifact(
        state,
        f"{artifact_prefix}-{new_run_id('disc')}.json",
        {"scope": scope, "seed_urls": seed_urls, "hints": hints, "artifacts": artifacts, "error": err},
        index_key=artifact_key,
    )


def _persist_semantic_discovery_artifact(state: GraphState, payload: dict[str, Any]) -> None:
    _write_artifact(state, f"semantic-discovery-{new_run_id('disc')}.json", payload)


def _persist_fusion_artifact(state: GraphState, meta: dict[str, Any]) -> None:
    _write_artifact(state, f"semantic-fusion-{new_run_id('disc')}.json", meta)


def _persist_auth_artifact(state: GraphState, auth_state: dict[str, Any]) -> None:
    _write_artifact(
        state,
        f"auth-state-{new_run_id('disc')}.json",
        {
            "auth_enabled": bool(auth_state.get("auth_enabled")),
            "login_url": auth_state.get("login_url"),
            "username": auth_state.get("username"),
            "cookie_names": sorted((auth_state.get("cookies") or {}).keys()) if isinstance(auth_state.get("cookies"), dict) else [],
            "cookie_count": len(auth_state.get("cookies", {})) if isinstance(auth_state.get("cookies"), dict) else 0,
            "summary": auth_state.get("summary", ""),
        },
    )


def _persist_discovery_summary_artifact(state: GraphState, payload: dict[str, Any]) -> None:
    _write_artifact(
        state,
        f"discovery-summary-{new_run_id('disc')}.json",
        payload,
        index_key="discovery_summary",
    )


def _persist_failure_analysis_artifact(state: GraphState, analysis: FailureAnalysis) -> None:
    run_id = str(state.get("run_id", "run-unknown"))
    _write_artifact(state, f"failure-analysis-{run_id}.json", analysis.to_dict())


def _persist_runtime_liveness_artifact(state: GraphState, payload: dict[str, Any]) -> None:
    run_id = str(state.get("run_id", "run-unknown"))
    _write_artifact(state, f"runtime-liveness-{run_id}-{new_run_id('diag')}.json", payload)


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


def _agent_checkpoint_dir(state: GraphState) -> str:
    run_id = str(state.get("run_id") or "run-unknown")
    configured = str(state["config"].agent.checkpoint_dir or "").strip()
    base = Path(configured) if configured else Path(state["store"].langgraph_dir)
    path = base / run_id
    path.mkdir(parents=True, exist_ok=True)
    return str(path)


def _resume_compatible(
    metadata: dict[str, Any],
    *,
    config: PadvConfig,
    repo_root: str,
    mode: str,
    run_validation: bool,
) -> bool:
    base_url = str(config.target.base_url or "").strip()
    return (
        str(metadata.get("mode", "")).strip() == mode
        and bool(metadata.get("run_validation")) == bool(run_validation)
        and str(metadata.get("target_signature", "")).strip() == _target_signature_for(repo_root, base_url)
        and str(metadata.get("config_signature", "")).strip() == _config_signature(config, mode, run_validation)
    )


def _sanitize_frontier_for_persistence(frontier: dict[str, Any]) -> dict[str, Any]:
    import copy
    payload = copy.deepcopy(frontier)
    payload.pop("agent_threads", None)
    payload.pop("agent_thread_id", None)
    return payload


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


def _reset_iteration_state_for_new_objective(state: GraphState) -> None:
    state["research_tasks"] = []
    state["research_findings"] = []
    state["source_tasks"] = []
    state["graph_tasks"] = []
    state["web_tasks"] = []
    state["source_findings"] = []
    state["graph_findings"] = []
    state["web_findings"] = []
    state["source_trace"] = {}
    state["graph_trace"] = {}
    state["web_trace"] = {}
    state["hypothesis_board"] = []
    state["refutations"] = []
    state["experiment_board"] = []
    state["plans_by_candidate"] = {}
    state["witness_bundles"] = []
    state["iteration_bundles"] = []
    state["validation_board"] = {}
    state["execution_board"] = {}
    state["research_board"] = {}
    for key in (
        "source_branch_error",
        "graph_branch_error",
        "web_branch_error",
        "research_branch_errors",
        "source_context_delta",
        "graph_context_delta",
        "web_context_delta",
    ):
        state.pop(key, None)
    planner_trace = state.setdefault("planner_trace", {})
    for key in (
        "source_research",
        "graph_research",
        "web_research",
        "research_branch_errors",
        "hypothesis_board",
        "skeptic",
        "experiment",
    ):
        planner_trace.pop(key, None)
    update_agent_runtime_context(
        _state_runtime(state),
        research_findings=[],
        hypotheses=[],
        refutations=[],
        experiment_board=[],
        witness_bundles=[],
    )


def _init_state_fields(state: GraphState) -> None:
    if not state.get("run_id"):
        state["run_id"] = new_run_id("analyze")
    state["stage_seq"] = 0
    state["discovery_trace"] = {}
    state["planner_trace"] = {}
    state["plans_by_candidate"] = {}
    state["artifact_refs"] = []
    state["web_hints"] = {}
    state["web_artifacts"] = {}
    state["anonymous_web_hints"] = {}
    state["anonymous_web_artifacts"] = {}
    state["authenticated_web_hints"] = {}
    state["authenticated_web_artifacts"] = {}
    state["discovery_summary"] = {}
    state["web_error"] = None
    state["bundles"] = []
    state["all_bundles"] = []
    state["iteration_bundles"] = []
    state["objective_scores"] = {}
    state["schedule_all_candidates"] = []
    state["resume_filtered_candidates"] = []
    state["had_semantic_candidates"] = False
    state["loop_continue"] = False
    state["decisions"] = _default_decisions()
    state["auth_state"] = {}
    state["failure_analysis"] = None
    state["objective_queue"] = []
    state["active_objective"] = None
    state["research_tasks"] = []
    state["research_findings"] = []
    state["source_findings"] = []
    state["graph_findings"] = []
    state["web_findings"] = []
    state["source_tasks"] = []
    state["graph_tasks"] = []
    state["web_tasks"] = []
    state["source_trace"] = {}
    state["graph_trace"] = {}
    state["web_trace"] = {}
    state["hypothesis_board"] = []
    state["refutations"] = []
    state["experiment_board"] = []
    state["witness_bundles"] = []
    state["gate_history"] = []
    state["auth_contexts"] = {}
    state["artifact_index"] = {}
    state["continue_reason"] = ""
    state["run_iteration"] = 0
    state["detection_board"] = {}
    state["research_board"] = {}
    state["validation_board"] = {}
    state["execution_board"] = {}
    state["gate_board"] = {}
    state["candidates"] = list(state.get("candidates", []))
    state["static_evidence"] = list(state.get("static_evidence", []))
    state["selected_candidates"] = list(state.get("selected_candidates", []))
    state["selected_static"] = list(state.get("selected_static", []))


def _load_and_normalize_frontier(state: GraphState) -> dict[str, Any]:
    persisted = state["store"].load_frontier_state() or _default_frontier_state()
    if not isinstance(persisted, dict):
        persisted = _default_frontier_state()
    if not _frontier_matches_target_scope(persisted, state):
        persisted = _default_frontier_state()
    persisted.pop("agent_threads", None)
    persisted.pop("agent_thread_id", None)
    persisted.setdefault("coverage", _default_frontier_state()["coverage"])
    persisted.setdefault("history", [])
    persisted.setdefault("hypotheses", [])
    persisted.setdefault("failed_paths", [])
    persisted.setdefault("iteration", 0)
    persisted.setdefault("stagnation_rounds", 0)
    persisted.setdefault("attempt_history", [])
    persisted.setdefault("candidate_resume", {})
    persisted.setdefault("runtime_coverage", {"flags": [], "classes": []})
    persisted["target_scope"] = _current_target_scope(state)
    return persisted


def _init_failure_analysis(state: GraphState) -> None:
    analysis = analyze_failures(state["store"])
    state["failure_analysis"] = analysis
    _persist_failure_analysis_artifact(state, analysis)
    state["discovery_trace"]["failure_patterns"] = len(analysis.patterns)


def _node_init(state: GraphState) -> GraphState:
    _emit_progress(state, "init", "start")
    _init_state_fields(state)

    if state.get("skip_discovery"):
        _init_failure_analysis(state)
        state["frontier_state"] = _default_frontier_state()
        state["frontier_state"]["target_scope"] = _current_target_scope(state)
        state["had_semantic_candidates"] = bool(state.get("selected_candidates"))
        update_agent_runtime_context(_state_runtime(state), frontier_state=state["frontier_state"])
        return _finalize_stage(state, "init", "validate-only state initialized")

    state["frontier_state"] = _load_and_normalize_frontier(state)
    _init_failure_analysis(state)
    update_agent_runtime_context(_state_runtime(state), frontier_state=state["frontier_state"])
    return _finalize_stage(state, "init", "frontier and agent session ready")


def _node_static_discovery(state: GraphState) -> GraphState:
    _emit_progress(state, "static_discovery", "start")
    if state.get("skip_discovery"):
        state.setdefault("discovery_trace", {})["mode"] = "validate-only"
        return _finalize_stage(state, "static_discovery", _SKIPPED_VALIDATE_ONLY)

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
    state["detection_board"] = {
        "candidates": [item.to_dict() for item in semantic_candidates],
        "static_evidence": [item.to_dict() for item in semantic_evidence],
    }
    runtime = _state_runtime(state)
    update_agent_runtime_context(
        runtime,
        static_evidence=[item.to_dict() for item in semantic_evidence],
        candidate_seeds=[item.to_dict() for item in semantic_candidates],
        artifact_index=dict(state.get("artifact_index", {})),
    )
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


def _run_web_discovery_phase(state: GraphState, scope: str) -> GraphState:
    """Shared implementation for anonymous and authenticated web discovery."""
    is_authenticated = scope == "authenticated"
    stage_name = "authenticated_web_discovery" if is_authenticated else "web_discovery"
    hints_key = f"{scope}_web_hints"
    artifacts_key = f"{scope}_web_artifacts"

    _emit_progress(state, stage_name, "start")
    if state.get("skip_discovery"):
        return _finalize_stage(state, stage_name, _SKIPPED_VALIDATE_ONLY)
    if state.get(hints_key) and state.get(artifacts_key) and not state.get("web_error"):
        reuse_label = "authenticated " if is_authenticated else ""
        return _finalize_stage(state, stage_name, f"reused prior {reuse_label}web results")

    if is_authenticated:
        auth_state = state.get("auth_state", {})
        cookie_count = len(auth_state.get("cookies", {})) if isinstance(auth_state.get("cookies"), dict) else 0
        if not cookie_count:
            return _finalize_stage(state, stage_name, "skipped (no authenticated context)")
    else:
        auth_state = None

    config = state["config"]
    seed_urls = _seed_urls_from_frontier(
        state.get("frontier_state", {}),
        max_urls=config.web.max_pages,
        base_url=config.target.base_url,
    )
    discover_kwargs: dict[str, Any] = {"seed_urls": seed_urls}
    if is_authenticated:
        discover_kwargs["auth_state"] = auth_state
    hints, artifacts, err = discover_web_inventory(config, **discover_kwargs)
    _persist_web_artifact(
        state,
        seed_urls,
        hints,
        artifacts,
        err,
        artifact_key=f"web_discovery_{scope}",
        artifact_prefix=f"web-discovery-{scope}",
        scope=scope,
    )

    merged_hints = _merge_web_hints(state.get("web_hints", {}), hints)
    merged_artifacts = _merge_web_artifacts(state.get("web_artifacts", {}), artifacts, scope=scope)
    state[hints_key] = dict(hints)
    state[artifacts_key] = dict(artifacts)
    state["web_hints"] = merged_hints
    state["web_artifacts"] = merged_artifacts
    state["web_error"] = err

    if merged_hints:
        paths = list(merged_hints.keys())
        for candidate in state.get("candidates", []):
            candidate.web_path_hints = sorted(set(candidate.web_path_hints + paths))

    state["discovery_trace"][f"web_paths_{scope}"] = len(hints)
    state["discovery_trace"][f"web_pages_{scope}"] = len(artifacts.get("pages", [])) if isinstance(artifacts, dict) else 0
    state["discovery_trace"][f"web_requests_{scope}"] = len(artifacts.get("requests", [])) if isinstance(artifacts, dict) else 0
    state["discovery_trace"]["web_paths"] = len(merged_hints)
    state["discovery_trace"]["web_pages"] = len(merged_artifacts.get("pages", [])) if isinstance(merged_artifacts, dict) else 0
    state["discovery_trace"]["web_requests"] = len(merged_artifacts.get("requests", [])) if isinstance(merged_artifacts, dict) else 0
    runtime = _state_runtime(state)
    context_kwargs: dict[str, Any] = {
        "web_hints": merged_hints,
        "web_artifacts": merged_artifacts,
        "artifact_index": dict(state.get("artifact_index", {})),
    }
    if is_authenticated:
        context_kwargs["auth_contexts"] = state.get("auth_contexts", {})
    update_agent_runtime_context(runtime, **context_kwargs)
    if err:
        raise RuntimeError(f"{scope} web discovery failed: {err}")
    return _finalize_stage(state, stage_name, f"paths={len(merged_hints)}")


def _node_web_discovery(state: GraphState) -> GraphState:
    return _run_web_discovery_phase(state, "anonymous")


def _node_auth_setup(state: GraphState) -> GraphState:
    _emit_progress(state, "auth_setup", "start")
    config = state["config"]
    if state.get("auth_state") and state.get("auth_contexts"):
        return _finalize_stage(state, "auth_setup", "reused prior auth state")
    if not config.auth.enabled:
        state["auth_state"] = {"auth_enabled": False, "cookies": {}}
        state["auth_contexts"] = {"anonymous": {"auth_enabled": False, "cookies": {}}}
        state.setdefault("discovery_trace", {})["auth"] = {"enabled": False, "resolved": True, "cookies": 0}
        runtime = _state_runtime(state)
        update_agent_runtime_context(
            runtime,
            auth_contexts=state["auth_contexts"],
            candidate_seeds=[item.to_dict() for item in state.get("candidates", [])],
        )
        return _finalize_stage(state, "auth_setup", "auth disabled")

    auth_state = establish_auth_state(config)
    state["auth_state"] = auth_state
    state["auth_contexts"] = {"default": auth_state}
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
    runtime = _state_runtime(state)
    update_agent_runtime_context(
        runtime,
        auth_contexts=state["auth_contexts"],
        candidate_seeds=[item.to_dict() for item in state.get("candidates", [])],
    )
    return _finalize_stage(state, "auth_setup", f"cookies={cookie_count}")


def _node_authenticated_web_discovery(state: GraphState) -> GraphState:
    return _run_web_discovery_phase(state, "authenticated")


def _candidate_id_from_item(item: Any) -> str:
    if isinstance(item, Candidate):
        return str(item.candidate_id)
    if isinstance(item, dict):
        return str(item.get("candidate_id", ""))
    return str(getattr(item, "candidate_id", ""))


def _safe_artifact_count(artifacts: Any, key: str) -> int:
    """Count items in an artifacts dict sub-key, safely handling non-dict values."""
    if not isinstance(artifacts, dict):
        return 0
    items = artifacts.get(key, [])
    return len(items) if isinstance(items, list) else 0


def _build_web_summary(state: GraphState) -> dict[str, Any]:
    """Build the web section of the discovery summary."""
    return {
        "anonymous_paths": sorted((state.get("anonymous_web_hints") or {}).keys()),
        "authenticated_paths": sorted((state.get("authenticated_web_hints") or {}).keys()),
        "merged_paths": sorted((state.get("web_hints") or {}).keys()),
        "anonymous_page_count": _safe_artifact_count(state.get("anonymous_web_artifacts"), "pages"),
        "authenticated_page_count": _safe_artifact_count(state.get("authenticated_web_artifacts"), "pages"),
        "merged_page_count": _safe_artifact_count(state.get("web_artifacts"), "pages"),
        "anonymous_request_count": _safe_artifact_count(state.get("anonymous_web_artifacts"), "requests"),
        "authenticated_request_count": _safe_artifact_count(state.get("authenticated_web_artifacts"), "requests"),
        "merged_request_count": _safe_artifact_count(state.get("web_artifacts"), "requests"),
    }


def _build_auth_summary(state: GraphState) -> dict[str, Any]:
    """Build the auth section of the discovery summary."""
    auth_state = state.get("auth_state", {})
    auth_cookies = auth_state.get("cookies", {}) if isinstance(auth_state, dict) else {}
    auth_contexts = state.get("auth_contexts")
    return {
        "enabled": bool(auth_state.get("auth_enabled")) if isinstance(auth_state, dict) else False,
        "resolved": bool(auth_cookies) if isinstance(auth_cookies, dict) else False,
        "cookie_count": len(auth_cookies) if isinstance(auth_cookies, dict) else 0,
        "cookie_names": sorted(auth_cookies.keys()) if isinstance(auth_cookies, dict) else [],
        "contexts": sorted(auth_contexts.keys()) if isinstance(auth_contexts, dict) else [],
    }


def _node_discovery_summary(state: GraphState) -> GraphState:
    _emit_progress(state, "discovery_summary", "start")

    detection_board = state.get("detection_board", {})
    detection_candidates = detection_board.get("candidates", []) if isinstance(detection_board, dict) else []
    summary = {
        "candidate_count": len(state.get("candidates", [])),
        "static_evidence_count": len(state.get("static_evidence", [])),
        "candidate_ids": [_candidate_id_from_item(item) for item in list(state.get("candidates", []))[:50] if _candidate_id_from_item(item)],
        "semantic_discovery": dict(state.get("discovery_trace", {})),
        "detection_board_counts": {
            "candidates": len(detection_candidates) if isinstance(detection_candidates, list) else 0,
            "static_evidence": len(detection_board.get("static_evidence", [])) if isinstance(detection_board, dict) else 0,
        },
        "web": _build_web_summary(state),
        "auth": _build_auth_summary(state),
        "artifact_index": dict(state.get("artifact_index", {})),
    }
    state["discovery_summary"] = summary
    _persist_discovery_summary_artifact(state, summary)
    update_agent_runtime_context(
        _state_runtime(state),
        discovery_trace=dict(state.get("discovery_trace", {})),
        artifact_index=dict(state.get("artifact_index", {})),
    )
    return _finalize_stage(
        state,
        "discovery_summary",
        f"candidates={summary['candidate_count']} paths={len(summary['web']['merged_paths'])} auth={summary['auth']['cookie_count']}",
    )


def _persist_agent_workspace_artifact(state: GraphState, name: str, payload: dict[str, Any]) -> None:
    run_id = str(state.get("run_id", "run-unknown"))
    _write_artifact(
        state,
        f"{name}-{run_id}-{new_run_id('ws')}.json",
        payload,
        index_key=name,
    )


def _persist_research_branch_error_artifact(state: GraphState, role: str, detail: str) -> str:
    run_id = str(state.get("run_id", "run-unknown"))
    return _write_artifact(
        state,
        f"research-branch-error-{role}-{run_id}-{new_run_id('err')}.json",
        {
            "role": role,
            "detail": detail,
            "active_objective": getattr(state.get("active_objective"), "objective_id", None),
        },
    )


def _merge_web_hints(
    base: dict[str, list[str]] | None,
    incoming: dict[str, list[str]] | None,
) -> dict[str, list[str]]:
    merged: dict[str, list[str]] = dict(base or {})
    for path, params in (incoming or {}).items():
        if not isinstance(path, str):
            continue
        values = [str(item).strip() for item in (params or []) if str(item).strip()]
        merged[path] = sorted(set(merged.get(path, []) + values))
    return merged


def _dedup_string_list(payload: dict[str, Any], key: str, seen: set[str], out: list[str]) -> None:
    """Append unique stripped strings from payload[key] into out."""
    for raw in payload.get(key, []):
        value = str(raw).strip()
        if value and value not in seen:
            seen.add(value)
            out.append(value)


def _dedup_dict_list(
    payload: dict[str, Any],
    key: str,
    seen: set[str],
    out: list[dict[str, Any]],
    *,
    is_incoming: bool,
    scope: str,
) -> None:
    """Append unique dict items from payload[key] into out, setting scope."""
    for item in payload.get(key, []):
        if not isinstance(item, dict):
            continue
        dedup_key = json.dumps(item, sort_keys=True, ensure_ascii=True)
        if dedup_key in seen:
            continue
        seen.add(dedup_key)
        record = dict(item)
        record.setdefault("scope", scope if is_incoming else record.get("scope", "anonymous"))
        out.append(record)


def _merge_web_artifacts(
    base: dict[str, Any] | None,
    incoming: dict[str, Any] | None,
    *,
    scope: str,
) -> dict[str, Any]:
    pages_seen: set[str] = set()
    requests_seen: set[str] = set()
    visited_seen: set[str] = set()
    errors_seen: set[str] = set()
    seed_seen: set[str] = set()
    pages: list[dict[str, Any]] = []
    requests: list[dict[str, Any]] = []
    visited_urls: list[str] = []
    errors: list[str] = []
    seed_urls: list[str] = []

    base_payload = base or {}
    incoming_payload = incoming or {}
    for payload, is_incoming in ((base_payload, False), (incoming_payload, True)):
        if not isinstance(payload, dict):
            continue
        _dedup_string_list(payload, "seed_urls", seed_seen, seed_urls)
        _dedup_string_list(payload, "visited_urls", visited_seen, visited_urls)
        _dedup_string_list(payload, "errors", errors_seen, errors)
        _dedup_dict_list(payload, "pages", pages_seen, pages, is_incoming=is_incoming, scope=scope)
        _dedup_dict_list(payload, "requests", requests_seen, requests, is_incoming=is_incoming, scope=scope)

    return {
        "seed_urls": seed_urls,
        "visited_urls": visited_urls,
        "pages": pages,
        "requests": requests[:200],
        "errors": errors,
    }


def _candidate_from_hypothesis(hypothesis: Hypothesis) -> Candidate:
    def _stable_text_values(values: list[Any]) -> list[str]:
        out: list[str] = []
        seen: set[str] = set()
        for value in values:
            if isinstance(value, (str, int, float)):
                text = str(value).strip()
            elif isinstance(value, (dict, list)):
                text = json.dumps(value, ensure_ascii=True, sort_keys=True)
            else:
                continue
            if not text or text in seen:
                continue
            seen.add(text)
            out.append(text)
        return out

    candidate = _safe_copy_candidate(hypothesis.candidate)
    candidate.confidence = max(candidate.confidence, hypothesis.confidence)
    candidate.evidence_refs = sorted(_stable_text_values(candidate.evidence_refs + list(hypothesis.evidence_refs)))
    candidate.preconditions = sorted(_stable_text_values(candidate.preconditions + list(hypothesis.preconditions)))
    candidate.auth_requirements = sorted(_stable_text_values(candidate.auth_requirements + list(hypothesis.auth_requirements)))
    candidate.web_path_hints = sorted(_stable_text_values(candidate.web_path_hints + list(hypothesis.web_path_hints)))
    return candidate


def _selected_static_for_hypotheses(hypotheses: list[Hypothesis], static_evidence: list[StaticEvidence]) -> list[StaticEvidence]:
    if not hypotheses:
        return []
    selected_ids = {item.candidate.candidate_id for item in hypotheses}
    selected_refs = {
        ref
        for item in hypotheses
        for ref in (list(item.evidence_refs) + list(item.candidate.evidence_refs))
        if isinstance(ref, str) and ref.strip()
    }
    out: list[StaticEvidence] = []
    seen: set[tuple[str, str]] = set()
    for item in static_evidence:
        matches = item.candidate_id in selected_ids or item.hash in selected_refs or item.query_id in selected_refs
        if not matches:
            continue
        key = (item.candidate_id, item.hash)
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def _full_candidate_pool(state: GraphState) -> list[Candidate]:
    candidates = state.get("candidates", [])
    detection_board = state.get("detection_board", {})
    if isinstance(detection_board, dict):
        board_candidates = detection_board.get("candidates", [])
        if isinstance(board_candidates, list) and board_candidates:
            out: list[Candidate] = []
            for item in board_candidates:
                if isinstance(item, Candidate):
                    out.append(item)
                elif isinstance(item, dict):
                    out.append(Candidate(**item))
            if out:
                return out
    return list(candidates)


def _full_static_evidence_pool(state: GraphState) -> list[StaticEvidence]:
    static_evidence = state.get("static_evidence", [])
    detection_board = state.get("detection_board", {})
    if isinstance(detection_board, dict):
        board_evidence = detection_board.get("static_evidence", [])
        if isinstance(board_evidence, list) and board_evidence:
            out: list[StaticEvidence] = []
            for item in board_evidence:
                if isinstance(item, StaticEvidence):
                    out.append(item)
                elif isinstance(item, dict):
                    out.append(StaticEvidence(**item))
            if out:
                return out
    return list(static_evidence)


def _active_hypotheses_without_high_refutation(state: GraphState) -> list[Hypothesis]:
    def _is_nonblocking_refutation(refutation: Refutation) -> bool:
        text = " ".join(
            part.strip().lower()
            for part in (refutation.title, refutation.summary)
            if isinstance(part, str) and part.strip()
        )
        if not text:
            return False
        nonblocking_tokens = (
            ".htaccess",
            "network-level",
            "network barrier",
            "network access",
            "internal network",
            "rfc1918",
            "localhost",
            "deployment configuration",
            "default configuration",
            "external internet",
        )
        return any(token in text for token in nonblocking_tokens)

    high_refuted = {
        item.hypothesis_id
        for item in state.get("refutations", [])
        if item.severity.lower() == "high" and not _is_nonblocking_refutation(item)
    }
    return [
        item
        for item in state.get("hypothesis_board", [])
        if item.status != "rejected" and item.hypothesis_id not in high_refuted
    ]


def _node_orient(state: GraphState) -> GraphState:
    _emit_progress(state, "orient", "start")
    objectives, trace = orient_root_agent(
        _state_runtime(state),
        state["config"],
        frontier_state=state.get("frontier_state", {}),
        discovery_trace=state.get("discovery_trace", {}),
        run_validation=bool(state.get("run_validation")),
    )
    objectives, supplement_trace = _supplement_objectives_with_candidate_coverage(state, objectives)
    state["objective_queue"] = objectives
    planner_trace = state.setdefault("planner_trace", {})
    planner_trace["root_orient"] = trace
    planner_trace["objective_backfill"] = supplement_trace
    update_agent_runtime_context(_state_runtime(state), objective_queue=[item.to_dict() for item in objectives])
    _persist_agent_workspace_artifact(
        state,
        "objectives",
        {
            "objectives": [item.to_dict() for item in objectives],
            "trace": trace,
            "supplement": supplement_trace,
        },
    )
    return _finalize_stage(state, "orient", f"objectives={len(objectives)}")


def _node_select_objective(state: GraphState) -> GraphState:
    _emit_progress(state, "select_objective", "start")
    selected, trace = select_objective_with_root_agent(
        _state_runtime(state),
        state["config"],
        objective_queue=state.get("objective_queue", []),
        frontier_state=state.get("frontier_state", {}),
    )
    state["run_iteration"] = int(state.get("run_iteration", 0) or 0) + 1
    state["active_objective"] = selected
    _reset_iteration_state_for_new_objective(state)
    state.setdefault("planner_trace", {})["root_select_objective"] = trace
    return _finalize_stage(state, "select_objective", selected.objective_id)


def _run_parallel_research_branch(state: GraphState, role: str) -> dict[str, Any]:
    _emit_progress(state, f"{role}_research", "start")
    objective = state.get("active_objective")
    if objective is None:
        raise RuntimeError(f"{role} research requires active objective")
    branch_runtime = clone_runtime_for_parallel_role(_state_runtime(state), state["config"], role=role)
    try:
        tasks, findings, trace = run_research_subagent(
            branch_runtime,
            role,
            state["config"],
            objective=objective,
            frontier_state=state.get("frontier_state", {}),
        )
        context_delta = finalize_parallel_role_runtime(branch_runtime, role=role)
        branch_error: dict[str, Any] = {}
        _emit_progress(state, f"{role}_research", "done", f"findings={len(findings)}")
    except AgentExecutionError as exc:
        tasks = []
        findings = []
        context_delta = finalize_parallel_role_runtime(branch_runtime, role=role)
        error_ref = _persist_research_branch_error_artifact(state, role, str(exc))
        branch_error = {
            "role": role,
            "error": str(exc),
            "artifact_ref": error_ref,
            "objective_id": objective.objective_id,
        }
        trace = {
            "engine": "deepagents",
            "role": role,
            "error": str(exc),
            "artifact_ref": error_ref,
            "task_ids": [],
            "finding_ids": [],
        }
        _emit_progress(state, f"{role}_research", "error", str(exc))
    return {
        f"{role}_tasks": tasks,
        f"{role}_findings": findings,
        f"{role}_trace": trace,
        f"{role}_context_delta": context_delta,
        f"{role}_branch_error": branch_error,
    }


def _node_source_research_parallel(state: GraphState) -> dict[str, Any]:
    return _run_parallel_research_branch(state, "source")


def _node_graph_research_parallel(state: GraphState) -> dict[str, Any]:
    return _run_parallel_research_branch(state, "graph")


def _node_web_research_parallel(state: GraphState) -> dict[str, Any]:
    return _run_parallel_research_branch(state, "web")


def _merge_branch_traces(state: GraphState) -> None:
    """Copy non-empty branch traces into planner_trace."""
    planner_trace = state.setdefault("planner_trace", {})
    for role in ("source", "graph", "web"):
        trace = state.get(f"{role}_trace")
        if isinstance(trace, dict) and trace:
            planner_trace[f"{role}_research"] = dict(trace)


def _collect_branch_errors(state: GraphState) -> dict[str, dict[str, Any]]:
    """Collect non-empty branch errors from research fanout."""
    return {
        role: dict(item)
        for role in ("source", "graph", "web")
        if isinstance((item := state.get(f"{role}_branch_error")), dict) and item
    }


def _merge_context_deltas(state: GraphState) -> None:
    """Merge all research branch context deltas into the agent runtime."""
    runtime = _state_runtime(state)
    for key in ("source_context_delta", "graph_context_delta", "web_context_delta"):
        merge_agent_runtime_context_delta(runtime, state.get(key, {}))


def _handle_zero_findings(
    state: GraphState, branch_errors: dict[str, dict[str, Any]]
) -> GraphState | None:
    """Handle the case where research produced zero findings. Returns GraphState if handled, None otherwise."""
    if not state.get("candidates") and not state.get("static_evidence"):
        _merge_context_deltas(state)
        update_agent_runtime_context(_state_runtime(state), research_findings=[])
        _persist_agent_workspace_artifact(
            state,
            "research-findings",
            {
                "tasks": [],
                "findings": [],
                "branch_errors": branch_errors,
                "reason": "no-candidate-material",
            },
        )
        return _finalize_stage(state, "reduce_research", "findings=0 no-candidate-material")
    if branch_errors:
        detail = ", ".join(f"{role}: {item.get('error', 'unknown error')}" for role, item in sorted(branch_errors.items()))
        raise RuntimeError(f"research fanout produced zero findings; branch errors={detail}")
    raise RuntimeError("research fanout produced zero findings")


def _node_reduce_research(state: GraphState) -> GraphState:
    _emit_progress(state, "reduce_research", "start")
    tasks = state.get("source_tasks", []) + state.get("graph_tasks", []) + state.get("web_tasks", [])
    findings = state.get("source_findings", []) + state.get("graph_findings", []) + state.get("web_findings", [])
    dedup_tasks: dict[str, ResearchTask] = {item.task_id: item for item in tasks}
    dedup_findings: dict[str, ResearchFinding] = {item.finding_id: item for item in findings}
    state["research_tasks"] = list(dedup_tasks.values())
    state["research_findings"] = list(dedup_findings.values())
    state["research_board"] = {
        "tasks": [item.to_dict() for item in state["research_tasks"]],
        "findings": [item.to_dict() for item in state["research_findings"]],
    }
    _merge_branch_traces(state)
    branch_errors = _collect_branch_errors(state)
    if branch_errors:
        state["research_branch_errors"] = branch_errors
        state.setdefault("planner_trace", {})["research_branch_errors"] = branch_errors
    if not state["research_findings"]:
        result = _handle_zero_findings(state, branch_errors)
        if result is not None:
            return result
    _merge_context_deltas(state)
    update_agent_runtime_context(_state_runtime(state), research_findings=[item.to_dict() for item in state["research_findings"]])
    _persist_agent_workspace_artifact(
        state,
        "research-findings",
        {
            "tasks": [item.to_dict() for item in state["research_tasks"]],
            "findings": [item.to_dict() for item in state["research_findings"]],
            "branch_errors": branch_errors,
        },
    )
    return _finalize_stage(state, "reduce_research", f"findings={len(state['research_findings'])}")


def _node_hypothesis_board_update(state: GraphState) -> GraphState:
    _emit_progress(state, "hypothesis_board_update", "start")
    objective = state.get("active_objective")
    if objective is None:
        raise RuntimeError("hypothesis update requires active objective")
    hypotheses, trace = synthesize_hypotheses_with_subagent(
        _state_runtime(state),
        state["config"],
        objective=objective,
        findings=state.get("research_findings", []),
        frontier_state=state.get("frontier_state", {}),
    )
    state["hypothesis_board"] = hypotheses
    candidates = [_candidate_from_hypothesis(item) for item in hypotheses]
    static_evidence = _selected_static_for_hypotheses(hypotheses, _full_static_evidence_pool(state))
    state["candidates"] = candidates
    state["static_evidence"] = static_evidence
    state["validation_board"] = {
        "hypotheses": [item.to_dict() for item in hypotheses],
        "candidates": [item.to_dict() for item in candidates],
        "static_evidence": [item.to_dict() for item in static_evidence],
    }
    state.setdefault("planner_trace", {})["hypothesis_board"] = trace
    runtime = _state_runtime(state)
    update_agent_runtime_context(
        runtime,
        hypotheses=[item.to_dict() for item in hypotheses],
        candidate_seeds=[item.to_dict() for item in candidates],
        static_evidence=[item.to_dict() for item in static_evidence],
    )
    _persist_agent_workspace_artifact(
        state,
        "hypotheses",
        {"hypotheses": [item.to_dict() for item in hypotheses], "trace": trace},
    )
    return _finalize_stage(state, "hypothesis_board_update", f"hypotheses={len(hypotheses)}")


def _node_skeptic_challenge(state: GraphState) -> GraphState:
    _emit_progress(state, "skeptic_challenge", "start")
    rounds = max(1, int(state["config"].agent.skeptic_rounds))
    current_hypotheses = list(state.get("hypothesis_board", []))
    all_refutations: list[Refutation] = []
    round_traces: list[dict[str, Any]] = []
    for _ in range(rounds):
        refutations, trace = challenge_hypotheses_with_subagent(
            _state_runtime(state),
            state["config"],
            hypotheses=current_hypotheses,
        )
        all_refutations.extend(refutations)
        if isinstance(trace, dict):
            round_traces.append(trace)
        state["refutations"] = list(all_refutations)
        state["hypothesis_board"] = current_hypotheses
        current_hypotheses = _active_hypotheses_without_high_refutation(state)
        if not current_hypotheses:
            break

    state["refutations"] = all_refutations
    state["hypothesis_board"] = current_hypotheses
    state["candidates"] = [_candidate_from_hypothesis(item) for item in current_hypotheses]
    state["static_evidence"] = _selected_static_for_hypotheses(current_hypotheses, _full_static_evidence_pool(state))
    trace: dict[str, Any] = {"engine": "deepagents", "rounds": round_traces}
    if round_traces:
        trace.update(dict(round_traces[-1]))
        trace["rounds"] = round_traces
    state.setdefault("planner_trace", {})["skeptic"] = trace
    runtime = _state_runtime(state)
    update_agent_runtime_context(
        runtime,
        hypotheses=[item.to_dict() for item in current_hypotheses],
        refutations=[item.to_dict() for item in all_refutations],
        candidate_seeds=[item.to_dict() for item in state.get("candidates", [])],
        static_evidence=[item.to_dict() for item in state.get("static_evidence", [])],
    )
    _persist_agent_workspace_artifact(
        state,
        "refutations",
        {"refutations": [item.to_dict() for item in all_refutations], "trace": trace},
    )
    return _finalize_stage(state, "skeptic_challenge", f"remaining={len(state['hypothesis_board'])}")


def _node_experiment_plan(state: GraphState) -> GraphState:
    _emit_progress(state, "experiment_plan", "start")
    if not state.get("run_validation"):
        state["plans_by_candidate"] = {}
        state["experiment_board"] = []
        return _finalize_stage(state, "experiment_plan", "skipped (analyze-only)")
    plans_by_candidate, attempts, trace = plan_experiments_with_subagent(
        _state_runtime(state),
        state["config"],
        hypotheses=state.get("hypothesis_board", []),
    )
    state["plans_by_candidate"] = plans_by_candidate
    state["experiment_board"] = attempts
    state["validation_board"] = {
        "plans": {
            key: {
                "candidate_id": value.candidate_id,
                "validation_mode": value.validation_mode,
                "canonical_class": value.canonical_class,
                "class_contract_id": value.class_contract_id,
                "oracle_functions": value.oracle_functions,
                "requests": value.requests or value.positive_requests,
                "negative_controls": value.negative_controls or value.negative_requests,
                "response_witnesses": value.response_witnesses,
                "environment_requirements": value.environment_requirements,
            }
            for key, value in plans_by_candidate.items()
        },
        "attempts": [item.to_dict() for item in attempts],
    }
    planned_ids = set(plans_by_candidate.keys())
    if planned_ids:
        candidate_source = list(state.get("candidates", [])) or list(state.get("selected_candidates", [])) or _full_candidate_pool(state)
        static_source = list(state.get("static_evidence", [])) or list(state.get("selected_static", [])) or _full_static_evidence_pool(state)
        state["candidates"] = [
            item for item in candidate_source if item.candidate_id in planned_ids
        ]
        state["static_evidence"] = [
            item for item in static_source if item.candidate_id in planned_ids
        ]
    state.setdefault("planner_trace", {})["experiment"] = trace
    runtime = _state_runtime(state)
    update_agent_runtime_context(
        runtime,
        experiment_board=[item.to_dict() for item in attempts],
    )
    _persist_agent_workspace_artifact(
        state,
        "experiment-plans",
        {
                "plans": {
                    key: {
                        "candidate_id": value.candidate_id,
                        "oracle_functions": value.oracle_functions,
                        "request_expectations": value.request_expectations,
                        "response_witnesses": value.response_witnesses,
                        "intercepts": value.intercepts,
                        "validation_mode": value.validation_mode,
                        "canonical_class": value.canonical_class,
                        "class_contract_id": value.class_contract_id,
                        "environment_requirements": value.environment_requirements,
                        "requests": value.requests,
                        "negative_controls": value.negative_controls,
                        "positive_requests": value.positive_requests,
                        "negative_requests": value.negative_requests,
                        "canary": value.canary,
                        "strategy": value.strategy,
                    "negative_control_strategy": value.negative_control_strategy,
                    "plan_notes": value.plan_notes,
                }
                for key, value in plans_by_candidate.items()
            },
            "attempts": [item.to_dict() for item in attempts],
            "trace": trace,
        },
    )
    return _finalize_stage(state, "experiment_plan", f"planned={len(plans_by_candidate)}")


def _node_runtime_execute(state: GraphState) -> GraphState:
    _emit_progress(state, "runtime_execute", "start")
    if not state.get("run_validation"):
        state["bundles"] = []
        state["iteration_bundles"] = []
        return _finalize_stage(state, "runtime_execute", "skipped (analyze-only)")
    candidates = list(state.get("candidates", []))
    planned_ids = set((state.get("plans_by_candidate") or {}).keys())
    if planned_ids:
        candidates = [item for item in candidates if item.candidate_id in planned_ids]
        state["candidates"] = candidates
        state["static_evidence"] = [
            item for item in state.get("static_evidence", []) if item.candidate_id in planned_ids
        ]
    bundles, decisions = validate_candidates_runtime(
        config=state["config"],
        store=state["store"],
        static_evidence=state.get("static_evidence", []),
        candidates=candidates,
        run_id=str(state.get("run_id")),
        plans_by_candidate=state.get("plans_by_candidate", {}),
        planner_trace=state.get("planner_trace", {}),
        discovery_trace=state.get("discovery_trace", {}),
        artifact_refs=state.get("artifact_refs", []),
        auth_state=state.get("auth_state", {}),
    )
    if candidates and not bundles:
        _persist_runtime_liveness_artifact(
            state,
            {
                "run_id": state.get("run_id"),
                "reason": "zero-bundles-for-selected-candidates",
                "selected_candidate_ids": [item.candidate_id for item in candidates],
                "planned_candidate_ids": sorted((state.get("plans_by_candidate") or {}).keys()),
                "planner_trace": state.get("planner_trace", {}),
                "discovery_trace": state.get("discovery_trace", {}),
            },
        )
        raise RuntimeError("runtime validation invariant failed: selected candidates produced zero bundles")
    state["bundles"] = bundles
    state["iteration_bundles"] = list(bundles)
    state["all_bundles"] = list(state.get("all_bundles", [])) + list(bundles)
    state["decisions"] = decisions
    state["execution_board"] = {
        "bundles": [item.to_dict() for item in bundles],
        "decisions": dict(decisions),
    }
    return _finalize_stage(state, "runtime_execute", f"bundles={len(bundles)}")


def _node_evidence_reduce(state: GraphState) -> GraphState:
    _emit_progress(state, "evidence_reduce", "start")
    witness_bundles: list[WitnessBundle] = []
    runtime_history = list(state.get("runtime_history", []))
    for idx, bundle in enumerate(state.get("iteration_bundles", []), start=1):
        gate = getattr(bundle, "gate_result", None)
        decision = str(getattr(gate, "decision", "")).strip() or "UNKNOWN"
        witness_bundles.append(
            WitnessBundle(
                witness_id=f"wit-{idx:05d}",
                hypothesis_id=getattr(getattr(bundle, "candidate", None), "candidate_id", f"cand-{idx:05d}"),
                bundle_id=str(getattr(bundle, "bundle_id", "")),
                witness_type=str(getattr(getattr(bundle, "candidate", None), "vuln_class", "unknown")),
                status=decision,
                evidence_refs=list(getattr(getattr(bundle, "candidate", None), "evidence_refs", [])),
                negative_control_clean=not bool(getattr(gate, "failed_gate", None)),
                metadata={"reason": str(getattr(gate, "reason", ""))},
            )
        )
        runtime_history.append(
            {
                "bundle_id": str(getattr(bundle, "bundle_id", "")),
                "candidate_id": getattr(getattr(bundle, "candidate", None), "candidate_id", ""),
                "decision": decision,
            }
        )
    state["witness_bundles"] = witness_bundles
    state["runtime_history"] = runtime_history
    state["execution_board"] = dict(state.get("execution_board", {}))
    state["execution_board"]["witness_bundles"] = [item.to_dict() for item in witness_bundles]
    state["execution_board"]["runtime_history"] = list(runtime_history)
    runtime = _state_runtime(state)
    update_agent_runtime_context(
        runtime,
        runtime_history=runtime_history,
        witness_bundles=[item.to_dict() for item in witness_bundles],
    )
    _persist_agent_workspace_artifact(
        state,
        "witness-bundles",
        {"witness_bundles": [item.to_dict() for item in witness_bundles]},
    )
    return _finalize_stage(state, "evidence_reduce", f"witnesses={len(witness_bundles)}")


def _node_deterministic_gate(state: GraphState) -> GraphState:
    _emit_progress(state, "deterministic_gate", "start")
    gate_history = list(state.get("gate_history", []))
    for bundle in state.get("iteration_bundles", []):
        gate = getattr(bundle, "gate_result", None)
        gate_history.append(
            {
                "bundle_id": str(getattr(bundle, "bundle_id", "")),
                "candidate_id": getattr(getattr(bundle, "candidate", None), "candidate_id", ""),
                "decision": str(getattr(gate, "decision", "")),
                "reason": str(getattr(gate, "reason", "")),
                "failed_gate": str(getattr(gate, "failed_gate", "") or ""),
            }
        )
    state["gate_history"] = gate_history
    state["gate_board"] = {
        "gate_history": list(gate_history),
        "decisions": dict(state.get("decisions", {})),
    }
    update_agent_runtime_context(_state_runtime(state), gate_history=gate_history)
    return _finalize_stage(state, "deterministic_gate", f"gate_events={len(state.get('iteration_bundles', []))}")


def _node_continue_or_stop(state: GraphState) -> GraphState:
    _emit_progress(state, "continue_or_stop", "start")
    remaining = [item for item in state.get("objective_queue", []) if state.get("active_objective") is None or item.objective_id != state["active_objective"].objective_id]
    state["objective_queue"] = remaining
    should_continue, trace = decide_continue_with_root_agent(
        _state_runtime(state),
        state["config"],
        iteration=int(state.get("run_iteration", 0) or 0),
        objective_queue=remaining,
        hypotheses=state.get("hypothesis_board", []),
        refutations=state.get("refutations", []),
        witness_bundles=state.get("witness_bundles", []),
        max_iterations=state["config"].agent.max_iterations,
    )
    state["loop_continue"] = should_continue and bool(remaining)
    state["continue_reason"] = str(trace.get("reason", "")).strip()
    state.setdefault("planner_trace", {})["continue"] = trace
    return _finalize_stage(state, "continue_or_stop", f"continue={state['loop_continue']}")


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
            session=_state_runtime(state).root,
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
        session=_state_runtime(state).root,
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


def _normalize_candidate_intercepts(candidates: list[Candidate]) -> list[Candidate]:
    """Clone candidates and normalize their expected_intercepts."""
    out: list[Candidate] = []
    for candidate in candidates:
        clone = _safe_copy_candidate(candidate)
        if clone.expected_intercepts:
            clone.expected_intercepts = sorted(set(clone.expected_intercepts))
        elif clone.sink:
            clone.expected_intercepts = [clone.sink.replace("(", "").replace("->", "::")]
        out.append(clone)
    return out


def _aggregate_failed_paths(round_traces: list[dict[str, Any]]) -> list[str]:
    """Collect all failed_paths from skeptic round traces."""
    aggregated: list[str] = []
    for trace in round_traces:
        raw_failed = trace.get("failed_paths")
        if not isinstance(raw_failed, list):
            continue
        for item in raw_failed:
            if isinstance(item, str) and item.strip():
                aggregated.append(item.strip())
    return aggregated


def _build_skeptic_trace(round_traces: list[dict[str, Any]], aggregated_failed: list[str]) -> dict[str, Any]:
    """Assemble the final skeptic trace from round traces."""
    if round_traces:
        final_trace = dict(round_traces[-1])
        final_trace["rounds"] = [dict(item) for item in round_traces]
    else:
        final_trace = {"engine": "deepagents", "rounds": []}
    if aggregated_failed:
        final_trace["failed_paths"] = sorted(set(aggregated_failed))
    return final_trace


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
            session=_state_runtime(state).root,
            failure_analysis=state.get("failure_analysis"),
        )
        if isinstance(skeptic_trace, dict):
            skeptic_round_traces.append(skeptic_trace)
        current = refined
        if not current:
            break

    out = _normalize_candidate_intercepts(current)
    final_trace = _build_skeptic_trace(skeptic_round_traces, _aggregate_failed_paths(skeptic_round_traces))

    state["candidates"] = out
    state.setdefault("planner_trace", {})["skeptic"] = final_trace
    return _finalize_stage(state, "skeptic_refine", f"remaining={len(out)}")


def _apply_resume_filter(
    candidates: list[Candidate],
    frontier_state: dict[str, Any],
) -> tuple[list[Candidate], list[str]]:
    """Filter out candidates that completed cleanly in a prior run. Returns (remaining, filtered_ids)."""
    resume_map = frontier_state.get("candidate_resume", {}) if isinstance(frontier_state, dict) else {}
    if not isinstance(resume_map, dict):
        return list(candidates), []
    filtered: list[Candidate] = []
    filtered_ids: list[str] = []
    for candidate in candidates:
        entry = resume_map.get(_candidate_signature(candidate))
        if isinstance(entry, dict) and bool(entry.get("completed_clean")):
            filtered_ids.append(candidate.candidate_id)
            continue
        filtered.append(candidate)
    scheduler_input = filtered if filtered else []
    return scheduler_input, filtered_ids


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
        scheduler_input, filtered_ids = _apply_resume_filter(candidates, frontier_state)
        state["resume_filtered_candidates"] = sorted(set(filtered_ids))

    selected, scores, scheduler_trace = schedule_actions_with_deepagents(
        scheduler_input,
        state["config"],
        max_candidates=state["config"].budgets.max_candidates,
        frontier_state=frontier_state,
        repo_root=state.get("repo_root"),
        session=_state_runtime(state).root,
    )
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
        return _finalize_stage(state, "frontier_update", _SKIPPED_VALIDATE_ONLY)

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

    for item in state.get("hypothesis_board", [])[:100]:
        frontier.setdefault("hypotheses", []).append(
            {
                "hypothesis_id": item.hypothesis_id,
                "candidate_id": item.candidate.candidate_id,
                "vuln_class": item.vuln_class,
                "rationale": item.rationale,
                "score": item.confidence,
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

    for item in state.get("refutations", [])[:100]:
        if item.evidence_refs:
            for ref in item.evidence_refs[:10]:
                frontier.setdefault("failed_paths", []).append(
                    {"path": ref, "reason": item.summary, "iteration": iteration}
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
            "selected": [c.candidate_id for c in state.get("candidates", [])],
            "objective_id": getattr(state.get("active_objective"), "objective_id", None),
            "delta": delta,
            "runtime_delta": runtime_delta,
            "web_error": state.get("web_error"),
            "continue_reason": state.get("continue_reason", ""),
        }
    )

    has_discovery_delta = any(delta.get(key) for key in delta)
    has_runtime_delta = bool(runtime_delta["new_flags"] or runtime_delta["new_classes"])
    has_delta = has_discovery_delta or has_runtime_delta
    stagnation = int(frontier.get("stagnation_rounds", 0))
    frontier["stagnation_rounds"] = 0 if has_delta else stagnation + 1
    frontier["iteration"] = iteration
    frontier["updated_at"] = _now_iso()
    frontier["target_scope"] = _current_target_scope(state)
    frontier["hypotheses"] = list(frontier.get("hypotheses", []))[-1000:]
    frontier["failed_paths"] = list(frontier.get("failed_paths", []))[-1000:]
    frontier["attempt_history"] = list(frontier.get("attempt_history", []))[-5000:]

    state["frontier_state"] = frontier
    state["discovery_trace"]["frontier_delta"] = delta
    state["discovery_trace"]["runtime_delta"] = runtime_delta
    state["discovery_trace"]["frontier_iteration"] = frontier["iteration"]
    state["iteration_bundles"] = []

    state["loop_continue"] = False

    state["store"].save_frontier_state(_sanitize_frontier_for_persistence(frontier))
    update_agent_runtime_context(_state_runtime(state), frontier_state=frontier)
    return _finalize_stage(
        state,
        "frontier_update",
        f"iteration={frontier['iteration']}",
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
        session=_state_runtime(state).root,
    )
    planner_trace["validation_plan"] = validation_trace
    state["plans_by_candidate"] = plans_by_candidate
    state["planner_trace"] = planner_trace
    return _finalize_stage(state, "validation_plan", f"planned={len(plans_by_candidate)}")


def _skip_reason_for_candidate(
    candidate_id: str,
    resume_filtered: set[str],
    selected_ids: set[str],
    scheduler_trace: dict[str, Any],
) -> str:
    if candidate_id in resume_filtered and candidate_id not in selected_ids:
        reason = "resume-clean-completed"
    elif candidate_id in selected_ids:
        reason = "selected-not-executed"
    else:
        reason = "scheduler-not-selected"
    triage_reason = _triage_reason_for_candidate(
        scheduler_trace if isinstance(scheduler_trace, dict) else {},
        candidate_id,
    )
    if triage_reason:
        reason = f"{reason}; {triage_reason}"
    return reason


def _build_mapping_record(
    candidate: Candidate,
    bundle: Any | None,
    iteration: int,
    plans_by_candidate: dict[str, Any],
    resume_filtered: set[str],
    selected_ids: set[str],
    scheduler_trace: dict[str, Any],
) -> dict[str, Any]:
    candidate_id = candidate.candidate_id
    attempts = _extract_bundle_attempts(bundle) if bundle is not None else []
    decision = ""
    bundle_id = ""
    reason_if_skipped = ""
    if bundle is not None:
        gate_result = getattr(bundle, "gate_result", None)
        decision = str(getattr(gate_result, "decision", "")).strip()
        bundle_id = str(getattr(bundle, "bundle_id", "")).strip()
    else:
        reason_if_skipped = _skip_reason_for_candidate(candidate_id, resume_filtered, selected_ids, scheduler_trace)

    return {
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
    decisions = _default_decisions()
    for bundle in state["bundles"]:
        decisions[bundle.gate_result.decision] = decisions.get(bundle.gate_result.decision, 0) + 1
    state["decisions"] = decisions
    return _finalize_stage(state, "dedup_topk", f"bundles={len(state['bundles'])}")


def _node_persist(state: GraphState) -> GraphState:
    _emit_progress(state, "persist", "start")
    store = state["store"]
    store.save_candidates(state.get("candidates", []))
    store.save_static_evidence(state.get("static_evidence", []))
    store.save_json_artifact(
        "agent_workspace/latest.json",
        {
            "run_id": state.get("run_id"),
            "objective_queue": [item.to_dict() for item in state.get("objective_queue", [])],
            "research_tasks": [item.to_dict() for item in state.get("research_tasks", [])],
            "research_findings": [item.to_dict() for item in state.get("research_findings", [])],
            "hypotheses": [item.to_dict() for item in state.get("hypothesis_board", [])],
            "refutations": [item.to_dict() for item in state.get("refutations", [])],
            "experiment_board": [item.to_dict() for item in state.get("experiment_board", [])],
            "witness_bundles": [item.to_dict() for item in state.get("witness_bundles", [])],
            "gate_history": list(state.get("gate_history", [])),
            "artifact_index": dict(state.get("artifact_index", {})),
        },
    )
    if state.get("frontier_state"):
        store.save_frontier_state(state["frontier_state"])
    return _finalize_stage(state, "persist", "evidence persisted")


def _after_frontier_route(current: GraphState) -> str:
    if current.get("skip_discovery") or not current.get("loop_continue"):
        return "done"
    return "again"


def _build_pipeline_graph(include_validation: bool) -> Any:
    """Build and return the compiled LangGraph StateGraph pipeline."""
    from langgraph.graph import END, START, StateGraph  # type: ignore[import-not-found]

    builder = StateGraph(GraphState)
    builder.add_node("init", _node_init)
    builder.add_node("static_discovery", _node_static_discovery)
    builder.add_node("web_discovery", _node_web_discovery)
    builder.add_node("auth_setup", _node_auth_setup)
    builder.add_node("authenticated_web_discovery", _node_authenticated_web_discovery)
    builder.add_node("discovery_summary", _node_discovery_summary)
    builder.add_node("orient", _node_orient)
    builder.add_node("select_objective", _node_select_objective)
    builder.add_node("source_research", _node_source_research_parallel)
    builder.add_node("graph_research", _node_graph_research_parallel)
    builder.add_node("web_research", _node_web_research_parallel)
    builder.add_node("reduce_research", _node_reduce_research)
    builder.add_node("hypothesis_board_update", _node_hypothesis_board_update)
    builder.add_node("skeptic_challenge", _node_skeptic_challenge)
    builder.add_node("frontier_update", _node_frontier_update)
    builder.add_node("experiment_plan", _node_experiment_plan)
    builder.add_node("runtime_execute", _node_runtime_execute)
    builder.add_node("evidence_reduce", _node_evidence_reduce)
    builder.add_node("deterministic_gate", _node_deterministic_gate)
    builder.add_node("continue_or_stop", _node_continue_or_stop)
    builder.add_node("dedup_topk", _node_dedup_topk)
    builder.add_node("persist", _node_persist)

    builder.add_edge(START, "init")
    builder.add_edge("init", "static_discovery")
    builder.add_edge("static_discovery", "web_discovery")
    builder.add_edge("web_discovery", "auth_setup")
    builder.add_edge("auth_setup", "authenticated_web_discovery")
    builder.add_edge("authenticated_web_discovery", "discovery_summary")
    builder.add_edge("discovery_summary", "orient")
    builder.add_edge("orient", "select_objective")
    builder.add_edge("select_objective", "source_research")
    builder.add_edge("select_objective", "graph_research")
    builder.add_edge("select_objective", "web_research")
    builder.add_edge("source_research", "reduce_research")
    builder.add_edge("graph_research", "reduce_research")
    builder.add_edge("web_research", "reduce_research")
    builder.add_edge("reduce_research", "hypothesis_board_update")
    builder.add_edge("hypothesis_board_update", "skeptic_challenge")
    if include_validation:
        builder.add_edge("skeptic_challenge", "experiment_plan")
        builder.add_edge("experiment_plan", "runtime_execute")
        builder.add_edge("runtime_execute", "evidence_reduce")
        builder.add_edge("evidence_reduce", "deterministic_gate")
        builder.add_edge("deterministic_gate", "frontier_update")
    else:
        builder.add_edge("skeptic_challenge", "frontier_update")
    builder.add_edge("frontier_update", "continue_or_stop")

    builder.add_conditional_edges(
        "continue_or_stop",
        _after_frontier_route,
        {
            "again": "orient",
            "done": "dedup_topk" if include_validation else "persist",
        },
    )

    if include_validation:
        builder.add_edge("dedup_topk", "persist")
    builder.add_edge("persist", END)
    return builder


def _handle_graph_invoke_error(
    exc: BaseException,
    state: GraphState,
    graph: Any,
    graph_config: dict[str, Any],
    thread_id: str,
) -> None:
    """Save resume metadata for a failed or yielded graph invocation."""
    checkpoint_id, next_nodes = _latest_checkpoint_info(graph, graph_config)
    state["graph_checkpoint_id"] = checkpoint_id
    error_text = str(exc).strip() or exc.__class__.__name__
    status = "failed"
    if isinstance(exc, AgentSoftYield):
        status = "yielded"
        state["soft_yield"] = {
            "role": exc.role,
            "category": exc.category,
            "turn": exc.turn,
            "handoff_ref": exc.handoff_ref,
            "progress_ref": exc.progress_ref,
            "response_ref": exc.response_ref,
            "last_response": dict(exc.last_response),
        }
    state["store"].save_resume_metadata(
        str(state.get("run_id") or ""),
        _graph_resume_payload(
            state,
            thread_id=thread_id,
            checkpoint_id=checkpoint_id,
            status=status,
            next_nodes=next_nodes,
            error=error_text,
        ),
    )


def _run_langgraph(state: GraphState, include_validation: bool) -> GraphState:
    try:
        builder = _build_pipeline_graph(include_validation)
    except Exception as exc:
        raise RuntimeError(f"langgraph import failed: {exc}") from exc

    thread_id = _graph_thread_id(state)
    checkpointer = FileBackedMemorySaver(_graph_checkpointer_path(state["store"], thread_id))
    graph = builder.compile(checkpointer=checkpointer)
    graph_config = {"configurable": {"thread_id": thread_id}}

    resume_mode = bool(state.get("resume_mode"))
    stored_tuple = checkpointer.get_tuple(graph_config)
    invoke_input: GraphState | None = state
    if resume_mode and stored_tuple is not None:
        invoke_input = None

    state["graph_thread_id"] = thread_id
    state["store"].save_resume_metadata(
        str(state.get("run_id") or ""),
        _graph_resume_payload(state, thread_id=thread_id, status="open"),
    )
    _emit_progress(state, "graph", "start", f"include_validation={include_validation}")
    try:
        result = graph.invoke(invoke_input, config=graph_config)
    except BaseException as exc:
        _handle_graph_invoke_error(exc, state, graph, graph_config, thread_id)
        raise

    checkpoint_id, next_nodes = _latest_checkpoint_info(graph, graph_config)
    if isinstance(result, dict):
        result["graph_thread_id"] = thread_id
        result["graph_checkpoint_id"] = checkpoint_id
    state["graph_checkpoint_id"] = checkpoint_id
    state["store"].save_resume_metadata(
        str(state.get("run_id") or ""),
        _graph_resume_payload(
            result if isinstance(result, dict) else state,
            thread_id=thread_id,
            checkpoint_id=checkpoint_id,
            status="completed",
            next_nodes=next_nodes,
        ),
    )
    _emit_progress(result if isinstance(result, dict) else state, "graph", "done", "langgraph complete")
    return result


def _resolve_resume_metadata(
    store: EvidenceStore,
    resume_run_id: str | None,
    *,
    mode: str,
    run_validation: bool,
    resolved_repo_root: str,
    config: PadvConfig,
    check_compatibility: bool = True,
) -> dict[str, Any] | None:
    """Resolve resume metadata from a run ID or 'latest' sentinel.

    Returns the metadata dict or None if no resume was requested.
    Raises RuntimeError if the requested run is not found or incompatible.
    """
    if not resume_run_id:
        return None
    if resume_run_id == "latest":
        meta = store.latest_resumable_run(
            mode=mode,
            run_validation=run_validation,
            target_signature=_target_signature_for(resolved_repo_root, str(config.target.base_url or "")),
            config_signature=_config_signature(config, mode, run_validation),
        )
    else:
        meta = store.load_resume_metadata(resume_run_id)
    if meta is None:
        raise RuntimeError(f"resume run not found: {resume_run_id}")
    if check_compatibility and not _resume_compatible(
        meta, config=config, repo_root=resolved_repo_root, mode=mode, run_validation=run_validation
    ):
        raise RuntimeError(f"resume metadata incompatible with current {mode} target/config: {meta.get('run_id')}")
    return meta


def _state_from_resume_meta(
    resume_meta: dict[str, Any] | None,
    *,
    config: PadvConfig,
    resolved_repo_root: str,
    store: EvidenceStore,
    mode: str,
    run_validation: bool,
    run_id_prefix: str,
) -> GraphState:
    """Build the initial GraphState from optional resume metadata."""
    meta = resume_meta or {}
    run_id = str(meta.get("run_id") or new_run_id(run_id_prefix))
    return {
        "config": config,
        "repo_root": resolved_repo_root,
        "store": store,
        "mode": mode,
        "run_validation": run_validation,
        "run_id": run_id,
        "resume_mode": bool(resume_meta),
        "resume_requested_run_id": str(meta.get("run_id") or ""),
        "started_at": str(meta.get("started_at") or _now_iso()),
        "graph_thread_id": str(meta.get("thread_id") or ""),
        "graph_checkpoint_id": str(meta.get("checkpoint_id") or ""),
    }


def analyze_with_graph(
    config: PadvConfig,
    repo_root: str,
    store: EvidenceStore,
    mode: str,
    progress_callback: Callable[[dict[str, Any]], None] | None = None,
    resume_run_id: str | None = None,
) -> tuple[list[Candidate], list[StaticEvidence], dict[str, Any]]:
    resolved_repo_root = str(Path(repo_root).resolve())
    resume_meta = _resolve_resume_metadata(
        store, resume_run_id,
        mode=mode, run_validation=False,
        resolved_repo_root=resolved_repo_root, config=config,
    )
    state = _state_from_resume_meta(
        resume_meta,
        config=config, resolved_repo_root=resolved_repo_root, store=store,
        mode=mode, run_validation=False, run_id_prefix="analyze",
    )
    run_id = str(state["run_id"])
    _set_progress_callback(run_id, progress_callback)
    try:
        result = _run_langgraph(state, include_validation=False)
        return result.get("candidates", []), result.get("static_evidence", []), result.get("discovery_trace", {})
    finally:
        _clear_state_runtime(run_id)
        _set_progress_callback(run_id, None)


def run_with_graph(
    config: PadvConfig,
    repo_root: str,
    store: EvidenceStore,
    mode: str,
    progress_callback: Callable[[dict[str, Any]], None] | None = None,
    resume_run_id: str | None = None,
) -> RunSummary:
    resolved_repo_root = str(Path(repo_root).resolve())
    resume_meta = _resolve_resume_metadata(
        store, resume_run_id,
        mode=mode, run_validation=True,
        resolved_repo_root=resolved_repo_root, config=config,
    )
    state = _state_from_resume_meta(
        resume_meta,
        config=config, resolved_repo_root=resolved_repo_root, store=store,
        mode=mode, run_validation=True, run_id_prefix="run",
    )
    run_id = str(state["run_id"])
    started = str(state.get("started_at") or _now_iso())
    _set_progress_callback(run_id, progress_callback)

    if config.sandbox.deploy_cmd:
        sandbox_adapter.deploy(config.sandbox)

    try:
        result = _run_langgraph(state, include_validation=True)
        completed = datetime.now(tz=timezone.utc).isoformat()

        bundles = result.get("bundles", [])
        decisions = result.get("decisions", _default_decisions())
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
    finally:
        _clear_state_runtime(run_id)
        _set_progress_callback(run_id, None)


def validate_with_graph(
    config: PadvConfig,
    store: EvidenceStore,
    static_evidence: list[StaticEvidence],
    candidates: list[Candidate],
    run_id: str,
    repo_root: str | None = None,
    progress_callback: Callable[[dict[str, Any]], None] | None = None,
    resume_run_id: str | None = None,
) -> tuple[list[Any], dict[str, int]]:
    resolved_repo_root = str(Path(repo_root or ".").resolve())
    resume_meta = _resolve_resume_metadata(
        store, resume_run_id,
        mode="variant", run_validation=True,
        resolved_repo_root=resolved_repo_root, config=config,
        check_compatibility=False,
    )
    if resume_meta is not None:
        run_id = str(resume_meta.get("run_id") or run_id)
    _set_progress_callback(run_id, progress_callback)
    state: GraphState = {
        "config": config,
        "repo_root": resolved_repo_root,
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
        "resume_mode": bool(resume_meta),
        "resume_requested_run_id": str((resume_meta or {}).get("run_id") or ""),
        "graph_thread_id": str((resume_meta or {}).get("thread_id") or ""),
        "graph_checkpoint_id": str((resume_meta or {}).get("checkpoint_id") or ""),
        "started_at": str((resume_meta or {}).get("started_at") or _now_iso()),
    }
    try:
        result = _run_langgraph(state, include_validation=True)
        return result.get("bundles", []), result.get("decisions", {})
    finally:
        _clear_state_runtime(run_id)
        _set_progress_callback(run_id, None)

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import padv.orchestrator.graphs as graph_mod
from padv.config.schema import load_config
from padv.models import Candidate, EvidenceBundle, GateResult, RunSummary, RuntimeEvidence, StaticEvidence, ValidationPlan
from padv.orchestrator.graphs import analyze_with_graph, run_with_graph
from padv.store.evidence_store import EvidenceStore


def _mk_candidate(candidate_id: str, provenance: list[str]) -> Candidate:
    return Candidate(
        candidate_id=candidate_id,
        vuln_class="sql_injection_boundary",
        title="A03 SQL boundary influence",
        file_path="src/a.php",
        line=12,
        sink="mysqli_query",
        expected_intercepts=["mysqli_query"],
        notes="test",
        provenance=provenance,
        confidence=0.5,
    )


def _mk_evidence(candidate_id: str, query_id: str) -> StaticEvidence:
    return StaticEvidence(
        candidate_id=candidate_id,
        query_profile="default",
        query_id=query_id,
        file_path="src/a.php",
        line=12,
        snippet="mysqli_query($db, $q)",
        hash=f"h-{query_id}",
    )


def _force_node_runner(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(graph_mod, "_run_langgraph", lambda state, include_validation: graph_mod._run_nodes(state, include_validation))


def _mk_joern_meta(
    *,
    findings: int = 0,
    app_findings: int = 0,
    candidate_count: int = 0,
    manifest_candidates: int = 0,
) -> SimpleNamespace:
    return SimpleNamespace(
        joern_findings=findings,
        joern_app_findings=app_findings,
        joern_candidate_count=candidate_count,
        manifest_candidates=manifest_candidates,
    )


def _mk_scip_meta(
    *,
    raw_hits: int = 0,
    mapped_hits: int = 0,
    app_scoped_sinks: int = 0,
    dropped_non_app_sinks: int = 0,
    candidate_count: int = 0,
) -> SimpleNamespace:
    return SimpleNamespace(
        raw_scip_hits=raw_hits,
        mapped_scip_sinks=mapped_hits,
        app_scoped_sinks=app_scoped_sinks,
        dropped_non_app_sinks=dropped_non_app_sinks,
        candidate_count=candidate_count,
    )


def test_analyze_with_graph_combines_semantic_sources(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    store = EvidenceStore(tmp_path / ".padv")
    _force_node_runner(monkeypatch)
    monkeypatch.setattr("padv.orchestrator.graphs.ensure_agent_session", lambda *args, **kwargs: object())

    monkeypatch.setattr(
        "padv.orchestrator.graphs.discover_candidates_with_meta",
        lambda repo_root, config: (
            [_mk_candidate("joern-1", ["joern"])],
            [_mk_evidence("joern-1", "joern::sql")],
            _mk_joern_meta(findings=1, app_findings=1, candidate_count=1),
        ),
    )
    monkeypatch.setattr(
        "padv.orchestrator.graphs.discover_scip_candidates_safe_with_meta",
        lambda repo_root, config: (
            [_mk_candidate("scip-1", ["scip"])],
            [_mk_evidence("scip-1", "scip::sql")],
            [],
            _mk_scip_meta(raw_hits=1, mapped_hits=1, app_scoped_sinks=1, candidate_count=1),
            None,
        ),
    )
    monkeypatch.setattr("padv.orchestrator.graphs.discover_web_hints", lambda config, seed_urls=None: ({"/index.php": ["padv_canary"]}, None))
    monkeypatch.setattr(
        "padv.orchestrator.graphs.rank_candidates_with_deepagents",
        lambda candidates, *_args, **_kwargs: (candidates, {"engine": "deepagents", "ordered_ids": [c.candidate_id for c in candidates]}),
    )
    monkeypatch.setattr(
        "padv.orchestrator.graphs.skeptic_refine_with_deepagents",
        lambda candidates, *_args, **_kwargs: (candidates, {"engine": "deepagents", "failed_paths": []}),
    )
    monkeypatch.setattr(
        "padv.orchestrator.graphs.schedule_actions_with_deepagents",
        lambda candidates, *_args, **_kwargs: (
            candidates[:1],
            {candidates[0].candidate_id: 1.0} if candidates else {},
            {"engine": "deepagents", "selected": [candidates[0].candidate_id] if candidates else []},
        ),
    )

    candidates, evidence, trace = analyze_with_graph(config, str(tmp_path), store, "variant")
    assert len(candidates) == 1
    assert set(candidates[0].provenance) == {"joern", "scip"}
    assert len(evidence) == 2
    assert trace["raw_scip_hits"] == 1
    assert trace["mapped_scip_sinks"] == 1
    assert trace["joern_findings"] == 1
    assert trace["fused_candidates"] == 1
    assert trace["fusion_dual_signal"] == 1
    assert trace["fusion_dropped_nonsemantic"] == 0
    assert trace["web_paths"] == 1

    semantic_files = sorted((store.root / "artifacts").glob("semantic-discovery-*.json"))
    assert semantic_files
    fusion_files = sorted((store.root / "artifacts").glob("semantic-fusion-*.json"))
    assert fusion_files
    fusion_payload = json.loads(fusion_files[-1].read_text(encoding="utf-8"))
    assert fusion_payload["dual_signal_candidates"] == 1
    assert "cand-00001" in fusion_payload["evidence_graph"]


def test_run_with_graph_uses_validation_node(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    store = EvidenceStore(tmp_path / ".padv")
    _force_node_runner(monkeypatch)
    monkeypatch.setattr("padv.orchestrator.graphs.ensure_agent_session", lambda *args, **kwargs: object())

    candidate = _mk_candidate("cand-00001", ["joern"])
    static = _mk_evidence("cand-00001", "joern::sql")

    monkeypatch.setattr(
        "padv.orchestrator.graphs.discover_candidates_with_meta",
        lambda repo_root, config: ([candidate], [static], _mk_joern_meta(findings=1, app_findings=1, candidate_count=1)),
    )
    monkeypatch.setattr(
        "padv.orchestrator.graphs.discover_scip_candidates_safe_with_meta",
        lambda *args, **kwargs: ([], [], [], _mk_scip_meta(), None),
    )
    monkeypatch.setattr("padv.orchestrator.graphs.discover_web_hints", lambda config, seed_urls=None: ({}, None))
    monkeypatch.setattr(
        "padv.orchestrator.graphs.rank_candidates_with_deepagents",
        lambda candidates, *_args, **_kwargs: (candidates, {"engine": "deepagents", "ordered_ids": [c.candidate_id for c in candidates]}),
    )
    monkeypatch.setattr(
        "padv.orchestrator.graphs.skeptic_refine_with_deepagents",
        lambda candidates, *_args, **_kwargs: (candidates, {"engine": "deepagents", "failed_paths": []}),
    )
    monkeypatch.setattr(
        "padv.orchestrator.graphs.schedule_actions_with_deepagents",
        lambda candidates, *_args, **_kwargs: (
            candidates[:1],
            {candidates[0].candidate_id: 1.0} if candidates else {},
            {"engine": "deepagents", "selected": [candidates[0].candidate_id] if candidates else []},
        ),
    )
    monkeypatch.setattr(
        "padv.orchestrator.graphs.make_validation_plans_with_deepagents",
        lambda candidates, config, repo_root=None, session=None: (
            {
                c.candidate_id: ValidationPlan(
                    candidate_id=c.candidate_id,
                    intercepts=["mysqli_query"],
                    positive_requests=[{"method": "GET", "path": "/", "query": {config.canary.parameter_name: "a"}}] * 3,
                    negative_requests=[{"method": "GET", "path": "/", "query": {config.canary.parameter_name: "b"}}],
                    canary="a",
                )
                for c in candidates
            },
            {"engine": "deepagents"},
        ),
    )

    def fake_validate(*args, **kwargs):
        bundle = EvidenceBundle(
            bundle_id="bundle-1",
            created_at="2026-03-06T00:00:00+00:00",
            candidate=candidate,
            static_evidence=[static],
            positive_runtime=[RuntimeEvidence("r1", "ok", 1, False, False, False, None, [], {})],
            negative_runtime=[RuntimeEvidence("r2", "ok", 0, False, False, False, None, [], {})],
            repro_run_ids=["r1"],
            gate_result=GateResult("DROPPED", ["V0"], "V3", "missing"),
            limitations=["missing"],
        )
        return [bundle], {"VALIDATED": 0, "DROPPED": 1, "NEEDS_HUMAN_SETUP": 0}

    monkeypatch.setattr("padv.orchestrator.graphs.validate_candidates_runtime", fake_validate)

    summary = run_with_graph(config, str(tmp_path), store, "variant")
    assert isinstance(summary, RunSummary)
    assert summary.decisions["DROPPED"] == 1
    assert summary.bundle_ids == ["bundle-1"]
    assert summary.discovery_trace["source_count"] == 0
    assert "proposer" in summary.planner_trace
    assert isinstance(summary.frontier_state, dict)


def test_analyze_with_graph_applies_configured_skeptic_rounds(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    config.agent.max_iterations = 1
    config.agent.improvement_patience = 0
    config.agent.skeptic_rounds = 3
    store = EvidenceStore(tmp_path / ".padv")
    _force_node_runner(monkeypatch)
    monkeypatch.setattr("padv.orchestrator.graphs.ensure_agent_session", lambda *args, **kwargs: object())

    monkeypatch.setattr(
        "padv.orchestrator.graphs.discover_candidates_with_meta",
        lambda repo_root, config: (
            [_mk_candidate("joern-1", ["joern"])],
            [_mk_evidence("joern-1", "joern::sql")],
            _mk_joern_meta(findings=1, app_findings=1, candidate_count=1),
        ),
    )
    monkeypatch.setattr(
        "padv.orchestrator.graphs.discover_scip_candidates_safe_with_meta",
        lambda repo_root, config: ([], [], [], _mk_scip_meta(), None),
    )
    monkeypatch.setattr("padv.orchestrator.graphs.discover_web_hints", lambda config, seed_urls=None: ({}, None))
    monkeypatch.setattr(
        "padv.orchestrator.graphs.rank_candidates_with_deepagents",
        lambda candidates, *_args, **_kwargs: (candidates, {"engine": "deepagents", "ordered_ids": [c.candidate_id for c in candidates]}),
    )
    monkeypatch.setattr(
        "padv.orchestrator.graphs.schedule_actions_with_deepagents",
        lambda candidates, *_args, **_kwargs: (
            candidates,
            {c.candidate_id: 1.0 for c in candidates},
            {"engine": "deepagents", "selected": [c.candidate_id for c in candidates]},
        ),
    )

    calls = {"count": 0}

    def _fake_skeptic(candidates, _config, frontier_state=None, repo_root=None, session=None, failure_analysis=None):
        calls["count"] += 1
        return candidates, {"engine": "deepagents", "failed_paths": [f"/p/{calls['count']}"]}

    monkeypatch.setattr("padv.orchestrator.graphs.skeptic_refine_with_deepagents", _fake_skeptic)

    candidates, _, _ = analyze_with_graph(config, str(tmp_path), store, "variant")
    assert len(candidates) == 1
    assert calls["count"] == 3


def test_web_seed_urls_are_normalized_and_artifact_is_persisted(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    config.agent.max_iterations = 1
    config.agent.improvement_patience = 0
    store = EvidenceStore(tmp_path / ".padv")
    _force_node_runner(monkeypatch)
    monkeypatch.setattr("padv.orchestrator.graphs.ensure_agent_session", lambda *args, **kwargs: object())

    frontier_state = {
        "version": 1,
        "updated_at": "2026-03-06T00:00:00+00:00",
        "iteration": 0,
        "stagnation_rounds": 0,
        "hypotheses": [],
        "failed_paths": [
            {"path": "/admin"},
            "javascript:alert(1)",
            "http://example.test/ok",
            "/admin",
        ],
        "coverage": {"files": [], "classes": [], "signals": [], "sinks": [], "web_paths": []},
        "history": [],
    }
    store.save_frontier_state(frontier_state)

    monkeypatch.setattr(
        "padv.orchestrator.graphs.discover_candidates_with_meta",
        lambda *_args, **_kwargs: (
            [_mk_candidate("joern-1", ["joern"])],
            [_mk_evidence("joern-1", "joern::sql")],
            _mk_joern_meta(findings=1, app_findings=1, candidate_count=1),
        ),
    )
    monkeypatch.setattr(
        "padv.orchestrator.graphs.discover_scip_candidates_safe_with_meta",
        lambda *_args, **_kwargs: ([], [], [], _mk_scip_meta(), None),
    )

    seen: dict[str, list[str]] = {"seed_urls": []}

    def _fake_web(config, seed_urls=None):
        seen["seed_urls"] = list(seed_urls or [])
        return {}, None

    monkeypatch.setattr("padv.orchestrator.graphs.discover_web_hints", _fake_web)
    monkeypatch.setattr(
        "padv.orchestrator.graphs.rank_candidates_with_deepagents",
        lambda candidates, *_args, **_kwargs: (candidates, {"engine": "deepagents", "ordered_ids": [c.candidate_id for c in candidates]}),
    )
    monkeypatch.setattr(
        "padv.orchestrator.graphs.skeptic_refine_with_deepagents",
        lambda candidates, *_args, **_kwargs: (candidates, {"engine": "deepagents", "failed_paths": []}),
    )
    monkeypatch.setattr(
        "padv.orchestrator.graphs.schedule_actions_with_deepagents",
        lambda candidates, *_args, **_kwargs: (
            candidates,
            {c.candidate_id: 1.0 for c in candidates},
            {"engine": "deepagents", "selected": [c.candidate_id for c in candidates]},
        ),
    )

    candidates, _, _ = analyze_with_graph(config, str(tmp_path), store, "variant")
    assert len(candidates) == 1
    assert f"{config.target.base_url.rsplit('/', 1)[0]}/admin" in seen["seed_urls"]
    assert "http://example.test/ok" in seen["seed_urls"]
    assert all(not u.startswith("javascript:") for u in seen["seed_urls"])

    artifacts_dir = store.root / "artifacts"
    files = sorted(artifacts_dir.glob("web-discovery-*.json"))
    assert files
    payload = json.loads(files[-1].read_text(encoding="utf-8"))
    assert "seed_urls" in payload
    assert payload["hints"] == {}


def test_static_discovery_raises_when_no_semantic_candidates(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    store = EvidenceStore(tmp_path / ".padv")
    _force_node_runner(monkeypatch)
    monkeypatch.setattr("padv.orchestrator.graphs.ensure_agent_session", lambda *args, **kwargs: object())
    monkeypatch.setattr(
        "padv.orchestrator.graphs.discover_candidates_with_meta",
        lambda *_args, **_kwargs: ([], [], _mk_joern_meta()),
    )
    monkeypatch.setattr(
        "padv.orchestrator.graphs.discover_scip_candidates_safe_with_meta",
        lambda *_args, **_kwargs: ([], [], [], _mk_scip_meta(), None),
    )

    with pytest.raises(RuntimeError, match="semantic discovery produced zero candidates"):
        analyze_with_graph(config, str(tmp_path), store, "variant")


def test_static_discovery_rejects_nonsemantic_manifest_only_candidates(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    store = EvidenceStore(tmp_path / ".padv")
    _force_node_runner(monkeypatch)
    monkeypatch.setattr("padv.orchestrator.graphs.ensure_agent_session", lambda *args, **kwargs: object())

    manifest_candidate = _mk_candidate("manifest-1", ["manifest"])
    monkeypatch.setattr(
        "padv.orchestrator.graphs.discover_candidates_with_meta",
        lambda *_args, **_kwargs: (
            [manifest_candidate],
            [_mk_evidence("manifest-1", "manifest::vulnerable_components")],
            _mk_joern_meta(findings=0, app_findings=0, candidate_count=0, manifest_candidates=1),
        ),
    )
    monkeypatch.setattr(
        "padv.orchestrator.graphs.discover_scip_candidates_safe_with_meta",
        lambda *_args, **_kwargs: ([], [], [], _mk_scip_meta(), None),
    )

    with pytest.raises(RuntimeError, match="semantic discovery produced zero candidates"):
        analyze_with_graph(config, str(tmp_path), store, "variant")


def test_auth_setup_resolves_auth_precondition(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    config.auth.enabled = True
    config.auth.login_url = "http://127.0.0.1:8080/login"
    config.auth.username = "admin"
    config.auth.password = "secret"
    config.agent.max_iterations = 1
    config.agent.improvement_patience = 0
    store = EvidenceStore(tmp_path / ".padv")
    _force_node_runner(monkeypatch)
    monkeypatch.setattr("padv.orchestrator.graphs.ensure_agent_session", lambda *args, **kwargs: object())

    cand = _mk_candidate("joern-auth-1", ["joern"])
    cand.preconditions = ["auth-state-known"]
    monkeypatch.setattr(
        "padv.orchestrator.graphs.discover_candidates_with_meta",
        lambda *_args, **_kwargs: (
            [cand],
            [_mk_evidence(cand.candidate_id, "joern::sql")],
            _mk_joern_meta(findings=1, app_findings=1, candidate_count=1),
        ),
    )
    monkeypatch.setattr(
        "padv.orchestrator.graphs.discover_scip_candidates_safe_with_meta",
        lambda *_args, **_kwargs: ([], [], [], _mk_scip_meta(), None),
    )
    monkeypatch.setattr("padv.orchestrator.graphs.discover_web_hints", lambda *_args, **_kwargs: ({}, None))
    monkeypatch.setattr(
        "padv.orchestrator.graphs.establish_auth_state",
        lambda _config: {"auth_enabled": True, "login_url": _config.auth.login_url, "username": _config.auth.username, "cookies": {"PHPSESSID": "x"}},
    )
    monkeypatch.setattr(
        "padv.orchestrator.graphs.rank_candidates_with_deepagents",
        lambda candidates, *_args, **_kwargs: (candidates, {"engine": "deepagents", "ordered_ids": [c.candidate_id for c in candidates]}),
    )
    monkeypatch.setattr(
        "padv.orchestrator.graphs.skeptic_refine_with_deepagents",
        lambda candidates, *_args, **_kwargs: (candidates, {"engine": "deepagents", "failed_paths": []}),
    )
    monkeypatch.setattr(
        "padv.orchestrator.graphs.schedule_actions_with_deepagents",
        lambda candidates, *_args, **_kwargs: (
            candidates,
            {c.candidate_id: 1.0 for c in candidates},
            {"engine": "deepagents", "selected": [c.candidate_id for c in candidates]},
        ),
    )

    candidates, _, trace = analyze_with_graph(config, str(tmp_path), store, "variant")
    assert len(candidates) == 1
    assert "auth-state-known" not in candidates[0].preconditions
    assert trace["auth"]["resolved"] is True


def test_progress_callback_receives_step_events(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    config.agent.max_iterations = 1
    config.agent.improvement_patience = 0
    store = EvidenceStore(tmp_path / ".padv")
    _force_node_runner(monkeypatch)
    monkeypatch.setattr("padv.orchestrator.graphs.ensure_agent_session", lambda *args, **kwargs: object())

    monkeypatch.setattr(
        "padv.orchestrator.graphs.discover_candidates_with_meta",
        lambda *_args, **_kwargs: (
            [_mk_candidate("joern-1", ["joern"])],
            [_mk_evidence("joern-1", "joern::sql")],
            _mk_joern_meta(findings=1, app_findings=1, candidate_count=1),
        ),
    )
    monkeypatch.setattr(
        "padv.orchestrator.graphs.discover_scip_candidates_safe_with_meta",
        lambda *_args, **_kwargs: ([], [], [], _mk_scip_meta(), None),
    )
    monkeypatch.setattr("padv.orchestrator.graphs.discover_web_hints", lambda *_args, **_kwargs: ({}, None))
    monkeypatch.setattr(
        "padv.orchestrator.graphs.rank_candidates_with_deepagents",
        lambda candidates, *_args, **_kwargs: (candidates, {"engine": "deepagents", "ordered_ids": [c.candidate_id for c in candidates]}),
    )
    monkeypatch.setattr(
        "padv.orchestrator.graphs.skeptic_refine_with_deepagents",
        lambda candidates, *_args, **_kwargs: (candidates, {"engine": "deepagents", "failed_paths": []}),
    )
    monkeypatch.setattr(
        "padv.orchestrator.graphs.schedule_actions_with_deepagents",
        lambda candidates, *_args, **_kwargs: (
            candidates,
            {c.candidate_id: 1.0 for c in candidates},
            {"engine": "deepagents", "selected": [c.candidate_id for c in candidates]},
        ),
    )

    events: list[dict[str, object]] = []
    analyze_with_graph(config, str(tmp_path), store, "variant", progress_callback=events.append)
    steps = {(str(e.get("step")), str(e.get("status"))) for e in events}
    assert ("run", "start") in steps
    assert ("static_discovery", "start") in steps
    assert ("web_discovery", "done") in steps
    assert ("objective_schedule", "done") in steps
    assert ("persist", "done") in steps


def test_analyze_writes_stage_snapshots(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    config.agent.max_iterations = 1
    config.agent.improvement_patience = 0
    store = EvidenceStore(tmp_path / ".padv")
    _force_node_runner(monkeypatch)
    monkeypatch.setattr("padv.orchestrator.graphs.ensure_agent_session", lambda *args, **kwargs: object())

    monkeypatch.setattr(
        "padv.orchestrator.graphs.discover_candidates_with_meta",
        lambda *_args, **_kwargs: (
            [_mk_candidate("joern-1", ["joern"])],
            [_mk_evidence("joern-1", "joern::sql")],
            _mk_joern_meta(findings=1, app_findings=1, candidate_count=1),
        ),
    )
    monkeypatch.setattr(
        "padv.orchestrator.graphs.discover_scip_candidates_safe_with_meta",
        lambda *_args, **_kwargs: ([], [], [], _mk_scip_meta(), None),
    )
    monkeypatch.setattr("padv.orchestrator.graphs.discover_web_hints", lambda *_args, **_kwargs: ({"/": ["q"]}, None))
    monkeypatch.setattr(
        "padv.orchestrator.graphs.rank_candidates_with_deepagents",
        lambda candidates, *_args, **_kwargs: (candidates, {"engine": "deepagents", "ordered_ids": [c.candidate_id for c in candidates]}),
    )
    monkeypatch.setattr(
        "padv.orchestrator.graphs.skeptic_refine_with_deepagents",
        lambda candidates, *_args, **_kwargs: (candidates, {"engine": "deepagents", "failed_paths": []}),
    )
    monkeypatch.setattr(
        "padv.orchestrator.graphs.schedule_actions_with_deepagents",
        lambda candidates, *_args, **_kwargs: (
            candidates,
            {c.candidate_id: 1.0 for c in candidates},
            {"engine": "deepagents", "selected": [c.candidate_id for c in candidates]},
        ),
    )

    analyze_with_graph(config, str(tmp_path), store, "variant")

    stage_files = sorted(store.runs_dir.glob("analyze-*/stages/*.json"))
    assert stage_files
    names = [p.stem.split("-", 1)[1] for p in stage_files]
    assert "init" in names
    assert "static_discovery" in names
    assert "persist" in names

    payload = json.loads(stage_files[-1].read_text(encoding="utf-8"))
    assert payload["stage"] == "persist"
    assert payload["counts"]["candidates"] >= 0


def test_candidate_synthesis_invariant_rejects_invalid_proposer_trace(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    config.agent.max_iterations = 1
    config.agent.improvement_patience = 0
    store = EvidenceStore(tmp_path / ".padv")
    _force_node_runner(monkeypatch)
    monkeypatch.setattr("padv.orchestrator.graphs.ensure_agent_session", lambda *args, **kwargs: object())

    monkeypatch.setattr(
        "padv.orchestrator.graphs.discover_candidates_with_meta",
        lambda *_args, **_kwargs: (
            [_mk_candidate("joern-1", ["joern"])],
            [_mk_evidence("joern-1", "joern::sql")],
            _mk_joern_meta(findings=1, app_findings=1, candidate_count=1),
        ),
    )
    monkeypatch.setattr(
        "padv.orchestrator.graphs.discover_scip_candidates_safe_with_meta",
        lambda *_args, **_kwargs: ([], [], [], _mk_scip_meta(), None),
    )
    monkeypatch.setattr("padv.orchestrator.graphs.discover_web_hints", lambda *_args, **_kwargs: ({}, None))
    monkeypatch.setattr(
        "padv.orchestrator.graphs.rank_candidates_with_deepagents",
        lambda candidates, *_args, **_kwargs: (candidates, "invalid-trace"),
    )

    with pytest.raises(RuntimeError, match="candidate_synthesis invariant failed"):
        analyze_with_graph(config, str(tmp_path), store, "variant")


def test_run_with_graph_persists_attempt_history_across_iterations(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    config.agent.max_iterations = 2
    config.agent.improvement_patience = 0
    config.budgets.max_candidates = 1
    store = EvidenceStore(tmp_path / ".padv")
    _force_node_runner(monkeypatch)
    monkeypatch.setattr("padv.orchestrator.graphs.ensure_agent_session", lambda *args, **kwargs: object())

    candidate = _mk_candidate("cand-00001", ["joern"])
    static = _mk_evidence("cand-00001", "joern::sql")
    monkeypatch.setattr(
        "padv.orchestrator.graphs.discover_candidates_with_meta",
        lambda *_args, **_kwargs: (
            [candidate],
            [static],
            _mk_joern_meta(findings=1, app_findings=1, candidate_count=1),
        ),
    )
    monkeypatch.setattr(
        "padv.orchestrator.graphs.discover_scip_candidates_safe_with_meta",
        lambda *_args, **_kwargs: ([], [], [], _mk_scip_meta(), None),
    )
    monkeypatch.setattr("padv.orchestrator.graphs.discover_web_hints", lambda *_args, **_kwargs: ({}, None))
    monkeypatch.setattr(
        "padv.orchestrator.graphs.rank_candidates_with_deepagents",
        lambda candidates, *_args, **_kwargs: (candidates, {"engine": "deepagents", "ordered_ids": [c.candidate_id for c in candidates]}),
    )
    monkeypatch.setattr(
        "padv.orchestrator.graphs.skeptic_refine_with_deepagents",
        lambda candidates, *_args, **_kwargs: (candidates, {"engine": "deepagents", "failed_paths": []}),
    )
    monkeypatch.setattr(
        "padv.orchestrator.graphs.schedule_actions_with_deepagents",
        lambda candidates, *_args, **_kwargs: (
            candidates[:1],
            {candidates[0].candidate_id: 1.0} if candidates else {},
            {"engine": "deepagents", "selected": [candidates[0].candidate_id] if candidates else []},
        ),
    )
    monkeypatch.setattr(
        "padv.orchestrator.graphs.make_validation_plans_with_deepagents",
        lambda candidates, config, repo_root=None, session=None: (
            {
                c.candidate_id: ValidationPlan(
                    candidate_id=c.candidate_id,
                    intercepts=["mysqli_query"],
                    positive_requests=[{"method": "GET", "path": "/", "query": {config.canary.parameter_name: "a"}}] * 3,
                    negative_requests=[{"method": "GET", "path": "/", "query": {config.canary.parameter_name: "b"}}],
                    canary="a",
                )
                for c in candidates
            },
            {"engine": "deepagents"},
        ),
    )

    call_counter = {"n": 0}

    def _fake_validate(*args, **kwargs):
        call_counter["n"] += 1
        flag = f"flag-{call_counter['n']}"
        bundle = EvidenceBundle(
            bundle_id=f"bundle-{call_counter['n']}",
            created_at="2026-03-06T00:00:00+00:00",
            candidate=candidate,
            static_evidence=[static],
            positive_runtime=[RuntimeEvidence("r1", "ok", 1, False, False, False, None, [], {})],
            negative_runtime=[RuntimeEvidence("r2", "ok", 0, False, False, False, None, [], {})],
            repro_run_ids=["r1"],
            gate_result=GateResult("DROPPED", ["V0"], "V3", "missing"),
            limitations=["missing"],
            planner_trace={
                "attempts": [
                    {
                        "phase": "positive",
                        "index": 0,
                        "request_id": f"req-{call_counter['n']}",
                        "request": {"method": "GET", "path": "/"},
                        "runtime_status": "ok",
                        "http_status": 200,
                        "call_count": 1,
                        "analysis_flags": [flag],
                        "new_flags": [flag],
                        "elapsed_ms": 1,
                        "auth_context": "anonymous",
                    }
                ]
            },
        )
        return [bundle], {"VALIDATED": 0, "DROPPED": 1, "NEEDS_HUMAN_SETUP": 0}

    monkeypatch.setattr("padv.orchestrator.graphs.validate_candidates_runtime", _fake_validate)

    summary = run_with_graph(config, str(tmp_path), store, "variant")
    assert call_counter["n"] == 2
    assert len(summary.bundle_ids) == 1

    frontier = store.load_frontier_state()
    assert frontier is not None
    assert frontier["iteration"] == 2
    assert len(frontier.get("attempt_history", [])) == 2
    assert set(frontier.get("runtime_coverage", {}).get("flags", [])) == {"flag-1", "flag-2"}

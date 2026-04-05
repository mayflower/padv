from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import padv.orchestrator.graphs as graph_mod
from padv.agents.deepagents_harness import AgentExecutionError, AgentSoftYield
from padv.config.schema import load_config
from padv.models import (
    Candidate,
    EvidenceBundle,
    ExperimentAttempt,
    GateResult,
    Hypothesis,
    ObjectiveScore,
    Refutation,
    ResearchFinding,
    ResearchTask,
    RunSummary,
    RuntimeEvidence,
    StaticEvidence,
    ValidationPlan,
)
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



def _mk_candidate_custom(candidate_id: str, provenance: list[str], *, line: int, file_path: str = "src/a.php") -> Candidate:
    return Candidate(
        candidate_id=candidate_id,
        vuln_class="sql_injection_boundary",
        title="A03 SQL boundary influence",
        file_path=file_path,
        line=line,
        sink="mysqli_query",
        expected_intercepts=["mysqli_query"],
        notes="test",
        provenance=provenance,
        confidence=0.5,
    )



def _force_node_runner(monkeypatch: pytest.MonkeyPatch) -> None:
    del monkeypatch
    pytest.importorskip("langgraph")



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



def _install_agent_stubs(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    objective_count: int = 1,
    continue_sequence: list[bool] | None = None,
) -> dict[str, object]:
    state: dict[str, object] = {"continue_sequence": list(continue_sequence or [False]), "challenge_calls": 0}
    runtime = SimpleNamespace(
        root=SimpleNamespace(thread_id="root-thread", role="root"),
        subagents={
            "source": SimpleNamespace(thread_id="source-thread", role="source"),
            "graph": SimpleNamespace(thread_id="graph-thread", role="graph"),
            "web": SimpleNamespace(thread_id="web-thread", role="web"),
            "exploit": SimpleNamespace(thread_id="exploit-thread", role="exploit"),
            "skeptic": SimpleNamespace(thread_id="skeptic-thread", role="skeptic"),
            "experiment": SimpleNamespace(thread_id="experiment-thread", role="experiment"),
        },
        shared_context={},
        checkpoint_dir=str(tmp_path / ".padv" / "langgraph"),
        model="test-model",
        repo_root=str(tmp_path),
    )

    def _ensure_agent_runtime(config, frontier_state=None, repo_root=None, checkpoint_dir=None, runtime=None):
        state["last_checkpoint_dir"] = checkpoint_dir
        return runtime or state["runtime"]

    def _update_context(rt, **updates):
        shared = dict(getattr(rt, "shared_context", {}))
        for key, value in updates.items():
            shared[key] = value
        rt.shared_context = shared

    def _orient(_runtime, _config, *, frontier_state, discovery_trace, run_validation, objective_queue=None):
        return (
            [
                ObjectiveScore(
                    objective_id=f"obj-{idx:04d}",
                    title=f"Objective {idx}",
                    rationale="test objective",
                    expected_info_gain=1.0 - (idx * 0.1),
                    priority=1.0 - (idx * 0.1),
                    channels=["source", "graph", "web"],
                )
                for idx in range(1, objective_count + 1)
            ],
            {"engine": "stub", "run_validation": run_validation},
        )

    def _select(_runtime, _config, *, objective_queue, frontier_state):
        return objective_queue[0], {"engine": "stub", "selected_objective_id": objective_queue[0].objective_id}

    def _research(_runtime, role, _config, *, objective, frontier_state):
        candidate_seeds = list(_runtime.shared_context.get("candidate_seeds", []))
        web_hints = dict(_runtime.shared_context.get("web_hints", {}))
        task = ResearchTask(
            task_id=f"{role}-task-1",
            objective_id=objective.objective_id,
            channel=role,
            target_ref=candidate_seeds[0]["file_path"] if candidate_seeds else ".",
            prompt=f"research {role}",
            status="done",
        )
        finding = ResearchFinding(
            finding_id=f"{role}-finding-1",
            objective_id=objective.objective_id,
            channel=role,
            title=f"{role} finding",
            summary=f"{role} summary",
            evidence_refs=[seed["candidate_id"] for seed in candidate_seeds],
            file_refs=[seed["file_path"] for seed in candidate_seeds],
            web_paths=list(web_hints.keys()) if role == "web" else [],
            params=sorted({param for params in web_hints.values() for param in params}) if role == "web" else [],
            sink_refs=[seed["sink"] for seed in candidate_seeds],
        )
        return [task], [finding], {"engine": "stub", "role": role, "finding_ids": [finding.finding_id]}

    def _synthesize(_runtime, _config, *, objective, findings, frontier_state):
        candidate_seeds = list(_runtime.shared_context.get("candidate_seeds", []))
        static_evidence = list(_runtime.shared_context.get("static_evidence", []))
        web_hints = dict(_runtime.shared_context.get("web_hints", {}))
        grouped: dict[tuple[str, str, int, str], dict[str, object]] = {}
        for seed in candidate_seeds:
            signature = (seed["vuln_class"], seed["file_path"], int(seed["line"]), seed["sink"])
            bucket = grouped.setdefault(
                signature,
                {
                    "candidate_ids": [],
                    "title": seed["title"],
                    "notes": seed.get("notes", ""),
                    "vuln_class": seed["vuln_class"],
                    "file_path": seed["file_path"],
                    "line": int(seed["line"]),
                    "sink": seed["sink"],
                    "expected_intercepts": [],
                    "provenance": [],
                    "confidence": 0.0,
                    "preconditions": [],
                    "auth_requirements": [],
                    "web_path_hints": [],
                },
            )
            bucket["candidate_ids"].append(seed["candidate_id"])
            bucket["expected_intercepts"] = sorted(set(bucket["expected_intercepts"]) | set(seed.get("expected_intercepts", [])))
            bucket["provenance"] = sorted(set(bucket["provenance"]) | set(seed.get("provenance", [])))
            bucket["confidence"] = max(float(bucket["confidence"]), float(seed.get("confidence", 0.0)))
            bucket["preconditions"] = sorted(set(bucket["preconditions"]) | set(seed.get("preconditions", [])))
            bucket["auth_requirements"] = sorted(set(bucket["auth_requirements"]) | set(seed.get("auth_requirements", [])))
            bucket["web_path_hints"] = sorted(set(bucket["web_path_hints"]) | set(seed.get("web_path_hints", [])) | set(web_hints.keys()))

        hypotheses: list[Hypothesis] = []
        for idx, bucket in enumerate(grouped.values(), start=1):
            candidate_ids = set(bucket["candidate_ids"])
            evidence_refs = [
                item.get("hash") or item.get("query_id")
                for item in static_evidence
                if item.get("candidate_id") in candidate_ids
            ]
            evidence_refs.extend(f.finding_id for f in findings)
            candidate = Candidate(
                candidate_id=str(sorted(candidate_ids)[0]),
                vuln_class=str(bucket["vuln_class"]),
                title=str(bucket["title"]),
                file_path=str(bucket["file_path"]),
                line=int(bucket["line"]),
                sink=str(bucket["sink"]),
                expected_intercepts=list(bucket["expected_intercepts"]),
                notes=str(bucket["notes"]),
                provenance=list(bucket["provenance"]),
                evidence_refs=[ref for ref in evidence_refs if isinstance(ref, str)],
                confidence=float(bucket["confidence"]),
                preconditions=list(bucket["preconditions"]),
                auth_requirements=list(bucket["auth_requirements"]),
                web_path_hints=list(bucket["web_path_hints"]),
            )
            hypotheses.append(
                Hypothesis(
                    hypothesis_id=f"hyp-{idx:04d}",
                    objective_id=objective.objective_id,
                    vuln_class=candidate.vuln_class,
                    title=candidate.title,
                    rationale="merged from seed evidence",
                    evidence_refs=list(candidate.evidence_refs),
                    candidate=candidate,
                    confidence=max(candidate.confidence, 0.6),
                    preconditions=list(candidate.preconditions),
                    auth_requirements=list(candidate.auth_requirements),
                    web_path_hints=list(candidate.web_path_hints),
                )
            )
        return hypotheses, {"engine": "stub", "hypothesis_ids": [item.hypothesis_id for item in hypotheses]}

    def _challenge(_runtime, _config, *, hypotheses):
        state["challenge_calls"] = int(state["challenge_calls"]) + 1
        return [], {"engine": "stub", "round": state["challenge_calls"]}

    def _plan(_runtime, config, *, hypotheses):
        plans: dict[str, ValidationPlan] = {}
        attempts: list[ExperimentAttempt] = []
        for idx, hypothesis in enumerate(hypotheses, start=1):
            plans[hypothesis.candidate.candidate_id] = ValidationPlan(
                candidate_id=hypothesis.candidate.candidate_id,
                intercepts=list(hypothesis.candidate.expected_intercepts),
                positive_requests=[{"method": "GET", "path": "/", "query": {config.canary.parameter_name: f"pos-{idx}"}}] * 3,
                negative_requests=[{"method": "GET", "path": "/", "query": {config.canary.parameter_name: f"neg-{idx}"}}],
                canary=f"pos-{idx}",
                strategy="stub-plan",
                negative_control_strategy="stub-negative",
                plan_notes=["stub-plan"],
            )
            attempts.append(
                ExperimentAttempt(
                    attempt_id=f"attempt-{idx:04d}",
                    hypothesis_id=hypothesis.hypothesis_id,
                    plan_id=f"plan-{idx:04d}",
                    request_refs=[f"req-{idx:04d}"],
                    witness_goal=hypothesis.vuln_class,
                    status="planned",
                )
            )
        return plans, attempts, {"engine": "stub", "planned_candidate_ids": sorted(plans.keys())}

    def _continue(_runtime, _config, *, iteration, objective_queue, hypotheses, refutations, witness_bundles, max_iterations):
        sequence = state["continue_sequence"]
        decision = bool(sequence.pop(0)) if sequence else False
        return decision, {"engine": "stub", "reason": "continue" if decision else "stop", "iteration": iteration}

    state["runtime"] = runtime
    monkeypatch.setattr("padv.orchestrator.graphs.ensure_agent_runtime", _ensure_agent_runtime)
    monkeypatch.setattr("padv.orchestrator.graphs.update_agent_runtime_context", _update_context)
    monkeypatch.setattr("padv.orchestrator.graphs.orient_root_agent", _orient)
    monkeypatch.setattr("padv.orchestrator.graphs.select_objective_with_root_agent", _select)
    monkeypatch.setattr("padv.orchestrator.graphs.run_research_subagent", _research)
    monkeypatch.setattr("padv.orchestrator.graphs.synthesize_hypotheses_with_subagent", _synthesize)
    monkeypatch.setattr("padv.orchestrator.graphs.challenge_hypotheses_with_subagent", _challenge)
    monkeypatch.setattr("padv.orchestrator.graphs.plan_experiments_with_subagent", _plan)
    monkeypatch.setattr("padv.orchestrator.graphs.decide_continue_with_root_agent", _continue, raising=False)
    return state


def test_environmental_high_refutation_does_not_drop_hypothesis() -> None:
    hypothesis = Hypothesis(
        hypothesis_id="hyp-001",
        objective_id="obj-001",
        vuln_class="sql_injection_boundary",
        title="SQLi hypothesis",
        rationale="test rationale",
        evidence_refs=["cand-001"],
        candidate=_mk_candidate("cand-001", ["joern", "scip"]),
    )
    refutation = Refutation(
        refutation_id="ref-001",
        hypothesis_id="hyp-001",
        title="Network Access Control Severely Limits Real-World Exploitability",
        summary="Default .htaccess configuration restricts access to RFC1918 private network ranges and localhost.",
        severity="high",
    )

    kept = graph_mod._active_hypotheses_without_high_refutation(
        {"hypothesis_board": [hypothesis], "refutations": [refutation]}
    )

    assert [item.hypothesis_id for item in kept] == ["hyp-001"]


def test_analyze_with_graph_combines_semantic_sources(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    store = EvidenceStore(tmp_path / ".padv")
    _force_node_runner(monkeypatch)
    _install_agent_stubs(monkeypatch, tmp_path)

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
    monkeypatch.setattr(
        "padv.orchestrator.graphs.discover_web_inventory",
        lambda config, seed_urls=None: (
            {"/index.php": ["padv_canary"]},
            {"pages": [{"url": config.target.base_url, "path": "/index.php", "forms": [], "params": ["padv_canary"]}], "requests": []},
            None,
        ),
    )

    candidates, evidence, trace = analyze_with_graph(config, str(tmp_path), store, "variant")
    assert len(candidates) == 1
    assert set(candidates[0].provenance) == {"joern", "scip"}
    assert len(evidence) == 2
    assert trace["raw_scip_hits"] == 1
    assert trace["mapped_scip_sinks"] == 1
    assert trace["joern_findings"] == 1
    assert trace["semantic_count"] == 2
    assert trace["web_paths"] == 1
    assert trace["web_pages"] == 1

    semantic_files = sorted((store.root / "artifacts").glob("semantic-discovery-*.json"))
    assert semantic_files
    hypothesis_files = sorted((store.root / "artifacts").glob("hypotheses-*.json"))
    assert hypothesis_files
    hypothesis_payload = json.loads(hypothesis_files[-1].read_text(encoding="utf-8"))
    assert len(hypothesis_payload["hypotheses"]) == 1



def test_run_with_graph_uses_agentic_validation_nodes(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    store = EvidenceStore(tmp_path / ".padv")
    _force_node_runner(monkeypatch)
    _install_agent_stubs(monkeypatch, tmp_path)

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
    monkeypatch.setattr("padv.orchestrator.graphs.discover_web_inventory", lambda config, seed_urls=None: ({}, {}, None))

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
    assert "experiment" in summary.planner_trace
    assert "root_orient" in summary.planner_trace
    assert isinstance(summary.frontier_state, dict)



def test_analyze_with_graph_applies_configured_skeptic_rounds(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    config.agent.max_iterations = 1
    config.agent.improvement_patience = 0
    config.agent.skeptic_rounds = 3
    store = EvidenceStore(tmp_path / ".padv")
    _force_node_runner(monkeypatch)
    _install_agent_stubs(monkeypatch, tmp_path)

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
    monkeypatch.setattr("padv.orchestrator.graphs.discover_web_inventory", lambda config, seed_urls=None: ({}, {}, None))

    calls = {"count": 0}

    def _fake_challenge(_runtime, _config, *, hypotheses):
        calls["count"] += 1
        return [], {"engine": "stub", "round": calls["count"]}

    monkeypatch.setattr("padv.orchestrator.graphs.challenge_hypotheses_with_subagent", _fake_challenge)

    candidates, _, trace = analyze_with_graph(config, str(tmp_path), store, "variant")
    assert len(candidates) == 1
    assert calls["count"] == 3
    assert len(trace["frontier_delta"]["new_files"]) == 1


def test_objective_backfill_adds_missing_vulnerability_families(tmp_path: Path) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    state = {
        "config": config,
        "candidates": [
            Candidate(
                candidate_id="cand-sql",
                vuln_class="sql_injection_boundary",
                title="SQL sink",
                file_path="src/sql.php",
                line=10,
                sink="mysqli_query",
                expected_intercepts=["mysqli_query"],
                confidence=0.6,
            ),
            Candidate(
                candidate_id="cand-cmd",
                vuln_class="command_injection_boundary",
                title="Command sink",
                file_path="src/cmd.php",
                line=20,
                sink="shell_exec",
                expected_intercepts=["shell_exec"],
                confidence=0.7,
            ),
            Candidate(
                candidate_id="cand-ldap",
                vuln_class="ldap_injection_boundary",
                title="LDAP sink",
                file_path="src/ldap.php",
                line=30,
                sink="ldap_search",
                expected_intercepts=["ldap_search"],
                confidence=0.5,
            ),
        ],
    }
    objectives = [
        ObjectiveScore(
            objective_id="obj-sqli-primary",
            title="Investigate SQLi",
            rationale="primary SQL objective",
            expected_info_gain=0.9,
            priority=0.9,
            channels=["source", "graph", "web"],
        )
    ]

    supplemented, trace = graph_mod._supplement_objectives_with_candidate_coverage(state, objectives)

    ids = {item.objective_id for item in supplemented}
    assert "obj-sqli-primary" in ids
    assert "obj-auto-command_injection" in ids
    assert "obj-auto-ldap_injection" in ids
    assert trace["added"] == ["obj-auto-command_injection", "obj-auto-ldap_injection"]


def test_objective_backfill_keeps_more_than_sixteen_families(tmp_path: Path) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    config.agent.max_iterations = 8
    state = {
        "config": config,
        "candidates": [
            Candidate(candidate_id="cand-sql", vuln_class="sql_injection_boundary", title="SQL", file_path="a.php", line=1, sink="mysqli_query", expected_intercepts=["mysqli_query"], confidence=0.8),
            Candidate(candidate_id="cand-xss", vuln_class="xss_output_boundary", title="XSS", file_path="b.php", line=1, sink="echo", expected_intercepts=["echo"], confidence=0.8),
            Candidate(candidate_id="cand-cmd", vuln_class="command_injection_boundary", title="CMD", file_path="c.php", line=1, sink="shell_exec", expected_intercepts=["shell_exec"], confidence=0.8),
            Candidate(candidate_id="cand-code", vuln_class="code_injection_boundary", title="CODE", file_path="d.php", line=1, sink="eval", expected_intercepts=["eval"], confidence=0.8),
            Candidate(candidate_id="cand-ldap", vuln_class="ldap_injection_boundary", title="LDAP", file_path="e.php", line=1, sink="ldap_search", expected_intercepts=["ldap_search"], confidence=0.8),
            Candidate(candidate_id="cand-xpath", vuln_class="xpath_injection", title="XPATH", file_path="f.php", line=1, sink="xpath", expected_intercepts=["xpath"], confidence=0.8),
            Candidate(candidate_id="cand-file", vuln_class="file_boundary_influence", title="FILE", file_path="g.php", line=1, sink="include", expected_intercepts=["include"], confidence=0.8),
            Candidate(candidate_id="cand-upload", vuln_class="file_upload_influence", title="UPLOAD", file_path="h.php", line=1, sink="move_uploaded_file", expected_intercepts=["move_uploaded_file"], confidence=0.8),
            Candidate(candidate_id="cand-info", vuln_class="information_disclosure", title="INFO", file_path="i.php", line=1, sink="phpinfo", expected_intercepts=["phpinfo"], confidence=0.8),
            Candidate(candidate_id="cand-ssrf", vuln_class="ssrf", title="SSRF", file_path="j.php", line=1, sink="curl_exec", expected_intercepts=["curl_exec"], confidence=0.8),
            Candidate(candidate_id="cand-xxe", vuln_class="xxe_influence", title="XXE", file_path="k.php", line=1, sink="simplexml_load_string", expected_intercepts=["simplexml_load_string"], confidence=0.8),
            Candidate(candidate_id="cand-deser", vuln_class="deserialization_influence", title="DESER", file_path="l.php", line=1, sink="unserialize", expected_intercepts=["unserialize"], confidence=0.8),
            Candidate(candidate_id="cand-header", vuln_class="header_injection_boundary", title="HEADER", file_path="m.php", line=1, sink="header", expected_intercepts=["header"], confidence=0.8),
            Candidate(candidate_id="cand-regex", vuln_class="regex_dos_boundary", title="REGEX", file_path="n.php", line=1, sink="preg_match", expected_intercepts=["preg_match"], confidence=0.8),
            Candidate(candidate_id="cand-auth", vuln_class="auth_and_session_failures", title="AUTH", file_path="o.php", line=1, sink="session_start", expected_intercepts=["session_start"], confidence=0.8),
            Candidate(candidate_id="cand-csrf", vuln_class="csrf_invariant", title="CSRF", file_path="p.php", line=1, sink="post", expected_intercepts=["post"], confidence=0.8),
            Candidate(candidate_id="cand-session", vuln_class="session_misuse", title="SESSION", file_path="q.php", line=1, sink="setcookie", expected_intercepts=["setcookie"], confidence=0.8),
            Candidate(candidate_id="cand-crypto", vuln_class="crypto_failures", title="CRYPTO", file_path="r.php", line=1, sink="md5", expected_intercepts=["md5"], confidence=0.8),
            Candidate(candidate_id="cand-integrity", vuln_class="software_data_integrity", title="INTEGRITY", file_path="s.php", line=1, sink="signature", expected_intercepts=["signature"], confidence=0.8),
            Candidate(candidate_id="cand-logging", vuln_class="logging_monitoring_failures", title="LOGGING", file_path="t.php", line=1, sink="log", expected_intercepts=["log"], confidence=0.8),
        ],
    }
    objectives = [
        ObjectiveScore(
            objective_id="obj-sqli-primary",
            title="Investigate SQLi",
            rationale="primary SQL objective",
            expected_info_gain=0.9,
            priority=0.9,
            channels=["source", "graph", "web"],
        )
    ]

    supplemented, _trace = graph_mod._supplement_objectives_with_candidate_coverage(state, objectives)

    ids = {item.objective_id for item in supplemented}
    assert len(supplemented) > 16
    assert "obj-auto-ldap_injection" in ids
    assert "obj-auto-logging_monitoring_failures" in ids


def test_run_with_graph_stops_on_stagnation_without_root_continue(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    config.agent.max_iterations = 5
    config.agent.improvement_patience = 1
    store = EvidenceStore(tmp_path / ".padv")
    _force_node_runner(monkeypatch)
    _install_agent_stubs(monkeypatch, tmp_path, objective_count=4)

    candidate = _mk_candidate("joern-1", ["joern"])
    static = _mk_evidence("joern-1", "joern::sql")

    persisted = graph_mod._default_frontier_state()
    persisted["coverage"] = {
        "files": [candidate.file_path],
        "classes": [candidate.vuln_class],
        "signals": list(candidate.provenance),
        "sinks": [candidate.sink],
        "web_paths": [],
    }
    persisted["runtime_coverage"] = {"flags": [], "classes": [candidate.vuln_class]}
    persisted["target_scope"] = {
        "repo_root": str(tmp_path.resolve()),
        "base_url": config.target.base_url,
        "fingerprint": "test-fingerprint",
    }
    store.save_frontier_state(persisted)
    monkeypatch.setattr("padv.orchestrator.graphs._frontier_matches_target_scope", lambda frontier, state: True)

    monkeypatch.setattr(
        "padv.orchestrator.graphs.discover_candidates_with_meta",
        lambda repo_root, config: (
            [candidate],
            [static],
            _mk_joern_meta(findings=1, app_findings=1, candidate_count=1),
        ),
    )
    monkeypatch.setattr(
        "padv.orchestrator.graphs.discover_scip_candidates_safe_with_meta",
        lambda repo_root, config: ([], [], [], _mk_scip_meta(), None),
    )
    monkeypatch.setattr("padv.orchestrator.graphs.discover_web_inventory", lambda config, seed_urls=None: ({}, {}, None))
    monkeypatch.setattr(
        "padv.orchestrator.graphs.decide_continue_with_root_agent",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("root continue should not run")),
        raising=False,
    )

    call_counter = {"n": 0}

    def _fake_validate(*args, **kwargs):
        call_counter["n"] += 1
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
                        "analysis_flags": [],
                        "new_flags": [],
                        "elapsed_ms": 1,
                        "auth_context": "anonymous",
                    }
                ]
            },
        )
        return [bundle], {"VALIDATED": 0, "DROPPED": 1, "NEEDS_HUMAN_SETUP": 0}

    monkeypatch.setattr("padv.orchestrator.graphs.validate_candidates_runtime", _fake_validate)

    run_with_graph(config, str(tmp_path), store, "variant")

    assert call_counter["n"] == 2
    frontier = store.load_frontier_state()
    assert frontier is not None
    assert frontier["iteration"] == 2
    assert frontier["stagnation_rounds"] == 2



def test_web_seed_urls_are_normalized_and_artifact_is_persisted(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    config.agent.max_iterations = 1
    config.agent.improvement_patience = 0
    store = EvidenceStore(tmp_path / ".padv")
    _force_node_runner(monkeypatch)
    _install_agent_stubs(monkeypatch, tmp_path)

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
        "target_scope": {
            "repo_root": str(tmp_path.resolve()),
            "base_url": config.target.base_url,
            "fingerprint": "unused-in-test",
        },
    }
    import hashlib
    frontier_state["target_scope"]["fingerprint"] = hashlib.sha256(
        f"{str(tmp_path.resolve())}\n{config.target.base_url}".encode("utf-8")
    ).hexdigest()[:16]
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
        return {}, {"pages": [{"url": config.target.base_url, "path": "/"}], "requests": [], "visited_urls": list(seed_urls or [])}, None

    monkeypatch.setattr("padv.orchestrator.graphs.discover_web_inventory", _fake_web)

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
    assert payload["artifacts"]["pages"][0]["path"] == "/"


def test_web_discovery_updates_runtime_with_playwright_artifacts(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    store = EvidenceStore(tmp_path / ".padv")
    _force_node_runner(monkeypatch)
    state = _install_agent_stubs(monkeypatch, tmp_path)

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
    monkeypatch.setattr(
        "padv.orchestrator.graphs.discover_web_inventory",
        lambda config, seed_urls=None: (
            {"/": ["page"]},
            {
                "pages": [{"url": config.target.base_url, "path": "/", "forms": [{"method": "post", "inputs": [{"name": "username"}]}]}],
                "requests": [{"url": config.target.base_url, "path": "/", "method": "GET", "params": []}],
                "visited_urls": [config.target.base_url],
                "errors": [],
            },
            None,
        ),
    )

    analyze_with_graph(config, str(tmp_path), store, "variant")

    runtime = state["runtime"]
    assert runtime.shared_context["web_hints"]["/"] == ["page"]
    assert runtime.shared_context["web_artifacts"]["pages"][0]["forms"][0]["inputs"][0]["name"] == "username"
    assert runtime.shared_context["artifact_index"]["web_discovery_anonymous"].endswith(".json")



def test_static_discovery_raises_when_no_semantic_candidates(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    store = EvidenceStore(tmp_path / ".padv")
    _force_node_runner(monkeypatch)
    _install_agent_stubs(monkeypatch, tmp_path)
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
    _install_agent_stubs(monkeypatch, tmp_path)

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
    store = EvidenceStore(tmp_path / ".padv")
    _force_node_runner(monkeypatch)
    _install_agent_stubs(monkeypatch, tmp_path)

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
    monkeypatch.setattr("padv.orchestrator.graphs.discover_web_inventory", lambda *_args, **_kwargs: ({}, {}, None))
    monkeypatch.setattr(
        "padv.orchestrator.graphs.establish_auth_state",
        lambda _config: {"auth_enabled": True, "login_url": _config.auth.login_url, "username": _config.auth.username, "cookies": {"PHPSESSID": "x"}},
    )

    candidates, _, trace = analyze_with_graph(config, str(tmp_path), store, "variant")
    assert len(candidates) == 1
    assert "auth-state-known" not in candidates[0].preconditions
    assert trace["auth"]["resolved"] is True



def test_authenticated_web_discovery_runs_after_auth_and_merges_inventory(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    config.auth.enabled = True
    config.auth.login_url = "http://127.0.0.1:8080/login"
    config.auth.username = "admin"
    config.auth.password = "secret"
    store = EvidenceStore(tmp_path / ".padv")
    _force_node_runner(monkeypatch)
    state = _install_agent_stubs(monkeypatch, tmp_path)

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

    calls: list[dict[str, object]] = []

    def _fake_web(_config, seed_urls=None, auth_state=None):
        calls.append({"seed_urls": list(seed_urls or []), "auth_state": dict(auth_state or {})})
        if auth_state:
            return (
                {"/admin": ["id"]},
                {
                    "pages": [{"url": _config.target.base_url + "/admin", "path": "/admin"}],
                    "requests": [{"url": _config.target.base_url + "/admin", "path": "/admin", "method": "GET", "params": ["id"]}],
                    "visited_urls": [_config.target.base_url + "/admin"],
                    "errors": [],
                },
                None,
            )
        return (
            {"/": ["page"]},
            {
                "pages": [{"url": _config.target.base_url, "path": "/"}],
                "requests": [{"url": _config.target.base_url, "path": "/", "method": "GET", "params": []}],
                "visited_urls": [_config.target.base_url],
                "errors": [],
            },
            None,
        )

    monkeypatch.setattr("padv.orchestrator.graphs.discover_web_inventory", _fake_web)
    monkeypatch.setattr(
        "padv.orchestrator.graphs.establish_auth_state",
        lambda _config: {
            "auth_enabled": True,
            "login_url": _config.auth.login_url,
            "username": _config.auth.username,
            "cookies": {"PHPSESSID": "x"},
        },
    )

    analyze_with_graph(config, str(tmp_path), store, "variant")

    assert len(calls) == 2
    assert calls[0]["auth_state"] == {}
    assert calls[1]["auth_state"] == {
        "auth_enabled": True,
        "login_url": config.auth.login_url,
        "username": config.auth.username,
        "cookies": {"PHPSESSID": "x"},
    }

    runtime = state["runtime"]
    assert set(runtime.shared_context["web_hints"]) >= {"/", "/admin"}
    assert any(page["path"] == "/admin" and page["scope"] == "authenticated" for page in runtime.shared_context["web_artifacts"]["pages"])
    assert runtime.shared_context["artifact_index"]["web_discovery_authenticated"].endswith(".json")


def test_discovery_summary_is_persisted_before_orient(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    config.auth.enabled = True
    config.auth.login_url = "http://127.0.0.1:8080/login"
    config.auth.username = "admin"
    config.auth.password = "secret"
    store = EvidenceStore(tmp_path / ".padv")
    _force_node_runner(monkeypatch)
    _install_agent_stubs(monkeypatch, tmp_path)

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
    monkeypatch.setattr(
        "padv.orchestrator.graphs.discover_web_inventory",
        lambda _config, seed_urls=None, auth_state=None: (
            {"/admin" if auth_state else "/": ["id" if auth_state else "page"]},
            {
                "pages": [{"url": _config.target.base_url, "path": "/admin" if auth_state else "/"}],
                "requests": [],
                "visited_urls": list(seed_urls or []),
                "errors": [],
            },
            None,
        ),
    )
    monkeypatch.setattr(
        "padv.orchestrator.graphs.establish_auth_state",
        lambda _config: {
            "auth_enabled": True,
            "login_url": _config.auth.login_url,
            "username": _config.auth.username,
            "cookies": {"PHPSESSID": "x"},
        },
    )

    analyze_with_graph(config, str(tmp_path), store, "variant")

    stage_files = sorted((store.runs_dir / next((store.runs_dir).iterdir()).name / "stages").glob("*.json"))
    stage_names = [path.name for path in stage_files]
    summary_idx = next(idx for idx, name in enumerate(stage_names) if name.endswith("discovery_summary.json"))
    orient_idx = next(idx for idx, name in enumerate(stage_names) if name.endswith("orient.json"))
    assert summary_idx < orient_idx

    artifact_files = sorted((store.root / "artifacts").glob("discovery-summary-*.json"))
    assert artifact_files
    payload = json.loads(artifact_files[-1].read_text(encoding="utf-8"))
    assert payload["web"]["anonymous_paths"] == ["/"]
    assert payload["web"]["authenticated_paths"] == ["/admin"]
    assert payload["auth"]["cookie_count"] == 1


def test_progress_callback_receives_agentic_step_events(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    store = EvidenceStore(tmp_path / ".padv")
    _force_node_runner(monkeypatch)
    _install_agent_stubs(monkeypatch, tmp_path)

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
    monkeypatch.setattr("padv.orchestrator.graphs.discover_web_inventory", lambda *_args, **_kwargs: ({}, {}, None))

    events: list[dict[str, object]] = []
    analyze_with_graph(config, str(tmp_path), store, "variant", progress_callback=events.append)
    steps = {(str(e.get("step")), str(e.get("status"))) for e in events}
    assert ("graph", "start") in steps
    assert ("static_discovery", "start") in steps
    assert ("web_research", "done") in steps
    assert ("continue_or_stop", "done") in steps
    assert ("persist", "done") in steps


def test_state_runtime_syncs_progress_callback_into_shared_context(tmp_path: Path) -> None:
    runtime = SimpleNamespace(shared_context={})
    store = EvidenceStore(tmp_path / ".padv")
    state: graph_mod.GraphState = {
        "run_id": "analyze-test",
        "config": load_config(Path(__file__).resolve().parents[1] / "padv.toml"),
        "repo_root": str(tmp_path),
        "store": store,
        "mode": "variant",
        "run_validation": False,
        "agent_runtime": runtime,
    }
    events: list[dict[str, object]] = []
    graph_mod._set_progress_callback("analyze-test", events.append)
    try:
        resolved = graph_mod._state_runtime(state)
    finally:
        graph_mod._set_progress_callback("analyze-test", None)

    assert resolved is runtime
    callback = runtime.shared_context["__progress_callback__"]
    assert callable(callback)
    callback({"step": "test", "status": "activity"})
    assert events == [{"step": "test", "status": "activity"}]


def test_real_langgraph_merges_parallel_research_branches(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    pytest.importorskip("langgraph")
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    store = EvidenceStore(tmp_path / ".padv")
    _install_agent_stubs(monkeypatch, tmp_path)

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
    monkeypatch.setattr("padv.orchestrator.graphs.discover_web_inventory", lambda *_args, **_kwargs: ({"/": ["q"]}, {"pages": [], "requests": []}, None))

    result = graph_mod._run_langgraph(
        {
            "config": config,
            "repo_root": str(tmp_path),
            "store": store,
            "mode": "variant",
            "run_validation": False,
        },
        include_validation=False,
    )

    assert len(result["research_findings"]) == 3
    assert len(result["research_tasks"]) == 3
    assert set(result["planner_trace"].keys()) >= {"source_research", "graph_research", "web_research"}


def test_reduce_research_merges_branch_context_deltas_into_runtime(tmp_path: Path) -> None:
    runtime = SimpleNamespace(
        shared_context={"workspace_index": {}, "tool_usage": {}, "worklog": {}},
    )
    state: graph_mod.GraphState = {
        "store": EvidenceStore(tmp_path / ".padv"),
        "run_id": "analyze-test",
        "mode": "variant",
        "run_validation": False,
        "loop_continue": False,
        "decisions": {},
        "candidates": [],
        "static_evidence": [],
        "objective_queue": [],
        "hypothesis_board": [],
        "refutations": [],
        "experiment_board": [],
        "witness_bundles": [],
        "selected_candidates": [],
        "selected_static": [],
        "bundles": [],
        "all_bundles": [],
        "iteration_bundles": [],
        "artifact_refs": [],
        "frontier_state": graph_mod._default_frontier_state(),
        "source_tasks": [
            ResearchTask(
                task_id="source-task-1",
                objective_id="obj-1",
                channel="source",
                target_ref="cand-1",
                prompt="investigate",
                status="done",
            )
        ],
        "graph_tasks": [],
        "web_tasks": [],
        "source_findings": [
            ResearchFinding(
                finding_id="source-finding-1",
                objective_id="obj-1",
                channel="source",
                title="source finding",
                summary="summary",
                evidence_refs=["source::evidence"],
                file_refs=[],
                web_paths=[],
                params=[],
                sink_refs=[],
            )
        ],
        "graph_findings": [],
        "web_findings": [],
        "planner_trace": {},
        "agent_runtime": runtime,
        "source_context_delta": {
            "workspace_index": {"source": {"worklog": ["source/worklog/a.json"]}},
            "tool_usage": {"source": [{"ref": "source/tool_calls/a.json", "tool": "search_repo_text"}]},
            "worklog": {"source": [{"ref": "source/worklog/a.json", "role": "source"}]},
        },
        "graph_context_delta": {},
        "web_context_delta": {},
    }

    out = graph_mod._node_reduce_research(state)
    assert len(out["research_findings"]) == 1
    assert runtime.shared_context["workspace_index"]["source"]["worklog"] == ["source/worklog/a.json"]
    assert runtime.shared_context["tool_usage"]["source"][0]["tool"] == "search_repo_text"
    assert runtime.shared_context["worklog"]["source"][0]["ref"] == "source/worklog/a.json"


def test_parallel_research_branch_error_is_preserved_and_successful_findings_reduce(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    runtime = SimpleNamespace(
        shared_context={"workspace_index": {}, "tool_usage": {}, "worklog": {}},
    )
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    objective = ObjectiveScore(
        objective_id="obj-sqli",
        title="SQLi",
        rationale="test",
        expected_info_gain=0.9,
        priority=1.0,
        channels=["source", "graph", "web"],
    )
    state: graph_mod.GraphState = {
        "config": config,
        "repo_root": str(tmp_path),
        "store": EvidenceStore(tmp_path / ".padv"),
        "run_id": "analyze-test",
        "mode": "variant",
        "run_validation": False,
        "loop_continue": False,
        "decisions": {},
        "candidates": [],
        "static_evidence": [],
        "objective_queue": [objective],
        "active_objective": objective,
        "hypothesis_board": [],
        "refutations": [],
        "experiment_board": [],
        "witness_bundles": [],
        "selected_candidates": [],
        "selected_static": [],
        "bundles": [],
        "all_bundles": [],
        "iteration_bundles": [],
        "artifact_refs": [],
        "frontier_state": graph_mod._default_frontier_state(),
        "planner_trace": {},
        "agent_runtime": runtime,
    }

    def _fake_run(_runtime: object, role: str, *_args: object, **_kwargs: object):
        if role == "web":
            raise AgentExecutionError("web invocation failed: Connection error.")
        finding = ResearchFinding(
            finding_id=f"{role}-finding-1",
            objective_id=objective.objective_id,
            channel=role,
            title=f"{role} finding",
            summary="summary",
            evidence_refs=[f"{role}::evidence"],
            file_refs=[],
            web_paths=[],
            params=[],
            sink_refs=[],
        )
        task = ResearchTask(
            task_id=f"{role}-task-1",
            objective_id=objective.objective_id,
            channel=role,
            target_ref="cand-1",
            prompt="investigate",
            status="done",
        )
        return [task], [finding], {"engine": "deepagents", "role": role}

    monkeypatch.setattr("padv.orchestrator.graphs.clone_runtime_for_parallel_role", lambda runtime, *_args, **_kwargs: runtime)
    monkeypatch.setattr("padv.orchestrator.graphs.finalize_parallel_role_runtime", lambda *_args, **_kwargs: {})
    monkeypatch.setattr("padv.orchestrator.graphs.run_research_subagent", _fake_run)

    state.update(graph_mod._node_source_research_parallel(state))
    state.update(graph_mod._node_graph_research_parallel(state))
    state.update(graph_mod._node_web_research_parallel(state))

    out = graph_mod._node_reduce_research(state)
    assert {item.finding_id for item in out["research_findings"]} == {"source-finding-1", "graph-finding-1"}
    assert out["research_branch_errors"]["web"]["error"] == "web invocation failed: Connection error."
    error_ref = out["planner_trace"]["research_branch_errors"]["web"]["artifact_ref"]
    assert error_ref.endswith(".json")
    artifact_payload = json.loads(Path(error_ref).read_text(encoding="utf-8"))
    assert artifact_payload["role"] == "web"


def test_reduce_research_allows_empty_findings_when_no_candidate_material_remains(tmp_path: Path) -> None:
    runtime = SimpleNamespace(shared_context={"workspace_index": {}, "tool_usage": {}, "worklog": {}})
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    objective = ObjectiveScore(
        objective_id="obj-authz",
        title="AuthZ",
        rationale="test",
        expected_info_gain=0.3,
        priority=0.3,
        channels=["source", "graph", "web"],
    )
    state: graph_mod.GraphState = {
        "config": config,
        "repo_root": str(tmp_path),
        "store": EvidenceStore(tmp_path / ".padv"),
        "run_id": "run-empty-material",
        "mode": "variant",
        "run_validation": True,
        "loop_continue": True,
        "decisions": {},
        "candidates": [],
        "static_evidence": [],
        "selected_candidates": [],
        "selected_static": [],
        "objective_queue": [objective],
        "active_objective": objective,
        "hypothesis_board": [],
        "refutations": [],
        "experiment_board": [],
        "witness_bundles": [],
        "bundles": [],
        "all_bundles": [],
        "iteration_bundles": [],
        "artifact_refs": [],
        "planner_trace": {},
        "frontier_state": graph_mod._default_frontier_state(),
        "agent_runtime": runtime,
        "source_tasks": [],
        "graph_tasks": [],
        "web_tasks": [],
        "source_findings": [],
        "graph_findings": [],
        "web_findings": [],
        "source_context_delta": {},
        "graph_context_delta": {},
        "web_context_delta": {},
        "source_branch_error": {"error": "source invocation timed out after 120s", "artifact_ref": "source/error.json"},
        "graph_branch_error": {"error": "graph invocation timed out after 120s", "artifact_ref": "graph/error.json"},
        "web_branch_error": {"error": "web invocation timed out after 120s", "artifact_ref": "web/error.json"},
    }

    out = graph_mod._node_reduce_research(state)

    assert out["research_findings"] == []
    assert out["planner_trace"]["research_branch_errors"]["source"]["error"] == "source invocation timed out after 120s"


def test_continue_or_stop_stops_deterministically_when_no_candidate_material_remains(tmp_path: Path) -> None:
    runtime = SimpleNamespace(shared_context={})
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    objective = ObjectiveScore(
        objective_id="obj-authz",
        title="AuthZ",
        rationale="test",
        expected_info_gain=0.3,
        priority=0.3,
        channels=["source"],
    )
    state: graph_mod.GraphState = {
        "config": config,
        "repo_root": str(tmp_path),
        "store": EvidenceStore(tmp_path / ".padv"),
        "run_id": "run-stop-empty-material",
        "mode": "variant",
        "run_validation": True,
        "loop_continue": True,
        "decisions": {},
        "candidates": [],
        "static_evidence": [],
        "selected_candidates": [],
        "selected_static": [],
        "objective_queue": [objective],
        "active_objective": objective,
        "hypothesis_board": [],
        "refutations": [],
        "experiment_board": [],
        "witness_bundles": [],
        "bundles": [],
        "all_bundles": [],
        "iteration_bundles": [],
        "artifact_refs": [],
        "planner_trace": {},
        "frontier_state": graph_mod._default_frontier_state(),
        "agent_runtime": runtime,
        "run_iteration": 4,
    }

    out = graph_mod._node_continue_or_stop(state)

    assert out["loop_continue"] is False
    assert out["continue_reason"] == "no runnable candidates remain"
    assert out["planner_trace"]["continue"]["engine"] == "deterministic"
    assert out["planner_trace"]["continue"]["stop_rule"] == "no_runnable_candidates"


def test_node_orient_passes_remaining_objective_queue_to_root_agent(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    runtime = SimpleNamespace(shared_context={})
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    objective = ObjectiveScore(
        objective_id="obj-authz",
        title="AuthZ",
        rationale="test",
        expected_info_gain=0.3,
        priority=0.3,
        channels=["source"],
    )
    seen: dict[str, object] = {}

    monkeypatch.setattr(graph_mod, "_state_runtime", lambda state: runtime)

    def _fake_orient(_runtime, _config, *, frontier_state, discovery_trace, run_validation, objective_queue):
        seen["frontier_state"] = frontier_state
        seen["discovery_trace"] = discovery_trace
        seen["run_validation"] = run_validation
        seen["objective_ids"] = [item.objective_id for item in objective_queue]
        return [objective], {"engine": "stub", "objective_ids": ["obj-authz"]}

    monkeypatch.setattr(graph_mod, "orient_root_agent", _fake_orient)

    state: graph_mod.GraphState = {
        "config": config,
        "repo_root": str(tmp_path),
        "store": EvidenceStore(tmp_path / ".padv"),
        "run_id": "run-orient-pass-queue",
        "mode": "variant",
        "run_validation": False,
        "loop_continue": True,
        "decisions": {},
        "candidates": [],
        "static_evidence": [],
        "selected_candidates": [],
        "selected_static": [],
        "objective_queue": [objective],
        "hypothesis_board": [],
        "refutations": [],
        "experiment_board": [],
        "witness_bundles": [],
        "bundles": [],
        "all_bundles": [],
        "iteration_bundles": [],
        "artifact_refs": [],
        "planner_trace": {},
        "frontier_state": graph_mod._default_frontier_state(),
        "discovery_trace": {"semantic_count": 2},
        "agent_runtime": runtime,
    }

    out = graph_mod._node_orient(state)

    assert seen["objective_ids"] == ["obj-authz"]
    assert seen["run_validation"] is False
    assert out["objective_queue"][0].objective_id == "obj-authz"


def test_objective_schedule_does_not_fallback_when_resume_filter_empties_pool(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    runtime = SimpleNamespace(root=SimpleNamespace(thread_id="root-thread"), shared_context={})
    candidate = _mk_candidate("cand-00001", ["joern"])
    signature = graph_mod._candidate_signature(candidate)
    seen: dict[str, object] = {}

    monkeypatch.setattr(graph_mod, "_state_runtime", lambda state: runtime)

    def _fake_schedule(candidates, *_args, **_kwargs):
        seen["candidate_ids"] = [item.candidate_id for item in candidates]
        return [], {}, {"engine": "stub", "reason": "no-actions"}

    monkeypatch.setattr(graph_mod, "schedule_actions_with_deepagents", _fake_schedule)

    state: graph_mod.GraphState = {
        "config": config,
        "repo_root": str(tmp_path),
        "store": EvidenceStore(tmp_path / ".padv"),
        "run_id": "run-no-fallback-resume-filter",
        "run_validation": True,
        "had_semantic_candidates": True,
        "candidates": [candidate],
        "static_evidence": [_mk_evidence(candidate.candidate_id, "joern::sql")],
        "frontier_state": {
            **graph_mod._default_frontier_state(),
            "candidate_resume": {signature: {"completed_clean": True}},
        },
        "planner_trace": {},
    }

    result = graph_mod._node_objective_schedule(state)

    assert seen["candidate_ids"] == []
    assert result["selected_candidates"] == []
    assert result["selected_static"] == []
    assert result["planner_trace"]["scheduler"]["schedule_pool_size"] == 0
    assert "fallback_selected" not in result["planner_trace"]["scheduler"]


def test_objective_schedule_does_not_fallback_when_scheduler_returns_empty_selection(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    runtime = SimpleNamespace(root=SimpleNamespace(thread_id="root-thread"), shared_context={})
    candidate = _mk_candidate("cand-00001", ["joern"])
    seen: dict[str, object] = {}

    monkeypatch.setattr(graph_mod, "_state_runtime", lambda state: runtime)

    def _fake_schedule(candidates, *_args, **_kwargs):
        seen["candidate_ids"] = [item.candidate_id for item in candidates]
        return [], {}, {"engine": "stub", "reason": "no-valid-actions"}

    monkeypatch.setattr(graph_mod, "schedule_actions_with_deepagents", _fake_schedule)

    state: graph_mod.GraphState = {
        "config": config,
        "repo_root": str(tmp_path),
        "store": EvidenceStore(tmp_path / ".padv"),
        "run_id": "run-no-fallback-empty-selection",
        "run_validation": True,
        "had_semantic_candidates": True,
        "candidates": [candidate],
        "static_evidence": [_mk_evidence(candidate.candidate_id, "joern::sql")],
        "frontier_state": graph_mod._default_frontier_state(),
        "planner_trace": {},
    }

    result = graph_mod._node_objective_schedule(state)

    assert seen["candidate_ids"] == [candidate.candidate_id]
    assert result["selected_candidates"] == []
    assert result["selected_static"] == []
    assert result["planner_trace"]["scheduler"]["reason"] == "no-valid-actions"
    assert "fallback_selected" not in result["planner_trace"]["scheduler"]


def test_objective_schedule_retains_static_evidence_matched_by_evidence_refs(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    runtime = SimpleNamespace(root=SimpleNamespace(thread_id="root-thread"), shared_context={})
    candidate = _mk_candidate_custom("cand-derived", ["joern"], line=12)
    candidate.evidence_refs = ["joern::sql::1:src/a.php:12"]
    static_source = _mk_evidence("cand-source", "joern::sql::1")
    stale_static = StaticEvidence(
        candidate_id="cand-stale",
        query_profile="default",
        query_id="scip::sql::2",
        file_path="src/other.php",
        line=44,
        snippet="mysqli_query($other, $q)",
        hash="h-stale",
    )

    monkeypatch.setattr(graph_mod, "_state_runtime", lambda state: runtime)
    monkeypatch.setattr(
        graph_mod,
        "schedule_actions_with_deepagents",
        lambda *_args, **_kwargs: ([candidate], {candidate.candidate_id: 1.0}, {"engine": "stub"}),
    )

    state: graph_mod.GraphState = {
        "config": config,
        "repo_root": str(tmp_path),
        "store": EvidenceStore(tmp_path / ".padv"),
        "run_id": "run-objective-derived-static",
        "run_validation": True,
        "had_semantic_candidates": True,
        "candidates": [candidate],
        "static_evidence": [static_source, stale_static],
        "frontier_state": graph_mod._default_frontier_state(),
        "planner_trace": {},
    }

    result = graph_mod._node_objective_schedule(state)

    assert [item.candidate_id for item in result["selected_candidates"]] == ["cand-derived"]
    assert [item.candidate_id for item in result["selected_static"]] == ["cand-source"]
    assert [item.candidate_id for item in result["static_evidence"]] == ["cand-source"]


def test_analyze_writes_stage_and_checkpoint_snapshots(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    store = EvidenceStore(tmp_path / ".padv")
    _force_node_runner(monkeypatch)
    _install_agent_stubs(monkeypatch, tmp_path)

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
    monkeypatch.setattr("padv.orchestrator.graphs.discover_web_inventory", lambda *_args, **_kwargs: ({"/": ["q"]}, {"pages": [], "requests": []}, None))

    analyze_with_graph(config, str(tmp_path), store, "variant")

    stage_files = sorted(store.runs_dir.glob("analyze-*/stages/*.json"))
    assert stage_files
    checkpoint_files = sorted(store.langgraph_dir.glob("analyze-*/*.json"))
    assert checkpoint_files
    names = [p.stem.split("-", 1)[1] for p in stage_files]
    assert "orient" in names
    assert "hypothesis_board_update" in names
    assert "persist" in names

    payload = json.loads(stage_files[-1].read_text(encoding="utf-8"))
    assert payload["stage"] == "persist"
    assert payload["counts"]["hypotheses"] >= 0



def test_hypothesis_board_update_raises_when_exploit_subagent_returns_zero_hypotheses(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    store = EvidenceStore(tmp_path / ".padv")
    _force_node_runner(monkeypatch)
    _install_agent_stubs(monkeypatch, tmp_path)

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
    monkeypatch.setattr("padv.orchestrator.graphs.discover_web_inventory", lambda *_args, **_kwargs: ({}, {}, None))
    monkeypatch.setattr(
        "padv.orchestrator.graphs.synthesize_hypotheses_with_subagent",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AgentExecutionError("exploit subagent returned zero hypotheses")),
    )

    with pytest.raises(AgentExecutionError, match="zero hypotheses"):
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
    _install_agent_stubs(monkeypatch, tmp_path, objective_count=2, continue_sequence=[True, False])

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
    monkeypatch.setattr("padv.orchestrator.graphs.discover_web_inventory", lambda *_args, **_kwargs: ({}, {}, None))

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



def test_run_with_graph_fails_when_selected_candidates_produce_zero_bundles(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    config.agent.max_iterations = 1
    config.agent.improvement_patience = 0
    store = EvidenceStore(tmp_path / ".padv")
    _force_node_runner(monkeypatch)
    _install_agent_stubs(monkeypatch, tmp_path)

    candidate = _mk_candidate("cand-00001", ["joern"])
    static = _mk_evidence("cand-00001", "joern::sql")
    monkeypatch.setattr(
        "padv.orchestrator.graphs.discover_candidates_with_meta",
        lambda *_args, **_kwargs: ([candidate], [static], _mk_joern_meta(findings=1, app_findings=1, candidate_count=1)),
    )
    monkeypatch.setattr(
        "padv.orchestrator.graphs.discover_scip_candidates_safe_with_meta",
        lambda *_args, **_kwargs: ([], [], [], _mk_scip_meta(), None),
    )
    monkeypatch.setattr("padv.orchestrator.graphs.discover_web_inventory", lambda *_args, **_kwargs: ({}, {}, None))
    monkeypatch.setattr(
        "padv.orchestrator.graphs.validate_candidates_runtime",
        lambda *args, **kwargs: ([], {"VALIDATED": 0, "DROPPED": 0, "NEEDS_HUMAN_SETUP": 0}),
    )

    with pytest.raises(RuntimeError, match="selected candidates produced zero bundles"):
        run_with_graph(config, str(tmp_path), store, "variant")

    liveness_artifacts = sorted((store.root / "artifacts").glob("runtime-liveness-*.json"))
    assert liveness_artifacts
    payload = json.loads(liveness_artifacts[-1].read_text(encoding="utf-8"))
    assert payload["reason"] == "zero-bundles-for-selected-candidates"



def test_agent_workspace_artifact_is_persisted(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    store = EvidenceStore(tmp_path / ".padv")
    _force_node_runner(monkeypatch)
    _install_agent_stubs(monkeypatch, tmp_path)

    candidate = _mk_candidate_custom("cand-00001", ["joern"], line=34)
    static = _mk_evidence("cand-00001", "joern::sql::2")
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
    monkeypatch.setattr("padv.orchestrator.graphs.discover_web_inventory", lambda *_args, **_kwargs: ({}, {}, None))

    def _fake_validate(*args, **kwargs):
        bundle = EvidenceBundle(
            bundle_id="bundle-active",
            created_at="2026-03-07T00:00:00+00:00",
            candidate=candidate,
            static_evidence=[static],
            positive_runtime=[RuntimeEvidence("r1", "ok", 1, False, False, False, None, [], {})],
            negative_runtime=[RuntimeEvidence("r2", "ok", 0, False, False, False, None, [], {})],
            repro_run_ids=["r1"],
            gate_result=GateResult("DROPPED", ["V0"], "V3", "missing"),
            limitations=["missing"],
        )
        return [bundle], {"VALIDATED": 0, "DROPPED": 1, "NEEDS_HUMAN_SETUP": 0}

    monkeypatch.setattr("padv.orchestrator.graphs.validate_candidates_runtime", _fake_validate)

    run_with_graph(config, str(tmp_path), store, "variant")
    workspace = store.load_json_artifact("agent_workspace/latest.json")
    assert workspace is not None
    assert len(workspace["hypotheses"]) == 1
    assert len(workspace["witness_bundles"]) == 1
    assert workspace["gate_history"][0]["decision"] == "DROPPED"


def test_agent_runtime_shared_context_tracks_hypotheses_refutations_and_experiments(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    store = EvidenceStore(tmp_path / ".padv")
    _force_node_runner(monkeypatch)
    state = _install_agent_stubs(monkeypatch, tmp_path)

    candidate = _mk_candidate_custom("cand-00001", ["joern"], line=34)
    static = _mk_evidence("cand-00001", "joern::sql::2")
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
    monkeypatch.setattr("padv.orchestrator.graphs.discover_web_inventory", lambda *_args, **_kwargs: ({"/admin": ["id"]}, {"pages": [], "requests": []}, None))

    def _fake_validate(*args, **kwargs):
        bundle = EvidenceBundle(
            bundle_id="bundle-active",
            created_at="2026-03-07T00:00:00+00:00",
            candidate=candidate,
            static_evidence=[static],
            positive_runtime=[RuntimeEvidence("r1", "ok", 1, False, False, False, None, [], {})],
            negative_runtime=[RuntimeEvidence("r2", "ok", 0, False, False, False, None, [], {})],
            repro_run_ids=["r1"],
            gate_result=GateResult("DROPPED", ["V0"], "V3", "missing"),
            limitations=["missing"],
        )
        return [bundle], {"VALIDATED": 0, "DROPPED": 1, "NEEDS_HUMAN_SETUP": 0}

    monkeypatch.setattr("padv.orchestrator.graphs.validate_candidates_runtime", _fake_validate)

    result = graph_mod._run_langgraph(
        {
            "config": config,
            "repo_root": str(tmp_path),
            "store": store,
            "mode": "variant",
            "run_validation": True,
        },
        include_validation=True,
    )

    runtime = state["runtime"]
    assert len(runtime.shared_context["hypotheses"]) == 1
    assert runtime.shared_context["hypotheses"][0]["hypothesis_id"] == "hyp-0001"
    assert isinstance(runtime.shared_context["refutations"], list)
    assert len(runtime.shared_context["experiment_board"]) == 1
    assert runtime.shared_context["experiment_board"][0]["attempt_id"] == "attempt-0001"
    assert runtime.shared_context["candidate_seeds"][0]["candidate_id"] == "cand-00001"
    assert runtime.shared_context["static_evidence"][0]["candidate_id"] == "cand-00001"
    assert result["gate_history"][0]["decision"] == "DROPPED"


def test_state_runtime_rehydrates_shared_context_from_state_on_resume(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    run_id = "resume-rehydrate"
    graph_mod._clear_state_runtime(run_id)
    candidate = _mk_candidate_custom("cand-00001", ["joern"], line=34)
    static = _mk_evidence("cand-00001", "joern::sql::2")
    finding = ResearchFinding(
        finding_id="finding-0001",
        objective_id="obj-0001",
        channel="graph",
        title="graph finding",
        summary="summary",
        evidence_refs=["cand-00001"],
        file_refs=["src/a.php"],
        sink_refs=["mysqli_query"],
    )
    hypothesis = Hypothesis(
        hypothesis_id="hyp-0001",
        objective_id="obj-0001",
        vuln_class=candidate.vuln_class,
        title=candidate.title,
        rationale="runtime rehydration",
        evidence_refs=["cand-00001"],
        candidate=candidate,
        confidence=0.8,
    )
    refutation = Refutation(
        refutation_id="ref-0001",
        hypothesis_id="hyp-0001",
        title="low confidence refutation",
        summary="not fatal",
        evidence_refs=["cand-00001"],
        severity="medium",
    )
    attempt = ExperimentAttempt(
        attempt_id="attempt-0001",
        hypothesis_id="hyp-0001",
        plan_id="plan-0001",
        request_refs=["req-0001"],
        witness_goal="sql_injection_boundary",
        status="planned",
    )
    runtime = SimpleNamespace(
        root=SimpleNamespace(thread_id="root-thread", role="root"),
        subagents={},
        shared_context={},
        checkpoint_dir=str(tmp_path / ".padv" / "langgraph"),
        model="test-model",
        repo_root=str(tmp_path),
    )
    monkeypatch.setattr(graph_mod, "ensure_agent_runtime", lambda *args, **kwargs: runtime)

    state: graph_mod.GraphState = {
        "config": config,
        "run_id": run_id,
        "repo_root": str(tmp_path),
        "store": EvidenceStore(tmp_path / ".padv"),
        "frontier_state": {
            "iteration": 3,
            "agent_threads": {"root": "stale-thread"},
            "coverage": {"files": [], "classes": [], "signals": [], "sinks": [], "web_paths": []},
            "history": [],
            "attempt_history": [],
            "candidate_resume": {},
            "runtime_coverage": {"flags": [], "classes": []},
        },
        "objective_queue": [
            ObjectiveScore(
                objective_id="obj-0001",
                title="Objective 1",
                rationale="resume target",
                expected_info_gain=0.9,
                priority=0.8,
                channels=["graph"],
            )
        ],
        "candidates": [candidate],
        "static_evidence": [static],
        "research_findings": [finding],
        "hypothesis_board": [hypothesis],
        "refutations": [refutation],
        "experiment_board": [attempt],
        "web_hints": {"/": ["id"]},
        "web_artifacts": {"pages": [{"url": "http://127.0.0.1:18080/"}]},
        "auth_contexts": {"default": {"cookies": {"sid": "cookie"}}},
        "artifact_index": {"web_discovery": "artifacts/web.json"},
    }

    rt = graph_mod._state_runtime(state)

    assert rt is runtime
    assert runtime.shared_context["hypotheses"][0]["hypothesis_id"] == "hyp-0001"
    assert runtime.shared_context["refutations"][0]["refutation_id"] == "ref-0001"
    assert runtime.shared_context["experiment_board"][0]["attempt_id"] == "attempt-0001"
    assert runtime.shared_context["candidate_seeds"][0]["candidate_id"] == "cand-00001"
    assert runtime.shared_context["research_findings"][0]["finding_id"] == "finding-0001"
    assert runtime.shared_context["frontier_state"]["iteration"] == 3
    assert "agent_threads" not in runtime.shared_context["frontier_state"]
    assert runtime.shared_context["artifact_index"]["web_discovery"] == "artifacts/web.json"

    state["hypothesis_board"] = []
    state["refutations"] = []
    state["experiment_board"] = []
    # Mark dirty so _state_runtime re-syncs after direct state mutation.
    # In the real graph, _finalize_stage handles this automatically.
    graph_mod._RUNTIME_SYNC_DIRTY.add(run_id)
    graph_mod._state_runtime(state)

    assert runtime.shared_context["hypotheses"] == []
    assert runtime.shared_context["refutations"] == []
    assert runtime.shared_context["experiment_board"] == []
    graph_mod._clear_state_runtime(run_id)


def test_experiment_plan_filters_runtime_candidates_to_planned_subset(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    candidate_one = _mk_candidate_custom("cand-00001", ["joern"], line=34)
    candidate_two = _mk_candidate_custom("cand-00002", ["scip"], line=52)
    static_one = _mk_evidence("cand-00001", "joern::sql::1")
    static_two = _mk_evidence("cand-00002", "scip::sql::2")
    hypothesis_one = Hypothesis(
        hypothesis_id="hyp-0001",
        objective_id="obj-0001",
        vuln_class=candidate_one.vuln_class,
        title=candidate_one.title,
        rationale="keep planned candidate",
        evidence_refs=["cand-00001"],
        candidate=candidate_one,
        confidence=0.9,
    )
    hypothesis_two = Hypothesis(
        hypothesis_id="hyp-0002",
        objective_id="obj-0001",
        vuln_class=candidate_two.vuln_class,
        title=candidate_two.title,
        rationale="leave for later iteration",
        evidence_refs=["cand-00002"],
        candidate=candidate_two,
        confidence=0.7,
    )
    runtime = SimpleNamespace(shared_context={}, checkpoint_dir=str(tmp_path / ".padv" / "langgraph"))
    monkeypatch.setattr(graph_mod, "_state_runtime", lambda state: runtime)
    monkeypatch.setattr(graph_mod, "update_agent_runtime_context", lambda *args, **kwargs: None)
    monkeypatch.setattr(graph_mod, "_persist_agent_workspace_artifact", lambda *args, **kwargs: "artifact.json")
    monkeypatch.setattr(
        graph_mod,
        "plan_experiments_with_subagent",
        lambda *_args, **_kwargs: (
            {
                "cand-00001": ValidationPlan(
                    candidate_id="cand-00001",
                    intercepts=["mysqli_query"],
                    oracle_functions=["mysqli_query"],
                    positive_requests=[{"method": "GET", "path": "/", "query": {"x": "1"}}] * 3,
                    negative_requests=[{"method": "GET", "path": "/", "query": {"x": "0"}}],
                    canary="x",
                )
            },
            [
                ExperimentAttempt(
                    attempt_id="attempt-0001",
                    hypothesis_id="hyp-0001",
                    plan_id="plan-0001",
                    request_refs=[],
                    witness_goal="sql_injection_boundary",
                    status="planned",
                )
            ],
            {"engine": "stub"},
        ),
    )

    state: graph_mod.GraphState = {
        "config": config,
        "run_id": "run-filter-plans",
        "repo_root": str(tmp_path),
        "store": EvidenceStore(tmp_path / ".padv"),
        "run_validation": True,
        "candidates": [candidate_one, candidate_two],
        "static_evidence": [static_one, static_two],
        "hypothesis_board": [hypothesis_one, hypothesis_two],
        "frontier_state": {},
        "artifact_refs": [],
    }

    result = graph_mod._node_experiment_plan(state)

    assert [item.candidate_id for item in result["candidates"]] == ["cand-00001"]
    assert [item.candidate_id for item in result["static_evidence"]] == ["cand-00001"]
    assert sorted(result["plans_by_candidate"].keys()) == ["cand-00001"]


def test_experiment_plan_rehydrates_from_selected_pool_when_current_candidates_are_empty(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    candidate_one = _mk_candidate_custom("cand-00001", ["joern"], line=34)
    candidate_two = _mk_candidate_custom("cand-00002", ["scip"], line=52)
    static_one = _mk_evidence("cand-00001", "joern::sql::1")
    static_two = _mk_evidence("cand-00002", "scip::sql::2")
    runtime = SimpleNamespace(shared_context={}, checkpoint_dir=str(tmp_path / ".padv" / "langgraph"))
    monkeypatch.setattr(graph_mod, "_state_runtime", lambda state: runtime)
    monkeypatch.setattr(graph_mod, "update_agent_runtime_context", lambda *args, **kwargs: None)
    monkeypatch.setattr(graph_mod, "_persist_agent_workspace_artifact", lambda *args, **kwargs: "artifact.json")
    monkeypatch.setattr(
        graph_mod,
        "plan_experiments_with_subagent",
        lambda *_args, **_kwargs: (
            {
                "cand-00001": ValidationPlan(
                    candidate_id="cand-00001",
                    intercepts=["mysqli_query"],
                    oracle_functions=["mysqli_query"],
                    positive_requests=[{"method": "GET", "path": "/", "query": {"x": "1"}}] * 3,
                    negative_requests=[{"method": "GET", "path": "/", "query": {"x": "0"}}],
                    canary="x",
                )
            },
            [
                ExperimentAttempt(
                    attempt_id="attempt-0001",
                    hypothesis_id="hyp-0001",
                    plan_id="plan-0001",
                    request_refs=[],
                    witness_goal="sql_injection_boundary",
                    status="planned",
                )
            ],
            {"engine": "stub"},
        ),
    )

    state: graph_mod.GraphState = {
        "config": config,
        "run_id": "run-filter-selected-fallback",
        "repo_root": str(tmp_path),
        "store": EvidenceStore(tmp_path / ".padv"),
        "run_validation": True,
        "selected_candidates": [candidate_one, candidate_two],
        "selected_static": [static_one, static_two],
        "candidates": [],
        "static_evidence": [],
        "hypothesis_board": [],
        "frontier_state": {},
        "artifact_refs": [],
    }

    result = graph_mod._node_experiment_plan(state)

    assert [item.candidate_id for item in result["candidates"]] == ["cand-00001"]
    assert [item.candidate_id for item in result["static_evidence"]] == ["cand-00001"]
    assert sorted(result["plans_by_candidate"].keys()) == ["cand-00001"]


def test_experiment_plan_retains_static_evidence_matched_by_evidence_refs(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    candidate = _mk_candidate_custom("cand-derived", ["joern"], line=12)
    candidate.evidence_refs = ["joern::sql::1:src/a.php:12"]
    static_source = _mk_evidence("cand-source", "joern::sql::1")
    stale_static = StaticEvidence(
        candidate_id="cand-stale",
        query_profile="default",
        query_id="scip::sql::2",
        file_path="src/other.php",
        line=44,
        snippet="mysqli_query($other, $q)",
        hash="h-stale",
    )
    hypothesis = Hypothesis(
        hypothesis_id="hyp-derived",
        objective_id="obj-0001",
        vuln_class=candidate.vuln_class,
        title=candidate.title,
        rationale="keep derived candidate",
        evidence_refs=["src/a.php:12"],
        candidate=candidate,
        confidence=0.9,
    )
    runtime = SimpleNamespace(shared_context={}, checkpoint_dir=str(tmp_path / ".padv" / "langgraph"))

    monkeypatch.setattr(graph_mod, "_state_runtime", lambda state: runtime)
    monkeypatch.setattr(graph_mod, "update_agent_runtime_context", lambda *args, **kwargs: None)
    monkeypatch.setattr(graph_mod, "_persist_agent_workspace_artifact", lambda *args, **kwargs: "artifact.json")
    monkeypatch.setattr(
        graph_mod,
        "plan_experiments_with_subagent",
        lambda *_args, **_kwargs: (
            {
                candidate.candidate_id: ValidationPlan(
                    candidate_id=candidate.candidate_id,
                    intercepts=["mysqli_query"],
                    oracle_functions=["mysqli_query"],
                    positive_requests=[{"method": "GET", "path": "/", "query": {"x": "1"}}] * 3,
                    negative_requests=[{"method": "GET", "path": "/", "query": {"x": "0"}}],
                    canary="x",
                )
            },
            [
                ExperimentAttempt(
                    attempt_id="attempt-derived",
                    hypothesis_id="hyp-derived",
                    plan_id="plan-derived",
                    request_refs=[],
                    witness_goal="sql_injection_boundary",
                    status="planned",
                )
            ],
            {"engine": "stub"},
        ),
    )

    state: graph_mod.GraphState = {
        "config": config,
        "run_id": "run-plan-derived-static",
        "repo_root": str(tmp_path),
        "store": EvidenceStore(tmp_path / ".padv"),
        "run_validation": True,
        "candidates": [candidate],
        "static_evidence": [static_source, stale_static],
        "hypothesis_board": [hypothesis],
        "frontier_state": {},
        "artifact_refs": [],
    }

    result = graph_mod._node_experiment_plan(state)

    assert [item.candidate_id for item in result["candidates"]] == ["cand-derived"]
    assert [item.candidate_id for item in result["static_evidence"]] == ["cand-source"]
    assert sorted(result["plans_by_candidate"].keys()) == ["cand-derived"]


def test_experiment_plan_does_not_short_circuit_on_stale_plans(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    candidate = _mk_candidate_custom("cand-00001", ["joern"], line=34)
    runtime = SimpleNamespace(shared_context={}, checkpoint_dir=str(tmp_path / ".padv" / "langgraph"))
    calls = {"count": 0}

    monkeypatch.setattr(graph_mod, "_state_runtime", lambda state: runtime)
    monkeypatch.setattr(graph_mod, "update_agent_runtime_context", lambda *args, **kwargs: None)
    monkeypatch.setattr(graph_mod, "_persist_agent_workspace_artifact", lambda *args, **kwargs: "artifact.json")

    def _fake_plan(*_args, **_kwargs):
        calls["count"] += 1
        return (
            {
                "cand-00001": ValidationPlan(
                    candidate_id="cand-00001",
                    intercepts=["mysqli_query"],
                    oracle_functions=["mysqli_query"],
                    positive_requests=[{"method": "GET", "path": "/", "query": {"x": "1"}}] * 3,
                    negative_requests=[{"method": "GET", "path": "/", "query": {"x": "0"}}],
                    canary="x",
                )
            },
            [],
            {"engine": "stub"},
        )

    monkeypatch.setattr(graph_mod, "plan_experiments_with_subagent", _fake_plan)

    state: graph_mod.GraphState = {
        "config": config,
        "run_id": "run-no-reuse-plan",
        "repo_root": str(tmp_path),
        "store": EvidenceStore(tmp_path / ".padv"),
        "run_validation": True,
        "plans_by_candidate": {
            "stale": ValidationPlan(
                candidate_id="stale",
                intercepts=["mysqli_query"],
                positive_requests=[{}] * 3,
                negative_requests=[{}],
                canary="x",
            )
        },
        "experiment_board": [ExperimentAttempt(attempt_id="stale", hypothesis_id="stale", plan_id="stale", request_refs=[], witness_goal="x", status="planned")],
        "hypothesis_board": [
            Hypothesis(
                hypothesis_id="hyp-0001",
                objective_id="obj-0001",
                vuln_class=candidate.vuln_class,
                title=candidate.title,
                rationale="fresh",
                evidence_refs=["cand-00001"],
                candidate=candidate,
                confidence=0.9,
            )
        ],
        "frontier_state": {},
        "artifact_refs": [],
        "candidates": [candidate],
        "static_evidence": [],
    }

    result = graph_mod._node_experiment_plan(state)

    assert calls["count"] == 1
    assert sorted(result["plans_by_candidate"].keys()) == ["cand-00001"]


def test_select_objective_resets_iteration_scoped_validation_state(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    objective = ObjectiveScore(
        objective_id="obj-next",
        title="Next objective",
        rationale="test",
        expected_info_gain=0.8,
        priority=0.8,
        channels=["source", "graph", "web"],
    )
    runtime = SimpleNamespace(shared_context={}, checkpoint_dir=str(tmp_path / ".padv" / "langgraph"))
    monkeypatch.setattr(graph_mod, "_state_runtime", lambda state: runtime)
    monkeypatch.setattr(
        graph_mod,
        "select_objective_with_root_agent",
        lambda *_args, **_kwargs: (objective, {"engine": "stub", "selected_objective_id": "obj-next"}),
    )

    candidate = _mk_candidate_custom("cand-00001", ["joern"], line=34)
    evidence = _mk_evidence("cand-00001", "joern::sql::1")
    hypothesis = Hypothesis(
        hypothesis_id="hyp-0001",
        objective_id="obj-prev",
        vuln_class=candidate.vuln_class,
        title=candidate.title,
        rationale="old hypothesis",
        evidence_refs=["cand-00001"],
        candidate=candidate,
        confidence=0.9,
    )
    refutation = Refutation(
        refutation_id="ref-0001",
        hypothesis_id="hyp-0001",
        title="old refutation",
        summary="old summary",
        evidence_refs=[],
        severity="low",
    )
    attempt = ExperimentAttempt(
        attempt_id="attempt-0001",
        hypothesis_id="hyp-0001",
        plan_id="plan-0001",
        request_refs=[],
        witness_goal="sql_injection_boundary",
        status="planned",
    )
    state: graph_mod.GraphState = {
        "config": config,
        "run_id": "run-reset-iteration-state",
        "repo_root": str(tmp_path),
        "store": EvidenceStore(tmp_path / ".padv"),
        "run_validation": True,
        "objective_queue": [objective],
        "frontier_state": {},
        "research_tasks": [ResearchTask(task_id="task-0001", objective_id="obj-prev", channel="source", target_ref="src/a.php", prompt="x", status="done")],
        "research_findings": [ResearchFinding(finding_id="finding-0001", objective_id="obj-prev", channel="source", title="x", summary="y", evidence_refs=[], file_refs=["src/a.php"], web_paths=[], params=[], sink_refs=["mysqli_query"])],
        "source_tasks": [ResearchTask(task_id="source-task", objective_id="obj-prev", channel="source", target_ref="src/a.php", prompt="x", status="done")],
        "graph_tasks": [ResearchTask(task_id="graph-task", objective_id="obj-prev", channel="graph", target_ref="src/a.php", prompt="x", status="done")],
        "web_tasks": [ResearchTask(task_id="web-task", objective_id="obj-prev", channel="web", target_ref="src/a.php", prompt="x", status="done")],
        "source_findings": [],
        "graph_findings": [],
        "web_findings": [],
        "source_trace": {"engine": "stub"},
        "graph_trace": {"engine": "stub"},
        "web_trace": {"engine": "stub"},
        "hypothesis_board": [hypothesis],
        "refutations": [refutation],
        "experiment_board": [attempt],
        "plans_by_candidate": {
            "cand-00001": ValidationPlan(
                candidate_id="cand-00001",
                intercepts=["mysqli_query"],
                oracle_functions=["mysqli_query"],
                positive_requests=[{"method": "GET", "path": "/"}],
                negative_requests=[{"method": "GET", "path": "/x"}],
                canary="x",
            )
        },
        "witness_bundles": ["stale-witness"],
        "iteration_bundles": ["stale-bundle"],
        "validation_board": {"plans": {"cand-00001": {}}},
        "execution_board": {"bundles": [{"bundle_id": "bundle-0001"}]},
        "research_board": {"findings": [{"finding_id": "finding-0001"}]},
        "planner_trace": {
            "source_research": {"engine": "stub"},
            "graph_research": {"engine": "stub"},
            "web_research": {"engine": "stub"},
            "hypothesis_board": {"engine": "stub"},
            "skeptic": {"engine": "stub"},
            "experiment": {"engine": "stub"},
            "research_branch_errors": {"source": {"error": "x"}},
        },
    }

    result = graph_mod._node_select_objective(state)

    assert result["active_objective"].objective_id == "obj-next"
    assert result["research_tasks"] == []
    assert result["research_findings"] == []
    assert result["hypothesis_board"] == []
    assert result["refutations"] == []
    assert result["experiment_board"] == []
    assert result["plans_by_candidate"] == {}
    assert result["witness_bundles"] == []
    assert result["iteration_bundles"] == []
    assert result["validation_board"] == {}
    assert result["execution_board"] == {}
    assert result["research_board"] == {}
    assert runtime.shared_context["research_findings"] == []
    assert runtime.shared_context["hypotheses"] == []
    assert runtime.shared_context["refutations"] == []
    assert runtime.shared_context["experiment_board"] == []
    assert runtime.shared_context["witness_bundles"] == []


def test_hypothesis_board_update_uses_detection_board_static_pool(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    candidate = _mk_candidate_custom("cand-00077", ["scip"], line=77)
    matching_static = _mk_evidence("cand-00077", "scip::cmd::77")
    stale_static = _mk_evidence("cand-00001", "joern::sql::1")
    objective = ObjectiveScore(
        objective_id="obj-cmdi",
        title="CMDi",
        rationale="test",
        expected_info_gain=0.8,
        priority=0.8,
        channels=["source", "graph", "web"],
    )
    runtime = SimpleNamespace(shared_context={}, checkpoint_dir=str(tmp_path / ".padv" / "langgraph"))
    monkeypatch.setattr(graph_mod, "_state_runtime", lambda state: runtime)
    monkeypatch.setattr(graph_mod, "update_agent_runtime_context", lambda *args, **kwargs: None)
    monkeypatch.setattr(graph_mod, "_persist_agent_workspace_artifact", lambda *args, **kwargs: "artifact.json")
    monkeypatch.setattr(
        graph_mod,
        "synthesize_hypotheses_with_subagent",
        lambda *_args, **_kwargs: (
            [
                Hypothesis(
                    hypothesis_id="hyp-0077",
                    objective_id="obj-cmdi",
                    vuln_class="command_injection",
                    title="cmdi",
                    rationale="test",
                    evidence_refs=["cand-00077", matching_static.hash],
                    candidate=candidate,
                    confidence=0.9,
                )
            ],
            {"engine": "stub"},
        ),
    )

    state: graph_mod.GraphState = {
        "config": config,
        "run_id": "run-detection-board-static-fallback",
        "repo_root": str(tmp_path),
        "store": EvidenceStore(tmp_path / ".padv"),
        "run_validation": True,
        "active_objective": objective,
        "research_findings": [],
        "frontier_state": {},
        "artifact_refs": [],
        "static_evidence": [stale_static],
        "detection_board": {
            "candidates": [candidate.to_dict()],
            "static_evidence": [matching_static.to_dict(), stale_static.to_dict()],
        },
    }

    result = graph_mod._node_hypothesis_board_update(state)

    assert [item.candidate_id for item in result["static_evidence"]] == ["cand-00077"]
    assert result["validation_board"]["static_evidence"][0]["candidate_id"] == "cand-00077"


def test_runtime_execute_filters_resumed_candidates_to_planned_subset(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    candidate_one = _mk_candidate_custom("cand-00001", ["joern"], line=34)
    candidate_two = _mk_candidate_custom("cand-00002", ["scip"], line=52)
    static_one = _mk_evidence("cand-00001", "joern::sql::1")
    static_two = _mk_evidence("cand-00002", "scip::sql::2")
    seen: dict[str, list[str]] = {}

    monkeypatch.setattr(
        graph_mod,
        "validate_candidates_runtime",
        lambda **kwargs: (
            seen.setdefault("candidate_ids", [item.candidate_id for item in kwargs["candidates"]]),
            seen.setdefault("static_ids", [item.candidate_id for item in kwargs["static_evidence"]]),
            [EvidenceBundle(
                bundle_id="bundle-0001",
                created_at="2026-03-14T00:00:00+00:00",
                candidate=candidate_one,
                static_evidence=[static_one],
                positive_runtime=[],
                negative_runtime=[],
                repro_run_ids=[],
                gate_result=GateResult("DROPPED", ["V0"], "V3", "test"),
                limitations=[],
            )],
            {"VALIDATED": 0, "DROPPED": 1, "NEEDS_HUMAN_SETUP": 0},
        )[2:],
    )

    state: graph_mod.GraphState = {
        "config": config,
        "run_id": "run-runtime-filter",
        "repo_root": str(tmp_path),
        "store": EvidenceStore(tmp_path / ".padv"),
        "run_validation": True,
        "candidates": [candidate_one, candidate_two],
        "static_evidence": [static_one, static_two],
        "plans_by_candidate": {
            "cand-00001": ValidationPlan(
                candidate_id="cand-00001",
                intercepts=["mysqli_query"],
                oracle_functions=["mysqli_query"],
                positive_requests=[{"method": "GET", "path": "/", "query": {"x": "1"}}] * 3,
                negative_requests=[{"method": "GET", "path": "/", "query": {"x": "0"}}],
                canary="x",
            )
        },
        "planner_trace": {},
        "discovery_trace": {},
        "artifact_refs": [],
        "auth_state": {},
    }

    result = graph_mod._node_runtime_execute(state)

    assert seen["candidate_ids"] == ["cand-00001"]
    assert seen["static_ids"] == ["cand-00001"]
    assert [item.candidate_id for item in result["candidates"]] == ["cand-00001"]
    assert [item.candidate_id for item in result["static_evidence"]] == ["cand-00001"]


def test_selected_static_for_hypotheses_matches_rewritten_candidate_refs() -> None:
    candidate = _mk_candidate_custom("cand-derived", ["joern"], line=101, file_path="src/ws.php")
    candidate.evidence_refs = ["joern::command_injection_boundary:src/ws.php:101"]
    hypothesis = Hypothesis(
        hypothesis_id="hyp-1",
        objective_id="obj-1",
        vuln_class="command_injection_boundary",
        title="derived cmdi",
        rationale="copied from research evidence",
        evidence_refs=["src/ws.php:93-107"],
        candidate=candidate,
    )
    matching_static = StaticEvidence(
        candidate_id="cand-source",
        query_profile="default",
        query_id="joern::command_injection_boundary",
        file_path="src/ws.php",
        line=101,
        snippet="shell_exec($target)",
        hash="h-cmdi",
    )
    stale_static = StaticEvidence(
        candidate_id="cand-other",
        query_profile="default",
        query_id="joern::command_injection_boundary",
        file_path="src/other.php",
        line=44,
        snippet="shell_exec($other)",
        hash="h-other",
    )

    selected = graph_mod._selected_static_for_hypotheses([hypothesis], [matching_static, stale_static])

    assert [(item.candidate_id, item.hash) for item in selected] == [("cand-source", "h-cmdi")]


def test_runtime_execute_retains_static_evidence_matched_by_evidence_refs(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    candidate = _mk_candidate_custom("cand-derived", ["joern"], line=12)
    candidate.evidence_refs = ["joern::sql::1:src/a.php:12"]
    static_source = _mk_evidence("cand-source", "joern::sql::1")
    stale_static = StaticEvidence(
        candidate_id="cand-stale",
        query_profile="default",
        query_id="scip::sql::2",
        file_path="src/other.php",
        line=44,
        snippet="mysqli_query($other, $q)",
        hash="h-stale",
    )
    seen: dict[str, list[str]] = {}

    monkeypatch.setattr(
        graph_mod,
        "validate_candidates_runtime",
        lambda **kwargs: (
            seen.setdefault("candidate_ids", [item.candidate_id for item in kwargs["candidates"]]),
            seen.setdefault("static_ids", [item.candidate_id for item in kwargs["static_evidence"]]),
            [EvidenceBundle(
                bundle_id="bundle-0002",
                created_at="2026-03-14T00:00:00+00:00",
                candidate=candidate,
                static_evidence=[static_source],
                positive_runtime=[],
                negative_runtime=[],
                repro_run_ids=[],
                gate_result=GateResult("DROPPED", ["V0"], "V3", "test"),
                limitations=[],
            )],
            {"VALIDATED": 0, "DROPPED": 1, "NEEDS_HUMAN_SETUP": 0},
        )[2:],
    )

    state: graph_mod.GraphState = {
        "config": config,
        "run_id": "run-runtime-derived-static",
        "repo_root": str(tmp_path),
        "store": EvidenceStore(tmp_path / ".padv"),
        "run_validation": True,
        "candidates": [candidate],
        "static_evidence": [static_source, stale_static],
        "plans_by_candidate": {
            candidate.candidate_id: ValidationPlan(
                candidate_id=candidate.candidate_id,
                intercepts=["mysqli_query"],
                oracle_functions=["mysqli_query"],
                positive_requests=[{"method": "GET", "path": "/", "query": {"x": "1"}}] * 3,
                negative_requests=[{"method": "GET", "path": "/", "query": {"x": "0"}}],
                canary="x",
            )
        },
        "planner_trace": {},
        "discovery_trace": {},
        "artifact_refs": [],
        "auth_state": {},
    }

    result = graph_mod._node_runtime_execute(state)

    assert seen["candidate_ids"] == ["cand-derived"]
    assert seen["static_ids"] == ["cand-source"]


def test_runtime_execute_recovers_candidates_from_selected_pool(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    candidate = _mk_candidate_custom("cand-derived", ["joern"], line=12)
    candidate.evidence_refs = ["plan-alias", "joern::sql::1:src/a.php:12"]
    static_source = _mk_evidence("cand-source", "joern::sql::1")
    seen: dict[str, list[str]] = {}

    monkeypatch.setattr(
        graph_mod,
        "validate_candidates_runtime",
        lambda **kwargs: (
            seen.setdefault("candidate_ids", [item.candidate_id for item in kwargs["candidates"]]),
            seen.setdefault("static_ids", [item.candidate_id for item in kwargs["static_evidence"]]),
            [EvidenceBundle(
                bundle_id="bundle-runtime-recover",
                created_at="2026-03-14T00:00:00+00:00",
                candidate=candidate,
                static_evidence=[static_source],
                positive_runtime=[],
                negative_runtime=[],
                repro_run_ids=[],
                gate_result=GateResult("DROPPED", ["V0"], "V3", "test"),
                limitations=[],
            )],
            {"VALIDATED": 0, "DROPPED": 1, "NEEDS_HUMAN_SETUP": 0},
        )[2:],
    )

    state: graph_mod.GraphState = {
        "config": config,
        "run_id": "run-runtime-selected-pool",
        "repo_root": str(tmp_path),
        "store": EvidenceStore(tmp_path / ".padv"),
        "candidates": [],
        "selected_candidates": [candidate],
        "static_evidence": [],
        "selected_static": [static_source],
        "plans_by_candidate": {
            candidate.candidate_id: ValidationPlan(
                candidate_id=candidate.candidate_id,
                intercepts=["mysqli_query"],
                positive_requests=[{"method": "GET", "path": "/", "query": {"x": "1"}}],
                negative_requests=[{"method": "GET", "path": "/", "query": {"x": "0"}}],
                canary="x",
            )
        },
        "planner_trace": {},
        "discovery_trace": {},
        "artifact_refs": [],
        "auth_state": {},
        "run_validation": True,
    }

    result = graph_mod._node_runtime_execute(state)

    assert seen["candidate_ids"] == ["cand-derived"]
    assert seen["static_ids"] == ["cand-source"]
    assert result["decisions"]["DROPPED"] == 1
    assert [item.candidate_id for item in result["static_evidence"]] == ["cand-source"]


def test_evidence_reduce_does_not_reuse_stale_witness_bundles(tmp_path: Path) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    runtime = SimpleNamespace(shared_context={}, checkpoint_dir=str(tmp_path / ".padv" / "langgraph"))
    state: graph_mod.GraphState = {
        "config": config,
        "run_id": "run-no-reuse-evidence",
        "repo_root": str(tmp_path),
        "store": EvidenceStore(tmp_path / ".padv"),
        "run_validation": True,
        "witness_bundles": ["stale"],
        "runtime_history": [{"bundle_id": "stale"}],
        "iteration_bundles": [],
        "execution_board": {},
        "agent_runtime": runtime,
    }

    result = graph_mod._node_evidence_reduce(state)

    assert result["witness_bundles"] == []
    assert result["runtime_history"] == [{"bundle_id": "stale"}]
    assert result["execution_board"]["witness_bundles"] == []
    assert result["execution_board"]["runtime_history"] == [{"bundle_id": "stale"}]


def test_deterministic_gate_does_not_short_circuit_on_stale_gate_history(tmp_path: Path) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    runtime = SimpleNamespace(shared_context={}, checkpoint_dir=str(tmp_path / ".padv" / "langgraph"))
    state: graph_mod.GraphState = {
        "config": config,
        "run_id": "run-no-reuse-gate",
        "repo_root": str(tmp_path),
        "store": EvidenceStore(tmp_path / ".padv"),
        "run_validation": True,
        "gate_history": [{"bundle_id": "old", "decision": "DROPPED"}],
        "iteration_bundles": [],
        "decisions": {"DROPPED": 1},
        "agent_runtime": runtime,
    }

    result = graph_mod._node_deterministic_gate(state)

    assert result["gate_history"] == [{"bundle_id": "old", "decision": "DROPPED"}]
    assert result["gate_board"]["gate_history"] == [{"bundle_id": "old", "decision": "DROPPED"}]


def test_agent_runtime_uses_run_scoped_checkpoint_dir(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    store = EvidenceStore(tmp_path / ".padv")
    _force_node_runner(monkeypatch)
    state = _install_agent_stubs(monkeypatch, tmp_path)

    candidate = _mk_candidate_custom("cand-00001", ["joern"], line=34)
    static = _mk_evidence("cand-00001", "joern::sql::2")
    monkeypatch.setattr(
        "padv.orchestrator.graphs.discover_candidates_with_meta",
        lambda *_args, **_kwargs: ([candidate], [static], _mk_joern_meta(findings=1, app_findings=1, candidate_count=1)),
    )
    monkeypatch.setattr(
        "padv.orchestrator.graphs.discover_scip_candidates_safe_with_meta",
        lambda *_args, **_kwargs: ([], [], [], _mk_scip_meta(), None),
    )
    monkeypatch.setattr("padv.orchestrator.graphs.discover_web_inventory", lambda *_args, **_kwargs: ({}, {}, None))

    analyze_with_graph(config, str(tmp_path), store, "variant")

    checkpoint_dir = Path(str(state["last_checkpoint_dir"]))
    assert checkpoint_dir.name.startswith("analyze-")
    assert checkpoint_dir.parent == store.langgraph_dir


def test_persisted_frontier_omits_agent_thread_metadata(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    store = EvidenceStore(tmp_path / ".padv")
    _force_node_runner(monkeypatch)
    state = _install_agent_stubs(monkeypatch, tmp_path)

    frontier_state = {
        "iteration": 4,
        "stagnation_rounds": 1,
        "coverage": {"files": [], "classes": [], "signals": [], "sinks": [], "web_paths": []},
        "history": [],
        "hypotheses": [],
        "failed_paths": [],
        "attempt_history": [],
        "candidate_resume": {},
        "runtime_coverage": {"flags": [], "classes": []},
        "agent_threads": {"root": "padv-root-old"},
        "agent_thread_id": "legacy-old-thread",
    }
    store.save_frontier_state(frontier_state)

    candidate = _mk_candidate_custom("cand-00001", ["joern"], line=34)
    static = _mk_evidence("cand-00001", "joern::sql::2")
    monkeypatch.setattr(
        "padv.orchestrator.graphs.discover_candidates_with_meta",
        lambda *_args, **_kwargs: ([candidate], [static], _mk_joern_meta(findings=1, app_findings=1, candidate_count=1)),
    )
    monkeypatch.setattr(
        "padv.orchestrator.graphs.discover_scip_candidates_safe_with_meta",
        lambda *_args, **_kwargs: ([], [], [], _mk_scip_meta(), None),
    )
    monkeypatch.setattr("padv.orchestrator.graphs.discover_web_inventory", lambda *_args, **_kwargs: ({}, {}, None))

    analyze_with_graph(config, str(tmp_path), store, "variant")

    persisted = store.load_frontier_state()
    assert persisted is not None
    assert "agent_threads" not in persisted
    assert "agent_thread_id" not in persisted
    assert "agent_threads" not in state["runtime"].shared_context["frontier_state"]


def test_frontier_state_resets_when_target_scope_changes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    config.target.base_url = "http://127.0.0.1:18080/"
    store = EvidenceStore(tmp_path / ".padv")
    _force_node_runner(monkeypatch)
    state = _install_agent_stubs(monkeypatch, tmp_path)

    stale_frontier = {
        "version": 1,
        "updated_at": "2026-03-07T00:00:00+00:00",
        "iteration": 12,
        "stagnation_rounds": 3,
        "coverage": {
            "files": ["phpmyfaq/index.php"],
            "classes": ["xss_output_boundary"],
            "signals": ["joern"],
            "sinks": ["echo"],
            "web_paths": ["/admin.php"],
        },
        "history": [{"iteration": 12}],
        "hypotheses": [],
        "failed_paths": [{"path": "phpmyfaq/index.php", "reason": "stale", "iteration": 12}],
        "attempt_history": [],
        "candidate_resume": {"old": {"candidate_id": "cand-old"}},
        "runtime_coverage": {"flags": [], "classes": []},
        "target_scope": {
            "repo_root": "/workspace/targets/phpmyfaq",
            "base_url": "http://host.docker.internal:18080/index.php",
            "fingerprint": "phpmyfaq-stale",
        },
    }
    store.save_frontier_state(stale_frontier)

    candidate = _mk_candidate_custom("cand-00001", ["joern"], line=34)
    static = _mk_evidence("cand-00001", "joern::sql::2")
    monkeypatch.setattr(
        "padv.orchestrator.graphs.discover_candidates_with_meta",
        lambda *_args, **_kwargs: ([candidate], [static], _mk_joern_meta(findings=1, app_findings=1, candidate_count=1)),
    )
    monkeypatch.setattr(
        "padv.orchestrator.graphs.discover_scip_candidates_safe_with_meta",
        lambda *_args, **_kwargs: ([], [], [], _mk_scip_meta(), None),
    )
    monkeypatch.setattr("padv.orchestrator.graphs.discover_web_inventory", lambda *_args, **_kwargs: ({"/": []}, {"pages": [], "requests": []}, None))

    analyze_with_graph(config, str(tmp_path), store, "variant")

    persisted = store.load_frontier_state()
    assert persisted is not None
    assert "phpmyfaq/index.php" not in persisted["coverage"]["files"]
    assert persisted["target_scope"]["base_url"] == "http://127.0.0.1:18080/"
    assert persisted["target_scope"]["repo_root"] == str(tmp_path.resolve())


def test_analyze_resume_reuses_graph_checkpoint_after_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    pytest.importorskip("langgraph")
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    store = EvidenceStore(tmp_path / ".padv")
    _install_agent_stubs(monkeypatch, tmp_path)

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
    monkeypatch.setattr(
        "padv.orchestrator.graphs.discover_web_inventory",
        lambda *_args, **_kwargs: ({"/": ["q"]}, {"pages": [], "requests": []}, None),
    )

    counters = {"static": 0, "select": 0}
    original_static = graph_mod._node_static_discovery
    original_select = graph_mod._node_select_objective

    def _count_static(state: graph_mod.GraphState) -> graph_mod.GraphState:
        counters["static"] += 1
        return original_static(state)

    def _fail_then_resume(state: graph_mod.GraphState) -> graph_mod.GraphState:
        counters["select"] += 1
        if counters["select"] == 1:
            raise RuntimeError("resume-me")
        return original_select(state)

    monkeypatch.setattr(graph_mod, "_node_static_discovery", _count_static)
    monkeypatch.setattr(graph_mod, "_node_select_objective", _fail_then_resume)

    with pytest.raises(RuntimeError, match="resume-me"):
        analyze_with_graph(config, str(tmp_path), store, "variant")

    resume_meta = store.latest_resumable_run(
        mode="variant",
        run_validation=False,
        target_signature=graph_mod._target_signature_for(str(tmp_path.resolve()), str(config.target.base_url or "")),
        config_signature=graph_mod._config_signature(config, "variant", False),
    )
    assert resume_meta is not None
    assert resume_meta["status"] == "failed"
    assert resume_meta["thread_id"].startswith("graph-analyze-")
    assert counters["static"] == 1
    assert counters["select"] == 1

    candidates, static_evidence, _trace = analyze_with_graph(
        config,
        str(tmp_path),
        store,
        "variant",
        resume_run_id=str(resume_meta["run_id"]),
    )

    assert counters["static"] == 1
    assert counters["select"] >= 2
    assert candidates
    assert static_evidence

    resumed_meta = store.load_resume_metadata(str(resume_meta["run_id"]))
    assert resumed_meta is not None
    assert resumed_meta["status"] == "completed"
    assert resumed_meta["thread_id"] == resume_meta["thread_id"]


def test_analyze_resume_latest_uses_newest_compatible_metadata(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    store = EvidenceStore(tmp_path / ".padv")
    target_signature = graph_mod._target_signature_for(str(tmp_path.resolve()), str(config.target.base_url or ""))
    config_signature = graph_mod._config_signature(config, "variant", False)
    store.save_resume_metadata(
        "analyze-old",
        {
            "run_id": "analyze-old",
            "thread_id": "graph-analyze-old",
            "checkpoint_id": "cp-old",
            "status": "failed",
            "mode": "variant",
            "run_validation": False,
            "repo_root": str(tmp_path.resolve()),
            "base_url": str(config.target.base_url or ""),
            "target_signature": target_signature,
            "config_signature": config_signature,
            "started_at": "2026-03-08T10:00:00+00:00",
            "updated_at": "2026-03-08T10:01:00+00:00",
            "next_nodes": ["select_objective"],
            "error": "boom",
        },
    )
    store.save_resume_metadata(
        "analyze-new",
        {
            "run_id": "analyze-new",
            "thread_id": "graph-analyze-new",
            "checkpoint_id": "cp-new",
            "status": "open",
            "mode": "variant",
            "run_validation": False,
            "repo_root": str(tmp_path.resolve()),
            "base_url": str(config.target.base_url or ""),
            "target_signature": target_signature,
            "config_signature": config_signature,
            "started_at": "2026-03-08T11:00:00+00:00",
            "updated_at": "2026-03-08T11:01:00+00:00",
            "next_nodes": ["orient"],
            "error": "",
        },
    )
    store.save_resume_metadata(
        "analyze-wrong",
        {
            "run_id": "analyze-wrong",
            "thread_id": "graph-analyze-wrong",
            "checkpoint_id": "cp-wrong",
            "status": "open",
            "mode": "variant",
            "run_validation": False,
            "repo_root": str(tmp_path.resolve()),
            "base_url": str(config.target.base_url or ""),
            "target_signature": "wrong-target",
            "config_signature": config_signature,
            "started_at": "2026-03-08T12:00:00+00:00",
            "updated_at": "2026-03-08T12:01:00+00:00",
            "next_nodes": ["orient"],
            "error": "",
        },
    )

    seen: dict[str, object] = {}

    def _fake_run(state: graph_mod.GraphState, include_validation: bool) -> graph_mod.GraphState:
        seen["run_id"] = state["run_id"]
        seen["resume_mode"] = state["resume_mode"]
        seen["graph_thread_id"] = state["graph_thread_id"]
        seen["graph_checkpoint_id"] = state["graph_checkpoint_id"]
        return {"candidates": [], "static_evidence": [], "discovery_trace": {}, **state}

    monkeypatch.setattr(graph_mod, "_run_langgraph", _fake_run)

    analyze_with_graph(config, str(tmp_path), store, "variant", resume_run_id="latest")

    assert seen["run_id"] == "analyze-new"
    assert seen["resume_mode"] is True
    assert seen["graph_thread_id"] == "graph-analyze-new"
    assert seen["graph_checkpoint_id"] == "cp-new"


def test_latest_resumable_run_accepts_yielded_status(tmp_path: Path) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    store = EvidenceStore(tmp_path / ".padv")
    target_signature = graph_mod._target_signature_for(str(tmp_path.resolve()), str(config.target.base_url or ""))
    config_signature = graph_mod._config_signature(config, "variant", False)
    store.save_resume_metadata(
        "analyze-yielded",
        {
            "run_id": "analyze-yielded",
            "thread_id": "graph-analyze-yielded",
            "checkpoint_id": "cp-yielded",
            "status": "yielded",
            "mode": "variant",
            "run_validation": False,
            "repo_root": str(tmp_path.resolve()),
            "base_url": str(config.target.base_url or ""),
            "target_signature": target_signature,
            "config_signature": config_signature,
            "started_at": "2026-03-08T11:00:00+00:00",
            "updated_at": "2026-03-08T11:01:00+00:00",
            "next_nodes": ["orient"],
            "error": "source yielded after max agent turns: 2",
            "soft_yield": {"role": "source", "category": "source_research", "turn": 2},
        },
    )

    resume_meta = store.latest_resumable_run(
        mode="variant",
        run_validation=False,
        target_signature=target_signature,
        config_signature=config_signature,
    )

    assert resume_meta is not None
    assert resume_meta["run_id"] == "analyze-yielded"
    assert resume_meta["status"] == "yielded"


def test_analyze_persists_failed_resume_metadata_on_keyboardinterrupt(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    pytest.importorskip("langgraph")
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    store = EvidenceStore(tmp_path / ".padv")
    _install_agent_stubs(monkeypatch, tmp_path)

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
    original_web = graph_mod._node_web_discovery
    hit = {"raised": False}

    def _interrupt_once(state: graph_mod.GraphState) -> graph_mod.GraphState:
        if not hit["raised"]:
            hit["raised"] = True
            raise KeyboardInterrupt()
        return original_web(state)

    monkeypatch.setattr(graph_mod, "_node_web_discovery", _interrupt_once)

    with pytest.raises(KeyboardInterrupt):
        analyze_with_graph(config, str(tmp_path), store, "variant")

    resume_meta = store.latest_resumable_run(
        mode="variant",
        run_validation=False,
        target_signature=graph_mod._target_signature_for(str(tmp_path.resolve()), str(config.target.base_url or "")),
        config_signature=graph_mod._config_signature(config, "variant", False),
    )
    assert resume_meta is not None
    assert resume_meta["status"] == "failed"
    assert resume_meta["error"] == "KeyboardInterrupt"


def test_analyze_persists_yielded_resume_metadata_on_agent_soft_yield(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    pytest.importorskip("langgraph")
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    store = EvidenceStore(tmp_path / ".padv")
    _install_agent_stubs(monkeypatch, tmp_path)

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
    original_orient = graph_mod._node_orient
    hit = {"raised": False}

    def _yield_once(state: graph_mod.GraphState) -> graph_mod.GraphState:
        if not hit["raised"]:
            hit["raised"] = True
            raise AgentSoftYield(
                "source yielded after max agent turns: 2",
                role="source",
                category="source_research",
                turn=2,
                handoff_ref="source/handoffs/test.json",
                progress_ref="source/yields/test.json",
                response_ref="source/responses/test.json",
                last_response={"status": "continue", "focus": "keep digging"},
            )
        return original_orient(state)

    monkeypatch.setattr(graph_mod, "_node_orient", _yield_once)

    with pytest.raises(AgentSoftYield):
        analyze_with_graph(config, str(tmp_path), store, "variant")

    resume_meta = store.latest_resumable_run(
        mode="variant",
        run_validation=False,
        target_signature=graph_mod._target_signature_for(str(tmp_path.resolve()), str(config.target.base_url or "")),
        config_signature=graph_mod._config_signature(config, "variant", False),
    )
    assert resume_meta is not None
    assert resume_meta["status"] == "yielded"
    assert resume_meta["soft_yield"]["category"] == "source_research"
    assert resume_meta["soft_yield"]["turn"] == 2


def test_validate_with_graph_bypasses_langgraph_objective_and_research_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    config.auth.enabled = False
    store = EvidenceStore(tmp_path / ".padv")
    candidate = _mk_candidate("cand-00001", ["joern"])
    static = _mk_evidence("cand-00001", "joern::sql")

    def _forbidden(*_args, **_kwargs):
        raise AssertionError("validate-only direct path should not call graph research/objective functions")

    monkeypatch.setattr(graph_mod, "_run_langgraph", _forbidden)
    monkeypatch.setattr(graph_mod, "orient_root_agent", _forbidden)
    monkeypatch.setattr(graph_mod, "select_objective_with_root_agent", _forbidden)
    monkeypatch.setattr(graph_mod, "run_research_subagent", _forbidden)
    monkeypatch.setattr(
        graph_mod,
        "make_validation_plans_with_deepagents",
        lambda candidates, *_args, **_kwargs: (
            {
                item.candidate_id: ValidationPlan(
                    candidate_id=item.candidate_id,
                    intercepts=["mysqli_query"],
                    oracle_functions=["mysqli_query"],
                    positive_requests=[{"method": "GET", "path": "/", "query": {"x": "1"}}] * 3,
                    negative_requests=[{"method": "GET", "path": "/", "query": {"x": "0"}}],
                    canary="padv-canary",
                )
                for item in candidates
            },
            {"engine": "stub", "planned_candidate_ids": [item.candidate_id for item in candidates]},
        ),
    )

    def _fake_validate_candidates_runtime(**kwargs):
        decisions = graph_mod._default_decisions()
        decisions["DROPPED"] = 1
        return (
            [
                EvidenceBundle(
                    bundle_id="bundle-run-validate-direct-cand-00001",
                    created_at="2026-04-05T00:00:00+00:00",
                    candidate=candidate,
                    static_evidence=kwargs["static_evidence"],
                    positive_runtime=[],
                    negative_runtime=[],
                    repro_run_ids=[],
                    gate_result=GateResult("DROPPED", ["V0"], "V3", "test"),
                    limitations=["test"],
                )
            ],
            decisions,
        )

    monkeypatch.setattr(graph_mod, "validate_candidates_runtime", _fake_validate_candidates_runtime)

    bundles, decisions = graph_mod.validate_with_graph(
        config=config,
        store=store,
        static_evidence=[static],
        candidates=[candidate],
        run_id="run-validate-direct",
        repo_root=str(tmp_path),
    )

    assert [item.bundle_id for item in bundles] == ["bundle-run-validate-direct-cand-00001"]
    assert decisions["DROPPED"] == 1
    assert [item.candidate_id for item in store.for_run("run-validate-direct").load_candidates()] == ["cand-00001"]
    assert [item.candidate_id for item in store.for_run("run-validate-direct").load_static_evidence()] == ["cand-00001"]


def test_validate_with_graph_direct_path_uses_selected_candidates_and_linked_static(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    config.auth.enabled = False
    store = EvidenceStore(tmp_path / ".padv")
    candidate = _mk_candidate_custom("cand-derived", ["joern"], line=12)
    candidate.evidence_refs = ["joern::sql::1:src/a.php:12"]
    static_source = _mk_evidence("cand-source", "joern::sql::1")
    stale_static = StaticEvidence(
        candidate_id="cand-stale",
        query_profile="default",
        query_id="scip::sql::2",
        file_path="src/other.php",
        line=44,
        snippet="mysqli_query($other, $q)",
        hash="h-stale",
    )
    seen: dict[str, list[str]] = {}

    monkeypatch.setattr(
        graph_mod,
        "make_validation_plans_with_deepagents",
        lambda candidates, *_args, **_kwargs: (
            {
                item.candidate_id: ValidationPlan(
                    candidate_id=item.candidate_id,
                    intercepts=["mysqli_query"],
                    oracle_functions=["mysqli_query"],
                    positive_requests=[{"method": "GET", "path": "/", "query": {"x": "1"}}] * 3,
                    negative_requests=[{"method": "GET", "path": "/", "query": {"x": "0"}}],
                    canary="padv-canary",
                )
                for item in candidates
            },
            {"engine": "stub", "planned_candidate_ids": [item.candidate_id for item in candidates]},
        ),
    )

    def _fake_validate_candidates_runtime(**kwargs):
        seen["candidate_ids"] = [item.candidate_id for item in kwargs["candidates"]]
        seen["static_ids"] = [item.candidate_id for item in kwargs["static_evidence"]]
        decisions = graph_mod._default_decisions()
        decisions["NEEDS_HUMAN_SETUP"] = 1
        return (
            [
                EvidenceBundle(
                    bundle_id="bundle-run-validate-selected-cand-derived",
                    created_at="2026-04-05T00:00:00+00:00",
                    candidate=candidate,
                    static_evidence=kwargs["static_evidence"],
                    positive_runtime=[],
                    negative_runtime=[],
                    repro_run_ids=[],
                    gate_result=GateResult(
                        "NEEDS_HUMAN_SETUP",
                        ["V0"],
                        "V1",
                        "typed_preconditions_unresolved: unknown_blockers=upload required",
                    ),
                    limitations=["typed_preconditions_unresolved: unknown_blockers=upload required"],
                )
            ],
            decisions,
        )

    monkeypatch.setattr(graph_mod, "validate_candidates_runtime", _fake_validate_candidates_runtime)

    bundles, decisions = graph_mod.validate_with_graph(
        config=config,
        store=store,
        static_evidence=[static_source, stale_static],
        candidates=[candidate],
        run_id="run-validate-selected",
        repo_root=str(tmp_path),
    )

    assert seen["candidate_ids"] == ["cand-derived"]
    assert seen["static_ids"] == ["cand-source"]
    assert [item.bundle_id for item in bundles] == ["bundle-run-validate-selected-cand-derived"]
    assert decisions["NEEDS_HUMAN_SETUP"] == 1
    assert [item.candidate_id for item in store.for_run("run-validate-selected").load_static_evidence()] == ["cand-source"]

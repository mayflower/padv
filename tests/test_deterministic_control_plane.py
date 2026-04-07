from __future__ import annotations

from typing import Any
import pytest
from pathlib import Path

from padv.orchestrator.graphs import _deterministic_continue_decision
from padv.orchestrator.runtime import validate_candidates_runtime, GateResult
from padv.models import Candidate, StaticEvidence, ValidationPlan, PlanBudget
from padv.config.schema import PadvConfig, TargetConfig, OracleConfig, CanaryConfig, BudgetConfig, SandboxConfig, StoreConfig
from padv.store.evidence_store import EvidenceStore
from padv.config.schema import load_config

def get_dummy_config() -> PadvConfig:
    return load_config(Path(__file__).resolve().parents[1] / "padv.toml")

def test_tiny_budget_tail_candidates_skipped(monkeypatch, tmp_path):
    config = get_dummy_config()
    config.budgets.max_requests = 1 # VERY SMALL BUDGET
    
    store = EvidenceStore(tmp_path / ".padv")
    
    cand1 = Candidate(candidate_id="c1", vuln_class="sql_injection_boundary", title="C1", file_path="c1.php", line=1, sink="exec", expected_intercepts=[])
    cand2 = Candidate(candidate_id="c2", vuln_class="sql_injection_boundary", title="C2", file_path="c2.php", line=2, sink="exec", expected_intercepts=[])
    
    plan1 = ValidationPlan(candidate_id="c1", intercepts=[], positive_requests=[{"method": "GET"}], negative_requests=[], canary="c")
    plan2 = ValidationPlan(candidate_id="c2", intercepts=[], positive_requests=[{"method": "GET"}], negative_requests=[], canary="c")
    
    def fake_process_candidate(ctx, target, request_budget_remaining, run_deadline):
        from padv.models import EvidenceBundle, GateResult
        # Cost is 1 request per candidate
        class FakeBundle:
            candidate_outcome = "VALIDATED"
            gate_result = GateResult("VALIDATED", [], "V0", "test")
            candidate_uid = "abc"
            def to_dict(self): return {}
        return FakeBundle(), 1

    monkeypatch.setattr("padv.orchestrator.runtime._process_candidate", fake_process_candidate)

    bundles, decisions = validate_candidates_runtime(
        config=config,
        store=store,
        static_evidence=[],
        candidates=[cand1, cand2],
        run_id="run-1",
        plans_by_candidate={"c1": plan1, "c2": plan2},
    )

    # First candidate processed, cost=1. Budget exhausted. Second should be SKIPPED_BUDGET
    assert len(bundles) == 2
    assert getattr(bundles[0], "candidate_outcome", bundles[0].gate_result.decision) == "VALIDATED"
    
    # Check that second candidate is correctly skipped
    assert getattr(bundles[1], "candidate_outcome", bundles[1].gate_result.decision) == "SKIPPED_BUDGET"

def test_stagnation_stop_triggers_at_n_rounds():
    # Mocking GraphState config for graph orchestration
    class FakeAgentConfig:
        max_iterations = 10
        improvement_patience = 2
        
    class FakeConfig:
        agent = FakeAgentConfig()

    state = {
        "config": FakeConfig(),
        "run_iteration": 3,
        "frontier_state": {
            "stagnation_rounds": 3 # greater than patience (2)
        },
        "decisions": {}
    }
    
    continue_run, trace = _deterministic_continue_decision(state, [{}])
    assert continue_run is False
    assert trace["stop_rule"] == "stagnation"

def test_nothing_validated_disambiguation_test():
    # If there are no candidates left, it should be unambiguously documented as "no runnable candidates" rather than stagnation or budget
    class FakeAgentConfig:
        max_iterations = 10
        improvement_patience = 2
        
    class FakeConfig:
        agent = FakeAgentConfig()

    state = {
        "config": FakeConfig(),
        "run_iteration": 1,
        "frontier_state": {
            "stagnation_rounds": 0
        },
        "decisions": {
            "DROPPED": 5
        }
    }
    
    # 0 remaining objectives passed
    continue_run, trace = _deterministic_continue_decision(state, [])
    assert continue_run is False
    assert trace["stop_rule"] == "no_runnable_candidates"

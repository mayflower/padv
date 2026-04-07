from __future__ import annotations

from padv.models import EvidenceBundle, Candidate, GateResult, RuntimeEvidence, WitnessEvidence
from padv.eval.coverage import evaluate_run_coverage

def test_attempted_but_dropped_is_none():
    cand = Candidate("1", "sql_injection", "", "", 1, "", [])
    b1 = EvidenceBundle(
        bundle_id="1", created_at="", candidate=cand, static_evidence=[],
        positive_runtime=[], negative_runtime=[], repro_run_ids=[],
        gate_result=GateResult("SKIPPED_BUDGET", [], "V0", ""), limitations=[]
    )
    b1.candidate_outcome = "SKIPPED_BUDGET"
    
    b2 = EvidenceBundle(
        bundle_id="2", created_at="", candidate=cand, static_evidence=[],
        positive_runtime=[], negative_runtime=[], repro_run_ids=[],
        gate_result=GateResult("DROPPED", [], "V0", ""), limitations=[]
    )
    b2.candidate_outcome = "REFUTED"
    
    coverage = evaluate_run_coverage([b1, b2])
    assert coverage["sql_injection"] == "NONE"

def test_validated_is_full():
    cand = Candidate("1", "sql_injection", "", "", 1, "", [])
    b = EvidenceBundle(
        bundle_id="1", created_at="", candidate=cand, static_evidence=[],
        positive_runtime=[], negative_runtime=[], repro_run_ids=[],
        gate_result=GateResult("VALIDATED", [], "V0", ""), limitations=[]
    )
    b.candidate_outcome = "VALIDATED"
    
    coverage = evaluate_run_coverage([b])
    assert coverage["sql_injection"] == "FULL"

def test_refuted_with_strong_witness_is_partial():
    cand = Candidate("1", "sql_injection", "", "", 1, "", [])
    pr = RuntimeEvidence(
        request_id="1", status="active", call_count=1, overflow=False,
        arg_truncated=False, result_truncated=False, correlation="1",
        witness_evidence=WitnessEvidence(class_name="sql_injection", witness_flags=["sql_error"])
    )
    b = EvidenceBundle(
        bundle_id="1", created_at="", candidate=cand, static_evidence=[],
        positive_runtime=[pr], negative_runtime=[], repro_run_ids=[],
        gate_result=GateResult("DROPPED", [], "V0", ""), limitations=[]
    )
    b.candidate_outcome = "REFUTED"
    
    coverage = evaluate_run_coverage([b])
    assert coverage["sql_injection"] == "PARTIAL"

def test_coverage_is_run_scoped():
    cand1 = Candidate("1", "sql_injection", "", "", 1, "", [])
    cand2 = Candidate("2", "xss", "", "", 1, "", [])
    
    b1 = EvidenceBundle(
        bundle_id="1", created_at="", candidate=cand1, static_evidence=[],
        positive_runtime=[], negative_runtime=[], repro_run_ids=[],
        gate_result=GateResult("VALIDATED", [], "V0", ""), limitations=[]
    )
    b1.candidate_outcome = "VALIDATED"
    
    b2 = EvidenceBundle(
        bundle_id="2", created_at="", candidate=cand2, static_evidence=[],
        positive_runtime=[], negative_runtime=[], repro_run_ids=[],
        gate_result=GateResult("SKIPPED_BUDGET", [], "V0", ""), limitations=[]
    )
    b2.candidate_outcome = "SKIPPED_BUDGET"
    
    # Passing only b1, run-scoped
    cov1 = evaluate_run_coverage([b1])
    assert "sql_injection" in cov1
    assert "xss" not in cov1
    
    # Passing only b2, run-scoped
    cov2 = evaluate_run_coverage([b2])
    assert cov2["xss"] == "NONE"
    assert "sql_injection" not in cov2

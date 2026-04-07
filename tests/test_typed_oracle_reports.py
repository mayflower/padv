
from __future__ import annotations
from padv.dynamic.http.runner import HttpResponse

import pytest
from padv.models import RuntimeEvidence, GateResult, OracleEvidence, RuntimeCall
from padv.config.schema import PadvConfig, TargetConfig, OracleConfig, CanaryConfig, BudgetConfig, SandboxConfig, StoreConfig
from padv.gates.engine import _evaluate_v0_scope, _has_oracle_hit, _run_has_canary_hit

from padv.config.schema import load_config
from pathlib import Path

def get_dummy_config() -> PadvConfig:
    return load_config(Path(__file__).resolve().parents[1] / "padv.toml")

def test_truncation_prevents_validation():
    # If a run is truncated, status is "insufficient_evidence", v0 scope should drop it with INSUFFICIENT_EVIDENCE
    pos_run = RuntimeEvidence(request_id="1", status="insufficient_evidence", call_count=1, overflow=True, arg_truncated=True, result_truncated=True, correlation="1", calls=[], raw_headers={}, http_status=200, body_excerpt="", location="", analysis_flags=[], aux={})
    
    in_pos, in_neg, v0_fail = _evaluate_v0_scope([pos_run], [])
    assert v0_fail is not None
    assert v0_fail.decision == "INSUFFICIENT_EVIDENCE"
    assert "truncated" in v0_fail.reason

def test_exact_canary_match_positive_negative():
    config = get_dummy_config()
    
    # Positive match in args
    call_with_hit = RuntimeCall(function="mysqli_query", file="a.php", line=1, args=["SELECT * FROM users WHERE id='canary123'"])
    evidence = RuntimeEvidence(request_id="1", status="active", call_count=1, overflow=False, arg_truncated=False, result_truncated=False, correlation="1", calls=[call_with_hit], raw_headers={}, http_status=200, body_excerpt="", location="", analysis_flags=[], aux={})
    
    assert _has_oracle_hit(evidence, {"mysqli_query"}, "canary123", config) is True
    
    # Negative match (no canary in args)
    call_no_hit = RuntimeCall(function="mysqli_query", file="a.php", line=1, args=["SELECT * FROM users WHERE id='123'"])
    evidence_no_hit = RuntimeEvidence(request_id="2", status="active", call_count=1, overflow=False, arg_truncated=False, result_truncated=False, correlation="1", calls=[call_no_hit], raw_headers={}, http_status=200, body_excerpt="", location="", analysis_flags=[], aux={})
    
    assert _has_oracle_hit(evidence_no_hit, {"mysqli_query"}, "canary123", config) is False
    
    # Negative match (function mismatch)
    call_wrong_func = RuntimeCall(function="other_function", file="a.php", line=1, args=["canary123"])
    evidence_wrong_func = RuntimeEvidence(request_id="3", status="active", call_count=1, overflow=False, arg_truncated=False, result_truncated=False, correlation="1", calls=[call_wrong_func], raw_headers={}, http_status=200, body_excerpt="", location="", analysis_flags=[], aux={})
    
    assert _has_oracle_hit(evidence_wrong_func, {"mysqli_query"}, "canary123", config) is False

def test_sql_error_marker_in_body_does_not_validate_without_oracle():
    from padv.validation.contracts import build_runtime_witness
    from padv.orchestrator.runtime import _collect_analysis_flags
    from padv.models import Candidate, ValidationPlan
    
    config = get_dummy_config()
    
    pos_run = RuntimeEvidence(request_id="1", status="active", call_count=1, overflow=False, arg_truncated=False, result_truncated=False, correlation="1", calls=[], raw_headers={}, http_status=200, body_excerpt="Warning: mysqli_query() expects parameter 1 to be mysqli", location="", analysis_flags=[], aux={})
    
    class DummyResponse(HttpResponse):
        def __init__(self):
            super().__init__(status_code=200, headers={}, body=pos_run.body_excerpt)    
    candidate = Candidate(candidate_id="1", vuln_class="sql_injection_boundary", title="", file_path="", line=1, sink="", expected_intercepts=[])
    plan = ValidationPlan(candidate_id="1", intercepts=["mysqli_query"], positive_requests=[], negative_requests=[], canary="canary123")
    
    flags = _collect_analysis_flags(pos_run, DummyResponse(), candidate, plan, config, {}, {}, None)
    
    pos_run.analysis_flags = list(flags)
    
    witness = build_runtime_witness(
        config=config,
        vuln_class="sql_injection_boundary",
        positive_runs=[pos_run],
        negative_runs=[],
        intercepts=["mysqli_query"],
        canary="canary123",
    )
    
    # Because we removed it, it shouldn't be populated via body markers
    assert "sql_error_witness" not in witness.positive_flags
    assert "sql_sink_oracle_witness" not in witness.positive_flags

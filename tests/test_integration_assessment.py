from __future__ import annotations

from padv.eval.integration_assessment import (
    RequirementResult,
    classify_failure,
    matrix_to_gap_list,
    prioritize_gap,
)


def test_classify_failure_detects_common_classes() -> None:
    assert classify_failure("missing or invalid section: joern") == "config"
    assert classify_failure("web discovery failed: playwright timeout") == "discovery_channel"
    assert classify_failure("deepagents invocation failed") == "agent"
    assert classify_failure("Connection refused to host") == "network"
    assert classify_failure("No such file or directory") == "io"


def test_prioritize_gap_mapping() -> None:
    assert prioritize_gap("CORE-INFRA", "FAIL") == "P1"
    assert prioritize_gap("CORE-GRAPH-FLOW", "FAIL") == "P1"
    assert prioritize_gap("CORE-CLI", "PARTIAL") == "P2"
    assert prioritize_gap("E4", "FAIL") == "P2"
    assert prioritize_gap("ANY", "FULL") == ""


def test_requirement_result_normalizes_invalid_status() -> None:
    result = RequirementResult(
        requirement_id="X",
        scenario="s",
        observed_result="o",
        evidence_path="e",
        status="unknown",
        root_cause="r",
        next_fix="n",
    ).to_dict()
    assert result["status"] == "FAIL"


def test_matrix_to_gap_list_sorts_priorities() -> None:
    matrix = [
        {"requirement_id": "E1", "status": "FAIL", "root_cause": "missing", "next_fix": "implement"},
        {"requirement_id": "CORE-RUN", "status": "FAIL", "root_cause": "crash", "next_fix": "stabilize"},
        {"requirement_id": "CORE-CLI", "status": "PARTIAL", "root_cause": "one command failed", "next_fix": "fix"},
        {"requirement_id": "CORE-INFRA", "status": "FULL", "root_cause": "", "next_fix": ""},
    ]
    gaps = matrix_to_gap_list(matrix)
    assert [g["priority"] for g in gaps] == ["P1", "P2", "P2"]
    assert gaps[0]["requirement_id"] == "CORE-RUN"

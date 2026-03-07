from __future__ import annotations

from pathlib import Path

import pytest

from padv.analytics.failure_patterns import analyze_failures, failure_penalty, format_analysis_table
from padv.models import Candidate, EvidenceBundle, FailurePattern, GateResult, RuntimeEvidence, StaticEvidence
from padv.store.evidence_store import EvidenceStore


def _runtime(request_id: str) -> RuntimeEvidence:
    return RuntimeEvidence(
        request_id=request_id,
        status="ok",
        call_count=1,
        overflow=False,
        arg_truncated=False,
        result_truncated=False,
        correlation=request_id,
        calls=[],
        raw_headers={},
    )


def _candidate(candidate_id: str, vuln_class: str, confidence: float, provenance: list[str]) -> Candidate:
    return Candidate(
        candidate_id=candidate_id,
        vuln_class=vuln_class,
        title="test",
        file_path="src/a.php",
        line=10,
        sink="mysqli_query",
        expected_intercepts=["mysqli_query"],
        notes="test",
        provenance=provenance,
        confidence=confidence,
    )


def _static(candidate_id: str) -> StaticEvidence:
    return StaticEvidence(
        candidate_id=candidate_id,
        query_profile="default",
        query_id="source::x",
        file_path="src/a.php",
        line=10,
        snippet="mysqli_query($db,$q)",
        hash=f"h-{candidate_id}",
    )


def _save_bundle(
    store: EvidenceStore,
    *,
    bundle_id: str,
    candidate: Candidate,
    decision: str,
    failed_gate: str | None,
    reason: str,
) -> None:
    bundle = EvidenceBundle(
        bundle_id=bundle_id,
        created_at="2026-03-07T00:00:00+00:00",
        candidate=candidate,
        static_evidence=[_static(candidate.candidate_id)],
        positive_runtime=[_runtime(f"{bundle_id}-p")],
        negative_runtime=[_runtime(f"{bundle_id}-n")],
        repro_run_ids=[f"{bundle_id}-p"],
        gate_result=GateResult(decision, ["V0"], failed_gate, reason),
        limitations=[reason],
    )
    store.save_bundle(bundle)


def test_analyze_failures_extracts_patterns_and_distribution(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path / ".padv")
    _save_bundle(
        store,
        bundle_id="b1",
        candidate=_candidate("cand-1", "xss_output_boundary", 0.40, ["source"]),
        decision="DROPPED",
        failed_gate="V3",
        reason="runtime class signal missing",
    )
    _save_bundle(
        store,
        bundle_id="b2",
        candidate=_candidate("cand-2", "xss_output_boundary", 0.50, ["source", "joern"]),
        decision="DROPPED",
        failed_gate="V3",
        reason="runtime class signal missing",
    )
    _save_bundle(
        store,
        bundle_id="b3",
        candidate=_candidate("cand-3", "xss_output_boundary", 0.45, ["source"]),
        decision="NEEDS_HUMAN_SETUP",
        failed_gate="V3",
        reason="runtime class signal missing",
    )
    _save_bundle(
        store,
        bundle_id="b4",
        candidate=_candidate("cand-4", "sql_injection_boundary", 0.55, ["source"]),
        decision="DROPPED",
        failed_gate="V2",
        reason="insufficient multi-evidence corroboration",
    )
    _save_bundle(
        store,
        bundle_id="b5",
        candidate=_candidate("cand-5", "xss_output_boundary", 0.60, ["source"]),
        decision="VALIDATED",
        failed_gate=None,
        reason="all required gates passed",
    )

    analysis = analyze_failures(store, min_occurrences=2)
    assert analysis.total_candidates_analyzed == 5
    assert analysis.total_failures == 4
    assert analysis.gate_failure_distribution["V3"] == 3
    assert analysis.gate_failure_distribution["V2"] == 1
    assert len(analysis.patterns) == 1

    pattern = analysis.patterns[0]
    assert pattern.vuln_class == "xss_output_boundary"
    assert pattern.failed_gate == "V3"
    assert pattern.occurrence_count == 3
    assert pattern.example_candidate_ids == ["cand-1", "cand-2", "cand-3"]
    assert pattern.provenance_correlation["source"] == pytest.approx(1.0)
    assert pattern.provenance_correlation["joern"] == pytest.approx(0.3333, abs=1e-4)
    assert pattern.confidence_range == (0.4, 0.5)


def test_analyze_failures_respects_min_occurrences(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path / ".padv")
    _save_bundle(
        store,
        bundle_id="b1",
        candidate=_candidate("cand-1", "xss_output_boundary", 0.40, ["source"]),
        decision="DROPPED",
        failed_gate="V3",
        reason="runtime class signal missing",
    )
    analysis = analyze_failures(store, min_occurrences=2)
    assert analysis.patterns == []


def test_failure_penalty_scoring() -> None:
    pattern = FailurePattern(
        pattern_id="fp-001",
        vuln_class="xss_output_boundary",
        failed_gate="V3",
        failure_reason="runtime class signal missing",
        occurrence_count=10,
        example_candidate_ids=["cand-1"],
        provenance_correlation={"source": 0.9, "joern": 0.3},
        confidence_range=(0.4, 0.6),
        suggestion="test",
    )

    score_match = failure_penalty("xss_output_boundary", ["source"], 0.5, [pattern])
    score_off_conf = failure_penalty("xss_output_boundary", ["source"], 0.9, [pattern])
    score_no_match = failure_penalty("sql_injection_boundary", ["source"], 0.5, [pattern])

    assert score_match > score_off_conf > 0.0
    assert score_no_match == 0.0
    assert failure_penalty("xss_output_boundary", ["source"], 0.5, []) == 0.0


def test_format_analysis_table_output(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path / ".padv")
    _save_bundle(
        store,
        bundle_id="b1",
        candidate=_candidate("cand-1", "xss_output_boundary", 0.40, ["source"]),
        decision="DROPPED",
        failed_gate="V3",
        reason="runtime class signal missing",
    )
    _save_bundle(
        store,
        bundle_id="b2",
        candidate=_candidate("cand-2", "xss_output_boundary", 0.50, ["source"]),
        decision="DROPPED",
        failed_gate="V3",
        reason="runtime class signal missing",
    )
    _save_bundle(
        store,
        bundle_id="b3",
        candidate=_candidate("cand-3", "xss_output_boundary", 0.45, ["source"]),
        decision="DROPPED",
        failed_gate="V3",
        reason="runtime class signal missing",
    )
    analysis = analyze_failures(store, min_occurrences=2)
    table = format_analysis_table(analysis)
    assert "Gate Failure Distribution:" in table
    assert "Top Failure Patterns:" in table
    assert "xss_output_boundary @ V3" in table
    assert "Suggestion:" in table


def test_analyze_failures_empty_store(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path / ".padv")
    analysis = analyze_failures(store)
    assert analysis.total_candidates_analyzed == 0
    assert analysis.total_failures == 0
    assert analysis.patterns == []
    table = format_analysis_table(analysis)
    assert "(no failures observed)" in table
    assert "(no recurring patterns)" in table

from __future__ import annotations

from pathlib import Path

from padv.config.schema import load_config
from padv.gates.engine import evaluate_candidate
from padv.models import RuntimeCall, RuntimeEvidence, StaticEvidence


def _runtime(request_id: str, canary: str, negative: bool = False) -> RuntimeEvidence:
    arg = '"safe-value"' if negative else f'"query {canary}"'
    return RuntimeEvidence(
        request_id=request_id,
        status="active_hits" if not negative else "active_no_hits",
        call_count=1,
        overflow=False,
        arg_truncated=False,
        result_truncated=False,
        correlation=request_id,
        calls=[RuntimeCall(function="mysqli_query", file="app.php", line=10, args=[arg])],
        raw_headers={},
    )


def test_gate_validated() -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    canary = "padv-canary-123"
    result = evaluate_candidate(
        config=config,
        static_evidence=[
            StaticEvidence(
                candidate_id="cand-1",
                query_profile="default",
                query_id="q1",
                file_path="app.php",
                line=10,
                snippet="mysqli_query($db, $q);",
                hash="abc",
            )
        ],
        positive_runs=[_runtime("p1", canary), _runtime("p2", canary), _runtime("p3", canary)],
        negative_runs=[_runtime("n1", canary, negative=True)],
        intercepts=["mysqli_query"],
        canary=canary,
        preconditions=[],
        evidence_signals=["joern", "web"],
    )
    assert result.decision == "VALIDATED"


def test_gate_needs_setup_when_preconditions() -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    canary = "padv-canary-123"
    result = evaluate_candidate(
        config=config,
        static_evidence=[],
        positive_runs=[_runtime("p1", canary)],
        negative_runs=[],
        intercepts=["mysqli_query"],
        canary=canary,
        preconditions=["runtime-oracle-not-applicable"],
        evidence_signals=["source", "web"],
    )
    assert result.decision == "NEEDS_HUMAN_SETUP"


def test_gate_drops_without_multi_evidence_signals() -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    canary = "padv-canary-123"
    result = evaluate_candidate(
        config=config,
        static_evidence=[
            StaticEvidence(
                candidate_id="cand-1",
                query_profile="default",
                query_id="joern::sql_boundary",
                file_path="app.php",
                line=10,
                snippet="mysqli_query($db, $q);",
                hash="abc",
            )
        ],
        positive_runs=[_runtime("p1", canary), _runtime("p2", canary), _runtime("p3", canary)],
        negative_runs=[_runtime("n1", canary, negative=True)],
        intercepts=["mysqli_query"],
        canary=canary,
        preconditions=[],
        evidence_signals=["joern"],
    )
    assert result.decision == "DROPPED"
    assert result.failed_gate == "V2"

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from padv.config.schema import load_config
from padv.eval.metrics import (
    confusion_from_matches,
    macro_recall,
    precision_recall_f1,
    summarize_outcomes,
)
from padv.gates.engine import evaluate_candidate
from padv.models import (
    CANDIDATE_OUTCOMES,
    Candidate,
    GateResult,
    RuntimeCall,
    RuntimeEvidence,
    StaticEvidence,
    count_candidate_outcomes,
    default_candidate_outcomes,
    explicit_candidate_outcome_for_decision,
)
from padv.validation.preconditions import GatePreconditions

CONFIG_PATH = Path(__file__).resolve().parents[1] / "padv.toml"
CANARY = "padv-canary-123"


def _config():
    return load_config(CONFIG_PATH)


def _runtime(
    request_id: str,
    *,
    negative: bool = False,
    hit_canary: bool | None = None,
    truncated: bool = False,
    status: str | None = None,
) -> RuntimeEvidence:
    carries_canary = (not negative) if hit_canary is None else hit_canary
    arg = f'"query {CANARY}"' if carries_canary else '"safe-value"'
    return RuntimeEvidence(
        request_id=request_id,
        status=status or ("active_no_hits" if negative else "active_hits"),
        call_count=1,
        overflow=False,
        arg_truncated=truncated,
        result_truncated=False,
        correlation=request_id,
        calls=[RuntimeCall(function="mysqli_query", file="app.php", line=10, args=[arg])],
        raw_headers={},
    )


def _static() -> list[StaticEvidence]:
    return [
        StaticEvidence(
            candidate_id="cand-1",
            query_profile="default",
            query_id="sql-1",
            file_path="app.php",
            line=10,
            snippet="mysqli_query($db, $q);",
            hash="abc",
        )
    ]


def _evaluate(**overrides) -> GateResult:
    kwargs: dict[str, Any] = dict(
        config=_config(),
        static_evidence=_static(),
        positive_runs=[_runtime("p1"), _runtime("p2")],
        negative_runs=[_runtime("n1", negative=True)],
        intercepts=["mysqli_query"],
        canary=CANARY,
        preconditions=GatePreconditions(),
        evidence_signals=["joern", "web"],
        vuln_class="legacy_probe",
    )
    kwargs.update(overrides)
    return evaluate_candidate(**kwargs)


# --- outcome vocabulary -------------------------------------------------


def test_outcome_vocabulary_separates_ignorance_from_refutation() -> None:
    assert CANDIDATE_OUTCOMES == (
        "VALIDATED",
        "REFUTED",
        "ANALYSIS_FINDING",
        "INCONCLUSIVE",
        "SKIPPED_PRECONDITION",
        "SKIPPED_BUDGET",
        "ERROR",
    )
    assert set(default_candidate_outcomes()) == set(CANDIDATE_OUTCOMES)


@pytest.mark.parametrize(
    ("decision", "expected"),
    [
        ("VALIDATED", "VALIDATED"),
        ("REFUTED", "REFUTED"),
        ("INCONCLUSIVE", "INCONCLUSIVE"),
        ("CONFIRMED_ANALYSIS_FINDING", "ANALYSIS_FINDING"),
        ("NEEDS_HUMAN_SETUP", "SKIPPED_PRECONDITION"),
        ("SKIPPED_BUDGET", "SKIPPED_BUDGET"),
        ("ERROR", "ERROR"),
        ("", "ERROR"),
        ("something-unknown", "ERROR"),
        # legacy decisions persisted by older runs
        ("DROPPED", "INCONCLUSIVE"),
        ("INSUFFICIENT_EVIDENCE", "INCONCLUSIVE"),
    ],
)
def test_decision_to_outcome_mapping(decision: str, expected: str) -> None:
    assert explicit_candidate_outcome_for_decision(decision) == expected


def test_analysis_finding_is_not_counted_as_validated() -> None:
    counts = count_candidate_outcomes(
        [
            _Bundle(GateResult("CONFIRMED_ANALYSIS_FINDING", ["A0", "A1", "A2"], None, "ok")),
            _Bundle(GateResult("VALIDATED", [], None, "ok")),
        ]
    )
    assert counts["VALIDATED"] == 1
    assert counts["ANALYSIS_FINDING"] == 1


class _Bundle:
    def __init__(self, gate_result: GateResult) -> None:
        self.gate_result = gate_result
        self.candidate_outcome = ""


# --- gate decisions -----------------------------------------------------


def test_missing_class_witness_refutes() -> None:
    """A delivered payload whose sink witness never appears is a real negative."""
    result = _evaluate(positive_runs=[_runtime("p1", hit_canary=False), _runtime("p2", hit_canary=False)])
    assert result.decision == "REFUTED"
    assert result.failed_gate == "V3"
    assert explicit_candidate_outcome_for_decision(result.decision) == "REFUTED"


def test_insufficient_corroboration_is_inconclusive_not_refuted() -> None:
    result = _evaluate(evidence_signals=["joern"])
    assert result.decision == "INCONCLUSIVE"
    assert result.failed_gate == "V2"


def test_missing_static_evidence_is_inconclusive() -> None:
    result = _evaluate(static_evidence=[])
    assert result.decision == "INCONCLUSIVE"
    assert result.failed_gate == "V2"


def test_out_of_scope_runtime_is_inconclusive() -> None:
    result = _evaluate(positive_runs=[_runtime("p1", status="auth_failed")])
    assert result.decision == "INCONCLUSIVE"
    assert result.failed_gate == "V0"


def test_truncated_oracle_output_is_inconclusive_not_error() -> None:
    result = _evaluate(positive_runs=[_runtime("p1", status="insufficient_evidence"), _runtime("p2")])
    assert result.decision == "INCONCLUSIVE"
    assert result.failed_gate == "V0"
    assert explicit_candidate_outcome_for_decision(result.decision) == "INCONCLUSIVE"


def test_dirty_negative_control_is_inconclusive_not_refuted() -> None:
    """A control that fires without the payload invalidates the experiment."""
    result = _evaluate(negative_runs=[_runtime("n1", negative=True, hit_canary=True)])
    assert result.decision == "INCONCLUSIVE"
    assert result.failed_gate == "V4"


def test_insufficient_repro_runs_is_inconclusive() -> None:
    result = _evaluate(positive_runs=[_runtime("p1")])
    assert result.decision == "INCONCLUSIVE"
    assert result.failed_gate == "V5"


def test_truncated_repro_evidence_is_inconclusive() -> None:
    result = _evaluate(positive_runs=[_runtime("p1"), _runtime("p2", truncated=True)])
    assert result.decision == "INCONCLUSIVE"
    assert result.failed_gate == "V5"


def test_unresolved_preconditions_skip_rather_than_refute() -> None:
    result = _evaluate(preconditions=GatePreconditions(requires_auth=True))
    assert result.decision == "NEEDS_HUMAN_SETUP"
    assert explicit_candidate_outcome_for_decision(result.decision) == "SKIPPED_PRECONDITION"


# --- analysis-only candidates ------------------------------------------


def _analysis_candidate(**overrides) -> Candidate:
    kwargs: dict[str, Any] = dict(
        candidate_id="cand-a",
        vuln_class="security_misconfiguration",
        title="Misconfig",
        file_path="config.php",
        line=1,
        sink="ini_set",
        expected_intercepts=["ini_set"],
        validation_mode="analysis_only",
        canonical_class="security_misconfiguration",
    )
    kwargs.update(overrides)
    return Candidate(**kwargs)


def test_analysis_only_still_requires_static_corroboration() -> None:
    """analysis_only must not be a free pass around every gate."""
    result = _evaluate(
        candidate=_analysis_candidate(),
        static_evidence=[],
        positive_runs=[],
        negative_runs=[],
        intercepts=[],
        evidence_signals=[],
    )
    assert result.decision == "INCONCLUSIVE"
    assert result.failed_gate == "A2"


def test_analysis_only_requires_multi_evidence_signals() -> None:
    result = _evaluate(
        candidate=_analysis_candidate(),
        positive_runs=[],
        negative_runs=[],
        intercepts=[],
        evidence_signals=["joern"],
    )
    assert result.decision == "INCONCLUSIVE"
    assert result.failed_gate == "A2"


def test_analysis_only_honours_preconditions() -> None:
    result = _evaluate(
        candidate=_analysis_candidate(),
        positive_runs=[],
        negative_runs=[],
        intercepts=[],
        preconditions=GatePreconditions(requires_auth=True),
    )
    assert result.decision == "NEEDS_HUMAN_SETUP"
    assert result.failed_gate == "A1"


def test_analysis_only_confirmed_records_analysis_gates() -> None:
    result = _evaluate(
        candidate=_analysis_candidate(),
        positive_runs=[],
        negative_runs=[],
        intercepts=[],
    )
    assert result.decision == "CONFIRMED_ANALYSIS_FINDING"
    assert result.passed_gates == ["A0", "A1", "A2"]
    assert result.failed_gate is None
    assert explicit_candidate_outcome_for_decision(result.decision) == "ANALYSIS_FINDING"


# --- metrics ------------------------------------------------------------


def test_summarize_outcomes_reports_every_outcome() -> None:
    ratios = summarize_outcomes({"VALIDATED": 1, "REFUTED": 1, "INCONCLUSIVE": 2})
    assert ratios["validated_ratio"] == 0.25
    assert ratios["refuted_ratio"] == 0.25
    assert ratios["inconclusive_ratio"] == 0.5
    assert ratios["analysis_finding_ratio"] == 0.0
    assert set(ratios) == {
        "validated_ratio",
        "refuted_ratio",
        "analysis_finding_ratio",
        "inconclusive_ratio",
        "skipped_precondition_ratio",
        "skipped_budget_ratio",
        "error_ratio",
    }


def test_summarize_outcomes_on_empty_input() -> None:
    ratios = summarize_outcomes({})
    assert set(ratios.values()) == {0.0}


def test_confusion_counts_instances_not_decisions() -> None:
    confusion = confusion_from_matches(
        expected_ids=["mut-001", "mut-002", "mut-003"],
        validated_ids=["mut-001", "mut-009"],
    )
    assert confusion == {
        "true_positives": 1,
        "false_positives": 1,
        "false_negatives": 2,
        "control_violations": 0,
    }


def test_confusion_counts_negative_controls_as_false_positives() -> None:
    confusion = confusion_from_matches(
        expected_ids=["mut-001"],
        validated_ids=["mut-001", "mut-001-patched"],
        negative_control_ids=["mut-001-patched"],
    )
    assert confusion["true_positives"] == 1
    assert confusion["false_positives"] == 1
    assert confusion["false_negatives"] == 0
    assert confusion["control_violations"] == 1


def test_precision_recall_f1() -> None:
    scores = precision_recall_f1(true_positives=3, false_positives=1, false_negatives=2)
    assert scores["precision"] == 0.75
    assert scores["recall"] == 0.6
    assert scores["f1"] == pytest.approx(2 * 0.75 * 0.6 / (0.75 + 0.6))


def test_precision_recall_f1_is_zero_without_signal() -> None:
    scores = precision_recall_f1(true_positives=0, false_positives=0, false_negatives=0)
    assert scores == {"precision": 0.0, "recall": 0.0, "f1": 0.0}


def test_macro_recall_weights_classes_equally() -> None:
    assert macro_recall({"sql_injection": (1, 1), "xss": (0, 3)}) == 0.5
    assert macro_recall({}) == 0.0

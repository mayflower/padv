from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from padv.config.schema import load_config
from padv.gates.engine import REQUIRED_GATES, evaluate_candidate
from padv.models import (
    STORE_SCHEMA_VERSION,
    Candidate,
    EvidenceBundle,
    GateResult,
    MissingRefutationEvidenceError,
    RefutationEvidence,
    RuntimeCall,
    RuntimeEvidence,
    StaticEvidence,
)
from padv.validation.preconditions import GatePreconditions

CONFIG_PATH = Path(__file__).resolve().parents[1] / "padv.toml"
CANARY = "padv-canary-123"


def _runtime(request_id: str, *, hit: bool = True, negative: bool = False) -> RuntimeEvidence:
    arg = f'"query {CANARY}"' if hit else '"safe-value"'
    return RuntimeEvidence(
        request_id=request_id,
        status="active_no_hits" if negative else "active_hits",
        call_count=1,
        overflow=False,
        arg_truncated=False,
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
        config=load_config(CONFIG_PATH),
        static_evidence=_static(),
        positive_runs=[_runtime("p1"), _runtime("p2")],
        negative_runs=[_runtime("n1", negative=True, hit=False)],
        intercepts=["mysqli_query"],
        canary=CANARY,
        preconditions=GatePreconditions(),
        evidence_signals=["joern", "web"],
        vuln_class="legacy_probe",
    )
    kwargs.update(overrides)
    return evaluate_candidate(**kwargs)


# --- REFUTED requires typed evidence ------------------------------------


def test_refuted_without_evidence_is_rejected() -> None:
    """A refutation without evidence is just an assertion."""
    with pytest.raises(MissingRefutationEvidenceError):
        GateResult("REFUTED", ["V0"], "V3", "no witness")


def test_other_decisions_do_not_require_refutation_evidence() -> None:
    for decision in ("VALIDATED", "INCONCLUSIVE", "NEEDS_HUMAN_SETUP", "SKIPPED_BUDGET", "ERROR"):
        assert GateResult(decision, [], None, "ok").refutation is None


def test_legacy_canary_refutation_carries_evidence() -> None:
    result = _evaluate(positive_runs=[_runtime("p1", hit=False), _runtime("p2", hit=False)])
    assert result.decision == "REFUTED"
    refutation = result.refutation
    assert refutation is not None
    assert refutation.kind == "canary_boundary_absent"
    assert refutation.failed_gate == "V3"
    assert refutation.positive_request_ids == ["p1", "p2"]
    assert refutation.negative_request_ids == ["n1"]


def test_class_witness_refutation_names_the_missing_flags() -> None:
    result = _evaluate(
        positive_runs=[_runtime("p1"), _runtime("p2")],
        vuln_class="sql_injection_boundary",
        candidate=Candidate(
            candidate_id="cand-1",
            vuln_class="sql_injection_boundary",
            title="SQLi",
            file_path="app.php",
            line=10,
            sink="mysqli_query",
            expected_intercepts=["mysqli_query"],
            canonical_class="sql_injection_boundary",
        ),
    )
    assert result.decision == "REFUTED"
    refutation = result.refutation
    assert refutation is not None
    assert refutation.kind == "class_witness_absent"
    assert refutation.vuln_class == "sql_injection_boundary"
    # The sink oracle did fire; what is missing is the required corroboration,
    # and the evidence has to name which side of the contract failed.
    assert "sql_sink_oracle_witness" in refutation.observed_positive_flags
    assert refutation.required_any
    assert not set(refutation.required_any) & set(refutation.observed_positive_flags)


def test_refutation_survives_serialisation() -> None:
    result = _evaluate(positive_runs=[_runtime("p1", hit=False), _runtime("p2", hit=False)])
    payload = result.to_dict()
    assert payload["refutation"]["kind"] == "canary_boundary_absent"

    restored = GateResult(**payload)
    assert isinstance(restored.refutation, RefutationEvidence)
    assert restored.refutation.kind == "canary_boundary_absent"


# --- V6 -----------------------------------------------------------------


def test_v6_is_gone_from_the_gate_set() -> None:
    """V6 was appended unconditionally, so it asserted nothing."""
    assert REQUIRED_GATES == ["V0", "V1", "V2", "V3", "V4", "V5"]


def test_validated_result_lists_only_real_gates() -> None:
    result = _evaluate()
    assert result.decision == "VALIDATED"
    assert result.passed_gates == ["V0", "V1", "V2", "V3", "V4", "V5"]


# --- store schema -------------------------------------------------------


def _bundle(gate_result: GateResult) -> EvidenceBundle:
    return EvidenceBundle(
        bundle_id="bundle-1",
        created_at="2026-07-25T00:00:00+00:00",
        candidate=Candidate(
            candidate_id="cand-1",
            vuln_class="sql_injection_boundary",
            title="SQLi",
            file_path="app.php",
            line=10,
            sink="mysqli_query",
            expected_intercepts=["mysqli_query"],
        ),
        static_evidence=[],
        positive_runtime=[],
        negative_runtime=[],
        repro_run_ids=[],
        gate_result=gate_result,
        limitations=[],
    )


def test_saved_bundle_records_the_schema_version() -> None:
    payload = _bundle(GateResult("VALIDATED", [], None, "ok")).to_dict()
    assert payload["schema_version"] == STORE_SCHEMA_VERSION


def test_legacy_bundle_migrates_dropped_to_inconclusive() -> None:
    from padv.store.evidence_store import migrate_bundle_payload

    legacy = {
        "bundle_id": "old",
        "gate_result": {"decision": "DROPPED", "passed_gates": ["V0"], "failed_gate": "V3", "reason": "x"},
        "candidate_outcome": "REFUTED",
    }
    migrated = migrate_bundle_payload(legacy)
    assert migrated["gate_result"]["decision"] == "INCONCLUSIVE"
    assert migrated["candidate_outcome"] == "INCONCLUSIVE"
    assert migrated["schema_version"] == STORE_SCHEMA_VERSION


def test_legacy_insufficient_evidence_migrates_to_inconclusive() -> None:
    from padv.store.evidence_store import migrate_bundle_payload

    migrated = migrate_bundle_payload(
        {"gate_result": {"decision": "INSUFFICIENT_EVIDENCE", "passed_gates": [], "failed_gate": "V0", "reason": "x"}}
    )
    assert migrated["gate_result"]["decision"] == "INCONCLUSIVE"
    assert migrated["candidate_outcome"] == "INCONCLUSIVE"


def test_current_schema_payload_is_left_alone() -> None:
    from padv.store.evidence_store import migrate_bundle_payload

    current = _bundle(GateResult("VALIDATED", [], None, "ok")).to_dict()
    assert migrate_bundle_payload(dict(current)) == current

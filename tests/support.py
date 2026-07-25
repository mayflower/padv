"""Shared helpers for tests that need a stand-in gate result.

REFUTED requires typed RefutationEvidence, so fixtures cannot assert a
refutation without one. This builds the minimal well-formed instance for tests
whose subject is something other than the refutation itself.
"""

from __future__ import annotations

from padv.models import GateResult, RefutationEvidence


def refuted_gate_result(
    reason: str = "test",
    *,
    vuln_class: str = "legacy_probe",
    failed_gate: str = "V3",
) -> GateResult:
    return GateResult(
        "REFUTED",
        ["V0"],
        failed_gate,
        reason,
        refutation=RefutationEvidence(
            kind="class_witness_absent",
            failed_gate=failed_gate,
            vuln_class=vuln_class,
            required_all=["sql_sink_oracle_witness"],
            observed_positive_flags=[],
            positive_request_ids=["p1", "p2"],
            negative_request_ids=["n1"],
            detail=reason,
        ),
    )

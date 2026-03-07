from __future__ import annotations

from pathlib import Path

import pytest

from padv.config.schema import load_config
from padv.gates.engine import evaluate_candidate
from padv.models import RuntimeEvidence, StaticEvidence
from padv.static.joern.query_sets import VULN_CLASS_SPECS


def _runtime(request_id: str) -> RuntimeEvidence:
    return RuntimeEvidence(
        request_id=request_id,
        status="http_observed",
        call_count=0,
        overflow=False,
        arg_truncated=False,
        result_truncated=False,
        correlation=request_id,
        calls=[],
        raw_headers={},
    )


@pytest.mark.parametrize(
    "vuln_class,intercepts",
    [
        (spec.vuln_class, list(spec.intercepts))
        for spec in VULN_CLASS_SPECS
        if spec.runtime_validatable
    ],
)
def test_runtime_validatable_class_without_witness_never_validates(
    vuln_class: str, intercepts: list[str]
) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    result = evaluate_candidate(
        config=config,
        static_evidence=[
            StaticEvidence(
                candidate_id="cand-1",
                query_profile="default",
                query_id=f"joern::{vuln_class}",
                file_path="src/app.php",
                line=10,
                snippet="sink($x);",
                hash="abc",
            )
        ],
        positive_runs=[_runtime("p1"), _runtime("p2"), _runtime("p3")],
        negative_runs=[_runtime("n1")],
        intercepts=intercepts,
        canary="padv-canary",
        preconditions=[],
        evidence_signals=["joern", "scip"],
        vuln_class=vuln_class,
    )
    assert result.decision == "DROPPED"
    assert result.failed_gate == "V3"

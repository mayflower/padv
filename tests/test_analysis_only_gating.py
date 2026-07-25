"""The runtime must not build analysis findings behind the gate engine's back.

`_process_candidate` short-circuited every non-runtime-validatable candidate into
a CONFIRMED_ANALYSIS_FINDING bundle without calling `evaluate_candidate`, so the
static gates were unreachable in production no matter what the engine enforced.
"""

from __future__ import annotations

from pathlib import Path

from padv.config.schema import load_config
from padv.models import Candidate, StaticEvidence
from padv.orchestrator.runtime import _build_analysis_only_bundle
from padv.validation.preconditions import GatePreconditions

CONFIG_PATH = Path(__file__).resolve().parents[1] / "padv.toml"


def _candidate(**overrides) -> Candidate:
    kwargs = dict(
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


def _static() -> list[StaticEvidence]:
    return [
        StaticEvidence(
            candidate_id="cand-a",
            query_profile="default",
            query_id="q1",
            file_path="config.php",
            line=1,
            snippet="ini_set('display_errors', 1);",
            hash="abc",
        )
    ]


class _Profile:
    class_contract_id = "analysis"
    validation_mode = "analysis_only"

    def to_dict(self) -> dict[str, str]:
        return {"class_contract_id": self.class_contract_id}


def _build(candidate: Candidate, static_evidence: list[StaticEvidence], signals: list[str]):
    return _build_analysis_only_bundle(
        config=load_config(CONFIG_PATH),
        run_id="run-a",
        candidate=candidate,
        candidate_static=static_evidence,
        evidence_signals=signals,
        artifact_refs=[],
        discovery_trace={},
        auth_state={},
        profile=_Profile(),
    )


def test_analysis_only_without_static_evidence_is_inconclusive() -> None:
    bundle = _build(_candidate(), [], ["joern", "web"])
    assert bundle.gate_result.decision == "INCONCLUSIVE"
    assert bundle.gate_result.failed_gate == "A2"
    assert bundle.candidate_outcome == "INCONCLUSIVE"


def test_analysis_only_with_single_evidence_signal_is_inconclusive() -> None:
    bundle = _build(_candidate(), _static(), ["joern"])
    assert bundle.gate_result.decision == "INCONCLUSIVE"
    assert bundle.gate_result.failed_gate == "A2"


def test_analysis_only_with_unresolved_preconditions_is_skipped() -> None:
    candidate = _candidate(gate_preconditions=GatePreconditions(requires_auth=True))
    bundle = _build(candidate, _static(), ["joern", "web"])
    assert bundle.gate_result.decision == "NEEDS_HUMAN_SETUP"
    assert bundle.gate_result.failed_gate == "A1"
    assert bundle.candidate_outcome == "SKIPPED_PRECONDITION"


def test_corroborated_analysis_only_is_confirmed_through_the_gates() -> None:
    bundle = _build(_candidate(), _static(), ["joern", "web"])
    assert bundle.gate_result.decision == "CONFIRMED_ANALYSIS_FINDING"
    assert bundle.gate_result.passed_gates == ["A0", "A1", "A2"]
    assert bundle.candidate_outcome == "ANALYSIS_FINDING"

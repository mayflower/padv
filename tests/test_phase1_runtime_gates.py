from __future__ import annotations

from pathlib import Path

from padv.config.schema import load_config
from padv.gates.engine import evaluate_candidate
from padv.models import RuntimeEvidence, StaticEvidence


def _runtime_with_flags(request_id: str, *flags: str) -> RuntimeEvidence:
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
        analysis_flags=list(flags),
    )


def _static() -> list[StaticEvidence]:
    return [
        StaticEvidence(
            candidate_id="cand-1",
            query_profile="default",
            query_id="source::xss_output_boundary",
            file_path="src/app.php",
            line=10,
            snippet="echo $_GET['x'];",
            hash="abc",
        )
    ]


def test_gate_xss_runtime_signal_validates() -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    result = evaluate_candidate(
        config=config,
        static_evidence=_static(),
        positive_runs=[
            _runtime_with_flags("p1", "xss_raw_canary"),
            _runtime_with_flags("p2", "xss_raw_canary"),
            _runtime_with_flags("p3", "xss_raw_canary"),
        ],
        negative_runs=[_runtime_with_flags("n1")],
        intercepts=[],
        canary="padv-canary",
        preconditions=[],
        evidence_signals=["source", "web"],
        vuln_class="xss_output_boundary",
    )
    assert result.decision == "VALIDATED"


def test_gate_xss_negative_control_fails_when_signal_repeats() -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    result = evaluate_candidate(
        config=config,
        static_evidence=_static(),
        positive_runs=[
            _runtime_with_flags("p1", "xss_raw_canary"),
            _runtime_with_flags("p2", "xss_raw_canary"),
            _runtime_with_flags("p3", "xss_raw_canary"),
        ],
        negative_runs=[_runtime_with_flags("n1", "xss_raw_canary")],
        intercepts=[],
        canary="padv-canary",
        preconditions=[],
        evidence_signals=["source", "web"],
        vuln_class="xss_output_boundary",
    )
    assert result.decision == "DROPPED"
    assert result.failed_gate == "V4"


def test_gate_access_control_uses_http_signal_without_negative_clean_requirement() -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    result = evaluate_candidate(
        config=config,
        static_evidence=_static(),
        positive_runs=[
            _runtime_with_flags("p1", "authz_bypass_status", "authz_pair_observed"),
            _runtime_with_flags("p2", "authz_bypass_status", "authz_pair_observed"),
            _runtime_with_flags("p3", "authz_bypass_status", "authz_pair_observed"),
        ],
        negative_runs=[_runtime_with_flags("n1", "authz_bypass_status")],
        intercepts=[],
        canary="padv-canary",
        preconditions=[],
        evidence_signals=["source", "web"],
        vuln_class="broken_access_control",
    )
    assert result.decision == "VALIDATED"


def test_gate_access_control_requires_pair_observation() -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    result = evaluate_candidate(
        config=config,
        static_evidence=_static(),
        positive_runs=[
            _runtime_with_flags("p1", "authz_bypass_status"),
            _runtime_with_flags("p2", "authz_bypass_status"),
            _runtime_with_flags("p3", "authz_bypass_status"),
        ],
        negative_runs=[_runtime_with_flags("n1")],
        intercepts=[],
        canary="padv-canary",
        preconditions=[],
        evidence_signals=["source", "web"],
        vuln_class="broken_access_control",
    )
    assert result.decision == "DROPPED"
    assert result.failed_gate == "V3"

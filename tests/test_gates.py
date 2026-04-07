from __future__ import annotations

import inspect
from pathlib import Path

import padv.validation.preconditions as preconditions_module
import pytest
from padv.config.schema import load_config
from padv.gates.engine import evaluate_candidate
from padv.models import Candidate, OracleEvidence, RuntimeCall, RuntimeEvidence, StaticEvidence
from padv.validation.preconditions import GatePreconditions, InvalidGatePreconditionsError


def _runtime(
    request_id: str,
    canary: str,
    negative: bool = False,
    *,
    body_excerpt: str = "",
    http_status: int | None = None,
) -> RuntimeEvidence:
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
        http_status=http_status,
        body_excerpt=body_excerpt,
    )


def _failed_runtime(request_id: str) -> RuntimeEvidence:
    return RuntimeEvidence(
        request_id=request_id,
        status="request_failed",
        call_count=0,
        overflow=False,
        arg_truncated=False,
        result_truncated=False,
        correlation=None,
        calls=[],
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
        preconditions=GatePreconditions(),
        evidence_signals=["joern", "web"],
    )
    assert result.decision == "VALIDATED"


def test_gate_needs_setup_when_preconditions() -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    canary = "padv-canary-123"
    result = evaluate_candidate(
        config=config,
        static_evidence=[],
        positive_runs=[_runtime("p1", canary), _runtime("p2", canary)],
        negative_runs=[_runtime("n1", canary, negative=True)],
        intercepts=["mysqli_query"],
        canary=canary,
        preconditions=GatePreconditions(unknown_blockers=["custom proxy must be configured"]),
        evidence_signals=["source", "web"],
    )
    assert result.decision == "NEEDS_HUMAN_SETUP"
    assert result.reason == "typed_preconditions_unresolved: unknown_blockers=custom proxy must be configured"


def test_gate_rejects_legacy_precondition_strings() -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    canary = "padv-canary-123"
    with pytest.raises(InvalidGatePreconditionsError, match="GatePreconditions object or structured mapping"):
        evaluate_candidate(
            config=config,
            static_evidence=[],
            positive_runs=[_runtime("p1", canary), _runtime("p2", canary)],
            negative_runs=[_runtime("n1", canary, negative=True)],
            intercepts=["mysqli_query"],
            canary=canary,
            preconditions=["manual VPN setup required before execution"],  # type: ignore[arg-type]
            evidence_signals=["source", "web"],
        )


def test_gate_needs_setup_for_typed_auth_and_csrf_requirements() -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    canary = "padv-canary-123"
    result = evaluate_candidate(
        config=config,
        static_evidence=[],
        positive_runs=[_runtime("p1", canary), _runtime("p2", canary)],
        negative_runs=[_runtime("n1", canary, negative=True)],
        intercepts=["mysqli_query"],
        canary=canary,
        preconditions=GatePreconditions(requires_auth=True, requires_csrf_token=True),
        evidence_signals=["source", "web"],
    )

    assert result.decision == "NEEDS_HUMAN_SETUP"
    assert result.reason == "typed_preconditions_unresolved: requires_auth, requires_csrf_token"


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
        preconditions=GatePreconditions(),
        evidence_signals=["joern"],
    )
    assert result.decision == "DROPPED"
    assert result.failed_gate == "V2"


def test_gate_v0_tolerates_partial_positive_request_failures() -> None:
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
        positive_runs=[_runtime("p1", canary), _runtime("p2", canary), _failed_runtime("p3")],
        negative_runs=[_runtime("n1", canary, negative=True)],
        intercepts=["mysqli_query"],
        canary=canary,
        preconditions=GatePreconditions(),
        evidence_signals=["joern", "web"],
    )
    assert result.failed_gate != "V0"


def test_gate_v0_drops_when_all_positive_requests_fail() -> None:
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
        positive_runs=[_failed_runtime("p1"), _failed_runtime("p2"), _failed_runtime("p3")],
        negative_runs=[_runtime("n1", canary, negative=True)],
        intercepts=["mysqli_query"],
        canary=canary,
        preconditions=GatePreconditions(),
        evidence_signals=["joern", "web"],
    )
    assert result.decision == "DROPPED"
    assert result.failed_gate == "V0"


def test_gate_canonicalizes_family_level_sql_aliases() -> None:
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
        positive_runs=[
            _runtime("p1", canary, body_excerpt="mysql syntax error near padv-canary-123", http_status=200),
            _runtime("p2", canary, body_excerpt="mysql syntax error near padv-canary-123", http_status=200),
        ],
        negative_runs=[
            _runtime("n1", canary, negative=True, body_excerpt="benign response", http_status=200),
        ],
        intercepts=["mysqli_query"],
        canary=canary,
        preconditions=GatePreconditions(),
        evidence_signals=["joern", "web"],
        vuln_class="legacy_probe",
    )
    assert result.decision == "VALIDATED"


def test_preconditions_policy_avoids_regex_parsing() -> None:
    source = inspect.getsource(preconditions_module)

    assert "import re" not in source
    assert "re." not in source


def test_gate_accepts_typed_oracle_evidence_without_analysis_flags() -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    canary = "padv-canary-typed"
    positive = RuntimeEvidence(
        request_id="p1",
        status="active_hits",
        call_count=1,
        overflow=False,
        arg_truncated=False,
        result_truncated=False,
        correlation="p1",
        calls=[RuntimeCall(function="mysqli_query", file="app.php", line=10, args=["query"])],
        raw_headers={},
        body_excerpt="mysql syntax error near padv-canary-typed",
        http_status=200,
        oracle_evidence=[
            OracleEvidence(
                correlation_id="p1",
                function="mysqli_query",
                file="app.php",
                line=10,
                full_args=[f"query {canary}"],
                display_args=[f"query {canary}"],
                matched_canary=True,
            )
        ],
    )
    negative = RuntimeEvidence(
        request_id="n1",
        status="active_no_hits",
        call_count=1,
        overflow=False,
        arg_truncated=False,
        result_truncated=False,
        correlation="n1",
        calls=[RuntimeCall(function="mysqli_query", file="app.php", line=10, args=["safe"])],
        raw_headers={},
        body_excerpt="benign response",
        http_status=200,
    )
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
        positive_runs=[positive, positive],
        negative_runs=[negative],
        intercepts=["mysqli_query"],
        canary=canary,
        preconditions=GatePreconditions(),
        evidence_signals=["joern", "web"],
        vuln_class="legacy_probe",
    )
    assert result.decision == "VALIDATED"


def test_gate_drops_truncated_runtime_evidence() -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    canary = "padv-canary-truncated"
    truncated_positive = _runtime("p1", canary)
    truncated_positive.status = "insufficient_evidence"
    truncated_positive.result_truncated = True
    truncated_positive.aux["truncation_reason"] = "result_truncated"
    clean_positive = _runtime("p2", canary)
    negative = _runtime("n1", canary, negative=True)

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
        positive_runs=[truncated_positive, clean_positive],
        negative_runs=[negative],
        intercepts=["mysqli_query"],
        canary=canary,
        preconditions=GatePreconditions(),
        evidence_signals=["joern", "web"],
        vuln_class="legacy_probe",
    )

    assert result.decision == "INSUFFICIENT_EVIDENCE"
    assert result.failed_gate == "V0"
    assert "truncated" in result.reason


def test_gate_returns_confirmed_analysis_for_analysis_only_candidate() -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    result = evaluate_candidate(
        config=config,
        static_evidence=[],
        positive_runs=[],
        negative_runs=[],
        intercepts=[],
        canary="padv",
        preconditions=GatePreconditions(),
        candidate=Candidate(
            candidate_id="cand-a",
            vuln_class="security_misconfiguration",
            title="Misconfig",
            file_path="config.php",
            line=1,
            sink="ini_set",
            expected_intercepts=["ini_set"],
            validation_mode="analysis_only",
            canonical_class="security_misconfiguration",
        ),
    )
    assert result.decision == "CONFIRMED_ANALYSIS_FINDING"

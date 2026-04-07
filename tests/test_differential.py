from __future__ import annotations

from pathlib import Path

import pytest

from padv.config.schema import load_config
from padv.gates.engine import evaluate_candidate
from padv.dynamic.http.runner import HttpResponse
from padv.models import Candidate, DifferentialPair, GateResult, RuntimeEvidence, StaticEvidence, ValidationPlan
from padv.orchestrator.differential import build_unprivileged_request, compare_responses, needs_differential
from padv.orchestrator.runtime import validate_candidates_runtime
from padv.store.evidence_store import EvidenceStore
from padv.validation.preconditions import GatePreconditions


def _runtime(request_id: str, *, http_status: int = 200, call_count: int = 3, body: str = "ok") -> RuntimeEvidence:
    return RuntimeEvidence(
        request_id=request_id,
        status="http_observed",
        call_count=call_count,
        overflow=False,
        arg_truncated=False,
        result_truncated=False,
        correlation=request_id,
        calls=[],
        raw_headers={},
        http_status=http_status,
        body_excerpt=body,
        location="",
        analysis_flags=[],
        aux={},
    )


def _candidate(vuln_class: str) -> Candidate:
    return Candidate(
        candidate_id="cand-authz",
        vuln_class=vuln_class,
        title="candidate",
        file_path="src/a.php",
        line=10,
        sink="header",
        expected_intercepts=["header"],
        provenance=["source", "web"],
        confidence=0.8,
    )


def _static(candidate_id: str) -> list[StaticEvidence]:
    return [
        StaticEvidence(
            candidate_id=candidate_id,
            query_profile="default",
            query_id="source::broken_access_control",
            file_path="src/a.php",
            line=10,
            snippet="header('Location: /admin.php')",
            hash="h1",
        )
    ]


def test_needs_differential_for_authz_classes() -> None:
    assert needs_differential("broken_access_control")
    assert needs_differential("idor_invariant_missing")
    assert needs_differential("auth_and_session_failures")
    assert not needs_differential("xss_output_boundary")
    assert not needs_differential("sql_injection_boundary")


def test_build_unprivileged_request_strips_auth() -> None:
    privileged_request = {
        "method": "GET",
        "path": "/admin",
        "headers": {"Authorization": "Bearer admin", "X-Test": "1"},
        "cookies": {"PHPSESSID": "abc", "lang": "de"},
    }
    auth_state = {"cookies": {"PHPSESSID": "abc", "csrftoken": "t1"}}

    unpriv = build_unprivileged_request(privileged_request, auth_state)

    assert unpriv["method"] == "GET"
    assert unpriv["path"] == "/admin"
    assert unpriv["headers"] == {"X-Test": "1"}
    assert unpriv["cookies"] == {"lang": "de"}


def test_build_unprivileged_request_uses_lower_privilege_state() -> None:
    privileged_request = {
        "method": "GET",
        "path": "/admin",
        "headers": {"Authorization": "Bearer admin", "X-Test": "1"},
        "cookies": {"PHPSESSID": "admin-session"},
    }
    auth_state = {
        "cookies": {"PHPSESSID": "admin-session"},
        "lower_privilege": {
            "headers": {"Authorization": "Bearer user"},
            "cookies": {"PHPSESSID": "user-session"},
        },
    }

    unpriv = build_unprivileged_request(privileged_request, auth_state)

    assert unpriv["headers"]["Authorization"] == "Bearer user"
    assert unpriv["headers"]["X-Test"] == "1"
    assert unpriv["cookies"]["PHPSESSID"] == "user-session"


def test_compare_responses_equivalent_when_all_signals_match() -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    privileged = _runtime("p1", http_status=200, call_count=2, body="x" * 100)
    unprivileged = _runtime("u1", http_status=200, call_count=2, body="y" * 95)

    pair = compare_responses(privileged, unprivileged, config)

    assert pair.response_equivalent is True
    assert set(pair.equivalence_signals) == {"same_http_status", "same_morcilla_calls", "same_body_length"}


def test_compare_responses_rejects_different_status() -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    privileged = _runtime("p1", http_status=200, call_count=2, body="x" * 100)
    unprivileged = _runtime("u1", http_status=403, call_count=2, body="y" * 100)

    pair = compare_responses(privileged, unprivileged, config)
    assert pair.response_equivalent is False
    assert "same_http_status" not in pair.equivalence_signals


def test_compare_responses_rejects_body_delta_outside_tolerance() -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    config.differential.body_length_tolerance = 0.05
    privileged = _runtime("p1", http_status=200, call_count=2, body="x" * 100)
    unprivileged = _runtime("u1", http_status=200, call_count=2, body="y" * 80)

    pair = compare_responses(privileged, unprivileged, config)
    assert pair.response_equivalent is False
    assert "same_body_length" not in pair.equivalence_signals


def test_gate_engine_accepts_differential_pairs_for_authz_classes() -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    canary = "padv-canary"
    static = _static("cand-1")
    positive_runs = [_runtime("p1"), _runtime("p2"), _runtime("p3")]
    negative_runs = [_runtime("n1")]
    differential = [
        DifferentialPair(
            privileged_run=_runtime("dp1"),
            unprivileged_run=_runtime("du1"),
            auth_diff="admin_vs_anonymous",
            response_equivalent=True,
            equivalence_signals=["same_http_status", "same_morcilla_calls", "same_body_length"],
        )
    ]

    result = evaluate_candidate(
        config=config,
        static_evidence=static,
        positive_runs=positive_runs,
        negative_runs=negative_runs,
        intercepts=["header"],
        canary=canary,
        preconditions=GatePreconditions(),
        evidence_signals=["source", "web"],
        vuln_class="broken_access_control",
        differential_pairs=differential,
    )
    assert result.decision == "VALIDATED"


def test_gate_engine_ignores_differential_pairs_for_non_authz() -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    canary = "padv-canary"
    static = _static("cand-1")
    positive_runs = [_runtime("p1"), _runtime("p2"), _runtime("p3")]
    negative_runs = [_runtime("n1")]
    differential = [
        DifferentialPair(
            privileged_run=_runtime("dp1"),
            unprivileged_run=_runtime("du1"),
            auth_diff="admin_vs_anonymous",
            response_equivalent=True,
            equivalence_signals=["same_http_status", "same_morcilla_calls", "same_body_length"],
        )
    ]

    result = evaluate_candidate(
        config=config,
        static_evidence=static,
        positive_runs=positive_runs,
        negative_runs=negative_runs,
        intercepts=["header"],
        canary=canary,
        preconditions=GatePreconditions(),
        evidence_signals=["source", "web"],
        vuln_class="xss_output_boundary",
        differential_pairs=differential,
    )
    assert result.decision == "DROPPED"
    assert result.failed_gate == "V3"


def test_differential_request_consumes_existing_budget(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    config.budgets.max_requests = 4
    store = EvidenceStore(tmp_path / ".padv")
    candidate = _candidate("broken_access_control")
    plan = ValidationPlan(
        candidate_id=candidate.candidate_id,
        intercepts=["header"],
        positive_requests=[
            {"method": "GET", "path": "/admin.php", "query": {"id": "1"}},
            {"method": "GET", "path": "/admin.php", "query": {"id": "1"}},
            {"method": "GET", "path": "/admin.php", "query": {"id": "1"}},
        ],
        negative_requests=[{"method": "GET", "path": "/admin.php", "query": {"id": "2"}}],
        canary="padv-canary",
    )

    send_calls = {"count": 0}
    seen_pairs: list[DifferentialPair] = []

    def _Resp():
        return HttpResponse(status_code=200, headers={}, body="ok")

    def _fake_send_request(*args, **kwargs):
        send_calls["count"] += 1
        return _Resp()

    def _fake_parse(request_id, headers, oracle):
        return _runtime(request_id, http_status=200, call_count=1, body="ok")

    def _fake_gate(**kwargs):
        pairs = kwargs.get("differential_pairs") or []
        seen_pairs.extend(pairs)
        return GateResult("DROPPED", ["V0"], "V3", "test")

    monkeypatch.setattr("padv.orchestrator.runtime.send_request", _fake_send_request)
    monkeypatch.setattr("padv.orchestrator.runtime.parse_response_headers", _fake_parse)
    monkeypatch.setattr("padv.orchestrator.runtime.evaluate_candidate", _fake_gate)

    validate_candidates_runtime(
        config=config,
        store=store,
        static_evidence=_static(candidate.candidate_id),
        candidates=[candidate],
        run_id="run-diff-budget",
        plans_by_candidate={candidate.candidate_id: plan},
        planner_trace={},
        discovery_trace={},
        artifact_refs=[],
        auth_state={},
    )

    assert send_calls["count"] == 4
    assert seen_pairs == []


def test_runtime_differential_uses_configured_auth_levels(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    config.budgets.max_requests = 6
    config.differential.auth_levels = ["anonymous", "user"]
    store = EvidenceStore(tmp_path / ".padv")
    candidate = _candidate("broken_access_control")
    plan = ValidationPlan(
        candidate_id=candidate.candidate_id,
        intercepts=["header"],
        positive_requests=[
            {"method": "GET", "path": "/admin.php", "query": {"id": "1"}},
            {"method": "GET", "path": "/admin.php", "query": {"id": "1"}},
            {"method": "GET", "path": "/admin.php", "query": {"id": "1"}},
        ],
        negative_requests=[{"method": "GET", "path": "/admin.php", "query": {"id": "2"}}],
        canary="padv-canary",
    )

    send_calls = {"count": 0}
    seen_pairs: list[DifferentialPair] = []

    def _Resp():
        return HttpResponse(status_code=200, headers={}, body="ok")

    def _fake_send_request(*args, **kwargs):
        send_calls["count"] += 1
        return _Resp()

    def _fake_parse(request_id, headers, oracle):
        return _runtime(request_id, http_status=200, call_count=1, body="ok")

    def _fake_gate(**kwargs):
        pairs = kwargs.get("differential_pairs") or []
        seen_pairs.extend(pairs)
        return GateResult("DROPPED", ["V0"], "V3", "test")

    monkeypatch.setattr("padv.orchestrator.runtime.send_request", _fake_send_request)
    monkeypatch.setattr("padv.orchestrator.runtime.parse_response_headers", _fake_parse)
    monkeypatch.setattr("padv.orchestrator.runtime.evaluate_candidate", _fake_gate)

    validate_candidates_runtime(
        config=config,
        store=store,
        static_evidence=_static(candidate.candidate_id),
        candidates=[candidate],
        run_id="run-diff-levels",
        plans_by_candidate={candidate.candidate_id: plan},
        planner_trace={},
        discovery_trace={},
        artifact_refs=[],
        auth_state={"auth_levels": {"user": {"cookies": {"sessionid": "user-cookie"}}}},
    )

    assert send_calls["count"] == 6
    assert len(seen_pairs) == 2
    assert any(pair.auth_diff.endswith("_vs_anonymous") for pair in seen_pairs)
    assert any(pair.auth_diff.endswith("_vs_user") for pair in seen_pairs)

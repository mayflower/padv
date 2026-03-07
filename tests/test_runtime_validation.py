from __future__ import annotations

from pathlib import Path

import pytest

from padv.config.schema import load_config
from padv.models import Candidate, GateResult, RuntimeEvidence, StaticEvidence, ValidationPlan
from padv.orchestrator.runtime import validate_candidates_runtime
from padv.store.evidence_store import EvidenceStore


def _candidate() -> Candidate:
    return Candidate(
        candidate_id="cand-1",
        vuln_class="sql_injection_boundary",
        title="A03 SQL boundary influence",
        file_path="src/a.php",
        line=10,
        sink="mysqli_query",
        expected_intercepts=["mysqli_query"],
        notes="test",
        provenance=["source", "joern"],
        confidence=0.6,
    )


def _evidence() -> StaticEvidence:
    return StaticEvidence(
        candidate_id="cand-1",
        query_profile="default",
        query_id="joern::sql_injection_boundary",
        file_path="src/a.php",
        line=10,
        snippet="mysqli_query($db,$q)",
        hash="h1",
    )


def test_validate_runtime_requires_agent_plan(tmp_path: Path) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    store = EvidenceStore(tmp_path / ".padv")

    with pytest.raises(RuntimeError, match="missing agent-generated validation plan"):
        validate_candidates_runtime(
            config=config,
            store=store,
            static_evidence=[_evidence()],
            candidates=[_candidate()],
            run_id="run-test",
            plans_by_candidate={},
            planner_trace={},
            discovery_trace={},
            artifact_refs=[],
        )


def test_validate_runtime_forwards_auth_cookies(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    store = EvidenceStore(tmp_path / ".padv")
    candidate = _candidate()
    candidate.preconditions = []
    plan = ValidationPlan(
        candidate_id=candidate.candidate_id,
        intercepts=["mysqli_query"],
        positive_requests=[
            {"method": "GET", "path": "/", "query": {config.canary.parameter_name: "p1"}},
            {"method": "GET", "path": "/", "query": {config.canary.parameter_name: "p2"}},
            {"method": "GET", "path": "/", "query": {config.canary.parameter_name: "p3"}},
        ],
        negative_requests=[{"method": "GET", "path": "/", "query": {config.canary.parameter_name: "neg"}}],
        canary="p1",
    )
    seen_cookie_jars: list[dict[str, str]] = []

    class _Resp:
        headers: dict[str, str] = {}
        status_code: int = 200
        body: str = ""

    def _fake_send_request(*args, **kwargs):
        seen_cookie_jars.append(dict(kwargs.get("cookie_jar", {})))
        return _Resp()

    monkeypatch.setattr("padv.orchestrator.runtime.send_request", _fake_send_request)
    monkeypatch.setattr(
        "padv.orchestrator.runtime.parse_response_headers",
        lambda request_id, headers, oracle: RuntimeEvidence(
            request_id=request_id,
            status="ok",
            call_count=1,
            overflow=False,
            arg_truncated=False,
            result_truncated=False,
            correlation=request_id,
            calls=[],
            raw_headers={},
        ),
    )
    monkeypatch.setattr(
        "padv.orchestrator.runtime.evaluate_candidate",
        lambda **kwargs: GateResult("DROPPED", ["V0"], "V3", "test"),
    )

    bundles, _decisions = validate_candidates_runtime(
        config=config,
        store=store,
        static_evidence=[_evidence()],
        candidates=[candidate],
        run_id="run-auth-cookie",
        plans_by_candidate={candidate.candidate_id: plan},
        planner_trace={},
        discovery_trace={},
        artifact_refs=[],
        auth_state={"cookies": {"sessionid": "abc123", "csrf": "token"}},
    )
    assert seen_cookie_jars
    assert all(jar.get("sessionid") == "abc123" for jar in seen_cookie_jars)
    assert bundles
    planner_trace = bundles[0].planner_trace
    assert planner_trace["validation_plan"]["positive_request_count"] == 3
    assert planner_trace["validation_plan"]["negative_request_count"] == 1
    assert planner_trace["attempts"]
    assert planner_trace["attempts"][0]["phase"] == "positive"


def test_validate_runtime_embeds_candidate_hypotheses(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    store = EvidenceStore(tmp_path / ".padv")
    candidate = _candidate()
    candidate.preconditions = []
    plan = ValidationPlan(
        candidate_id=candidate.candidate_id,
        intercepts=["mysqli_query"],
        positive_requests=[
            {"method": "GET", "path": "/", "query": {config.canary.parameter_name: "p1"}},
            {"method": "GET", "path": "/", "query": {config.canary.parameter_name: "p2"}},
            {"method": "GET", "path": "/", "query": {config.canary.parameter_name: "p3"}},
        ],
        negative_requests=[{"method": "GET", "path": "/", "query": {config.canary.parameter_name: "neg"}}],
        canary="p1",
    )

    class _Resp:
        headers: dict[str, str] = {}
        status_code: int = 200
        body: str = ""

    monkeypatch.setattr("padv.orchestrator.runtime.send_request", lambda *args, **kwargs: _Resp())
    monkeypatch.setattr(
        "padv.orchestrator.runtime.parse_response_headers",
        lambda request_id, headers, oracle: RuntimeEvidence(
            request_id=request_id,
            status="ok",
            call_count=1,
            overflow=False,
            arg_truncated=False,
            result_truncated=False,
            correlation=request_id,
            calls=[],
            raw_headers={},
        ),
    )
    monkeypatch.setattr(
        "padv.orchestrator.runtime.evaluate_candidate",
        lambda **kwargs: GateResult("DROPPED", ["V0"], "V3", "test"),
    )

    bundles, _decisions = validate_candidates_runtime(
        config=config,
        store=store,
        static_evidence=[_evidence()],
        candidates=[candidate],
        run_id="run-hypotheses",
        plans_by_candidate={candidate.candidate_id: plan},
        planner_trace={
            "proposer": {
                "hypotheses": [
                    {"candidate_id": "cand-1", "rationale": "sink reachable via GET"},
                    {"candidate_id": "cand-2", "rationale": "other"},
                ]
            }
        },
        discovery_trace={},
        artifact_refs=[],
        auth_state={},
    )
    assert bundles
    hypotheses = bundles[0].planner_trace["hypotheses"]
    assert len(hypotheses) == 1
    assert hypotheses[0]["candidate_id"] == "cand-1"

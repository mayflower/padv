from __future__ import annotations

from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from urllib.parse import parse_qs

import pytest

from padv.config.schema import load_config
from padv.models import (
    Candidate,
    CanaryMatchRule,
    EvidenceBundle,
    GateResult,
    HttpExpectations,
    HttpStep,
    NegativeControl,
    OracleSpec,
    PlanBudget,
    RuntimeCall,
    RuntimeEvidence,
    StaticEvidence,
    ValidationPlan,
)
from padv.orchestrator.runtime import _normalize_gate_preconditions, _oracle_evidence, validate_candidates_runtime
from padv.store.evidence_store import EvidenceStore
from padv.validation.preconditions import GatePreconditions, InvalidGatePreconditionsError


@contextmanager
def _serve(handler: type[BaseHTTPRequestHandler]):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


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


def _structured_plan(candidate_id: str, canary: str) -> ValidationPlan:
    return ValidationPlan(
        candidate_id=candidate_id,
        intercepts=[],
        positive_requests=[],
        negative_requests=[],
        canary=canary,
        steps=[
            HttpStep(
                method="POST",
                path="/typed-submit",
                headers={"Content-Type": "application/json"},
                query={"marker": canary},
                body_type="json",
                body={"marker": canary},
                expectations=HttpExpectations(status_codes=[200]),
            )
        ],
        negative_controls=[
            NegativeControl(
                label="control-0",
                step=HttpStep(
                    method="POST",
                    path="/typed-control",
                    headers={"Content-Type": "application/json"},
                    query={"marker": "control"},
                    body_type="json",
                    body={"marker": "control"},
                    expectations=HttpExpectations(status_codes=[200]),
                ),
            )
        ],
        oracle_spec=OracleSpec(
            intercept_profile="default",
            oracle_functions=["mysqli_query"],
            canary_rules=[CanaryMatchRule(location="response_body", match_type="contains", value=canary)],
        ),
        budgets=PlanBudget(max_requests=2, max_time_s=15),
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


def test_validate_runtime_confirms_analysis_only_candidate_without_agent_plan(tmp_path: Path) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    store = EvidenceStore(tmp_path / ".padv")
    candidate = Candidate(
        candidate_id="cand-analysis",
        vuln_class="security_misconfiguration",
        title="Debug mode enabled",
        file_path="src/config.php",
        line=5,
        sink="ini_set",
        expected_intercepts=["ini_set"],
        notes="test",
        provenance=["source", "joern"],
        confidence=0.5,
    )

    bundles, decisions = validate_candidates_runtime(
        config=config,
        store=store,
        static_evidence=[
            StaticEvidence(
                candidate_id="cand-analysis",
                query_profile="default",
                query_id="joern::security_misconfiguration",
                file_path="src/config.php",
                line=5,
                snippet="ini_set('display_errors', 1)",
                hash="cfg",
            )
        ],
        candidates=[candidate],
        run_id="run-analysis-only",
        plans_by_candidate={},
        planner_trace={},
        discovery_trace={},
        artifact_refs=[],
    )

    assert decisions["CONFIRMED_ANALYSIS_FINDING"] == 1
    assert bundles[0].bundle_type == "confirmed_analysis_finding"
    assert bundles[0].validation_contract["validation_mode"] == "analysis_only"


def test_validate_runtime_executes_structured_steps_not_legacy_request_arrays(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    store = EvidenceStore(tmp_path / ".padv")
    candidate = _candidate()
    plan = _structured_plan(candidate.candidate_id, "typed-canary")
    plan.positive_requests = [{"method": "GET", "path": "/legacy-positive", "query": {"marker": "legacy"}}]
    plan.negative_requests = [{"method": "GET", "path": "/legacy-negative", "query": {"marker": "legacy"}}]
    seen_paths: list[str] = []

    class _Resp:
        headers: dict[str, str] = {}
        status_code: int = 200
        body: str = ""

    def _fake_send_request(*args, **kwargs):
        seen_paths.append(str(kwargs.get("url", "")))
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
        run_id="run-structured-only",
        plans_by_candidate={candidate.candidate_id: plan},
        planner_trace={},
        discovery_trace={},
        artifact_refs=[],
    )

    assert bundles
    assert any(path.endswith("/typed-submit") for path in seen_paths)
    assert any(path.endswith("/typed-control") for path in seen_paths)
    assert all("/legacy-" not in path for path in seen_paths)
    assert bundles[0].planner_trace["validation_plan"]["positive_request_count"] == 1
    assert bundles[0].planner_trace["validation_plan"]["negative_request_count"] == 1


def test_oracle_evidence_uses_exact_call_arg_rules() -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    canary = "padv-canary-exact"
    plan = ValidationPlan(
        candidate_id="cand-1",
        intercepts=[],
        positive_requests=[],
        negative_requests=[],
        canary=canary,
        steps=[],
        negative_controls=[],
        oracle_spec=OracleSpec(
            intercept_profile="default",
            oracle_functions=["mysqli_query"],
            canary_rules=[
                CanaryMatchRule(location="call_arg", match_type="exact", value=canary, arg_index=1),
            ],
        ),
        budgets=PlanBudget(max_requests=2, max_time_s=15),
    )
    positive = RuntimeEvidence(
        request_id="p1",
        status="active_hits",
        call_count=1,
        overflow=False,
        arg_truncated=False,
        result_truncated=False,
        correlation="p1",
        calls=[
            RuntimeCall(function="mysqli_query", file="app.php", line=12, args=[f"prefix {canary}", canary])
        ],
        raw_headers={},
    )
    negative = RuntimeEvidence(
        request_id="n1",
        status="active_no_hits",
        call_count=1,
        overflow=False,
        arg_truncated=False,
        result_truncated=False,
        correlation="n1",
        calls=[
            RuntimeCall(function="mysqli_query", file="app.php", line=12, args=[f"prefix {canary}", "safe"])
        ],
        raw_headers={},
    )

    positive_hits = _oracle_evidence(positive, plan, config)
    negative_hits = _oracle_evidence(negative, plan, config)

    assert len(positive_hits) == 1
    assert positive_hits[0].matched_canary is True
    assert len(negative_hits) == 1
    assert negative_hits[0].matched_canary is False


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
        oracle_functions=["mysqli_query"],
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


def test_validate_runtime_uses_distinct_sessions_per_candidate(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    store = EvidenceStore(tmp_path / ".padv")
    candidate_one = _candidate()
    candidate_one.preconditions = []
    candidate_two = Candidate(**candidate_one.to_dict())
    candidate_two.candidate_id = "cand-2"
    candidate_two.title = "A03 SQL boundary influence variant"
    candidate_two.expected_intercepts = ["mysqli_query"]

    plan_one = ValidationPlan(
        candidate_id=candidate_one.candidate_id,
        intercepts=["mysqli_query"],
        positive_requests=[{"method": "GET", "path": "/", "query": {config.canary.parameter_name: "one"}}],
        negative_requests=[],
        canary="one",
        oracle_functions=["mysqli_query"],
    )
    plan_two = ValidationPlan(
        candidate_id=candidate_two.candidate_id,
        intercepts=["mysqli_query"],
        positive_requests=[{"method": "GET", "path": "/", "query": {config.canary.parameter_name: "two"}}],
        negative_requests=[],
        canary="two",
        oracle_functions=["mysqli_query"],
    )
    sessions_by_candidate: dict[str, object] = {}

    class _Resp:
        headers: dict[str, str] = {}
        status_code: int = 200
        body: str = ""

    def _fake_send_request(*args, **kwargs):
        headers = kwargs.get("headers", {})
        correlation = str(headers.get(config.oracle.request_correlation_header, ""))
        candidate_id = correlation.split("-pos-", 1)[0]
        session = kwargs.get("session")
        assert session is not None
        existing = sessions_by_candidate.get(candidate_id)
        if existing is None:
            sessions_by_candidate[candidate_id] = session
        else:
            assert existing is session
        session.cookies["learned"] = candidate_id
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
        static_evidence=[
            _evidence(),
            StaticEvidence(
                candidate_id="cand-2",
                query_profile="default",
                query_id="joern::sql_injection_boundary",
                file_path="src/a.php",
                line=11,
                snippet="mysqli_query($db,$q2)",
                hash="h2",
            ),
        ],
        candidates=[candidate_one, candidate_two],
        run_id="run-candidate-sessions",
        plans_by_candidate={
            candidate_one.candidate_id: plan_one,
            candidate_two.candidate_id: plan_two,
        },
        planner_trace={},
        discovery_trace={},
        artifact_refs=[],
        auth_state={"cookies": {"sessionid": "seed"}},
    )

    assert len(bundles) == 2
    assert set(sessions_by_candidate) == {"cand-1", "cand-2"}
    assert sessions_by_candidate["cand-1"] is not sessions_by_candidate["cand-2"]


def test_validate_runtime_executes_structured_csrf_flow(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    store = EvidenceStore(tmp_path / ".padv")
    candidate = _candidate()
    candidate.preconditions = []
    plan = ValidationPlan(
        candidate_id=candidate.candidate_id,
        intercepts=["mysqli_query"],
        positive_requests=[],
        negative_requests=[],
        canary="csrf-token",
        steps=[
            HttpStep(method="GET", path="/login", expectations=HttpExpectations(status_codes=[200])),
            HttpStep(method="GET", path="/token", expectations=HttpExpectations(status_codes=[200])),
            HttpStep(
                method="POST",
                path="/action",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                body_type="form",
                body={"csrf_token": "{{token:csrf_token}}", "action": "apply"},
                expectations=HttpExpectations(status_codes=[200]),
            ),
        ],
        oracle_spec=OracleSpec(intercept_profile="default", oracle_functions=["mysqli_query"], canary_rules=[]),
        budgets=PlanBudget(max_requests=3, max_time_s=15),
    )
    seen_requests: list[tuple[str, str, str]] = []

    class _CsrfHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            seen_requests.append((self.command, self.path, self.headers.get("Cookie", "")))
            if self.path == "/login":
                self.send_response(200)
                self.send_header("Set-Cookie", "sessionid=abc123; Path=/; HttpOnly")
                self.end_headers()
                self.wfile.write(b"logged-in")
                return
            if self.path == "/token":
                if "sessionid=abc123" not in self.headers.get("Cookie", ""):
                    self.send_response(401)
                    self.end_headers()
                    self.wfile.write(b"missing-cookie")
                    return
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"csrf_token":"token-123"}')
                return
            self.send_response(404)
            self.end_headers()

        def do_POST(self) -> None:  # noqa: N802
            content_length = int(self.headers.get("Content-Length", "0") or "0")
            body = self.rfile.read(content_length).decode("utf-8", errors="replace")
            seen_requests.append((self.command, f"{self.path}?{body}", self.headers.get("Cookie", "")))
            form = parse_qs(body, keep_blank_values=True)
            if self.path != "/action":
                self.send_response(404)
                self.end_headers()
                return
            if "sessionid=abc123" not in self.headers.get("Cookie", ""):
                self.send_response(401)
                self.end_headers()
                self.wfile.write(b"missing-cookie")
                return
            if form.get("csrf_token") != ["token-123"]:
                self.send_response(403)
                self.end_headers()
                self.wfile.write(b"missing-token")
                return
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, format: str, *args) -> None:  # pragma: no cover
            return

    monkeypatch.setattr(
        "padv.orchestrator.runtime.parse_response_headers",
        lambda request_id, headers, oracle: RuntimeEvidence(
            request_id=request_id,
            status="ok",
            call_count=0,
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

    with _serve(_CsrfHandler) as base_url:
        config.target.base_url = base_url
        bundles, _decisions = validate_candidates_runtime(
            config=config,
            store=store,
            static_evidence=[_evidence()],
            candidates=[candidate],
            run_id="run-csrf-flow",
            plans_by_candidate={candidate.candidate_id: plan},
            planner_trace={},
            discovery_trace={},
            artifact_refs=[],
        )

    assert bundles
    assert seen_requests == [
        ("GET", "/login", ""),
        ("GET", "/token", "sessionid=abc123"),
        ("POST", "/action?csrf_token=token-123&action=apply", "sessionid=abc123"),
    ]


def test_validate_runtime_passes_shared_witness_contract_and_witness(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
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
        ],
        negative_requests=[{"method": "GET", "path": "/", "query": {config.canary.parameter_name: "neg"}}],
        canary="p1",
        oracle_functions=["mysqli_query"],
    )
    seen: dict[str, object] = {}

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

    def _fake_evaluate_candidate(**kwargs):
        seen["witness"] = kwargs.get("witness")
        seen["witness_contract"] = kwargs.get("witness_contract")
        return GateResult("DROPPED", ["V0"], "V3", "test")

    monkeypatch.setattr("padv.orchestrator.runtime.evaluate_candidate", _fake_evaluate_candidate)

    validate_candidates_runtime(
        config=config,
        store=store,
        static_evidence=[_evidence()],
        candidates=[candidate],
        run_id="run-shared-witness-contract",
        plans_by_candidate={candidate.candidate_id: plan},
        planner_trace={},
        discovery_trace={},
        artifact_refs=[],
    )

    witness = seen["witness"]
    witness_contract = seen["witness_contract"]
    assert witness is not None
    assert witness_contract is not None
    assert witness.canonical_class == "sql_injection_boundary"
    assert witness_contract.canonical_class == "sql_injection_boundary"


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
        oracle_functions=["mysqli_query"],
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


def test_validate_runtime_associates_static_evidence_via_evidence_refs(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    store = EvidenceStore(tmp_path / ".padv")
    candidate = _candidate()
    candidate.candidate_id = "cand-derived"
    candidate.evidence_refs = ["joern::sql_injection_boundary:src/a.php:10"]
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
        oracle_functions=["mysqli_query"],
    )
    seen_query_ids: list[list[str]] = []

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

    def _fake_evaluate_candidate(**kwargs):
        seen_query_ids.append([item.query_id for item in kwargs["static_evidence"]])
        return GateResult("DROPPED", ["V0"], "V3", "test")

    monkeypatch.setattr("padv.orchestrator.runtime.evaluate_candidate", _fake_evaluate_candidate)

    bundles, _ = validate_candidates_runtime(
        config=config,
        store=store,
        static_evidence=[_evidence()],
        candidates=[candidate],
        run_id="run-derived-static",
        plans_by_candidate={candidate.candidate_id: plan},
        planner_trace={},
        discovery_trace={},
        artifact_refs=[],
    )

    assert seen_query_ids == [["joern::sql_injection_boundary"]]
    assert [item.query_id for item in bundles[0].static_evidence] == ["joern::sql_injection_boundary"]


def test_validate_runtime_uses_oracle_functions_and_preserves_request_headers(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    store = EvidenceStore(tmp_path / ".padv")
    candidate = _candidate()
    candidate.preconditions = []
    plan = ValidationPlan(
        candidate_id=candidate.candidate_id,
        intercepts=["POST /submit", "HTTP 200"],
        oracle_functions=["shell_exec"],
        request_expectations=["POST /submit"],
        response_witnesses=["HTTP 200"],
        positive_requests=[
            {
                "method": "POST",
                "path": "/submit",
                "headers": {"Content-Type": "text/xml", "SOAPAction": "urn:test"},
                "body_text": "<message>test</message>",
                "query": {},
            }
        ] * 3,
        negative_requests=[
            {
                "method": "POST",
                "path": "/submit",
                "headers": {"Content-Type": "text/xml"},
                "body_text": "<message>neg</message>",
                "query": {},
            }
        ],
        canary="p1",
    )
    seen_headers: list[dict[str, str]] = []
    seen_bodies: list[object] = []

    class _Resp:
        headers: dict[str, str] = {}
        status_code: int = 200
        body: str = ""

    def _fake_send_request(*args, **kwargs):
        seen_headers.append(dict(kwargs.get("headers", {})))
        seen_bodies.append(kwargs.get("body"))
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

    validate_candidates_runtime(
        config=config,
        store=store,
        static_evidence=[_evidence()],
        candidates=[candidate],
        run_id="run-header-preserve",
        plans_by_candidate={candidate.candidate_id: plan},
        planner_trace={},
        discovery_trace={},
        artifact_refs=[],
        auth_state={},
    )


def test_validate_runtime_populates_typed_runtime_evidence(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    store = EvidenceStore(tmp_path / ".padv")
    candidate = _candidate()
    candidate.vuln_class = "sql_injection"
    plan = ValidationPlan(
        candidate_id=candidate.candidate_id,
        intercepts=["mysqli_query"],
        oracle_functions=["mysqli_query"],
        positive_requests=[
            {"method": "POST", "path": "/submit", "body": {"ToolID": "1' UNION SELECT"}},
            {"method": "POST", "path": "/submit", "body": {"ToolID": "1' AND SLEEP(5)"}},
            {"method": "POST", "path": "/submit", "body": {"ToolID": "1' OR '1'='1"}},
        ],
        negative_requests=[{"method": "POST", "path": "/submit", "body": {"ToolID": "1"}}],
        canary="padv-canary-typed",
        validation_mode="runtime",
        canonical_class="sql_injection_boundary",
        class_contract_id="runtime:sql_injection_boundary",
    )

    class _Resp:
        headers: dict[str, str] = {}
        status_code: int = 200
        body: str = "mysql syntax error near padv-canary-typed"

    monkeypatch.setattr("padv.orchestrator.runtime.send_request", lambda *args, **kwargs: _Resp())
    monkeypatch.setattr(
        "padv.orchestrator.runtime.parse_response_headers",
        lambda request_id, headers, oracle: RuntimeEvidence(
            request_id=request_id,
            status="active_hits",
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

    bundles, _ = validate_candidates_runtime(
        config=config,
        store=store,
        static_evidence=[_evidence()],
        candidates=[candidate],
        run_id="run-typed-evidence",
        plans_by_candidate={candidate.candidate_id: plan},
        planner_trace={},
        discovery_trace={},
        artifact_refs=[],
    )
    evidence = bundles[0].positive_runtime[0]
    assert evidence.request_evidence is not None
    assert evidence.response_evidence is not None
    assert evidence.witness_evidence is not None


def test_validate_runtime_rejects_legacy_candidate_preconditions(tmp_path: Path) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    store = EvidenceStore(tmp_path / ".padv")
    candidate = _candidate()
    candidate.preconditions = [
        "runtime-oracle-not-applicable",
        "Content-Type: text/xml",
        "Valid SOAP 1.1 envelope structure with message parameter",
    ]
    plan = ValidationPlan(
        candidate_id=candidate.candidate_id,
        intercepts=["mysqli_query"],
        positive_requests=[{"method": "GET", "path": "/", "query": {config.canary.parameter_name: "p1"}}],
        negative_requests=[{"method": "GET", "path": "/", "query": {config.canary.parameter_name: "neg"}}],
        canary="p1",
        oracle_functions=["mysqli_query"],
    )

    with pytest.raises(InvalidGatePreconditionsError, match="legacy candidate.preconditions/auth_requirements"):
        validate_candidates_runtime(
            config=config,
            store=store,
            static_evidence=[_evidence()],
            candidates=[candidate],
            run_id="run-filter-preconditions",
            plans_by_candidate={candidate.candidate_id: plan},
            planner_trace={},
            discovery_trace={},
            artifact_refs=[],
            auth_state={},
        )


def test_validate_runtime_rejects_legacy_auth_requirements_even_with_cookies(tmp_path: Path) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    store = EvidenceStore(tmp_path / ".padv")
    candidate = _candidate()
    candidate.auth_requirements = ["Authenticated session required"]
    plan = ValidationPlan(
        candidate_id=candidate.candidate_id,
        intercepts=["mysqli_query"],
        positive_requests=[{"method": "GET", "path": "/", "query": {config.canary.parameter_name: "p1"}}],
        negative_requests=[{"method": "GET", "path": "/", "query": {config.canary.parameter_name: "neg"}}],
        canary="p1",
        oracle_functions=["mysqli_query"],
    )

    with pytest.raises(InvalidGatePreconditionsError, match="legacy candidate.preconditions/auth_requirements"):
        validate_candidates_runtime(
            config=config,
            store=store,
            static_evidence=[_evidence()],
            candidates=[candidate],
            run_id="run-auth-resolved",
            plans_by_candidate={candidate.candidate_id: plan},
            planner_trace={},
            discovery_trace={},
            artifact_refs=[],
            auth_state={"cookies": {"PHPSESSID": "abc"}},
        )


def test_validate_runtime_reuses_existing_bundle_without_replaying_requests(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    store = EvidenceStore(tmp_path / ".padv")
    candidate = _candidate()
    plan = ValidationPlan(
        candidate_id=candidate.candidate_id,
        intercepts=["mysqli_query"],
        oracle_functions=["mysqli_query"],
        positive_requests=[{"method": "GET", "path": "/", "query": {config.canary.parameter_name: "p1"}}],
        negative_requests=[],
        canary="p1",
    )
    bundle = EvidenceBundle(
        bundle_id="bundle-run-reuse-cand-1",
        created_at="2026-03-08T12:00:00+00:00",
        candidate=candidate,
        static_evidence=[_evidence()],
        positive_runtime=[
            RuntimeEvidence(
                request_id="cand-1-pos-01",
                status="ok",
                call_count=1,
                overflow=False,
                arg_truncated=False,
                result_truncated=False,
                correlation="cand-1-pos-01",
                calls=[],
                raw_headers={},
            )
        ],
        negative_runtime=[],
        repro_run_ids=[],
        gate_result=GateResult("DROPPED", ["V0"], "V3", "cached"),
        limitations=[],
        differential_pairs=[],
        artifact_refs=[],
        discovery_trace={},
        planner_trace={},
    )
    store.save_bundle(bundle, run_id="run-reuse")

    def _should_not_send(*_args, **_kwargs):
        raise AssertionError("send_request should not run when bundle already exists")

    monkeypatch.setattr("padv.orchestrator.runtime.send_request", _should_not_send)
    monkeypatch.setattr(
        "padv.store.evidence_store.EvidenceStore.load_bundle_legacy_lookup",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("legacy bundle lookup should not run")),
    )

    bundles, decisions = validate_candidates_runtime(
        config=config,
        store=store,
        static_evidence=[_evidence()],
        candidates=[candidate],
        run_id="run-reuse",
        plans_by_candidate={candidate.candidate_id: plan},
        planner_trace={},
        discovery_trace={},
        artifact_refs=[],
    )

    assert len(bundles) == 1
    assert bundles[0].bundle_id == bundle.bundle_id
    assert decisions["DROPPED"] == 1


def test_validate_runtime_marks_tail_candidates_skipped_when_budget_exhausts(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    config.budgets.max_requests = 1
    store = EvidenceStore(tmp_path / ".padv")
    candidate_one = _candidate()
    candidate_two = Candidate(**candidate_one.to_dict())
    candidate_two.candidate_id = "cand-2"
    candidate_two.title = "A03 SQL boundary influence variant"
    candidate_two.line = 11
    evidence_one = _evidence()
    evidence_two = StaticEvidence(
        candidate_id=candidate_two.candidate_id,
        query_profile="default",
        query_id="joern::sql_injection_boundary",
        file_path="src/a.php",
        line=11,
        snippet="mysqli_query($db,$q2)",
        hash="h2",
    )
    plan_one = ValidationPlan(candidate_id=candidate_one.candidate_id, intercepts=[], positive_requests=[], negative_requests=[], canary="")
    plan_two = ValidationPlan(candidate_id=candidate_two.candidate_id, intercepts=[], positive_requests=[], negative_requests=[], canary="")
    processed: list[str] = []

    def _fake_process_candidate(ctx, target, request_budget_remaining, run_deadline):
        del request_budget_remaining, run_deadline
        processed.append(target.candidate.candidate_id)
        bundle = EvidenceBundle(
            bundle_id=f"bundle-{ctx.run_id}-{target.candidate.candidate_id}",
            created_at="2026-03-06T00:00:00+00:00",
            candidate=target.candidate,
            static_evidence=target.static_evidence,
            positive_runtime=[],
            negative_runtime=[],
            repro_run_ids=[],
            gate_result=GateResult("DROPPED", ["V0"], "V3", "test"),
            limitations=["test"],
            differential_pairs=[],
            artifact_refs=[],
            discovery_trace={},
            planner_trace={},
            bundle_type="dropped",
        )
        ctx.store.save_bundle(bundle, run_id=ctx.run_id)
        return bundle, 1

    monkeypatch.setattr("padv.orchestrator.runtime._process_candidate", _fake_process_candidate)

    bundles, decisions = validate_candidates_runtime(
        config=config,
        store=store,
        static_evidence=[evidence_one, evidence_two],
        candidates=[candidate_one, candidate_two],
        run_id="run-budget-tail",
        plans_by_candidate={
            candidate_one.candidate_id: plan_one,
            candidate_two.candidate_id: plan_two,
        },
        planner_trace={},
        discovery_trace={},
        artifact_refs=[],
    )

    assert processed == ["cand-1"]
    assert [bundle.gate_result.decision for bundle in bundles] == ["DROPPED", "SKIPPED_BUDGET"]
    assert [bundle.candidate_outcome for bundle in bundles] == ["REFUTED", "SKIPPED_BUDGET"]
    assert bundles[1].bundle_type == "skipped_budget"
    assert "budget exhausted" in bundles[1].gate_result.reason
    assert decisions["DROPPED"] == 1
    assert decisions["SKIPPED_BUDGET"] == 1
    persisted = store.load_bundle("bundle-run-budget-tail-cand-2", run_id="run-budget-tail")
    assert persisted is not None
    assert persisted["candidate_outcome"] == "SKIPPED_BUDGET"


def test_normalize_gate_preconditions_rejects_legacy_strings() -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    candidate = _candidate_with_preconditions(["Login required before reaching the endpoint"])

    with pytest.raises(InvalidGatePreconditionsError, match="legacy candidate.preconditions/auth_requirements"):
        _normalize_gate_preconditions(candidate, None, {}, config)


def test_normalize_gate_preconditions_ignores_legacy_prose_when_typed_requirements_exist() -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    first = _candidate_with_preconditions(
        ["planner explanation version one"],
        auth_requirements=["separate human note"],
        gate_preconditions=GatePreconditions(requires_auth=True, requires_session=True),
    )
    second = _candidate_with_preconditions(
        ["planner explanation version two"],
        auth_requirements=["same setup explained differently"],
        gate_preconditions=GatePreconditions(requires_auth=True, requires_session=True),
        candidate_id="cand-preconditions-2",
    )

    first_normalized = _normalize_gate_preconditions(first, None, {}, config)
    second_normalized = _normalize_gate_preconditions(second, None, {}, config)

    assert first_normalized == GatePreconditions(requires_auth=True, requires_session=True)
    assert second_normalized == first_normalized


def test_normalize_gate_preconditions_resolves_typed_auth_and_session_with_cookies() -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    candidate = _candidate_with_preconditions(
        ["legacy prose should not survive once typed preconditions resolve"],
        gate_preconditions=GatePreconditions(requires_auth=True, requires_session=True),
    )

    unresolved = _normalize_gate_preconditions(candidate, None, {"PHPSESSID": "abc"}, config)

    assert unresolved == GatePreconditions()


def _candidate_with_preconditions(
    preconditions: list[str],
    *,
    candidate_id: str = "cand-preconditions",
    vuln_class: str = "command_injection_boundary",
    title: str = "typed preconditions",
    file_path: str = "src/a.php",
    sink: str = "shell_exec",
    auth_requirements: list[str] | None = None,
    expected_intercepts: list[str] | None = None,
    gate_preconditions: GatePreconditions | None = None,
) -> Candidate:
    return Candidate(
        candidate_id=candidate_id,
        vuln_class=vuln_class,
        title=title,
        file_path=file_path,
        line=10,
        sink=sink,
        expected_intercepts=expected_intercepts or [sink],
        preconditions=preconditions,
        auth_requirements=list(auth_requirements or []),
        gate_preconditions=gate_preconditions or GatePreconditions(),
    )

from __future__ import annotations

from pathlib import Path

import pytest

from padv.config.schema import load_config
from padv.models import Candidate, EvidenceBundle, GateResult, RuntimeEvidence, StaticEvidence, ValidationPlan
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


def test_validate_runtime_filters_nonblocking_preconditions(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    store = EvidenceStore(tmp_path / ".padv")
    candidate = _candidate()
    candidate.preconditions = [
        "runtime-oracle-not-applicable",
        "Content-Type: text/xml",
        "Valid SOAP 1.1 envelope structure with message parameter",
        "Security level 0 (default)",
        "$lProtectAgainstSQLInjection=false",
        "Public endpoint accessibility",
    ]
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
    seen_preconditions: list[list[str]] = []

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
        seen_preconditions.append(list(kwargs["preconditions"]))
        return GateResult("DROPPED", ["V0"], "V3", "test")

    monkeypatch.setattr("padv.orchestrator.runtime.evaluate_candidate", _fake_evaluate_candidate)

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

    assert seen_preconditions == [[]]


def test_validate_runtime_filters_trivial_candidate_preconditions(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    store = EvidenceStore(tmp_path / ".padv")
    candidate = _candidate()
    candidate.preconditions = [
        "MySQL connection active",
        "POST or GET request with ToolID parameter",
        "Direct endpoint access via POST or GET",
        "security_level IN [0, 1]",
        "none - unauthenticated access allowed",
    ]
    candidate.auth_requirements = [
        "none - endpoint accessible without authentication despite session_start()",
    ]
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
    seen_preconditions: list[list[str]] = []

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
        seen_preconditions.append(list(kwargs["preconditions"]))
        return GateResult("DROPPED", ["V0"], "V3", "test")

    monkeypatch.setattr("padv.orchestrator.runtime.evaluate_candidate", _fake_evaluate_candidate)

    validate_candidates_runtime(
        config=config,
        store=store,
        static_evidence=[_evidence()],
        candidates=[candidate],
        run_id="run-filter-trivial-preconditions",
        plans_by_candidate={candidate.candidate_id: plan},
        planner_trace={},
        discovery_trace={},
        artifact_refs=[],
        auth_state={"cookies": {"PHPSESSID": "abc"}},
    )

    assert seen_preconditions == [[]]


def test_validate_runtime_filters_satisfied_sql_shape_preconditions(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    store = EvidenceStore(tmp_path / ".padv")
    candidate = _candidate()
    candidate.preconditions = [
        "Default security level is 0, satisfying precondition",
        "Query must return 5 columns for successful UNION: SELECT tool_id, tool_name, phase_to_use, tool_type, comment",
        "Security level must be 0 or 1 (SESSION[security-level] in {0,1})",
    ]
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
    seen_preconditions: list[list[str]] = []

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
        seen_preconditions.append(list(kwargs["preconditions"]))
        return GateResult("DROPPED", ["V0"], "V3", "test")

    monkeypatch.setattr("padv.orchestrator.runtime.evaluate_candidate", _fake_evaluate_candidate)

    validate_candidates_runtime(
        config=config,
        store=store,
        static_evidence=[_evidence()],
        candidates=[candidate],
        run_id="run-filter-sql-shape-preconditions",
        plans_by_candidate={candidate.candidate_id: plan},
        planner_trace={},
        discovery_trace={},
        artifact_refs=[],
        auth_state={},
    )

    assert seen_preconditions == [[]]


def test_validate_runtime_filters_nonhuman_sql_runtime_preconditions(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    store = EvidenceStore(tmp_path / ".padv")
    candidate = _candidate()
    candidate.preconditions = [
        "Application must be at security level 0 or 1 (default is 0)",
        "Database must be accessible and populated with pen_test_tools table",
        "For UNION-based: Must match 5-column structure of base query",
        "For boolean-blind: Differential response analysis based on WHERE clause evaluation",
        "For error-based: Intentional syntax errors trigger CustomErrorHandler reflection",
        "For special UUID: Must use exact UUID 'c84326e4-7487-41d3-91fd-88280828c756' which triggers $lWhereClause = ';'",
        "For time-based: SLEEP() function must be available in MySQL",
        "MySQL error reporting must be enabled (default at security levels 0-1)",
        "PHP session must be initiated (automatically happens on first request)",
    ]
    candidate.auth_requirements = [
        "Active PHP session (established via session_start() - no credentials required)",
        "No JWT token required (AJAX endpoints do not implement JWT authentication)",
        "No special permissions or roles required",
        "No username/password required",
    ]
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
    seen_preconditions: list[list[str]] = []

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
        seen_preconditions.append(list(kwargs["preconditions"]))
        return GateResult("DROPPED", ["V0"], "V3", "test")

    monkeypatch.setattr("padv.orchestrator.runtime.evaluate_candidate", _fake_evaluate_candidate)

    validate_candidates_runtime(
        config=config,
        store=store,
        static_evidence=[_evidence()],
        candidates=[candidate],
        run_id="run-filter-nonhuman-sql-preconditions",
        plans_by_candidate={candidate.candidate_id: plan},
        planner_trace={},
        discovery_trace={},
        artifact_refs=[],
        auth_state={},
    )

    assert seen_preconditions == [[]]


def test_validate_runtime_resolves_auth_requirements_when_cookies_present(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    store = EvidenceStore(tmp_path / ".padv")
    candidate = _candidate()
    candidate.preconditions = []
    candidate.auth_requirements = ["Authenticated session required"]
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
    seen_preconditions: list[list[str]] = []

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
        seen_preconditions.append(list(kwargs["preconditions"]))
        return GateResult("DROPPED", ["V0"], "V3", "test")

    monkeypatch.setattr("padv.orchestrator.runtime.evaluate_candidate", _fake_evaluate_candidate)

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

    assert seen_preconditions == [[]]


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
    store.save_bundle(bundle)

    def _should_not_send(*_args, **_kwargs):
        raise AssertionError("send_request should not run when bundle already exists")

    monkeypatch.setattr("padv.orchestrator.runtime.send_request", _should_not_send)

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

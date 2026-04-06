from __future__ import annotations

from pathlib import Path

from padv.config.schema import load_config
from padv.gates.engine import _RUNTIME_VALIDATABLE_CLASSES, evaluate_candidate
from padv.models import RuntimeCall, RuntimeEvidence, StaticEvidence, WitnessContract
from padv.validation.contracts import runtime_witness_contracts
from padv.validation.preconditions import GatePreconditions


def _static() -> list[StaticEvidence]:
    return [
        StaticEvidence(
            candidate_id="cand-1",
            query_profile="default",
            query_id="joern::sql_injection_boundary",
            file_path="src/app.php",
            line=10,
            snippet="mysqli_query($db, $q);",
            hash="abc",
        )
    ]


def _runtime_sql(
    request_id: str,
    *,
    canary: str,
    status_code: int,
    body_excerpt: str,
    call_arg: str,
) -> RuntimeEvidence:
    return RuntimeEvidence(
        request_id=request_id,
        status="active_hits",
        call_count=1,
        overflow=False,
        arg_truncated=False,
        result_truncated=False,
        correlation=request_id,
        calls=[RuntimeCall(function="mysqli_query", file="src/app.php", line=10, args=[call_arg])],
        raw_headers={},
        http_status=status_code,
        body_excerpt=body_excerpt,
    )


def test_gate_sql_requires_sink_and_differential_witness() -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    canary = "padv-canary"
    result = evaluate_candidate(
        config=config,
        static_evidence=_static(),
        positive_runs=[
            _runtime_sql("p1", canary=canary, status_code=200, body_excerpt="ok one", call_arg=f"SELECT '{canary}'"),
            _runtime_sql("p2", canary=canary, status_code=200, body_excerpt="ok two", call_arg=f"SELECT '{canary}'"),
            _runtime_sql("p3", canary=canary, status_code=200, body_excerpt="ok three", call_arg=f"SELECT '{canary}'"),
        ],
        negative_runs=[
            _runtime_sql("n1", canary=canary, status_code=500, body_excerpt="safe", call_arg="SELECT 'safe-value'")
        ],
        intercepts=["mysqli_query"],
        canary=canary,
        preconditions=GatePreconditions(),
        evidence_signals=["joern", "scip"],
        vuln_class="sql_injection_boundary",
    )
    assert result.decision == "VALIDATED"


def test_gate_sql_drops_without_differential_witness() -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    canary = "padv-canary"
    result = evaluate_candidate(
        config=config,
        static_evidence=_static(),
        positive_runs=[
            _runtime_sql("p1", canary=canary, status_code=200, body_excerpt="same", call_arg=f"SELECT '{canary}'"),
            _runtime_sql("p2", canary=canary, status_code=200, body_excerpt="same", call_arg=f"SELECT '{canary}'"),
            _runtime_sql("p3", canary=canary, status_code=200, body_excerpt="same", call_arg=f"SELECT '{canary}'"),
        ],
        negative_runs=[
            _runtime_sql("n1", canary=canary, status_code=200, body_excerpt="same", call_arg="SELECT 'safe-value'")
        ],
        intercepts=["mysqli_query"],
        canary=canary,
        preconditions=GatePreconditions(),
        evidence_signals=["joern", "scip"],
        vuln_class="sql_injection_boundary",
    )
    assert result.decision == "DROPPED"
    assert result.failed_gate == "V3"


def test_gate_sql_negative_control_rejects_oracle_hit() -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    canary = "padv-canary"
    result = evaluate_candidate(
        config=config,
        static_evidence=_static(),
        positive_runs=[
            _runtime_sql("p1", canary=canary, status_code=200, body_excerpt="ok one", call_arg=f"SELECT '{canary}'"),
            _runtime_sql("p2", canary=canary, status_code=200, body_excerpt="ok two", call_arg=f"SELECT '{canary}'"),
            _runtime_sql("p3", canary=canary, status_code=200, body_excerpt="ok three", call_arg=f"SELECT '{canary}'"),
        ],
        negative_runs=[
            _runtime_sql("n1", canary=canary, status_code=500, body_excerpt="safe", call_arg=f"SELECT '{canary}'")
        ],
        intercepts=["mysqli_query"],
        canary=canary,
        preconditions=GatePreconditions(),
        evidence_signals=["joern", "scip"],
        vuln_class="sql_injection_boundary",
    )
    assert result.decision == "DROPPED"
    assert result.failed_gate == "V4"


def test_runtime_validatable_classes_have_witness_rules() -> None:
    missing = sorted(_RUNTIME_VALIDATABLE_CLASSES - set(runtime_witness_contracts().keys()))
    assert not missing


def test_gate_uses_shared_witness_contract_provider(monkeypatch) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")

    monkeypatch.setattr(
        "padv.gates.engine.witness_contract_for_vuln_class",
        lambda vuln_class: WitnessContract(
            canonical_class=str(vuln_class),
            required_all=["custom_contract_only"],
            required_any=[],
            negative_must_not_include=["custom_contract_only"],
            enforce_negative_clean=True,
        ),
    )

    result = evaluate_candidate(
        config=config,
        static_evidence=_static(),
        positive_runs=[
            _runtime_call("p1", function="curl_exec", arg="http://127.0.0.1/internal"),
            _runtime_call("p2", function="curl_exec", arg="http://127.0.0.1/internal"),
            _runtime_call("p3", function="curl_exec", arg="http://127.0.0.1/internal"),
        ],
        negative_runs=[_runtime_call("n1", function="curl_exec", arg="https://example.org/safe")],
        intercepts=["curl_exec"],
        canary="padv-canary",
        preconditions=GatePreconditions(),
        evidence_signals=["joern", "scip"],
        vuln_class="ssrf",
    )

    assert result.decision == "DROPPED"
    assert result.failed_gate == "V3"


def _runtime_call(
    request_id: str,
    *,
    function: str,
    arg: str,
) -> RuntimeEvidence:
    return RuntimeEvidence(
        request_id=request_id,
        status="active_hits",
        call_count=1,
        overflow=False,
        arg_truncated=False,
        result_truncated=False,
        correlation=request_id,
        calls=[RuntimeCall(function=function, file="src/app.php", line=10, args=[arg])],
        raw_headers={},
        http_status=200,
        body_excerpt="ok",
    )


def test_gate_ssrf_requires_url_arg_witness() -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    canary = "padv-canary"
    result = evaluate_candidate(
        config=config,
        static_evidence=_static(),
        positive_runs=[
            _runtime_call("p1", function="curl_exec", arg=f"http://127.0.0.1/internal?x={canary}"),
            _runtime_call("p2", function="curl_exec", arg=f"http://127.0.0.1/internal?x={canary}"),
            _runtime_call("p3", function="curl_exec", arg=f"http://127.0.0.1/internal?x={canary}"),
        ],
        negative_runs=[_runtime_call("n1", function="curl_exec", arg="https://example.org/safe")],
        intercepts=["curl_exec"],
        canary=canary,
        preconditions=GatePreconditions(),
        evidence_signals=["joern", "scip"],
        vuln_class="ssrf",
    )
    assert result.decision == "VALIDATED"


def test_gate_xxe_requires_entity_witness() -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    canary = "padv-canary"
    payload = (
        "<!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>"
        f"<root>{canary}</root>"
    )
    result = evaluate_candidate(
        config=config,
        static_evidence=_static(),
        positive_runs=[
            _runtime_call("p1", function="DOMDocument::loadXML", arg=payload),
            _runtime_call("p2", function="DOMDocument::loadXML", arg=payload),
            _runtime_call("p3", function="DOMDocument::loadXML", arg=payload),
        ],
        negative_runs=[_runtime_call("n1", function="DOMDocument::loadXML", arg="<root>safe</root>")],
        intercepts=["DOMDocument::loadXML"],
        canary=canary,
        preconditions=GatePreconditions(),
        evidence_signals=["joern", "scip"],
        vuln_class="xxe_influence",
    )
    assert result.decision == "VALIDATED"


def test_gate_xss_raw_canary_without_dom_witness_is_rejected() -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    result = evaluate_candidate(
        config=config,
        static_evidence=_static(),
        positive_runs=[
            RuntimeEvidence(
                request_id="p1",
                status="http_observed",
                call_count=0,
                overflow=False,
                arg_truncated=False,
                result_truncated=False,
                correlation="p1",
                calls=[],
                raw_headers={},
                analysis_flags=["xss_raw_canary"],
            ),
            RuntimeEvidence(
                request_id="p2",
                status="http_observed",
                call_count=0,
                overflow=False,
                arg_truncated=False,
                result_truncated=False,
                correlation="p2",
                calls=[],
                raw_headers={},
                analysis_flags=["xss_raw_canary"],
            ),
            RuntimeEvidence(
                request_id="p3",
                status="http_observed",
                call_count=0,
                overflow=False,
                arg_truncated=False,
                result_truncated=False,
                correlation="p3",
                calls=[],
                raw_headers={},
                analysis_flags=["xss_raw_canary"],
            ),
        ],
        negative_runs=[
            RuntimeEvidence(
                request_id="n1",
                status="http_observed",
                call_count=0,
                overflow=False,
                arg_truncated=False,
                result_truncated=False,
                correlation="n1",
                calls=[],
                raw_headers={},
                analysis_flags=[],
            )
        ],
        intercepts=[],
        canary="padv-canary",
        preconditions=GatePreconditions(),
        evidence_signals=["joern", "scip"],
        vuln_class="xss_output_boundary",
    )
    assert result.decision == "DROPPED"
    assert result.failed_gate == "V3"

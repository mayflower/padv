from __future__ import annotations

import base64
import json
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from urllib.parse import parse_qs, urlsplit

import pytest

import padv.orchestrator.graphs as graph_mod
from padv.config.schema import load_config
from padv.models import Candidate, HttpExpectations, HttpStep, NegativeControl, OracleSpec, PlanBudget, StaticEvidence, ValidationPlan
from padv.orchestrator.graphs import validate_with_graph
from padv.store.evidence_store import EvidenceStore


pytestmark = pytest.mark.integration


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


def _candidate(candidate_id: str, title: str) -> Candidate:
    return Candidate(
        candidate_id=candidate_id,
        vuln_class="sql_injection_boundary",
        title=title,
        file_path=f"src/{candidate_id}.php",
        line=10,
        sink="mysqli_query",
        expected_intercepts=["mysqli_query"],
        provenance=["scip", "joern"],
        confidence=0.8,
    )


def _evidence(candidate_id: str) -> StaticEvidence:
    return StaticEvidence(
        candidate_id=candidate_id,
        query_profile="default",
        query_id=f"joern::sql_injection_boundary::{candidate_id}",
        file_path=f"src/{candidate_id}.php",
        line=10,
        snippet="mysqli_query($db, $q)",
        hash=f"h-{candidate_id}",
    )


def _plan(candidate_id: str, *, canary: str, positive_values: list[str], negative_value: str) -> ValidationPlan:
    return ValidationPlan(
        candidate_id=candidate_id,
        intercepts=[],
        positive_requests=[],
        negative_requests=[],
        canary=canary,
        steps=[
            HttpStep(
                method="GET",
                path="/sql",
                query={"q": value},
                expectations=HttpExpectations(status_codes=[200]),
            )
            for value in positive_values
        ],
        negative_controls=[
            NegativeControl(
                label="control-0",
                step=HttpStep(
                    method="GET",
                    path="/sql",
                    query={"q": negative_value},
                    expectations=HttpExpectations(status_codes=[200]),
                ),
            )
        ],
        oracle_spec=OracleSpec(intercept_profile="default", oracle_functions=["mysqli_query"], canary_rules=[]),
        budgets=PlanBudget(max_requests=3, max_time_s=15),
    )


def _morcilla_payload(value: str) -> str:
    payload = json.dumps(
        [{"function": "mysqli_query", "file": "src/app.php", "line": 10, "args": [f"SELECT '{value}'"]}],
        separators=(",", ":"),
    ).encode("utf-8")
    return base64.b64encode(payload).decode("ascii")


def _bundle_snapshot(bundle) -> dict[str, object]:
    witness = (bundle.validation_contract or {}).get("witness", {})
    return {
        "candidate_id": bundle.candidate.candidate_id,
        "candidate_outcome": bundle.candidate_outcome,
        "decision": bundle.gate_result.decision,
        "failed_gate": bundle.gate_result.failed_gate,
        "positive_statuses": [run.status for run in bundle.positive_runtime],
        "negative_statuses": [run.status for run in bundle.negative_runtime],
        "positive_call_counts": [run.call_count for run in bundle.positive_runtime],
        "negative_call_counts": [run.call_count for run in bundle.negative_runtime],
        "positive_matched_canary": [
            [item.matched_canary for item in run.oracle_evidence]
            for run in bundle.positive_runtime
        ],
        "negative_matched_canary": [
            [item.matched_canary for item in run.oracle_evidence]
            for run in bundle.negative_runtime
        ],
        "positive_functions": [
            [item.function for item in run.oracle_evidence]
            for run in bundle.positive_runtime
        ],
        "negative_functions": [
            [item.function for item in run.oracle_evidence]
            for run in bundle.negative_runtime
        ],
        "witness_positive_flags": sorted(witness.get("positive_flags", [])),
        "witness_negative_flags": sorted(witness.get("negative_flags", [])),
    }


def test_validate_only_typed_oracle_is_reproducible_n3(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    config.auth.enabled = False
    config.target.request_timeout_seconds = 5
    store = EvidenceStore(tmp_path / ".padv")

    positive_candidate = _candidate("cand-positive", "Positive SQL boundary")
    negative_candidate = _candidate("cand-negative", "Negative SQL control")
    static_evidence = [_evidence(positive_candidate.candidate_id), _evidence(negative_candidate.candidate_id)]
    positive_plan = _plan(
        positive_candidate.candidate_id,
        canary="padv-positive-canary",
        positive_values=["padv-positive-canary", "padv-positive-canary"],
        negative_value="safe-control",
    )
    negative_plan = _plan(
        negative_candidate.candidate_id,
        canary="padv-negative-canary",
        positive_values=["safe-a", "safe-b"],
        negative_value="safe-control",
    )

    seen_research_calls: list[str] = []

    def _forbidden(name: str):
        def _inner(*_args, **_kwargs):
            seen_research_calls.append(name)
            raise AssertionError(f"validate-only direct path should not call {name}")

        return _inner

    monkeypatch.setattr(graph_mod, "_run_langgraph", _forbidden("_run_langgraph"))
    monkeypatch.setattr(graph_mod, "orient_root_agent", _forbidden("orient_root_agent"))
    monkeypatch.setattr(graph_mod, "select_objective_with_root_agent", _forbidden("select_objective_with_root_agent"))
    monkeypatch.setattr(graph_mod, "run_research_subagent", _forbidden("run_research_subagent"))
    monkeypatch.setattr(
        graph_mod,
        "make_validation_plans_with_deepagents",
        lambda candidates, *_args, **_kwargs: (
            {
                item.candidate_id: positive_plan if item.candidate_id == positive_candidate.candidate_id else negative_plan
                for item in candidates
            },
            {
                "engine": "integration-stub",
                "planned_candidate_ids": [item.candidate_id for item in candidates],
            },
        ),
    )

    class _OracleHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            parsed = urlsplit(self.path)
            if parsed.path != "/sql":
                self.send_response(404)
                self.end_headers()
                return

            query = parse_qs(parsed.query, keep_blank_values=True)
            value = query.get("q", [""])[0]
            correlation = self.headers.get("Morcilla-Correlation", "")
            has_hit = "padv-positive-canary" in value
            payload = _morcilla_payload(value) if has_hit else base64.b64encode(b"[]").decode("ascii")
            body = b"sql syntax error near canary" if has_hit else b"safe-search-results"

            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("X-Morcilla-Status", "active_hits" if has_hit else "observed")
            self.send_header("X-Morcilla-Call-Count", "1" if has_hit else "0")
            self.send_header("X-Morcilla-Overflow", "0")
            self.send_header("X-Morcilla-Arg-Truncated", "0")
            self.send_header("X-Morcilla-Result-Truncated", "0")
            self.send_header("X-Morcilla-Correlation", correlation)
            self.send_header("X-Morcilla-Result", payload)
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args) -> None:  # pragma: no cover
            return

    snapshots: list[list[dict[str, object]]] = []
    summaries: list[dict[str, object]] = []

    with _serve(_OracleHandler) as base_url:
        config.target.base_url = base_url
        for idx in range(3):
            run_id = f"run-validate-only-integration-{idx + 1}"
            bundles, decisions = validate_with_graph(
                config=config,
                store=store,
                static_evidence=static_evidence,
                candidates=[positive_candidate, negative_candidate],
                run_id=run_id,
                repo_root=str(tmp_path),
            )
            summary = store.load_run_summary(run_id)
            assert summary is not None
            assert summary["discovery_trace"]["execution_path"] == "direct-validate"
            assert summary["candidate_outcomes"]["VALIDATED"] == 1
            assert summary["candidate_outcomes"]["REFUTED"] == 1
            assert decisions["VALIDATED"] == 1
            assert decisions["DROPPED"] == 1
            snapshots.append([_bundle_snapshot(bundle) for bundle in bundles])
            summaries.append(
                {
                    "candidate_outcomes": summary["candidate_outcomes"],
                    "stop_rule": summary["stop_rule"],
                    "stop_reason": summary["stop_reason"],
                }
            )

    assert not seen_research_calls
    assert snapshots[0] == snapshots[1] == snapshots[2]
    assert summaries[0] == summaries[1] == summaries[2]

    positive_snapshot, negative_snapshot = snapshots[0]
    assert positive_snapshot["candidate_id"] == "cand-positive"
    assert positive_snapshot["candidate_outcome"] == "VALIDATED"
    assert positive_snapshot["decision"] == "VALIDATED"
    assert positive_snapshot["positive_call_counts"] == [1, 1]
    assert positive_snapshot["negative_call_counts"] == [0]
    assert positive_snapshot["positive_functions"] == [["mysqli_query"], ["mysqli_query"]]
    assert positive_snapshot["positive_matched_canary"] == [[True], [True]]
    assert "sql_sink_oracle_witness" in positive_snapshot["witness_positive_flags"]
    assert "sql_error_witness" in positive_snapshot["witness_positive_flags"] or "sql_body_diff_witness" in positive_snapshot["witness_positive_flags"]

    assert negative_snapshot["candidate_id"] == "cand-negative"
    assert negative_snapshot["candidate_outcome"] == "REFUTED"
    assert negative_snapshot["decision"] == "DROPPED"
    assert negative_snapshot["failed_gate"] == "V3"
    assert negative_snapshot["positive_call_counts"] == [0, 0]
    assert negative_snapshot["negative_call_counts"] == [0]
    assert negative_snapshot["positive_functions"] == [[], []]
    assert negative_snapshot["negative_functions"] == [[]]
    assert negative_snapshot["positive_matched_canary"] == [[], []]
    assert negative_snapshot["negative_matched_canary"] == [[]]

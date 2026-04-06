from __future__ import annotations

import json
import sqlite3
import threading
import time
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest
from langgraph.checkpoint.base import empty_checkpoint
from langchain.agents.middleware.types import ToolCallRequest
from langchain_core.messages import ToolMessage

from padv.agents.checkpoints import FileBackedMemorySaver
from padv.agents.deepagents_harness import (
    AgentExecutionError,
    AgentRuntime,
    AgentSession,
    TaskDelegationTraceMiddleware,
    _agent_middleware_for_role,
    _compact_frontier_state,
    _compact_research_frontier_state,
    _compact_hypotheses,
    _compact_research_findings,
    _handoff_timeout_seconds,
    _handoff_cache_key,
    _load_handoff_cache,
    _store_handoff_cache,
    _handoff_turn_checklist,
    _handoff_work_guidance,
    _inject_canary_into_xml,
    _invoke_agent_session_with_timeout,
    _limit_primary_objectives,
    _normalize_plan_request,
    clone_runtime_for_parallel_role,
    _extract_json,
    _normalize_experiment_attempts,
    _normalize_hypotheses,
    finalize_parallel_role_runtime,
    merge_agent_runtime_context_delta,
    challenge_hypotheses_with_subagent,
    decide_continue_with_root_agent,
    ensure_agent_runtime,
    invoke_agent_session_json,
    make_validation_plans_with_deepagents,
    orient_root_agent,
    plan_experiments_with_subagent,
    rank_candidates_with_deepagents,
    run_research_subagent,
    select_objective_with_root_agent,
    schedule_actions_with_deepagents,
    skeptic_refine_with_deepagents,
    update_agent_runtime_context,
)
from padv.config.schema import load_config
from padv.models import Candidate, Hypothesis, ObjectiveScore, ResearchFinding, ValidationPlan


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
        confidence=0.5,
    )


def _candidate2() -> Candidate:
    return Candidate(
        candidate_id="cand-2",
        vuln_class="ssrf",
        title="A10 SSRF",
        file_path="src/b.php",
        line=40,
        sink="curl_exec",
        expected_intercepts=["curl_exec"],
        notes="test",
        provenance=["source", "web"],
        confidence=0.6,
    )


def _scip_candidate() -> Candidate:
    return Candidate(
        candidate_id="scip-0002",
        vuln_class="ssrf",
        title="A10 SSRF",
        file_path="src/includes/database-config.inc",
        line=40,
        sink="curl_exec",
        expected_intercepts=["curl_exec"],
        notes="test",
        provenance=["scip"],
        confidence=0.6,
    )


def _runtime_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    config.agent.max_agent_turns = 3
    monkeypatch.setenv(config.llm.api_key_env, "test-key")
    monkeypatch.setattr(
        "deepagents.create_deep_agent",
        lambda **kwargs: SimpleNamespace(
            invoke=lambda *args, **kw: {"messages": [{"role": "assistant", "content": "{}"}]}
        ),
    )
    runtime = ensure_agent_runtime(
        config,
        frontier_state={},
        repo_root=str(tmp_path),
        checkpoint_dir=str(tmp_path / "langgraph-store"),
    )
    return config, runtime


def _objective() -> ObjectiveScore:
    return ObjectiveScore(
        objective_id="obj-001",
        title="Investigate admin SQL flows",
        rationale="test",
        expected_info_gain=0.9,
        priority=0.8,
        channels=["source", "graph", "web"],
    )


def _hypothesis() -> Hypothesis:
    return Hypothesis(
        hypothesis_id="hyp-001",
        objective_id="obj-001",
        vuln_class="sql_injection_boundary",
        title="Potential admin SQL injection",
        rationale="test",
        evidence_refs=["finding-001"],
        candidate=_candidate(),
        confidence=0.7,
    )


def _append_worklog(runtime, role: str, ref: str) -> None:
    workspace_index = runtime.shared_context.setdefault("workspace_index", {})
    workspace_index.setdefault(role, {})
    workspace_index[role].setdefault("worklog", [])
    workspace_index[role]["worklog"].append(ref)
    runtime.shared_context.setdefault("worklog", {})
    runtime.shared_context["worklog"].setdefault(role, [])
    runtime.shared_context["worklog"][role].append({"ref": ref, "role": role})


def _append_tool_call(runtime, role: str, ref: str, tool_name: str = "list_objectives") -> None:
    workspace_index = runtime.shared_context.setdefault("workspace_index", {})
    workspace_index.setdefault(role, {})
    workspace_index[role].setdefault("tool_calls", [])
    workspace_index[role]["tool_calls"].append(ref)
    runtime.shared_context.setdefault("tool_usage", {})
    runtime.shared_context["tool_usage"].setdefault(role, [])
    runtime.shared_context["tool_usage"][role].append({"ref": ref, "role": role, "tool": tool_name})


def _append_delegation(runtime, ref: str, subagent_type: str) -> None:
    workspace_index = runtime.shared_context.setdefault("workspace_index", {})
    workspace_index.setdefault("root", {})
    workspace_index["root"].setdefault("delegations", [])
    workspace_index["root"]["delegations"].append(ref)
    runtime.shared_context.setdefault("delegations", [])
    runtime.shared_context["delegations"].append(
        {"ref": ref, "tool": "task", "subagent_type": subagent_type, "description": f"delegate to {subagent_type}"}
    )


def test_rank_candidates_raises_without_key(monkeypatch: pytest.MonkeyPatch) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    config.agent.use_deepagents = True
    monkeypatch.delenv(config.llm.api_key_env, raising=False)

    with pytest.raises(AgentExecutionError):
        rank_candidates_with_deepagents([_candidate()], "variant", config)


def test_rank_candidates_raises_for_invalid_ranking_response(monkeypatch: pytest.MonkeyPatch) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    config.agent.use_deepagents = True
    monkeypatch.setattr(
        "padv.agents.deepagents_harness._invoke_deepagent_json",
        lambda *args, **kwargs: {"notes": ["missing ordered ids"]},
    )

    with pytest.raises(AgentExecutionError):
        rank_candidates_with_deepagents([_candidate()], "variant", config)


def test_schedule_actions_raises_for_invalid_response(monkeypatch: pytest.MonkeyPatch) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    monkeypatch.setattr(
        "padv.agents.deepagents_harness._invoke_deepagent_json",
        lambda *args, **kwargs: {"notes": ["no actions"]},
    )

    with pytest.raises(AgentExecutionError):
        schedule_actions_with_deepagents([_candidate()], config, max_candidates=1)


def test_schedule_actions_orders_by_expected_info_gain(monkeypatch: pytest.MonkeyPatch) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    monkeypatch.setattr(
        "padv.agents.deepagents_harness._invoke_deepagent_json",
        lambda *args, **kwargs: {
            "actions": [
                {"candidate_id": "cand-1", "action": "validate", "expected_info_gain": 0.3, "rationale": "low"},
                {"candidate_id": "cand-2", "action": "validate", "expected_info_gain": 0.9, "rationale": "high"},
            ]
        },
    )

    selected, scores, trace = schedule_actions_with_deepagents([_candidate(), _candidate2()], config, max_candidates=1)
    assert [c.candidate_id for c in selected] == ["cand-2"]
    assert scores["cand-2"] == pytest.approx(1.9)
    assert trace["engine"] == "deepagents"


def test_schedule_actions_captures_structured_triage_fields(monkeypatch: pytest.MonkeyPatch) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    monkeypatch.setattr(
        "padv.agents.deepagents_harness._invoke_deepagent_json",
        lambda *args, **kwargs: {
            "actions": [
                {"candidate_id": "cand-2", "action": "validate", "expected_info_gain": 0.7, "rationale": "best next"},
            ],
            "skip_reasons": [
                {
                    "candidate_id": "cand-1",
                    "reproducibility_gap": "missing deterministic endpoint",
                    "legitimacy_gap": "weak sink alignment",
                    "impact_gap": "unclear impact",
                    "missing_witness": "no class witness path",
                }
            ],
        },
    )

    _selected, _scores, trace = schedule_actions_with_deepagents([_candidate(), _candidate2()], config, max_candidates=1)
    triage = trace["triage_by_candidate"]["cand-1"]
    assert triage["reproducibility_gap"] == "missing deterministic endpoint"
    assert triage["missing_witness"] == "no class witness path"


def test_schedule_actions_respects_explicit_empty_action_set(monkeypatch: pytest.MonkeyPatch) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    monkeypatch.setattr(
        "padv.agents.deepagents_harness._invoke_deepagent_json",
        lambda *args, **kwargs: {
            "actions": [],
            "skip_reasons": [
                {
                    "candidate_id": "cand-1",
                    "reproducibility_gap": "already exhausted",
                    "legitimacy_gap": "",
                    "impact_gap": "",
                    "missing_witness": "",
                }
            ],
            "notes": ["no valid actions remain"],
        },
    )

    selected, scores, trace = schedule_actions_with_deepagents([_candidate(), _candidate2()], config, max_candidates=1)
    assert selected == []
    assert scores == {}
    assert trace["reason"] == "agent-no-actions"
    assert trace["selection_strategy"] == "agent-empty-selection"
    assert trace["triage_by_candidate"]["cand-1"]["reproducibility_gap"] == "already exhausted"


def test_schedule_actions_prioritizes_when_actions_are_unusable(monkeypatch: pytest.MonkeyPatch) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    monkeypatch.setattr(
        "padv.agents.deepagents_harness._invoke_deepagent_json",
        lambda *args, **kwargs: {
            "actions": [
                {"candidate_id": "unknown-id", "action": "validate", "expected_info_gain": "bad", "rationale": "x"}
            ],
            "notes": ["unusable actions"],
        },
    )

    selected, scores, trace = schedule_actions_with_deepagents([_candidate(), _candidate2()], config, max_candidates=1)
    assert len(selected) == 1
    assert len(scores) == 1
    assert trace["reason"] == "deterministic-priority"
    assert trace["selection_strategy"] == "class_quota_priority"


def test_schedule_actions_maps_cand_style_id_to_scip_candidate(monkeypatch: pytest.MonkeyPatch) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    monkeypatch.setattr(
        "padv.agents.deepagents_harness._invoke_deepagent_json",
        lambda *args, **kwargs: {
            "actions": [
                {
                    "candidate_id": "cand-0002",
                    "action": "validate",
                    "expected_info_gain": "0.77 high",
                    "rationale": "mapped by numeric suffix",
                }
            ]
        },
    )

    selected, scores, _trace = schedule_actions_with_deepagents([_scip_candidate()], config, max_candidates=1)
    assert [c.candidate_id for c in selected] == ["scip-0002"]
    assert scores["scip-0002"] == pytest.approx(1.77)


def test_schedule_actions_applies_class_quota_priority(monkeypatch: pytest.MonkeyPatch) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    a = _candidate()
    b = Candidate(
        candidate_id="cand-3",
        vuln_class="sql_injection_boundary",
        title="A03 SQL",
        file_path="src/c.php",
        line=11,
        sink="mysqli_query",
        expected_intercepts=["mysqli_query"],
        notes="test",
        provenance=["scip"],
        confidence=0.95,
    )
    c = _candidate2()
    monkeypatch.setattr(
        "padv.agents.deepagents_harness._invoke_deepagent_json",
        lambda *args, **kwargs: {
            "actions": [
                {"candidate_id": "unknown-id", "action": "validate", "expected_info_gain": "bad", "rationale": "x"}
            ]
        },
    )

    selected, _scores, trace = schedule_actions_with_deepagents([a, b, c], config, max_candidates=2)
    classes = {item.vuln_class for item in selected}
    assert len(selected) == 2
    assert "sql_injection_boundary" in classes
    assert "ssrf" in classes
    assert trace["reason"] == "deterministic-priority"


def test_skeptic_refine_penalizes_proposed_drops_instead_of_removing(monkeypatch: pytest.MonkeyPatch) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    monkeypatch.setattr(
        "padv.agents.deepagents_harness._invoke_deepagent_json",
        lambda *args, **kwargs: {
            "drop_ids": ["cand-1", "cand-2"],
            "confidence_overrides": {},
            "notes": ["proposed drops"],
            "failed_paths": [],
        },
    )

    refined, trace = skeptic_refine_with_deepagents([_candidate(), _candidate2()], config)
    assert len(refined) == 2
    by_id = {c.candidate_id: c for c in refined}
    assert by_id["cand-1"].confidence < 0.5
    assert by_id["cand-2"].confidence < 0.6
    assert trace["dropped"] == []
    assert sorted(trace["proposed_drops"]) == ["cand-1", "cand-2"]


def test_skeptic_refine_captures_structured_triage(monkeypatch: pytest.MonkeyPatch) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    monkeypatch.setattr(
        "padv.agents.deepagents_harness._invoke_deepagent_json",
        lambda *args, **kwargs: {
            "drop_ids": [],
            "confidence_overrides": {"cand-1": 0.2},
            "triage_by_candidate": {
                "cand-1": {
                    "reproducibility_gap": "non-deterministic path",
                    "legitimacy_gap": "insufficient corroboration",
                    "impact_gap": "impact unclear",
                    "missing_witness": "no witness",
                }
            },
            "notes": [],
            "failed_paths": [],
        },
    )

    _refined, trace = skeptic_refine_with_deepagents([_candidate(), _candidate2()], config)
    triage = trace["triage_by_candidate"]["cand-1"]
    assert triage["legitimacy_gap"] == "insufficient corroboration"
    assert triage["missing_witness"] == "no witness"


def test_rank_candidates_uses_provided_session_thread() -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    seen: dict[str, str] = {}

    class _FakeAgent:
        def invoke(self, *_args, **kwargs):
            seen["thread_id"] = kwargs["config"]["configurable"]["thread_id"]
            return {"messages": [{"role": "assistant", "content": '{"ordered_ids":["cand-1"]}'}]}

    session = SimpleNamespace(agent=_FakeAgent(), thread_id="padv-thread-fixed")
    ranked, trace = rank_candidates_with_deepagents([_candidate()], "variant", config, session=session)
    assert [c.candidate_id for c in ranked] == ["cand-1"]
    assert seen["thread_id"] == "padv-thread-fixed"
    assert trace["engine"] == "deepagents"


def test_rank_candidates_raises_when_ordered_ids_omit_candidates(monkeypatch: pytest.MonkeyPatch) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    monkeypatch.setattr(
        "padv.agents.deepagents_harness._invoke_deepagent_json",
        lambda *args, **kwargs: {"ordered_ids": ["cand-1"]},
    )

    with pytest.raises(AgentExecutionError):
        rank_candidates_with_deepagents([_candidate(), _candidate2()], "variant", config)


def test_make_validation_plans_batch_returns_multiple_plans(monkeypatch: pytest.MonkeyPatch) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    monkeypatch.setattr(
        "padv.agents.deepagents_harness._invoke_deepagent_json",
        lambda *args, **kwargs: {
            "plans": [
                {
                    "candidate_id": "cand-1",
                    "intercepts": ["mysqli_query"],
                    "positive_requests": [{"method": "GET", "path": "/", "query": {"x": "1"}}] * 3,
                    "negative_requests": [{"method": "GET", "path": "/", "query": {"x": "0"}}],
                },
                {
                    "candidate_id": "cand-2",
                    "intercepts": ["curl_exec"],
                    "positive_requests": [{"method": "GET", "path": "/", "query": {"y": "1"}}] * 3,
                    "negative_requests": [{"method": "GET", "path": "/", "query": {"y": "0"}}],
                },
            ]
        },
    )

    plans, trace = make_validation_plans_with_deepagents([_candidate(), _candidate2()], config, batch_size=2)
    assert sorted(plans.keys()) == ["cand-1", "cand-2"]
    assert plans["cand-1"].candidate_id == "cand-1"
    assert plans["cand-2"].candidate_id == "cand-2"
    assert trace["engine"] == "deepagents"
    assert trace["planned"] == 2


def test_make_validation_plans_batch_raises_for_missing_candidates(monkeypatch: pytest.MonkeyPatch) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    monkeypatch.setattr(
        "padv.agents.deepagents_harness._invoke_deepagent_json",
        lambda *args, **kwargs: {
            "plans": [
                {
                    "candidate_id": "cand-1",
                    "intercepts": ["mysqli_query"],
                    "positive_requests": [{"method": "GET", "path": "/", "query": {"x": "1"}}] * 3,
                    "negative_requests": [{"method": "GET", "path": "/", "query": {"x": "0"}}],
                }
            ]
        },
    )

    with pytest.raises(AgentExecutionError):
        make_validation_plans_with_deepagents([_candidate(), _candidate2()], config, batch_size=2)


def test_make_validation_plans_batch_normalizes_short_positive_count(monkeypatch: pytest.MonkeyPatch) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    monkeypatch.setattr(
        "padv.agents.deepagents_harness._invoke_deepagent_json",
        lambda *args, **kwargs: {
            "plans": [
                {
                    "candidate_id": "cand-1",
                    "intercepts": ["mysqli_query"],
                    "positive_requests": [{"method": "GET", "path": "/", "query": {"x": "1"}}],
                    "negative_requests": [{"method": "GET", "path": "/", "query": {"x": "0"}}],
                }
            ]
        },
    )

    plans, trace = make_validation_plans_with_deepagents([_candidate()], config, batch_size=1)
    assert "cand-1" in plans
    assert len(plans["cand-1"].positive_requests) == 3
    assert len(plans["cand-1"].negative_requests) >= 1
    assert trace["planned"] == 1


def test_make_validation_plans_batch_normalizes_string_body(monkeypatch: pytest.MonkeyPatch) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    monkeypatch.setattr(
        "padv.agents.deepagents_harness._invoke_deepagent_json",
        lambda *args, **kwargs: {
            "plans": [
                {
                    "candidate_id": "cand-1",
                    "oracle_functions": ["mysqli_query"],
                    "request_expectations": ["POST /submit", "raw=payload"],
                    "response_witnesses": ["HTTP 200"],
                    "intercepts": ["mysqli_query", "POST /submit", "HTTP 200"],
                    "positive_requests": [
                        {"method": "POST", "path": "submit", "query": {"x": "1"}, "body": "raw=payload"}
                    ],
                    "negative_requests": [{"method": "POST", "path": "submit", "body": "neg"}],
                }
            ]
        },
    )

    plans, _trace = make_validation_plans_with_deepagents([_candidate()], config, batch_size=1)
    req = plans["cand-1"].positive_requests[0]
    assert req["path"] == "/submit"
    assert isinstance(req["body"], dict)
    assert "raw" in req["body"]
    assert req["headers"]["Content-Type"] == "application/x-www-form-urlencoded"
    assert plans["cand-1"].oracle_functions == ["mysqli_query"]
    assert plans["cand-1"].request_expectations == ["POST /submit", "raw=payload"]
    assert plans["cand-1"].response_witnesses == ["HTTP 200"]


def test_make_validation_plans_splits_mixed_intercepts_into_clean_channels(monkeypatch: pytest.MonkeyPatch) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    candidate = Candidate(
        candidate_id="cand-1",
        vuln_class="command_injection",
        title="Command injection candidate",
        file_path="src/cmd.php",
        line=21,
        sink="shell_exec",
        expected_intercepts=["shell_exec"],
        notes="test",
        provenance=["source"],
        confidence=0.8,
    )
    monkeypatch.setattr(
        "padv.agents.deepagents_harness._invoke_deepagent_json",
        lambda *args, **kwargs: {
            "plans": [
                {
                    "candidate_id": "cand-1",
                    "intercepts": [
                        "shell_exec(\"echo test\")",
                        "POST /webservices/soap/ws-echo.php",
                        "SOAPAction: urn:echowsdl#echoMessage",
                        "<message>test</message>",
                        "<output>uid=",
                        "HTTP 200",
                    ],
                    "positive_requests": [{"method": "POST", "path": "webservices/soap/ws-echo.php", "body": "<message>test</message>"}],
                    "negative_requests": [{"method": "POST", "path": "webservices/soap/ws-echo.php", "body": "<message>neg</message>"}],
                }
            ]
        },
    )

    plans, _trace = make_validation_plans_with_deepagents([candidate], config, batch_size=1)
    plan = plans["cand-1"]
    assert plan.oracle_functions == ["shell_exec"]
    assert "POST /webservices/soap/ws-echo.php" in plan.request_expectations
    assert "SOAPAction: urn:echowsdl#echoMessage" in plan.request_expectations
    assert "<message>test</message>" in plan.request_expectations
    assert "<output>uid=" in plan.response_witnesses
    assert "HTTP 200" in plan.response_witnesses
    assert plan.positive_requests[0]["headers"]["Content-Type"] == "text/xml"
    assert "body_text" in plan.positive_requests[0]


def test_make_validation_plans_discards_non_function_oracle_expressions(monkeypatch: pytest.MonkeyPatch) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    monkeypatch.setattr(
        "padv.agents.deepagents_harness._invoke_deepagent_json",
        lambda *args, **kwargs: {
            "plans": [
                {
                    "candidate_id": "cand-1",
                    "oracle_functions": [
                        "response.status_code == 200",
                        "any(tool.get('tool_name') for tool in rows)",
                        "'application/json' in response.headers.get('Content-Type', '')",
                    ],
                    "request_expectations": ["POST /submit"],
                    "response_witnesses": ["HTTP 200"],
                    "positive_requests": [{"method": "POST", "path": "/submit", "query": {"x": "1"}}] * 3,
                    "negative_requests": [{"method": "POST", "path": "/submit", "query": {"x": "0"}}],
                }
            ]
        },
    )

    plans, _trace = make_validation_plans_with_deepagents([_candidate()], config, batch_size=1)
    assert plans["cand-1"].oracle_functions == ["mysqli_query"]


def test_make_validation_plans_infers_request_path_from_candidate_hints_when_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    candidate = _candidate()
    candidate.web_path_hints = ["/ajax/lookup-pen-test-tool.php", "/index.php?page=pen-test-tool-lookup-ajax.php"]
    monkeypatch.setattr(
        "padv.agents.deepagents_harness._invoke_deepagent_json",
        lambda *args, **kwargs: {
            "plans": [
                {
                    "candidate_id": "cand-1",
                    "oracle_functions": ["mysqli_query"],
                    "request_expectations": ["GET request to /ajax/lookup-pen-test-tool.php"],
                    "response_witnesses": ["HTTP 200"],
                    "positive_requests": [{"method": "GET", "query": {"ToolID": "1"}}] * 3,
                    "negative_requests": [{"method": "GET", "query": {"ToolID": "0"}}],
                }
            ]
        },
    )

    plans, _trace = make_validation_plans_with_deepagents([candidate], config, batch_size=1)
    assert plans["cand-1"].positive_requests[0]["path"] == "/ajax/lookup-pen-test-tool.php"
    assert plans["cand-1"].negative_requests[0]["path"] == "/ajax/lookup-pen-test-tool.php"


def test_make_validation_plans_applies_runtime_contract_metadata(monkeypatch: pytest.MonkeyPatch) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    candidate = _candidate()
    candidate.vuln_class = "sql_injection"
    candidate.web_path_hints = ["/ajax/lookup-pen-test-tool.php"]
    monkeypatch.setattr(
        "padv.agents.deepagents_harness._invoke_deepagent_json",
        lambda *args, **kwargs: {
            "plans": [
                {
                    "candidate_id": "cand-1",
                    "oracle_functions": ["mysqli_query"],
                    "request_expectations": ["POST /ajax/lookup-pen-test-tool.php"],
                    "response_witnesses": ["HTTP 200"],
                    "positive_requests": [{"method": "POST", "path": "/ajax/lookup-pen-test-tool.php", "body": "ToolID=1' UNION SELECT"}],
                    "negative_requests": [{"method": "POST", "path": "/ajax/lookup-pen-test-tool.php", "body": "ToolID=1"}],
                }
            ]
        },
    )
    plans, _trace = make_validation_plans_with_deepagents([candidate], config, batch_size=1)
    plan = plans["cand-1"]
    assert plan.validation_mode == "runtime"
    assert plan.canonical_class == "sql_injection_boundary"
    assert plan.class_contract_id == "runtime:sql_injection_boundary"
    assert len(plan.negative_controls) >= 2
    assert plan.requests == plan.positive_requests


def test_normalize_experiment_attempts_canonicalizes_variant_candidate_ids() -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    plans, attempts = _normalize_experiment_attempts(
        [
            {
                "hypothesis_id": "hyp-1",
                "candidate": {
                    "candidate_id": "cand-00010-union",
                    "vuln_class": "sql_injection",
                    "title": "union variant",
                    "file_path": "src/ajax/lookup-pen-test-tool.php",
                    "line": 113,
                    "sink": "mysqli::query",
                    "expected_intercepts": ["mysqli::query"],
                    "evidence_refs": ["cand-00010", "joern::sql_boundary:src/ajax/lookup-pen-test-tool.php:113"],
                },
                "oracle_functions": ["mysqli::query"],
                "request_expectations": ["POST /ajax/lookup-pen-test-tool.php"],
                "response_witnesses": ["HTTP 200"],
                "positive_requests": [{"method": "POST", "path": "/ajax/lookup-pen-test-tool.php", "body": "ToolID=1"}] * 3,
                "negative_requests": [{"method": "POST", "path": "/ajax/lookup-pen-test-tool.php", "body": "ToolID=0"}],
            }
        ],
        config,
    )

    assert sorted(plans.keys()) == ["cand-00010"]
    assert plans["cand-00010"].candidate_id == "cand-00010"
    assert attempts[0].hypothesis_id == "hyp-1"


def test_extract_json_recovers_object_from_mixed_text() -> None:
    payload = _extract_json(
        "I investigated the source branch and here is the result:\n"
        '{"tasks":[{"task_id":"task-1","target_ref":"src/a.php","prompt":"inspect","status":"done"}],"findings":[],"notes":["ok"]}\n'
        "Additional commentary after the JSON object."
    )
    assert payload is not None
    assert payload["tasks"][0]["task_id"] == "task-1"


def test_extract_json_ignores_non_json_braces_before_payload() -> None:
    payload = _extract_json(
        "Notes about code {not json} before the actual payload\n"
        '{"status":"continue","notes":["more"],"focus":"continue source_research"}'
    )
    assert payload is not None
    assert payload["status"] == "continue"


def test_file_backed_memory_saver_persists_checkpoint(tmp_path: Path) -> None:
    saver_path = tmp_path / "checkpoints" / "root" / "thread.pkl"
    saver = FileBackedMemorySaver(saver_path)
    checkpoint = empty_checkpoint()
    config = {"configurable": {"thread_id": "thread-1", "checkpoint_ns": "root"}}

    updated = saver.put(config, checkpoint, {"source": "test"}, {})
    saver.put_writes(updated, [("messages", {"text": "hello"})], task_id="task-1")

    reloaded = FileBackedMemorySaver(saver_path)
    loaded = reloaded.get_tuple(updated)
    assert loaded is not None
    assert loaded.checkpoint["id"] == checkpoint["id"]
    assert loaded.metadata["source"] == "test"
    assert len(loaded.pending_writes) == 1


def test_file_backed_memory_saver_serializes_put_and_put_writes(tmp_path: Path) -> None:
    saver_path = tmp_path / "checkpoints" / "root" / "thread.pkl"
    saver = FileBackedMemorySaver(saver_path)
    base_checkpoint = empty_checkpoint()
    base_config = {"configurable": {"thread_id": "thread-1", "checkpoint_ns": "root"}}
    current_config = saver.put(base_config, base_checkpoint, {"source": "seed"}, {})
    errors: list[Exception] = []

    def _put_loop() -> None:
        nonlocal current_config
        try:
            for _ in range(20):
                checkpoint = empty_checkpoint()
                checkpoint["id"] = str(uuid.uuid4())
                current_config = saver.put(current_config, checkpoint, {"source": "writer"}, {})
        except Exception as exc:  # pragma: no cover - regression guard
            errors.append(exc)

    def _write_loop() -> None:
        try:
            for idx in range(40):
                saver.put_writes(
                    current_config,
                    [("messages", {"text": f"msg-{idx}"})],
                    task_id=f"task-{idx % 4}",
                )
        except Exception as exc:  # pragma: no cover - regression guard
            errors.append(exc)

    writer_a = threading.Thread(target=_put_loop)
    writer_b = threading.Thread(target=_write_loop)
    writer_a.start()
    writer_b.start()
    writer_a.join()
    writer_b.join()

    assert not errors
    reloaded = FileBackedMemorySaver(saver_path)
    loaded = reloaded.get_tuple(current_config)
    assert loaded is not None


def test_file_backed_memory_saver_registers_padv_msgpack_allowlist(tmp_path: Path) -> None:
    saver = FileBackedMemorySaver(tmp_path / "checkpoints" / "root" / "thread.pkl")
    allowed = getattr(saver.serde, "_allowed_msgpack_modules", None)
    assert isinstance(allowed, set)
    assert ("padv.config.schema", "PadvConfig") in allowed
    assert ("padv.models", "Candidate") in allowed
    assert ("padv.store.evidence_store", "EvidenceStore") in allowed


def test_ensure_agent_runtime_uses_persistent_checkpointer(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    monkeypatch.setenv(config.llm.api_key_env, "test-key")

    calls: list[dict[str, object]] = []

    def _fake_create_deep_agent(*, model, tools, system_prompt, checkpointer=None, backend=None, store=None, subagents=None, **kwargs):
        calls.append(
            {
                "name": kwargs.get("name"),
                "checkpointer": checkpointer,
                "backend": backend,
                "store": store,
                "subagents": subagents,
                "memory": kwargs.get("memory"),
                "middleware": kwargs.get("middleware"),
            }
        )
        return SimpleNamespace(invoke=lambda *args, **kwargs: {"messages": [{"role": "assistant", "content": "{}"}]})

    monkeypatch.setattr("deepagents.create_deep_agent", _fake_create_deep_agent)

    runtime = ensure_agent_runtime(
        config,
        frontier_state={},
        repo_root=str(tmp_path),
        checkpoint_dir=str(tmp_path / "langgraph-store"),
    )

    assert runtime.checkpoint_dir == str(tmp_path / "langgraph-store")
    assert calls
    root_call = next(item for item in calls if item["name"] == "padv-root")
    subagent_calls = [item for item in calls if str(item["name"]).endswith("-subagent")]
    assert isinstance(root_call["checkpointer"], FileBackedMemorySaver)
    assert all(isinstance(item["checkpointer"], FileBackedMemorySaver) for item in subagent_calls)
    assert callable(root_call["backend"])
    assert root_call["store"] is runtime.store
    assert isinstance(root_call["subagents"], list)
    assert {item["name"] for item in root_call["subagents"]} == {"source", "graph", "web", "exploit", "skeptic", "experiment"}
    assert all("runnable" in item for item in root_call["subagents"])
    assert root_call["memory"] == ["/memories/padv/shared.md", "/memories/padv/root.md"]
    assert isinstance(root_call["middleware"], list)
    assert any(isinstance(item, TaskDelegationTraceMiddleware) for item in root_call["middleware"])


def test_agent_middleware_for_role_adds_root_trace_only(tmp_path: Path) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    root_middleware = _agent_middleware_for_role(
        config=config,
        role="root",
        shared_context={},
        checkpoint_dir=str(tmp_path / "langgraph-store"),
    )
    source_middleware = _agent_middleware_for_role(
        config=config,
        role="source",
        shared_context={},
        checkpoint_dir=str(tmp_path / "langgraph-store"),
    )

    assert any(isinstance(item, TaskDelegationTraceMiddleware) for item in root_middleware)
    assert source_middleware == []


def test_ensure_agent_runtime_uses_persistent_sqlite_store(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    monkeypatch.setenv(config.llm.api_key_env, "test-key")

    def _fake_create_deep_agent(*, model, tools, system_prompt, checkpointer=None, backend=None, store=None, subagents=None, **kwargs):
        return SimpleNamespace(invoke=lambda *args, **kwargs: {"messages": [{"role": "assistant", "content": "{}"}]})

    monkeypatch.setattr("deepagents.create_deep_agent", _fake_create_deep_agent)

    checkpoint_dir = str(tmp_path / "langgraph-store")
    runtime_a = ensure_agent_runtime(
        config,
        frontier_state={},
        repo_root=str(tmp_path),
        checkpoint_dir=checkpoint_dir,
    )
    runtime_a.store.put(("padv", "tests"), "memory-1", {"value": "persisted"})

    runtime_b = ensure_agent_runtime(
        config,
        frontier_state={},
        repo_root=str(tmp_path),
        checkpoint_dir=checkpoint_dir,
    )
    item = runtime_b.store.get(("padv", "tests"), "memory-1")

    assert item is not None
    assert item.value["value"] == "persisted"
    assert Path(checkpoint_dir, "memories.sqlite").exists()


def test_ensure_agent_runtime_seeds_official_memory_files(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    monkeypatch.setenv(config.llm.api_key_env, "test-key")

    def _fake_create_deep_agent(*, model, tools, system_prompt, checkpointer=None, backend=None, store=None, subagents=None, **kwargs):
        return SimpleNamespace(invoke=lambda *args, **kwargs: {"messages": [{"role": "assistant", "content": "{}"}]})

    monkeypatch.setattr("deepagents.create_deep_agent", _fake_create_deep_agent)

    runtime = ensure_agent_runtime(
        config,
        frontier_state={},
        repo_root=str(tmp_path),
        checkpoint_dir=str(tmp_path / "langgraph-store"),
    )

    shared = runtime.store.get(("padv", "deepagents", "memories"), "/memories/padv/shared.md")
    root = runtime.store.get(("padv", "deepagents", "memories"), "/memories/padv/root.md")
    source = runtime.store.get(("padv", "deepagents", "memories"), "/memories/padv/source.md")

    assert shared is not None
    assert root is not None
    assert source is not None
    assert "Repository root:" in "\n".join(shared.value["content"])
    assert "Role: root" in "\n".join(root.value["content"])
    assert "Role: source" in "\n".join(source.value["content"])


def test_agent_workspace_tools_can_persist_and_read_worklog(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    monkeypatch.setenv(config.llm.api_key_env, "test-key")

    calls: list[dict[str, object]] = []

    def _fake_create_deep_agent(*, model, tools, system_prompt, checkpointer=None, backend=None, store=None, subagents=None, **kwargs):
        calls.append(
            {
                "name": kwargs.get("name"),
                "tools": list(tools),
                "subagents": subagents,
            }
        )
        return SimpleNamespace(invoke=lambda *args, **kwargs: {"messages": [{"role": "assistant", "content": "{}"}]})

    monkeypatch.setattr("deepagents.create_deep_agent", _fake_create_deep_agent)

    runtime = ensure_agent_runtime(
        config,
        frontier_state={},
        repo_root=str(tmp_path),
        checkpoint_dir=str(tmp_path / "langgraph-store"),
    )

    source_call = next(item for item in calls if item["name"] == "padv-source-subagent")
    source_tools = {getattr(tool, "name", ""): tool for tool in source_call["tools"]}
    worklog_ref = source_tools["write_agent_worklog"].invoke(
        {
            "category": "research",
            "summary": "investigated sink reachability",
            "details": "looked at admin flow",
            "refs_json": "[\"ev-1\",\"ev-2\"]",
        }
    )
    listed = json.loads(source_tools["list_role_workspace"].invoke({"category": "worklog"}))
    payload = json.loads(source_tools["read_agent_workspace"].invoke({"path": worklog_ref}))
    tool_calls = runtime.shared_context["tool_usage"]["source"]

    assert worklog_ref.startswith("source/worklog/")
    assert worklog_ref in listed
    assert payload["role"] == "source"
    assert payload["category"] == "research"
    assert payload["refs"] == ["ev-1", "ev-2"]
    assert runtime.shared_context["worklog"]["source"][0]["ref"] == worklog_ref


def test_agent_workspace_tools_emit_progress_events(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    monkeypatch.setenv(config.llm.api_key_env, "test-key")

    calls: list[dict[str, object]] = []

    def _fake_create_deep_agent(*, model, tools, system_prompt, checkpointer=None, backend=None, store=None, subagents=None, **kwargs):
        calls.append({"name": kwargs.get("name"), "tools": list(tools)})
        return SimpleNamespace(invoke=lambda *args, **kwargs: {"messages": [{"role": "assistant", "content": "{}"}]})

    monkeypatch.setattr("deepagents.create_deep_agent", _fake_create_deep_agent)

    runtime = ensure_agent_runtime(
        config,
        frontier_state={},
        repo_root=str(tmp_path),
        checkpoint_dir=str(tmp_path / "langgraph-store"),
    )
    events: list[dict[str, object]] = []
    runtime.shared_context["__progress_callback__"] = events.append
    runtime.shared_context["__active_categories__"] = {"source": "source_research"}

    source_call = next(item for item in calls if item["name"] == "padv-source-subagent")
    source_tools = {getattr(tool, "name", ""): tool for tool in source_call["tools"]}

    source_tools["list_objectives"].invoke({})
    source_tools["write_agent_worklog"].invoke(
        {
            "category": "research",
            "summary": "looked at sink reachability",
            "details": "",
            "refs_json": "[]",
        }
    )

    assert any(e.get("step") == "source_research" and e.get("status") == "activity" for e in events)
    assert any(e.get("step") == "source_research" and e.get("status") == "worklog" for e in events)


def test_root_summary_tools_aggregate_all_candidate_and_evidence_classes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    monkeypatch.setenv(config.llm.api_key_env, "test-key")

    calls: list[dict[str, object]] = []

    def _fake_create_deep_agent(*, model, tools, system_prompt, checkpointer=None, backend=None, store=None, subagents=None, **kwargs):
        calls.append({"name": kwargs.get("name"), "tools": list(tools)})
        return SimpleNamespace(invoke=lambda *args, **kwargs: {"messages": [{"role": "assistant", "content": "{}"}]})

    monkeypatch.setattr("deepagents.create_deep_agent", _fake_create_deep_agent)

    runtime = ensure_agent_runtime(
        config,
        frontier_state={},
        repo_root=str(tmp_path),
        checkpoint_dir=str(tmp_path / "langgraph-store"),
    )
    runtime.shared_context["candidate_seeds"] = [
        {"candidate_id": "cand-1", "vuln_class": "command_injection_boundary", "file_path": "a.php", "sink": "shell_exec"},
        {"candidate_id": "cand-2", "vuln_class": "command_injection_boundary", "file_path": "b.php", "sink": "exec"},
        {"candidate_id": "cand-3", "vuln_class": "sql_injection_boundary", "file_path": "db.php", "sink": "query"},
    ]
    runtime.shared_context["static_evidence"] = [
        {"candidate_id": "cand-1", "query_id": "scip::command_injection_boundary", "file_path": "a.php", "snippet": "shell_exec"},
        {"candidate_id": "cand-3", "query_id": "joern::sql_injection_boundary", "file_path": "db.php", "snippet": "query"},
    ]

    root_call = next(item for item in calls if item["name"] == "padv-root")
    root_tools = {getattr(tool, "name", ""): tool for tool in root_call["tools"]}

    candidate_summary = json.loads(root_tools["summarize_candidate_seeds"].invoke({}))
    evidence_summary = json.loads(root_tools["summarize_semantic_evidence"].invoke({}))

    assert candidate_summary["total"] == 3
    assert candidate_summary["classes"]["command_injection_boundary"]["count"] == 2
    assert candidate_summary["classes"]["sql_injection_boundary"]["count"] == 1
    assert evidence_summary["total"] == 2
    assert evidence_summary["classes"]["command_injection_boundary"]["count"] == 1
    assert evidence_summary["classes"]["sql_injection_boundary"]["count"] == 1


def test_normalize_hypotheses_coerces_structured_auth_and_preconditions() -> None:
    hypotheses = _normalize_hypotheses(
        [
            {
                "hypothesis_id": "hyp-1",
                "objective_id": "obj-1",
                "vuln_class": "command_injection_boundary",
                "title": "cmd injection",
                "rationale": "rce",
                "evidence_refs": ["ev-1"],
                "candidate": {
                    "candidate_id": "cand-1",
                    "vuln_class": "command_injection_boundary",
                    "title": "cand",
                    "file_path": "src/a.php",
                    "line": 10,
                    "sink": "shell_exec",
                    "expected_intercepts": ["shell_exec"],
                    "notes": "",
                    "provenance": ["scip"],
                    "evidence_refs": ["ev-1"],
                    "confidence": 0.9,
                    "auth_requirements": [{"type": "none", "description": "default insecure"}],
                    "web_path_hints": ["/webservices/soap/ws-dns-lookup.php"],
                    "preconditions": [{"condition": "security_level=0", "status": "default"}],
                },
            }
        ]
    )

    assert len(hypotheses) == 1
    candidate = hypotheses[0].candidate
    assert candidate.auth_requirements == ['{"description": "default insecure", "type": "none"}']
    assert candidate.preconditions == ['{"condition": "security_level=0", "status": "default"}']


def test_normalize_hypotheses_accepts_single_hypothesis_object() -> None:
    hypotheses = _normalize_hypotheses(
        {
            "hypothesis_id": "hyp-single",
            "objective_id": "obj-1",
            "vuln_class": "sql_injection_boundary",
            "title": "single hypothesis",
            "rationale": "single object response",
            "evidence_refs": ["ev-1"],
            "candidate": {
                "candidate_id": "cand-1",
                "vuln_class": "sql_injection_boundary",
                "title": "cand",
                "file_path": "src/a.php",
                "line": 10,
                "sink": "mysqli_query",
                "expected_intercepts": ["mysqli_query"],
                "notes": "",
                "provenance": ["joern"],
                "evidence_refs": ["ev-1"],
                "confidence": 0.9,
            },
            "confidence": 0.9,
            "status": "active",
        }
    )

    assert len(hypotheses) == 1
    assert hypotheses[0].hypothesis_id == "hyp-single"
    assert hypotheses[0].candidate.candidate_id == "cand-1"


def test_root_agent_tools_are_coordination_only(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    monkeypatch.setenv(config.llm.api_key_env, "test-key")

    calls: list[dict[str, object]] = []

    def _fake_create_deep_agent(*, model, tools, system_prompt, checkpointer=None, backend=None, store=None, subagents=None, **kwargs):
        calls.append(
            {
                "name": kwargs.get("name"),
                "tools": list(tools),
                "subagents": subagents,
                "backend": backend,
            }
        )
        return SimpleNamespace(invoke=lambda *args, **kwargs: {"messages": [{"role": "assistant", "content": "{}"}]})

    monkeypatch.setattr("deepagents.create_deep_agent", _fake_create_deep_agent)

    ensure_agent_runtime(
        config,
        frontier_state={},
        repo_root=str(tmp_path),
        checkpoint_dir=str(tmp_path / "langgraph-store"),
    )

    root_call = next(item for item in calls if item["name"] == "padv-root")
    source_call = next(item for item in calls if item["name"] == "padv-source-subagent")
    root_tool_names = {getattr(tool, "name", "") for tool in root_call["tools"]}
    source_tool_names = {getattr(tool, "name", "") for tool in source_call["tools"]}

    assert "read_repo_file" not in root_tool_names
    assert "list_repo_dir" not in root_tool_names
    assert "search_repo_text" not in root_tool_names
    assert "read_agent_workspace" in root_tool_names
    assert "list_objectives" in root_tool_names
    assert "list_task_delegations" in root_tool_names
    assert "summarize_candidate_seeds" in root_tool_names
    assert "summarize_semantic_evidence" in root_tool_names
    assert "lookup_playwright_artifacts" in root_tool_names
    assert "read_repo_file" in source_tool_names
    assert "search_repo_text" in source_tool_names
    assert "lookup_playwright_artifacts" in source_tool_names


def test_root_backend_is_workspace_scoped_while_subagents_keep_repo_scope(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    monkeypatch.setenv(config.llm.api_key_env, "test-key")

    calls: list[dict[str, object]] = []

    def _fake_create_deep_agent(*, model, tools, system_prompt, checkpointer=None, backend=None, store=None, subagents=None, **kwargs):
        calls.append(
            {
                "name": kwargs.get("name"),
                "backend": backend,
            }
        )
        return SimpleNamespace(invoke=lambda *args, **kwargs: {"messages": [{"role": "assistant", "content": "{}"}]})

    monkeypatch.setattr("deepagents.create_deep_agent", _fake_create_deep_agent)

    runtime = ensure_agent_runtime(
        config,
        frontier_state={},
        repo_root=str(tmp_path / "repo"),
        checkpoint_dir=str(tmp_path / "langgraph-store"),
    )

    fake_runtime = SimpleNamespace(store=runtime.store, context=None, config={}, state={}, stream_writer=None, tool_call_id=None)
    root_backend = next(item for item in calls if item["name"] == "padv-root")["backend"]
    source_backend = next(item for item in calls if item["name"] == "padv-source-subagent")["backend"]

    root_instance = root_backend(fake_runtime)
    source_instance = source_backend(fake_runtime)

    root_root_dir = getattr(getattr(root_instance, "default", None), "cwd", None)
    source_root_dir = getattr(getattr(source_instance, "default", None), "cwd", None)

    assert str(root_root_dir) == runtime.workspace_dir
    assert str(source_root_dir) == str((tmp_path).resolve())


def test_runtime_exposes_persistent_subagent_sessions(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    monkeypatch.setenv(config.llm.api_key_env, "test-key")

    def _fake_create_deep_agent(*, model, tools, system_prompt, checkpointer=None, backend=None, store=None, subagents=None, **kwargs):
        return SimpleNamespace(invoke=lambda *args, **kwargs: {"messages": [{"role": "assistant", "content": "{}"}]})

    monkeypatch.setattr("deepagents.create_deep_agent", _fake_create_deep_agent)

    runtime = ensure_agent_runtime(
        config,
        frontier_state={},
        repo_root=str(tmp_path),
        checkpoint_dir=str(tmp_path / "langgraph-store"),
    )

    assert runtime.root.role == "root"
    assert set(runtime.subagents.keys()) == {"source", "graph", "web", "exploit", "skeptic", "experiment"}
    assert runtime.subagents["source"].role == "source"
    assert runtime.subagents["graph"].role == "graph"


def test_task_delegation_trace_middleware_records_task_tool_calls(tmp_path: Path) -> None:
    shared_context: dict[str, object] = {"workspace_index": {}, "delegations": []}
    middleware = TaskDelegationTraceMiddleware(
        shared_context=shared_context,
        checkpoint_dir=str(tmp_path / "langgraph-store"),
    )
    request = ToolCallRequest(
        tool_call={
            "name": "task",
            "id": "call-1",
            "args": {
                "subagent_type": "source",
                "description": "Investigate PHP entrypoints",
                "prompt": "Inspect the handoff artifact and return findings",
            },
        },
        tool=None,
        state={},
        runtime=SimpleNamespace(store=None, context=None, config={}, state={}, stream_writer=None, tool_call_id="call-1"),
    )

    result = middleware.wrap_tool_call(
        request,
        lambda _req: ToolMessage(content="delegated result", tool_call_id="call-1"),
    )

    assert result.content == "delegated result"
    delegations = shared_context["delegations"]
    assert isinstance(delegations, list)
    assert delegations
    assert delegations[0]["tool"] == "task"
    assert delegations[0]["subagent_type"] == "source"
    refs = shared_context["workspace_index"]["root"]["delegations"]
    assert refs and refs[0].startswith("root/delegations/")


def test_orient_root_agent_uses_workspace_handoff_artifact(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    monkeypatch.setenv(config.llm.api_key_env, "test-key")

    def _fake_create_deep_agent(*, model, tools, system_prompt, checkpointer=None, backend=None, store=None, subagents=None, **kwargs):
        return SimpleNamespace(invoke=lambda *args, **kwargs: {"messages": [{"role": "assistant", "content": "{}"}]})

    monkeypatch.setattr("deepagents.create_deep_agent", _fake_create_deep_agent)

    runtime = ensure_agent_runtime(
        config,
        frontier_state={},
        repo_root=str(tmp_path),
        checkpoint_dir=str(tmp_path / "langgraph-store"),
    )

    seen: dict[str, str] = {}

    calls = {"count": 0}

    def _fake_invoke(session, prompt, _config):
        calls["count"] += 1
        seen["prompt"] = prompt
        if calls["count"] == 1:
            _append_worklog(runtime, session.role, "root/worklog/orient-1.json")
            _append_tool_call(runtime, session.role, "root/tool_calls/orient-1.json", "list_objectives")
        return {
            "objectives": [
                {
                    "objective_id": "obj-001",
                    "title": "Investigate SQL flows",
                    "rationale": "test",
                    "expected_info_gain": 0.9,
                    "priority": 0.9,
                    "channels": ["source", "graph", "web"],
                }
            ],
            "notes": ["ok"],
        }

    monkeypatch.setattr("padv.agents.deepagents_harness.invoke_agent_session_json", _fake_invoke)
    monkeypatch.setattr(
        "padv.agents.deepagents_harness.make_validation_plans_with_deepagents",
        lambda *args, **kwargs: (_ for _ in ()).throw(AgentExecutionError("zero plans")),
    )
    monkeypatch.setattr(
        "padv.agents.deepagents_harness.make_validation_plans_with_deepagents",
        lambda *args, **kwargs: (_ for _ in ()).throw(AgentExecutionError("zero plans")),
    )

    objectives, trace = orient_root_agent(
        runtime,
        config,
        frontier_state={"coverage": {"files": ["src/a.php"]}},
        discovery_trace={"semantic_count": 1},
        run_validation=True,
        objective_queue=[_objective()],
    )

    assert objectives[0].objective_id == "obj-001"
    assert "handoffs/" in trace["handoff_ref"]
    assert "response_ref" in trace
    handoff_path = Path(runtime.workspace_dir) / trace["handoff_ref"]
    payload = json.loads(handoff_path.read_text(encoding="utf-8"))
    assert payload["category"] == "orient"
    assert payload["envelope"]["run_validation"] is True
    assert payload["envelope"]["remaining_objectives"][0]["objective_id"] == "obj-001"
    assert "read the handoff artifact" not in seen["prompt"].lower()
    assert "handoff artifact" in seen["prompt"].lower()
    assert "\"semantic_count\": 1" not in seen["prompt"]
    assert trace["turns"] == 1
    assert trace["worklog_refs"] == ["root/worklog/orient-1.json"]
    assert trace["tool_refs"] == ["root/tool_calls/orient-1.json"]


def test_orient_root_agent_compacts_frontier_in_handoff(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    monkeypatch.setenv(config.llm.api_key_env, "test-key")

    def _fake_create_deep_agent(*, model, tools, system_prompt, checkpointer=None, backend=None, store=None, subagents=None, **kwargs):
        return SimpleNamespace(invoke=lambda *args, **kwargs: {"messages": [{"role": "assistant", "content": "{}"}]})

    monkeypatch.setattr("deepagents.create_deep_agent", _fake_create_deep_agent)
    runtime = ensure_agent_runtime(
        config,
        frontier_state={},
        repo_root=str(tmp_path),
        checkpoint_dir=str(tmp_path / "langgraph-store"),
    )

    def _fake_invoke(session, prompt, _config):
        _append_worklog(runtime, session.role, "root/worklog/orient-compact.json")
        _append_tool_call(runtime, session.role, "root/tool_calls/orient-compact.json", "list_objectives")
        return {
            "objectives": [
                {
                    "objective_id": "obj-001",
                    "title": "Investigate SQL flows",
                    "rationale": "test",
                    "expected_info_gain": 0.9,
                    "priority": 0.9,
                    "channels": ["source", "graph", "web"],
                }
            ],
            "notes": ["ok"],
        }

    monkeypatch.setattr("padv.agents.deepagents_harness.invoke_agent_session_json", _fake_invoke)
    large_frontier = {
        "version": 1,
        "updated_at": "2026-03-07T00:00:00+00:00",
        "iteration": 29,
        "stagnation_rounds": 4,
        "coverage": {
            "files": [f"src/{idx}.php" for idx in range(50)],
            "classes": [f"class-{idx}" for idx in range(50)],
            "signals": [f"signal-{idx}" for idx in range(50)],
            "sinks": [f"sink-{idx}" for idx in range(50)],
            "web_paths": [f"/path/{idx}" for idx in range(50)],
        },
        "history": [{"candidate_id": f"cand-{idx:05d}", "iteration": idx, "decision": "DROPPED"} for idx in range(50)],
        "attempt_history": [{"candidate_id": f"cand-{idx:05d}", "iteration": idx, "phase": "positive"} for idx in range(50)],
        "hypotheses": [{"candidate_id": f"cand-{idx:05d}", "iteration": idx, "score": 0.5} for idx in range(50)],
        "candidate_resume": {
            f"sig-{idx}": {"candidate_id": f"cand-{idx:05d}", "completed_clean": bool(idx % 2), "last_iteration": idx}
            for idx in range(50)
        },
        "runtime_coverage": {"flags": [f"flag-{idx}" for idx in range(50)], "classes": [f"class-{idx}" for idx in range(50)]},
        "failed_paths": [f"/failed/{idx}" for idx in range(50)],
        "agent_threads": {"root": "padv-root-x"},
    }

    _objectives, trace = orient_root_agent(
        runtime,
        config,
        frontier_state=large_frontier,
        discovery_trace={"semantic_count": 1},
        run_validation=False,
        objective_queue=[_objective()],
    )

    handoff_path = Path(runtime.workspace_dir) / trace["handoff_ref"]
    payload = json.loads(handoff_path.read_text(encoding="utf-8"))
    compact = payload["envelope"]["frontier_state"]
    assert compact["iteration"] == 29
    assert len(compact["coverage"]["files"]) == 10
    assert compact["hypotheses_count"] == 50
    assert compact["history_count"] == 50
    assert compact["attempt_history_count"] == 50
    assert compact["candidate_resume_size"] == 50
    assert "candidate_resume_sample" not in compact
    assert "agent_threads" not in compact


def test_orient_root_agent_falls_back_to_remaining_objective_queue_on_empty_response(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    monkeypatch.setenv(config.llm.api_key_env, "test-key")

    def _fake_create_deep_agent(*, model, tools, system_prompt, checkpointer=None, backend=None, store=None, subagents=None, **kwargs):
        return SimpleNamespace(invoke=lambda *args, **kwargs: {"messages": [{"role": "assistant", "content": "{}"}]})

    monkeypatch.setattr("deepagents.create_deep_agent", _fake_create_deep_agent)
    runtime = ensure_agent_runtime(
        config,
        frontier_state={},
        repo_root=str(tmp_path),
        checkpoint_dir=str(tmp_path / "langgraph-store"),
    )

    fallback_objective = ObjectiveScore(
        objective_id="obj-fallback",
        title="Fallback objective",
        rationale="keep exploring",
        expected_info_gain=0.7,
        priority=0.8,
        channels=["source", "graph", "web"],
    )

    def _fake_invoke(session, prompt, _config):
        _append_worklog(runtime, session.role, "root/worklog/orient-empty.json")
        return {
            "objectives": [],
            "notes": ["diminishing returns"],
        }

    monkeypatch.setattr("padv.agents.deepagents_harness.invoke_agent_session_json", _fake_invoke)

    objectives, trace = orient_root_agent(
        runtime,
        config,
        frontier_state={},
        discovery_trace={"semantic_count": 1},
        run_validation=False,
        objective_queue=[fallback_objective],
    )

    assert [item.objective_id for item in objectives] == ["obj-fallback"]
    assert trace["fallback_used"] is True
    assert "empty orient response replaced with remaining objective queue fallback" in trace["notes"]


def test_compact_frontier_state_truncates_failed_path_reasons() -> None:
    compact = _compact_frontier_state(
        {
            "iteration": 9,
            "failed_paths": [
                {
                    "path": "hyp-001",
                    "iteration": 8,
                    "reason": "x" * 600,
                }
            ],
        }
    )

    assert compact["failed_paths_count"] == 1
    assert compact["failed_paths"][0]["path"] == "hyp-001"
    assert compact["failed_paths"][0]["iteration"] == 8
    assert len(compact["failed_paths"][0]["reason"]) <= 240
    assert compact["failed_paths"][0]["reason"].endswith("...")


def test_compact_research_frontier_state_drops_heavy_history_fields() -> None:
    compact = _compact_research_frontier_state(
        {
            "version": 1,
            "iteration": 28,
            "stagnation_rounds": 3,
            "failed_paths": [{"path": "a", "iteration": 1, "reason": "x" * 400}],
            "history": list(range(50)),
            "attempt_history": list(range(60)),
            "candidate_resume": {f"cand-{idx}": {"candidate_id": f"cand-{idx}"} for idx in range(20)},
            "coverage": {
                "files": [f"src/{idx}.php" for idx in range(20)],
                "classes": [f"class-{idx}" for idx in range(20)],
                "signals": [f"sig-{idx}" for idx in range(20)],
                "sinks": [f"sink-{idx}" for idx in range(20)],
                "web_paths": [f"/p/{idx}" for idx in range(20)],
            },
            "runtime_coverage": {
                "flags": [f"flag-{idx}" for idx in range(20)],
                "classes": [f"rclass-{idx}" for idx in range(20)],
            },
        }
    )

    assert compact["iteration"] == 28
    assert compact["failed_paths_count"] == 1
    assert "failed_paths" not in compact
    assert "history_count" not in compact
    assert "attempt_history_count" not in compact
    assert "candidate_resume_size" not in compact
    assert len(compact["coverage"]["files"]) == 6
    assert len(compact["coverage"]["classes"]) == 6
    assert len(compact["coverage"]["signals"]) == 6
    assert len(compact["coverage"]["sinks"]) == 4
    assert len(compact["coverage"]["web_paths"]) == 6
    assert len(compact["runtime_coverage"]["flags"]) == 6
    assert len(compact["runtime_coverage"]["classes"]) == 6


def test_handoff_timeout_seconds_disables_hard_agent_turn_timeouts() -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    config.llm.timeout_seconds = 240
    config.agent.max_agent_turns = 4

    assert _handoff_timeout_seconds("source_research", config) is None
    assert _handoff_timeout_seconds("graph_research", config) is None
    assert _handoff_timeout_seconds("web_research", config) is None
    assert _handoff_timeout_seconds("skeptic_challenge", config) is None
    assert _handoff_timeout_seconds("experiment_plan", config) is None
    assert _handoff_timeout_seconds("orient", config) is None


def test_compact_research_findings_truncates_and_limits_payload() -> None:
    findings = [
        ResearchFinding(
            finding_id=f"finding-{idx}",
            objective_id="obj-1",
            channel="graph",
            title="T" * 300,
            summary="S" * 1200,
            evidence_refs=[f"ev-{n}" for n in range(20)],
            file_refs=[f"src/{n}.php" for n in range(20)],
            web_paths=[f"/p/{n}" for n in range(20)],
            params=[f"param{n}" for n in range(20)],
            sink_refs=[f"sink{n}" for n in range(20)],
            metadata={"a": 1, "b": 2, "c": 3},
        )
        for idx in range(25)
    ]

    compact = _compact_research_findings(findings)
    assert len(compact) == 12
    assert len(compact[0]["title"]) == 140
    assert len(compact[0]["summary"]) == 400
    assert len(compact[0]["evidence_refs"]) == 6
    assert len(compact[0]["file_refs"]) == 4
    assert len(compact[0]["web_paths"]) == 4
    assert len(compact[0]["params"]) == 4
    assert len(compact[0]["sink_refs"]) == 4
    assert compact[0]["metadata_keys"] == ["a", "b", "c"]


def test_compact_hypotheses_truncates_and_limits_payload() -> None:
    hypotheses = []
    for idx in range(12):
        candidate = _candidate()
        candidate.expected_intercepts = [f"i{n}" for n in range(20)]
        candidate.evidence_refs = [f"ev-{n}" for n in range(20)]
        candidate.sink = "K" * 500
        hypotheses.append(
            Hypothesis(
                hypothesis_id=f"hyp-{idx}",
                objective_id="obj-1",
                vuln_class="sql_injection_boundary",
                title="H" * 300,
                rationale="R" * 1500,
                evidence_refs=[f"href-{n}" for n in range(20)],
                candidate=candidate,
                confidence=0.9,
                auth_requirements=[f"auth-{n}" for n in range(20)],
                web_path_hints=[f"/w/{n}" for n in range(20)],
                preconditions=[f"pre-{n}" for n in range(20)],
            )
        )

    compact = _compact_hypotheses(hypotheses)
    assert len(compact) == 6
    assert len(compact[0]["title"]) == 140
    assert len(compact[0]["rationale"]) == 160
    assert len(compact[0]["evidence_refs"]) == 4
    assert len(compact[0]["auth_requirements"]) == 3
    assert len(compact[0]["preconditions"]) == 3
    assert len(compact[0]["candidate"]["sink"]) == 180
    assert len(compact[0]["candidate"]["expected_intercepts"]) == 4
    assert len(compact[0]["candidate"]["evidence_refs"]) == 4


def test_inject_canary_into_xml_updates_element_text() -> None:
    body = (
        "<?xml version='1.0'?>"
        "<SOAP-ENV:Envelope>"
        "<SOAP-ENV:Body><ns1:lookupDNS><targetHost>127.0.0.1; id</targetHost>"
        "</ns1:lookupDNS></SOAP-ENV:Body></SOAP-ENV:Envelope>"
    )

    mutated = _inject_canary_into_xml(body, "padv-canary-123")

    assert "127.0.0.1; id padv-canary-123" in mutated


def test_normalize_plan_request_injects_canary_into_xml_body_text() -> None:
    candidate = _candidate()
    candidate.vuln_class = "command_injection"
    candidate.web_path_hints = ["/webservices/soap/ws-dns-lookup.php"]
    req = {
        "method": "POST",
        "path": "/webservices/soap/ws-dns-lookup.php",
        "headers": {"Content-Type": "text/xml; charset=utf-8"},
        "body": (
            "<?xml version='1.0'?>"
            "<SOAP-ENV:Envelope><SOAP-ENV:Body><ns1:lookupDNS>"
            "<targetHost>127.0.0.1; id</targetHost>"
            "</ns1:lookupDNS></SOAP-ENV:Body></SOAP-ENV:Envelope>"
        ),
    }

    normalized = _normalize_plan_request(
        req,
        "padv-canary-xml",
        candidate,
        ["POST to /webservices/soap/ws-dns-lookup.php", "SOAP envelope with lookupDNS method"],
        {"padv_canary"},
        "padv_canary",
    )

    assert normalized["query"]["padv_canary"] == "padv-canary-xml"
    assert "padv-canary-xml" in normalized["body_text"]
    assert "127.0.0.1; id padv-canary-xml" in normalized["body_text"]


def test_orient_root_agent_rejects_non_final_continue_response(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    config.agent.max_agent_turns = 3
    monkeypatch.setenv(config.llm.api_key_env, "test-key")

    def _fake_create_deep_agent(*, model, tools, system_prompt, checkpointer=None, backend=None, store=None, subagents=None, **kwargs):
        return SimpleNamespace(invoke=lambda *args, **kwargs: {"messages": [{"role": "assistant", "content": "{}"}]})

    monkeypatch.setattr("deepagents.create_deep_agent", _fake_create_deep_agent)
    runtime = ensure_agent_runtime(
        config,
        frontier_state={},
        repo_root=str(tmp_path),
        checkpoint_dir=str(tmp_path / "langgraph-store"),
    )

    calls = {"count": 0}

    def _fake_invoke(session, prompt, _config):
        calls["count"] += 1
        _append_worklog(runtime, session.role, "root/worklog/orient-1.json")
        _append_tool_call(runtime, session.role, "root/tool_calls/orient-1.json", "list_objectives")
        return {"status": "continue", "notes": ["need more"], "focus": "inspect findings"}

    monkeypatch.setattr("padv.agents.deepagents_harness.invoke_agent_session_json", _fake_invoke)

    with pytest.raises(AgentExecutionError, match="non-final continue response"):
        orient_root_agent(
            runtime,
            config,
            frontier_state={},
            discovery_trace={"semantic_count": 1},
            run_validation=False,
        )

    assert calls["count"] == 1


def test_limit_primary_objectives_keeps_highest_priority_entries() -> None:
    objectives = [
        ObjectiveScore(
            objective_id=f"obj-{idx}",
            title=f"Objective {idx}",
            rationale="test",
            expected_info_gain=0.1 * idx,
            priority=0.1 * idx,
            channels=["source"],
        )
        for idx in range(1, 9)
    ]

    limited = _limit_primary_objectives(objectives, limit=6)

    assert [item.objective_id for item in limited] == ["obj-8", "obj-7", "obj-6", "obj-5", "obj-4", "obj-3"]


def test_orient_root_agent_accepts_single_turn_without_worklog(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    config.agent.max_agent_turns = 2
    monkeypatch.setenv(config.llm.api_key_env, "test-key")

    def _fake_create_deep_agent(*, model, tools, system_prompt, checkpointer=None, backend=None, store=None, subagents=None, **kwargs):
        return SimpleNamespace(invoke=lambda *args, **kwargs: {"messages": [{"role": "assistant", "content": "{}"}]})

    monkeypatch.setattr("deepagents.create_deep_agent", _fake_create_deep_agent)
    runtime = ensure_agent_runtime(
        config,
        frontier_state={},
        repo_root=str(tmp_path),
        checkpoint_dir=str(tmp_path / "langgraph-store"),
    )

    monkeypatch.setattr(
        "padv.agents.deepagents_harness.invoke_agent_session_json",
        lambda *args, **kwargs: {
            "objectives": [
                {
                    "objective_id": "obj-001",
                    "title": "Investigate SQL flows",
                    "rationale": "done",
                    "expected_info_gain": 0.9,
                    "priority": 0.9,
                    "channels": ["source", "graph"],
                }
            ],
            "notes": ["final"],
        },
    )

    objectives, trace = orient_root_agent(
        runtime,
        config,
        frontier_state={},
        discovery_trace={"semantic_count": 1},
        run_validation=False,
    )

    assert [item.objective_id for item in objectives] == ["obj-001"]
    assert trace["turns"] == 1
    assert trace["worklog_refs"] == []
    assert trace["tool_refs"] == []
    assert trace["progress_refs"] == []


def test_orient_root_agent_accepts_single_turn_without_tool_use(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    config.agent.max_agent_turns = 2
    monkeypatch.setenv(config.llm.api_key_env, "test-key")
    calls = {"count": 0}

    def _fake_create_deep_agent(*, model, tools, system_prompt, checkpointer=None, backend=None, store=None, subagents=None, **kwargs):
        return SimpleNamespace(invoke=lambda *args, **kwargs: {"messages": [{"role": "assistant", "content": "{}"}]})

    monkeypatch.setattr("deepagents.create_deep_agent", _fake_create_deep_agent)
    runtime = ensure_agent_runtime(
        config,
        frontier_state={},
        repo_root=str(tmp_path),
        checkpoint_dir=str(tmp_path / "langgraph-store"),
    )

    def _fake_invoke(session, prompt, _config):
        calls["count"] += 1
        _append_worklog(runtime, session.role, "root/worklog/orient-1.json")
        return {
            "objectives": [
                {
                    "objective_id": "obj-001",
                    "title": "Investigate SQL flows",
                    "rationale": "done",
                    "expected_info_gain": 0.9,
                    "priority": 0.9,
                    "channels": ["source", "graph"],
                }
            ],
            "notes": ["final"],
        }

    monkeypatch.setattr("padv.agents.deepagents_harness.invoke_agent_session_json", _fake_invoke)

    objectives, trace = orient_root_agent(
        runtime,
        config,
        frontier_state={},
        discovery_trace={"semantic_count": 1},
        run_validation=False,
    )

    assert [item.objective_id for item in objectives] == ["obj-001"]
    assert calls["count"] == 1
    assert trace["turns"] == 1
    assert trace["worklog_refs"] == ["root/worklog/orient-1.json"]
    assert trace["tool_refs"] == []


def test_orient_root_agent_does_not_soft_yield_on_continue_response(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    config.agent.max_agent_turns = 2
    monkeypatch.setenv(config.llm.api_key_env, "test-key")

    def _fake_create_deep_agent(*, model, tools, system_prompt, checkpointer=None, backend=None, store=None, subagents=None, **kwargs):
        return SimpleNamespace(invoke=lambda *args, **kwargs: {"messages": [{"role": "assistant", "content": "{}"}]})

    monkeypatch.setattr("deepagents.create_deep_agent", _fake_create_deep_agent)
    runtime = ensure_agent_runtime(
        config,
        frontier_state={},
        repo_root=str(tmp_path),
        checkpoint_dir=str(tmp_path / "langgraph-store"),
    )

    monkeypatch.setattr(
        "padv.agents.deepagents_harness.invoke_agent_session_json",
        lambda *args, **kwargs: {"status": "continue", "notes": ["loop"]},
    )

    with pytest.raises(AgentExecutionError, match="non-final continue response"):
        orient_root_agent(
            runtime,
            config,
            frontier_state={},
            discovery_trace={"semantic_count": 1},
            run_validation=False,
        )


def test_select_objective_root_agent_accepts_single_turn(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    config.agent.max_agent_turns = 3
    monkeypatch.setenv(config.llm.api_key_env, "test-key")

    def _fake_create_deep_agent(*, model, tools, system_prompt, checkpointer=None, backend=None, store=None, subagents=None, **kwargs):
        return SimpleNamespace(invoke=lambda *args, **kwargs: {"messages": [{"role": "assistant", "content": "{}"}]})

    monkeypatch.setattr("deepagents.create_deep_agent", _fake_create_deep_agent)
    runtime = ensure_agent_runtime(
        config,
        frontier_state={},
        repo_root=str(tmp_path),
        checkpoint_dir=str(tmp_path / "langgraph-store"),
    )

    calls = {"count": 0}

    def _fake_invoke(session, prompt, _config):
        calls["count"] += 1
        if calls["count"] == 1:
            _append_worklog(runtime, session.role, "root/worklog/select-1.json")
            _append_tool_call(runtime, session.role, "root/tool_calls/select-1.json", "list_objectives")
            return {"objective_id": "obj-001", "notes": ["selected-early"]}
        return {"objective_id": "obj-001", "notes": ["selected"]}

    monkeypatch.setattr("padv.agents.deepagents_harness.invoke_agent_session_json", _fake_invoke)

    selected, trace = select_objective_with_root_agent(
        runtime,
        config,
        objective_queue=[_objective()],
        frontier_state={},
    )

    assert selected.objective_id == "obj-001"
    assert calls["count"] == 1
    assert trace["turns"] == 1
    assert len(trace["progress_refs"]) == 0
    assert trace["worklog_refs"] == ["root/worklog/select-1.json"]
    assert trace["tool_refs"] == ["root/tool_calls/select-1.json"]


def test_continue_root_agent_accepts_single_turn(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    config.agent.max_agent_turns = 3
    monkeypatch.setenv(config.llm.api_key_env, "test-key")

    def _fake_create_deep_agent(*, model, tools, system_prompt, checkpointer=None, backend=None, store=None, subagents=None, **kwargs):
        return SimpleNamespace(invoke=lambda *args, **kwargs: {"messages": [{"role": "assistant", "content": "{}"}]})

    monkeypatch.setattr("deepagents.create_deep_agent", _fake_create_deep_agent)
    runtime = ensure_agent_runtime(
        config,
        frontier_state={},
        repo_root=str(tmp_path),
        checkpoint_dir=str(tmp_path / "langgraph-store"),
    )

    calls = {"count": 0}

    def _fake_invoke(session, prompt, _config):
        calls["count"] += 1
        if calls["count"] == 1:
            _append_worklog(runtime, session.role, "root/worklog/continue-1.json")
            _append_tool_call(runtime, session.role, "root/tool_calls/continue-1.json", "list_hypotheses")
            return {"continue": False, "reason": "done-early", "notes": ["stop-early"]}
        return {"continue": False, "reason": "done", "notes": ["stop"]}

    monkeypatch.setattr("padv.agents.deepagents_harness.invoke_agent_session_json", _fake_invoke)

    should_continue, trace = decide_continue_with_root_agent(
        runtime,
        config,
        iteration=1,
        objective_queue=[_objective()],
        hypotheses=[],
        refutations=[],
        witness_bundles=[],
        max_iterations=3,
    )

    assert should_continue is False
    assert calls["count"] == 1
    assert trace["turns"] == 1
    assert len(trace["progress_refs"]) == 0
    assert trace["worklog_refs"] == ["root/worklog/continue-1.json"]
    assert trace["tool_refs"] == ["root/tool_calls/continue-1.json"]


def test_root_guidance_and_checklist_do_not_block_on_reachability_uncertainty() -> None:
    guidance = _handoff_work_guidance("root", "orient")
    checklist = _handoff_turn_checklist("orient", 2)

    assert "Do not block orient on unresolved deployment/reachability questions" in guidance
    assert "must return at least one objective" in guidance
    assert any("deployment or reachability" in item for item in checklist)


def test_research_subagent_accepts_single_turn_when_requirements_are_met(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config, runtime = _runtime_config(tmp_path, monkeypatch)
    calls = {"count": 0}
    prompts: list[str] = []

    def _fake_invoke(session, prompt, _config):
        calls["count"] += 1
        prompts.append(prompt)
        assert session.role == "source"
        _append_worklog(runtime, "source", "source/worklog/research-1.json")
        return {
            "tasks": [
                {"task_id": "task-001", "target_ref": "src/a.php", "prompt": "inspect", "status": "done"}
            ],
            "findings": [
                {
                    "finding_id": "finding-001",
                    "title": "Input reaches query builder",
                    "summary": "summary",
                    "evidence_refs": ["ev-1"],
                    "file_refs": ["src/a.php"],
                    "params": ["id"],
                    "sink_refs": ["mysqli_query"],
                }
            ],
            "notes": ["final"],
        }

    monkeypatch.setattr("padv.agents.deepagents_harness.invoke_agent_session_json", _fake_invoke)

    tasks, findings, trace = run_research_subagent(
        runtime,
        "source",
        config,
        objective=_objective(),
        frontier_state={},
    )

    assert calls["count"] == 1
    assert trace["turns"] == 1
    assert len(trace["progress_refs"]) == 0
    assert tasks[0].task_id == "task-001"
    assert findings[0].finding_id == "finding-001"
    assert trace["invocation_role"] == "source"
    assert trace["workspace_role"] == "source"
    assert trace["worklog_refs"] == ["source/worklog/research-1.json"]
    assert trace["delegation_refs"] == []
    assert "handoff artifact" in prompts[0]


def test_research_subagent_accepts_single_turn_without_worklog(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    config, runtime = _runtime_config(tmp_path, monkeypatch)
    config.agent.max_agent_turns = 2

    monkeypatch.setattr(
        "padv.agents.deepagents_harness.invoke_agent_session_json",
        lambda *args, **kwargs: {
            "tasks": [{"task_id": "task-001", "target_ref": "src/a.php", "prompt": "inspect", "status": "done"}],
            "findings": [
                {
                    "finding_id": "finding-001",
                    "title": "Input reaches query builder",
                    "summary": "summary",
                    "evidence_refs": ["ev-1"],
                    "file_refs": ["src/a.php"],
                    "params": ["id"],
                    "sink_refs": ["mysqli_query"],
                }
            ],
            "notes": ["premature"],
        },
    )

    tasks, findings, trace = run_research_subagent(
        runtime,
        "source",
        config,
        objective=_objective(),
        frontier_state={},
    )

    assert tasks[0].task_id == "task-001"
    assert findings[0].finding_id == "finding-001"
    assert trace["turns"] == 1
    assert trace["worklog_refs"] == []
    assert trace["tool_refs"] == []


def test_research_subagent_uses_compact_research_frontier_in_handoff(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config, runtime = _runtime_config(tmp_path, monkeypatch)
    seen_handoff: dict[str, Any] = {}

    def _fake_invoke(session, prompt, _config):
        handoff_ref = prompt.split("handoff artifact at '", 1)[1].split("'", 1)[0]
        payload = json.loads((Path(runtime.workspace_dir) / handoff_ref).read_text(encoding="utf-8"))
        seen_handoff.update(payload)
        _append_worklog(runtime, "source", "source/worklog/research-compact.json")
        _append_tool_call(runtime, "source", "source/tool_calls/research-compact.json", "search_repo_text")
        return {
            "findings": [
                {
                    "finding_id": "finding-001",
                    "title": "include_once sink",
                    "summary": "summary",
                    "evidence_refs": ["ev-1"],
                    "file_refs": ["src/a.php"],
                    "params": ["page"],
                    "sink_refs": ["include_once"],
                }
            ],
            "notes": ["final"],
        }

    monkeypatch.setattr("padv.agents.deepagents_harness.invoke_agent_session_json", _fake_invoke)

    frontier_state = {
        "version": 1,
        "iteration": 28,
        "stagnation_rounds": 3,
        "failed_paths": [{"path": "a", "iteration": 1, "reason": "x" * 500}],
        "history": list(range(50)),
        "attempt_history": list(range(60)),
        "candidate_resume": {f"cand-{idx}": {"candidate_id": f"cand-{idx}"} for idx in range(20)},
        "coverage": {
            "files": [f"src/{idx}.php" for idx in range(20)],
            "classes": [f"class-{idx}" for idx in range(20)],
            "signals": [f"sig-{idx}" for idx in range(20)],
            "sinks": [f"sink-{idx}" for idx in range(20)],
            "web_paths": [f"/p/{idx}" for idx in range(20)],
        },
        "runtime_coverage": {
            "flags": [f"flag-{idx}" for idx in range(20)],
            "classes": [f"rclass-{idx}" for idx in range(20)],
        },
    }

    tasks, findings, trace = run_research_subagent(
        runtime,
        "source",
        config,
        objective=_objective(),
        frontier_state=frontier_state,
    )

    compact = seen_handoff["envelope"]["frontier_state"]
    assert tasks == []
    assert findings[0].finding_id == "finding-001"
    assert trace["turns"] == 1
    assert compact["iteration"] == 28
    assert compact["failed_paths_count"] == 1
    assert "failed_paths" not in compact
    assert "history_count" not in compact
    assert "attempt_history_count" not in compact
    assert "candidate_resume_size" not in compact
    assert len(compact["coverage"]["sinks"]) == 4


def test_invoke_agent_session_with_timeout_passes_override_when_supported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    session = AgentSession(
        agent=SimpleNamespace(),
        thread_id="padv-source-test",
        model="test-model",
        repo_root=".",
        checkpoint_dir=".padv/langgraph",
        role="source",
    )
    seen: dict[str, Any] = {}

    def _fake_invoke(session_arg, prompt_arg, config_arg, timeout_seconds=None):
        seen["session"] = session_arg
        seen["prompt"] = prompt_arg
        seen["config"] = config_arg
        seen["timeout_seconds"] = timeout_seconds
        return {"ok": True}

    monkeypatch.setattr("padv.agents.deepagents_harness.invoke_agent_session_json", _fake_invoke)

    parsed = _invoke_agent_session_with_timeout(
        session,
        "prompt",
        config,
        timeout_seconds=77,
    )

    assert parsed == {"ok": True}
    assert seen["session"] is session
    assert seen["prompt"] == "prompt"
    assert seen["config"] is config
    assert seen["timeout_seconds"] == 77


def test_research_subagent_uses_role_specific_session(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    config, runtime = _runtime_config(tmp_path, monkeypatch)
    seen: list[str] = []

    def _fake_invoke(session, prompt, _config):
        seen.append(session.role)
        _append_worklog(runtime, "source", "source/worklog/research-1.json")
        return {"status": "continue", "notes": ["more"]}

    monkeypatch.setattr("padv.agents.deepagents_harness.invoke_agent_session_json", _fake_invoke)

    with pytest.raises(AgentExecutionError, match="non-final continue response"):
        run_research_subagent(
            runtime,
            "source",
            config,
            objective=_objective(),
            frontier_state={},
        )

    assert seen == ["source"]


def test_invoke_agent_session_json_persists_exception_trace(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    session = AgentSession(
        agent=SimpleNamespace(invoke=lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("boom"))),
        thread_id="padv-source-test",
        model="test-model",
        repo_root=str(tmp_path),
        checkpoint_dir=str(tmp_path / ".padv" / "langgraph"),
        role="source",
    )

    with pytest.raises(AgentExecutionError, match=r"source invocation failed: boom \(raw_ref=source/raw_outputs/"):
        invoke_agent_session_json(session, "test prompt", config)


def test_web_research_accepts_single_turn_without_playwright_artifact_tool_use(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config, runtime = _runtime_config(tmp_path, monkeypatch)
    config.agent.max_agent_turns = 2

    def _fake_invoke(session, prompt, _config):
        assert session.role == "web"
        _append_worklog(runtime, "web", "web/worklog/research-1.json")
        _append_tool_call(runtime, "web", "web/tool_calls/research-1.json", "list_role_workspace")
        return {
            "tasks": [{"task_id": "task-001", "target_ref": "web:/", "prompt": "inspect", "status": "done"}],
            "findings": [
                {
                    "finding_id": "finding-001",
                    "title": "Reachable flow",
                    "summary": "summary",
                    "evidence_refs": ["ev-1"],
                    "web_paths": ["/"],
                    "params": ["page"],
                    "sink_refs": ["echo"],
                }
            ],
            "notes": ["final-without-playwright-artifact-tool"],
        }

    monkeypatch.setattr("padv.agents.deepagents_harness.invoke_agent_session_json", _fake_invoke)

    tasks, findings, trace = run_research_subagent(
        runtime,
        "web",
        config,
        objective=_objective(),
        frontier_state={},
    )

    assert trace["turns"] == 1
    assert tasks[0].channel == "web"
    assert findings[0].web_paths == ["/"]
    assert any(ref.endswith(".json") for ref in trace["tool_refs"])


def test_web_research_accepts_single_turn_when_playwright_artifact_tool_is_used(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config, runtime = _runtime_config(tmp_path, monkeypatch)

    def _fake_invoke(session, prompt, _config):
        assert session.role == "web"
        _append_worklog(runtime, "web", "web/worklog/research-1.json")
        _append_tool_call(runtime, "web", "web/tool_calls/research-1.json", "lookup_playwright_artifacts")
        return {
            "tasks": [{"task_id": "task-001", "target_ref": "web:/", "prompt": "inspect", "status": "done"}],
            "findings": [
                {
                    "finding_id": "finding-001",
                    "title": "Reachable form flow",
                    "summary": "summary",
                    "evidence_refs": ["ev-1"],
                    "web_paths": ["/"],
                    "params": ["page"],
                    "sink_refs": ["echo"],
                }
            ],
            "notes": ["final-with-playwright-artifact-tool"],
        }

    monkeypatch.setattr("padv.agents.deepagents_harness.invoke_agent_session_json", _fake_invoke)

    tasks, findings, trace = run_research_subagent(
        runtime,
        "web",
        config,
        objective=_objective(),
        frontier_state={},
    )

    assert trace["turns"] == 1
    assert len(trace["progress_refs"]) == 0
    assert tasks[0].channel == "web"
    assert findings[0].web_paths == ["/"]
    assert any(ref.endswith(".json") for ref in trace["tool_refs"])


def test_invoke_agent_session_json_persists_raw_output_on_non_json(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config, runtime = _runtime_config(tmp_path, monkeypatch)
    session = runtime.subagents["source"]
    session.agent = SimpleNamespace(
        invoke=lambda *_args, **_kwargs: {
            "messages": [{"role": "assistant", "content": "analysis first\n{not valid json}\nmore text"}]
        }
    )

    with pytest.raises(AgentExecutionError, match=r"raw_ref=source/raw_outputs/"):
        invoke_agent_session_json(session, "inspect", config)

    raw_files = sorted((Path(runtime.workspace_dir) / "source" / "raw_outputs").glob("*.json"))
    assert raw_files
    payload = json.loads(raw_files[-1].read_text(encoding="utf-8"))
    assert payload["role"] == "source"
    assert payload["kind"] == "non_json_response"


def test_skeptic_subagent_accepts_single_turn_when_requirements_are_met(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config, runtime = _runtime_config(tmp_path, monkeypatch)
    calls = {"count": 0}
    prompts: list[str] = []

    def _fake_invoke(session, prompt, _config):
        calls["count"] += 1
        prompts.append(prompt)
        assert session.role == "skeptic"
        _append_worklog(runtime, "skeptic", "skeptic/worklog/refute-1.json")
        return {
            "refutations": [
                {
                    "refutation_id": "ref-001",
                    "hypothesis_id": "hyp-001",
                    "title": "Potential sanitization",
                    "summary": "needs proof",
                    "evidence_refs": ["ev-2"],
                    "severity": "medium",
                }
            ],
            "notes": ["final"],
        }

    monkeypatch.setattr("padv.agents.deepagents_harness.invoke_agent_session_json", _fake_invoke)

    refutations, trace = challenge_hypotheses_with_subagent(
        runtime,
        config,
        hypotheses=[_hypothesis()],
    )

    assert calls["count"] == 1
    assert trace["turns"] == 1
    assert len(trace["progress_refs"]) == 0
    assert refutations[0].refutation_id == "ref-001"
    assert trace["invocation_role"] == "skeptic"
    assert trace["workspace_role"] == "skeptic"
    assert trace["worklog_refs"] == ["skeptic/worklog/refute-1.json"]
    assert trace["delegation_refs"] == []
    assert "handoff artifact" in prompts[0]


def test_skeptic_subagent_falls_back_on_agent_timeout(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config, runtime = _runtime_config(tmp_path, monkeypatch)
    hypothesis = _hypothesis()

    monkeypatch.setattr(
        "padv.agents.deepagents_harness._invoke_agent_handoff",
        lambda *args, **kwargs: (_ for _ in ()).throw(AgentExecutionError("skeptic invocation timed out after 120s")),
    )

    refutations, trace = challenge_hypotheses_with_subagent(
        runtime,
        config,
        hypotheses=[hypothesis],
    )

    assert refutations == []
    assert trace["engine"] == "deepagents-fallback"
    assert trace["fallback_error"] == "skeptic invocation timed out after 120s"
    assert trace["hypothesis_ids"] == [hypothesis.hypothesis_id]


def test_skeptic_subagent_limits_scope_to_top_three_hypotheses(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config, runtime = _runtime_config(tmp_path, monkeypatch)
    envelopes: list[dict[str, object]] = []

    def _fake_invoke(session, prompt, _config):
        assert session.role == "skeptic"
        handoff_ref = prompt.split("handoff artifact at '", 1)[1].split("'", 1)[0]
        payload = json.loads((Path(runtime.workspace_dir) / handoff_ref).read_text(encoding="utf-8"))
        envelopes.append(payload["envelope"])
        _append_worklog(runtime, "skeptic", "skeptic/worklog/refute-top3.json")
        return {"refutations": [], "notes": ["final"]}

    monkeypatch.setattr("padv.agents.deepagents_harness.invoke_agent_session_json", _fake_invoke)
    monkeypatch.setattr(
        "padv.agents.deepagents_harness.make_validation_plans_with_deepagents",
        lambda *args, **kwargs: (_ for _ in ()).throw(AgentExecutionError("zero plans")),
    )

    hypotheses = []
    for idx, confidence in enumerate([0.1, 0.9, 0.4, 0.8], start=1):
        item = _hypothesis()
        item.hypothesis_id = f"hyp-{idx:03d}"
        item.title = f"Hypothesis {idx}"
        item.confidence = confidence
        hypotheses.append(item)

    refutations, _trace = challenge_hypotheses_with_subagent(
        runtime,
        config,
        hypotheses=hypotheses,
    )

    assert refutations == []
    assert len(envelopes) == 1
    envelope = envelopes[0]
    assert "frontier_state" not in envelope
    compact = envelope["hypotheses"]
    assert isinstance(compact, list)
    assert [item["hypothesis_id"] for item in compact] == ["hyp-002", "hyp-004", "hyp-003"]


def test_skeptic_subagent_deprioritizes_environmental_preconditions_in_handoff(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config, runtime = _runtime_config(tmp_path, monkeypatch)
    envelopes: list[dict[str, object]] = []

    def _fake_invoke(session, prompt, _config):
        assert session.role == "skeptic"
        handoff_ref = prompt.split("handoff artifact at '", 1)[1].split("'", 1)[0]
        payload = json.loads((Path(runtime.workspace_dir) / handoff_ref).read_text(encoding="utf-8"))
        envelopes.append(payload["envelope"])
        _append_worklog(runtime, "skeptic", "skeptic/worklog/refute-env.json")
        return {"refutations": [], "notes": ["final"]}

    monkeypatch.setattr("padv.agents.deepagents_harness.invoke_agent_session_json", _fake_invoke)

    hypothesis = _hypothesis()
    hypothesis.preconditions = ["security_level < 2", "parser accepts shell metacharacters"]
    hypothesis.auth_requirements = ["auth-state-known", "admin session required"]

    refutations, _trace = challenge_hypotheses_with_subagent(
        runtime,
        config,
        hypotheses=[hypothesis],
    )

    assert refutations == []
    envelope = envelopes[0]
    assert envelope["skeptic_scope"]["defer_environmental_constraints"] is True
    compact = envelope["hypotheses"][0]
    assert compact["preconditions"] == ["parser accepts shell metacharacters"]
    assert compact["auth_requirements"] == ["admin session required"]
    assert compact["environment_constraints_tracked_elsewhere"] is True


def test_skeptic_subagent_filters_environmental_refutations(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config, runtime = _runtime_config(tmp_path, monkeypatch)

    def _fake_invoke(session, prompt, _config):
        assert session.role == "skeptic"
        _append_worklog(runtime, "skeptic", "skeptic/worklog/refute-filter.json")
        return {
            "refutations": [
                {
                    "refutation_id": "ref-env",
                    "hypothesis_id": "hyp-001",
                    "title": "Security level requirement",
                    "summary": "security_level must remain below 2 in the default configuration",
                    "evidence_refs": ["ev-env"],
                    "severity": "high",
                },
                {
                    "refutation_id": "ref-real",
                    "hypothesis_id": "hyp-001",
                    "title": "Input is normalized before sink",
                    "summary": "Request value is canonicalized before shell metacharacters reach the sink",
                    "evidence_refs": ["ev-real"],
                    "severity": "high",
                },
            ],
            "notes": ["final"],
        }

    monkeypatch.setattr("padv.agents.deepagents_harness.invoke_agent_session_json", _fake_invoke)

    refutations, trace = challenge_hypotheses_with_subagent(
        runtime,
        config,
        hypotheses=[_hypothesis()],
    )

    assert [item.refutation_id for item in refutations] == ["ref-real"]
    assert trace["refutation_ids"] == ["ref-real"]


def test_skeptic_guidance_caps_material_refutations() -> None:
    guidance = _handoff_work_guidance("skeptic", "skeptic_challenge")
    checklist = _handoff_turn_checklist("skeptic_challenge", 1)

    assert "at most 3 material refutations" in guidance
    assert "Do not spend the turn re-checking deployment or environment preconditions" in guidance
    assert any("strongest 1-3 objections" in item for item in checklist)


def test_experiment_subagent_accepts_single_turn_when_requirements_are_met(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config, runtime = _runtime_config(tmp_path, monkeypatch)
    calls = {"count": 0}
    prompts: list[str] = []

    def _plan_payload():
        candidate = _candidate().to_dict()
        return {
            "plans": [
                {
                    "hypothesis_id": "hyp-001",
                    "candidate": candidate,
                    "intercepts": ["mysqli_query"],
                    "positive_requests": [
                        {"method": "GET", "path": "/admin.php", "params": {"id": "1' OR '1'='1"}}
                    ],
                    "negative_requests": [{"method": "GET", "path": "/admin.php", "params": {"id": "1"}}],
                    "strategy": "sql boolean",
                    "negative_control_strategy": "benign id",
                    "plan_notes": ["test"],
                    "attempt_id": "attempt-001",
                    "plan_id": "plan-001",
                    "request_refs": ["req-1"],
                    "witness_goal": "query witness",
                    "status": "planned",
                    "analysis_flags": ["sql"],
                }
            ],
            "notes": ["final"],
        }

    def _fake_invoke(session, prompt, _config):
        calls["count"] += 1
        prompts.append(prompt)
        assert session.role == "experiment"
        _append_worklog(runtime, "experiment", "experiment/worklog/plan-1.json")
        return _plan_payload()

    monkeypatch.setattr("padv.agents.deepagents_harness.invoke_agent_session_json", _fake_invoke)

    plans, attempts, trace = plan_experiments_with_subagent(
        runtime,
        config,
        hypotheses=[_hypothesis()],
    )

    assert calls["count"] == 1
    assert trace["turns"] == 1
    assert len(trace["progress_refs"]) == 0
    assert sorted(plans.keys()) == ["cand-1"]
    assert attempts[0].attempt_id == "attempt-001"
    assert trace["invocation_role"] == "experiment"
    assert trace["workspace_role"] == "experiment"
    assert trace["worklog_refs"] == ["experiment/worklog/plan-1.json"]
    assert trace["delegation_refs"] == []
    assert "handoff artifact" in prompts[0]


def test_experiment_subagent_limits_scope_to_top_three_hypotheses(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config, runtime = _runtime_config(tmp_path, monkeypatch)
    envelopes: list[dict[str, object]] = []

    def _fake_invoke(session, prompt, _config):
        assert session.role == "experiment"
        handoff_ref = prompt.split("handoff artifact at '", 1)[1].split("'", 1)[0]
        payload = json.loads((Path(runtime.workspace_dir) / handoff_ref).read_text(encoding="utf-8"))
        envelopes.append(payload["envelope"])
        _append_worklog(runtime, "experiment", "experiment/worklog/plan-top3.json")
        return {"plans": [], "notes": ["final"]}

    monkeypatch.setattr("padv.agents.deepagents_harness.invoke_agent_session_json", _fake_invoke)
    monkeypatch.setattr(
        "padv.agents.deepagents_harness.make_validation_plans_with_deepagents",
        lambda *args, **kwargs: (_ for _ in ()).throw(AgentExecutionError("zero plans")),
    )

    hypotheses = []
    for idx, confidence in enumerate([0.2, 0.95, 0.4, 0.8], start=1):
        item = _hypothesis()
        item.hypothesis_id = f"hyp-plan-{idx:03d}"
        item.title = f"Plan Hypothesis {idx}"
        item.confidence = confidence
        item.candidate = _candidate()
        item.candidate.candidate_id = f"cand-plan-{idx:03d}"
        hypotheses.append(item)

    with pytest.raises(AgentExecutionError, match="zero plans"):
        plan_experiments_with_subagent(
            runtime,
            config,
            hypotheses=hypotheses,
        )

    assert len(envelopes) == 1
    envelope = envelopes[0]
    assert "frontier_state" not in envelope
    compact = envelope["hypotheses"]
    assert isinstance(compact, list)
    assert [item["hypothesis_id"] for item in compact] == [
        "hyp-plan-002",
        "hyp-plan-004",
        "hyp-plan-003",
    ]


def test_experiment_subagent_accepts_single_plan_object(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config, runtime = _runtime_config(tmp_path, monkeypatch)
    hypothesis = _hypothesis()

    def _fake_handoff(*args, **kwargs):
        return (
            {
                "candidate_id": hypothesis.candidate.candidate_id,
                "vuln_class": hypothesis.candidate.vuln_class,
                "title": hypothesis.candidate.title,
                "file_path": hypothesis.candidate.file_path,
                "line": hypothesis.candidate.line,
                "sink": hypothesis.candidate.sink,
                "expected_intercepts": hypothesis.candidate.expected_intercepts,
                "oracle_functions": ["mysqli_query"],
                "request_expectations": ["GET request to /ajax/lookup-pen-test-tool.php"],
                "response_witnesses": ["error output contains canary"],
                "positive_requests": [{"method": "GET", "path": "/ajax/lookup-pen-test-tool.php", "query": {"ToolID": "1"}}] * 3,
                "negative_requests": [{"method": "GET", "path": "/ajax/lookup-pen-test-tool.php", "query": {"ToolID": "0"}}],
                "strategy": "direct single-plan response",
                "plan_notes": ["single object"],
            },
            {"engine": "deepagents", "turns": 1},
        )

    monkeypatch.setattr("padv.agents.deepagents_harness._invoke_agent_handoff", _fake_handoff)

    plans, attempts, trace = plan_experiments_with_subagent(
        runtime,
        config,
        hypotheses=[hypothesis],
    )

    assert sorted(plans.keys()) == [hypothesis.candidate.candidate_id]
    assert plans[hypothesis.candidate.candidate_id].oracle_functions == ["mysqli_query"]
    assert attempts[0].hypothesis_id == hypothesis.candidate.candidate_id
    assert trace["planned_candidate_ids"] == [hypothesis.candidate.candidate_id]


def test_experiment_guidance_caps_number_of_plans() -> None:
    guidance = _handoff_work_guidance("experiment", "experiment_plan")
    checklist = _handoff_turn_checklist("experiment_plan", 1)

    assert "Return at most 3 concrete validation plans" in guidance
    assert any("strongest 2-3 surviving hypotheses" in item for item in checklist)


def test_experiment_subagent_falls_back_to_batch_planner(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config, runtime = _runtime_config(tmp_path, monkeypatch)
    hypothesis = _hypothesis()

    monkeypatch.setattr(
        "padv.agents.deepagents_harness._invoke_agent_handoff",
        lambda *args, **kwargs: (_ for _ in ()).throw(AgentExecutionError("experiment invocation timed out after 60s")),
    )

    fallback_plan = ValidationPlan(
        candidate_id=hypothesis.candidate.candidate_id,
        intercepts=["mysqli_query"],
        oracle_functions=["mysqli_query"],
        positive_requests=[
            {"method": "GET", "path": "/", "query": {"p": "1"}},
            {"method": "GET", "path": "/", "query": {"p": "2"}},
            {"method": "GET", "path": "/", "query": {"p": "3"}},
        ],
        negative_requests=[{"method": "GET", "path": "/", "query": {"p": "0"}}],
        canary="p1",
        strategy="fallback",
    )

    def _fake_batch_planner(candidates, _config, *, repo_root=None, session=None, batch_size=4):
        assert [item.candidate_id for item in candidates] == [hypothesis.candidate.candidate_id]
        assert repo_root == runtime.repo_root
        assert session.role == "experiment"
        assert batch_size == 2
        return ({hypothesis.candidate.candidate_id: fallback_plan}, {"engine": "batch-fallback"})

    monkeypatch.setattr(
        "padv.agents.deepagents_harness.make_validation_plans_with_deepagents",
        _fake_batch_planner,
    )

    plans, attempts, trace = plan_experiments_with_subagent(
        runtime,
        config,
        hypotheses=[hypothesis],
    )

    assert sorted(plans.keys()) == [hypothesis.candidate.candidate_id]
    assert attempts[0].analysis_flags == ["fallback-plan"]
    assert attempts[0].metadata["fallback_error"] == "experiment invocation timed out after 60s"
    assert trace["engine"] == "deepagents-fallback"
    assert trace["fallback_trace"]["engine"] == "batch-fallback"


def test_invoke_agent_session_json_serializes_parallel_calls_per_session() -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    config.llm.timeout_seconds = 5

    state = {"active": 0, "max_active": 0}
    gate = threading.Event()

    class _FakeAgent:
        def invoke(self, payload, config=None):
            state["active"] += 1
            state["max_active"] = max(state["max_active"], state["active"])
            gate.wait(1.0)
            time.sleep(0.05)
            state["active"] -= 1
            return {"messages": [{"role": "assistant", "content": "{\"ok\":true}"}]}

    session = AgentSession(
        agent=_FakeAgent(),
        thread_id="shared-thread",
        model="test-model",
        repo_root=None,
        role="root",
    )

    results: list[dict[str, object]] = []
    errors: list[BaseException] = []

    def _call() -> None:
        try:
            results.append(invoke_agent_session_json(session, "{}", config))
        except BaseException as exc:  # pragma: no cover - defensive for test thread
            errors.append(exc)

    t1 = threading.Thread(target=_call)
    t2 = threading.Thread(target=_call)
    t1.start()
    t2.start()
    time.sleep(0.1)
    gate.set()
    t1.join()
    t2.join()

    assert not errors
    assert len(results) == 2
    assert state["max_active"] == 1


def test_research_handoff_exact_cache_reuses_identical_request_across_runtime_restarts(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    config.agent.max_agent_turns = 2
    monkeypatch.setenv(config.llm.api_key_env, "test-key")
    monkeypatch.setattr(
        "deepagents.create_deep_agent",
        lambda **kwargs: SimpleNamespace(
            invoke=lambda *args, **kw: {"messages": [{"role": "assistant", "content": "{}"}]}
        ),
    )
    checkpoint_dir = str(tmp_path / "langgraph-store")
    runtime1 = ensure_agent_runtime(
        config,
        frontier_state={},
        repo_root=str(tmp_path),
        checkpoint_dir=checkpoint_dir,
    )
    objective = _objective()
    calls = {"count": 0}

    def _fake_invoke(session, prompt, _config):
        calls["count"] += 1
        _append_tool_call(runtime1, "source", "source/tool_calls/cacheable.json", "search_repo_text")
        _append_worklog(runtime1, "source", "source/worklog/cacheable.json")
        return {
            "tasks": [
                {
                    "task_id": "source-task-1",
                    "target_ref": "cand-1",
                    "prompt": "inspect source",
                    "status": "done",
                }
            ],
            "findings": [
                {
                    "finding_id": "source-finding-1",
                    "title": "source finding",
                    "summary": "summary",
                    "evidence_refs": ["ev-1"],
                    "file_refs": ["src/a.php"],
                    "web_paths": ["/"],
                    "params": ["id"],
                    "sink_refs": ["mysqli_query"],
                }
            ],
            "notes": ["final"],
        }

    monkeypatch.setattr("padv.agents.deepagents_harness.invoke_agent_session_json", _fake_invoke)

    tasks1, findings1, trace1 = run_research_subagent(
        runtime1,
        "source",
        config,
        objective=objective,
        frontier_state={},
    )
    assert calls["count"] == 1
    assert not trace1.get("cache_hit", False)
    assert tasks1[0].task_id == "source-task-1"
    assert findings1[0].finding_id == "source-finding-1"

    runtime2 = ensure_agent_runtime(
        config,
        frontier_state={},
        repo_root=str(tmp_path),
        checkpoint_dir=checkpoint_dir,
    )

    def _should_not_invoke(*_args, **_kwargs):
        raise AssertionError("identical cached handoff should not invoke the LLM again")

    monkeypatch.setattr("padv.agents.deepagents_harness.invoke_agent_session_json", _should_not_invoke)

    tasks2, findings2, trace2 = run_research_subagent(
        runtime2,
        "source",
        config,
        objective=objective,
        frontier_state={},
    )
    assert calls["count"] == 1
    assert trace2["cache_hit"] is True
    assert trace2["cache_source"] == "sqlite-exact"
    assert tasks2[0].task_id == "source-task-1"
    assert findings2[0].finding_id == "source-finding-1"


def test_research_handoff_exact_cache_reuses_across_run_scoped_checkpoint_dirs(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    config.agent.max_agent_turns = 2
    monkeypatch.setenv(config.llm.api_key_env, "test-key")
    monkeypatch.setattr(
        "deepagents.create_deep_agent",
        lambda **kwargs: SimpleNamespace(
            invoke=lambda *args, **kw: {"messages": [{"role": "assistant", "content": "{}"}]}
        ),
    )
    base_dir = tmp_path / "langgraph"
    run1_dir = str(base_dir / "analyze-run1")
    run2_dir = str(base_dir / "analyze-run2")
    objective = _objective()
    calls = {"count": 0}

    runtime1 = ensure_agent_runtime(
        config,
        frontier_state={},
        repo_root=str(tmp_path / "repo"),
        checkpoint_dir=run1_dir,
    )

    def _fake_invoke(session, prompt, _config):
        calls["count"] += 1
        _append_tool_call(runtime1, "source", "source/tool_calls/cacheable.json", "search_repo_text")
        _append_worklog(runtime1, "source", "source/worklog/cacheable.json")
        return {
            "tasks": [
                {
                    "task_id": "source-task-1",
                    "target_ref": "cand-1",
                    "prompt": "inspect source",
                    "status": "done",
                }
            ],
            "findings": [
                {
                    "finding_id": "source-finding-1",
                    "title": "source finding",
                    "summary": "summary",
                    "evidence_refs": ["ev-1"],
                    "file_refs": ["src/a.php"],
                    "web_paths": ["/"],
                    "params": ["id"],
                    "sink_refs": ["mysqli_query"],
                }
            ],
            "notes": ["final"],
        }

    monkeypatch.setattr("padv.agents.deepagents_harness.invoke_agent_session_json", _fake_invoke)
    _tasks1, _findings1, trace1 = run_research_subagent(
        runtime1,
        "source",
        config,
        objective=objective,
        frontier_state={},
    )
    assert trace1["cache_hit"] is False
    assert calls["count"] == 1
    assert (base_dir / "handoff_cache.sqlite").exists()

    runtime2 = ensure_agent_runtime(
        config,
        frontier_state={},
        repo_root=str(tmp_path / "repo"),
        checkpoint_dir=run2_dir,
    )

    def _should_not_invoke(*_args, **_kwargs):
        raise AssertionError("cross-run cache should satisfy identical handoff")

    monkeypatch.setattr("padv.agents.deepagents_harness.invoke_agent_session_json", _should_not_invoke)
    _tasks2, _findings2, trace2 = run_research_subagent(
        runtime2,
        "source",
        config,
        objective=objective,
        frontier_state={},
    )
    assert calls["count"] == 1
    assert trace2["cache_hit"] is True
    assert trace2["cache_source"] == "sqlite-exact"


def test_research_handoff_inflight_deduplicates_identical_parallel_requests(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config, runtime = _runtime_config(tmp_path, monkeypatch)
    objective = _objective()
    state = {"calls": 0}
    gate = threading.Event()
    errors: list[BaseException] = []
    results: list[tuple[list[ResearchTask], list[ResearchFinding], dict[str, Any]]] = []

    def _fake_invoke(session, prompt, _config):
        state["calls"] += 1
        gate.wait(1.0)
        _append_tool_call(runtime, "source", "source/tool_calls/dedup.json", "search_repo_text")
        _append_worklog(runtime, "source", "source/worklog/dedup.json")
        return {
            "tasks": [
                {
                    "task_id": "source-task-dedup",
                    "target_ref": "cand-1",
                    "prompt": "inspect source",
                    "status": "done",
                }
            ],
            "findings": [
                {
                    "finding_id": "source-finding-dedup",
                    "title": "source finding",
                    "summary": "summary",
                    "evidence_refs": ["ev-1"],
                    "file_refs": ["src/a.php"],
                    "web_paths": ["/"],
                    "params": ["id"],
                    "sink_refs": ["mysqli_query"],
                }
            ],
            "notes": ["final"],
        }

    monkeypatch.setattr("padv.agents.deepagents_harness.invoke_agent_session_json", _fake_invoke)

    def _call() -> None:
        try:
            results.append(
                run_research_subagent(
                    runtime,
                    "source",
                    config,
                    objective=objective,
                    frontier_state={},
                )
            )
        except BaseException as exc:  # pragma: no cover - defensive for test thread
            errors.append(exc)

    t1 = threading.Thread(target=_call)
    t2 = threading.Thread(target=_call)
    t1.start()
    t2.start()
    time.sleep(0.1)
    gate.set()
    t1.join()
    t2.join()

    assert not errors
    assert len(results) == 2
    assert state["calls"] == 1
    cache_hits = sorted(result[2].get("cache_hit", False) for result in results)
    assert cache_hits == [False, True]


def test_handoff_cache_key_ignores_run_volatile_frontier_metadata(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config, runtime = _runtime_config(tmp_path, monkeypatch)
    session = runtime.root
    envelope_a = {
        "run_validation": False,
        "discovery_trace": {"semantic_count": 120, "web_paths": 3},
        "frontier_state": {
            "iteration": 5,
            "coverage": {"files": ["src/a.php"], "classes": ["sql_injection"]},
            "agent_threads": {"root": "padv-root-old"},
            "updated_at": "2026-03-08T15:00:00+00:00",
        },
    }
    envelope_b = {
        "run_validation": False,
        "discovery_trace": {"semantic_count": 120, "web_paths": 3},
        "frontier_state": {
            "iteration": 5,
            "coverage": {"files": ["src/a.php"], "classes": ["sql_injection"]},
            "agent_threads": {"root": "padv-root-new"},
            "updated_at": "2026-03-08T15:05:00+00:00",
        },
    }

    key_a = _handoff_cache_key(
        session,
        config=config,
        category="orient",
        envelope=envelope_a,
        response_contract='{"objectives":[],"notes":[]}',
        workspace_role="root",
        delegated_role=None,
    )
    key_b = _handoff_cache_key(
        session,
        config=config,
        category="orient",
        envelope=envelope_b,
        response_contract='{"objectives":[],"notes":[]}',
        workspace_role="root",
        delegated_role=None,
    )

    assert key_a == key_b


def test_handoff_cache_key_changes_when_config_signature_changes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config_a, runtime = _runtime_config(tmp_path, monkeypatch)
    config_b, _runtime2 = _runtime_config(tmp_path / "other", monkeypatch)
    config_b.budgets.max_requests = config_a.budgets.max_requests + 1
    session = runtime.root
    envelope = {
        "frontier_state": {"iteration": 1, "coverage": {"files": ["src/a.php"]}},
        "discovery_trace": {"semantic_count": 1},
    }

    key_a = _handoff_cache_key(
        session,
        config=config_a,
        category="source_research",
        envelope=envelope,
        response_contract='{"tasks":[],"findings":[],"notes":[]}',
        workspace_role="source",
        delegated_role=None,
    )
    key_b = _handoff_cache_key(
        session,
        config=config_b,
        category="source_research",
        envelope=envelope,
        response_contract='{"tasks":[],"findings":[],"notes":[]}',
        workspace_role="source",
        delegated_role=None,
    )

    assert key_a != key_b


def test_handoff_cache_ignores_stale_sqlite_entry(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config, runtime = _runtime_config(tmp_path, monkeypatch)
    session = runtime.root
    key = _handoff_cache_key(
        session,
        config=config,
        category="source_research",
        envelope={"frontier_state": {}, "objective": {"objective_id": "obj-1"}},
        response_contract='{"tasks":[],"findings":[],"notes":[]}',
        workspace_role="source",
        delegated_role=None,
    )
    _store_handoff_cache(runtime.checkpoint_dir, key, {"tasks": [], "findings": [], "notes": ["fresh"]})
    db_path = Path(runtime.checkpoint_dir) / "handoff_cache.sqlite"
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "UPDATE handoff_exact_cache SET created_at = ? WHERE cache_key = ?",
            ("2000-01-01T00:00:00+00:00", key),
        )
        conn.commit()

    monkeypatch.setattr("padv.agents.deepagents_harness._HANDOFF_CACHE_TTL_SECONDS", 1)

    assert _load_handoff_cache(runtime.checkpoint_dir, key) is None


def test_parallel_role_runtime_uses_isolated_shared_context_and_merge() -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    shared_context = {
        "workspace_dir": "/tmp/workspace",
        "workspace_index": {"source": {"worklog": ["source/worklog/existing.json"]}},
        "tool_usage": {"source": [{"ref": "source/tool_calls/existing.json", "tool": "list_objectives"}]},
        "worklog": {"source": [{"ref": "source/worklog/existing.json", "role": "source"}]},
    }
    runtime = AgentRuntime(
        root=SimpleNamespace(role="root"),
        subagents={},
        shared_context=shared_context,
        checkpoint_dir="/tmp/checkpoints",
        workspace_dir="/tmp/workspace",
        model="test-model",
        repo_root="/tmp/repo",
        store=None,
        prompts={},
    )

    branch_runtime = clone_runtime_for_parallel_role(runtime, config, role="source")
    assert branch_runtime is runtime

    # Emulate a real isolated branch runtime produced by the production path.
    branch_runtime = AgentRuntime(
        root=SimpleNamespace(role="root"),
        subagents={},
        shared_context={
            "workspace_index": {"source": {"worklog": ["source/worklog/new.json"], "tool_calls": ["source/tool_calls/new.json"]}},
            "tool_usage": {"source": [{"ref": "source/tool_calls/new.json", "tool": "search_repo_text"}]},
            "worklog": {"source": [{"ref": "source/worklog/new.json", "role": "source"}]},
        },
        checkpoint_dir="/tmp/checkpoints",
        workspace_dir="/tmp/workspace",
        model="test-model",
        repo_root="/tmp/repo",
        store=None,
        prompts={"source": "prompt"},
    )

    delta = finalize_parallel_role_runtime(branch_runtime, role="source")
    assert delta["workspace_index"]["source"]["worklog"] == ["source/worklog/new.json"]

    merge_agent_runtime_context_delta(runtime, delta)
    assert runtime.shared_context["workspace_index"]["source"]["worklog"] == [
        "source/worklog/existing.json",
        "source/worklog/new.json",
    ]
    assert runtime.shared_context["tool_usage"]["source"][-1]["tool"] == "search_repo_text"
    assert runtime.shared_context["worklog"]["source"][-1]["ref"] == "source/worklog/new.json"
    assert "__lock__" in runtime.shared_context
    assert "__lock__" in branch_runtime.shared_context


def test_update_agent_runtime_context_defensively_copies_mutable_payload(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _config, runtime = _runtime_config(tmp_path, monkeypatch)
    payload = {
        "frontier_state": {
            "iteration": 3,
            "coverage": {"files": ["src/a.php"]},
        }
    }

    update_agent_runtime_context(runtime, **payload)
    payload["frontier_state"]["coverage"]["files"].append("src/b.php")
    payload["frontier_state"]["iteration"] = 99

    stored = runtime.shared_context["frontier_state"]
    assert stored["iteration"] == 3
    assert stored["coverage"]["files"] == ["src/a.php"]


def test_extract_json_accepts_markdown_fenced_pseudo_json_with_invalid_escape() -> None:
    raw = """Perfect. Now I'll finalize the objective selection with comprehensive justification:

```json
{
  "objective_id": "obj-sqli-ajax-pentest-001",
  "notes": [
    "Weak sanitization: str_replace(\\"\\\\\\'\\",\\"\\\\\\\\\\\\\\\\'\\",$lPostedToolID) is bypassable"
  ]
}
```"""
    parsed = _extract_json(raw)
    assert parsed is not None
    assert parsed["objective_id"] == "obj-sqli-ajax-pentest-001"

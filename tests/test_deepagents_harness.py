from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from padv.agents.deepagents_harness import (
    AgentExecutionError,
    make_validation_plans_with_deepagents,
    rank_candidates_with_deepagents,
    schedule_actions_with_deepagents,
    skeptic_refine_with_deepagents,
)
from padv.config.schema import load_config
from padv.models import Candidate


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
        file_path="phpmyfaq/src/phpMyFAQ/Network.php",
        line=40,
        sink="curl_exec",
        expected_intercepts=["curl_exec"],
        notes="test",
        provenance=["scip"],
        confidence=0.6,
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
        lambda *args, **kwargs: {"actions": []},
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
                    "intercepts": ["mysqli_query"],
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

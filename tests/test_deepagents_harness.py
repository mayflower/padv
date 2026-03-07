from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from padv.agents.deepagents_harness import (
    AgentExecutionError,
    rank_candidates_with_deepagents,
    schedule_actions_with_deepagents,
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
    assert scores["cand-2"] == pytest.approx(0.9)
    assert trace["engine"] == "deepagents"


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

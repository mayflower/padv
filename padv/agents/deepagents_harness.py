from __future__ import annotations

import json
import os
import re
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from padv.analytics.failure_patterns import failure_penalty
from padv.config.schema import PadvConfig
from padv.models import Candidate, FailureAnalysis, ValidationPlan


_JSON_BLOCK_RE = re.compile(r"\{.*\}", re.DOTALL)


class AgentExecutionError(RuntimeError):
    pass


@dataclass(slots=True)
class AgentSession:
    agent: Any
    thread_id: str
    model: str
    repo_root: str | None


def _default_rank(candidates: list[Candidate], mode: str) -> list[Candidate]:
    runtime_first = sorted(
        candidates,
        key=lambda c: (len(c.expected_intercepts) == 0, -c.confidence, c.file_path, c.line),
    )
    if mode == "delta":
        return [c for c in runtime_first if "vendor/" not in c.file_path]
    return runtime_first


def _default_plan(candidate: Candidate, config: PadvConfig) -> ValidationPlan:
    canary = f"padv-{candidate.candidate_id}-{uuid.uuid4().hex[:10]}"
    intercepts = sorted(set(candidate.expected_intercepts)) if candidate.expected_intercepts else [candidate.sink]
    default_path = "/"
    if candidate.web_path_hints:
        for hint in candidate.web_path_hints:
            if isinstance(hint, str) and hint.startswith("/"):
                default_path = hint
                break

    query_payload = {config.canary.parameter_name: canary}
    method = "GET"
    body: dict[str, str] | None = None
    if candidate.vuln_class == "idor_invariant_missing":
        query_payload["id"] = "1"
    if candidate.vuln_class == "csrf_invariant_missing":
        method = "POST"
        body = {"action": "update", config.canary.parameter_name: canary}

    positive_requests = [
        {
            "method": method,
            "query": dict(query_payload),
            "path": default_path,
            "body": body,
        }
    ]
    while len(positive_requests) < 3:
        positive_requests.append(
            {
                "method": method,
                "query": dict(query_payload),
                "path": default_path,
                "body": body,
            }
        )

    negative_requests = [
        {
            "method": method,
            "query": {config.canary.parameter_name: "padv-negative-control"},
            "path": default_path,
            "body": ({"action": "update", config.canary.parameter_name: "padv-negative-control"} if method == "POST" else None),
        }
    ]
    return ValidationPlan(
        candidate_id=candidate.candidate_id,
        intercepts=intercepts,
        positive_requests=positive_requests,
        negative_requests=negative_requests,
        canary=canary,
        strategy="default",
        negative_control_strategy="canary-mismatch",
        plan_notes=[],
    )


def _extract_text(result: dict[str, Any]) -> str:
    messages = result.get("messages")
    if not isinstance(messages, list):
        return ""
    for msg in reversed(messages):
        content = getattr(msg, "content", None)
        if isinstance(content, str) and content.strip():
            return content
        if isinstance(msg, dict):
            raw = msg.get("content")
            if isinstance(raw, str) and raw.strip():
                return raw
            if isinstance(raw, list):
                chunks = [part.get("text", "") for part in raw if isinstance(part, dict)]
                joined = "\n".join(x for x in chunks if x)
                if joined.strip():
                    return joined
    return ""


def _extract_json(text: str) -> dict[str, Any] | None:
    if not text.strip():
        return None
    try:
        data = json.loads(text)
        if isinstance(data, dict):
            return data
    except json.JSONDecodeError:
        pass
    match = _JSON_BLOCK_RE.search(text)
    if not match:
        return None
    try:
        data = json.loads(match.group(0))
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


def _build_filesystem_tools(repo_root: str) -> list[Any]:
    try:
        from langchain_core.tools import tool  # type: ignore[import-not-found]
    except Exception as exc:
        raise AgentExecutionError(f"langchain_core tools import failed: {exc}") from exc

    root = Path(repo_root).resolve()

    def _safe_path(rel_path: str) -> Path | None:
        try:
            candidate = (root / rel_path).resolve()
        except Exception:
            return None
        if root == candidate or root in candidate.parents:
            return candidate
        return None

    @tool("list_repo_dir")
    def list_repo_dir(path: str = ".") -> str:
        """List files and directories for a repo-relative path."""
        target = _safe_path(path or ".")
        if target is None or not target.exists() or not target.is_dir():
            return "invalid directory path"
        entries = sorted(p.name for p in target.iterdir())
        return "\n".join(entries[:500])

    @tool("read_repo_file")
    def read_repo_file(path: str) -> str:
        """Read a UTF-8 text file by repo-relative path."""
        target = _safe_path(path)
        if target is None or not target.exists() or not target.is_file():
            return "invalid file path"
        try:
            content = target.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return "file read failed"
        return content[:12000]

    return [list_repo_dir, read_repo_file]


def _resolve_model(config: PadvConfig) -> str:
    if ":" in config.llm.model:
        return config.llm.model
    return f"{config.llm.provider}:{config.llm.model}"


def ensure_agent_session(
    config: PadvConfig,
    *,
    frontier_state: dict[str, Any] | None = None,
    repo_root: str | None = None,
    session: AgentSession | None = None,
) -> AgentSession:
    if session is not None:
        return session

    api_key = os.environ.get(config.llm.api_key_env)
    if not api_key:
        raise AgentExecutionError(f"missing API key env var: {config.llm.api_key_env}")

    try:
        from deepagents import create_deep_agent  # type: ignore[import-not-found]
        from langgraph.checkpoint.memory import InMemorySaver  # type: ignore[import-not-found]
    except Exception as exc:
        raise AgentExecutionError(f"deepagents/langgraph import failed: {exc}") from exc

    thread_id = ""
    if isinstance(frontier_state, dict):
        maybe_thread = frontier_state.get("agent_thread_id")
        if isinstance(maybe_thread, str) and maybe_thread.strip():
            thread_id = maybe_thread.strip()
    if not thread_id:
        thread_id = f"{config.agent.thread_prefix}-{uuid.uuid4().hex[:10]}"

    model = _resolve_model(config)
    system_prompt = (
        "You are a strict security planning sub-agent for web exploitation discovery and validation. "
        "Return JSON only and avoid markdown."
    )
    tools = _build_filesystem_tools(repo_root) if repo_root else []
    try:
        agent = create_deep_agent(
            model=model,
            tools=tools,
            system_prompt=system_prompt,
            checkpointer=InMemorySaver(),
        )
    except Exception as exc:
        raise AgentExecutionError(f"deepagents agent creation failed: {exc}") from exc

    if isinstance(frontier_state, dict):
        frontier_state["agent_thread_id"] = thread_id
    return AgentSession(agent=agent, thread_id=thread_id, model=model, repo_root=repo_root)


def _invoke_deepagent_json(
    prompt: str,
    config: PadvConfig,
    *,
    frontier_state: dict[str, Any] | None = None,
    repo_root: str | None = None,
    session: AgentSession | None = None,
) -> dict[str, Any]:
    active_session = ensure_agent_session(
        config,
        frontier_state=frontier_state,
        repo_root=repo_root,
        session=session,
    )
    try:
        result = active_session.agent.invoke(
            {"messages": [{"role": "user", "content": prompt}]},
            config={"configurable": {"thread_id": active_session.thread_id}},
        )
    except Exception as exc:
        raise AgentExecutionError(f"deepagents invocation failed: {exc}") from exc

    content = _extract_text(result if isinstance(result, dict) else {})
    parsed = _extract_json(content)
    if parsed is None:
        raise AgentExecutionError("deepagents returned non-JSON response")
    return parsed


def rank_candidates_with_deepagents(
    candidates: list[Candidate],
    mode: str,
    config: PadvConfig,
    frontier_state: dict[str, Any] | None = None,
    repo_root: str | None = None,
    session: AgentSession | None = None,
) -> tuple[list[Candidate], dict[str, Any]]:
    ranked = _default_rank(candidates, mode)
    frontier_state = frontier_state or {}
    if not ranked:
        return [], {"engine": "deepagents", "reason": "no-candidates"}

    payload = [
        {
            "candidate_id": c.candidate_id,
            "vuln_class": c.vuln_class,
            "file_path": c.file_path,
            "line": c.line,
            "confidence": c.confidence,
            "provenance": c.provenance,
            "expected_intercepts": c.expected_intercepts,
            "web_path_hints": c.web_path_hints[:20],
        }
        for c in ranked[: min(150, len(ranked))]
    ]
    coverage = frontier_state.get("coverage", {})
    prompt = (
        "Rank these web-security candidates by maximizing expected information gain for the next validation cycle. "
        "Prefer multi-signal corroboration, reachable web-path hints, and novelty versus prior coverage. "
        'Return JSON: {"ordered_ids":[...], "notes":[...], "hypotheses":[{"candidate_id":"...","rationale":"..."}], "failed_paths":[...]}. '
        f"Frontier coverage: {json.dumps(coverage, ensure_ascii=True)}. "
        f"Candidates: {json.dumps(payload, ensure_ascii=True)}"
    )
    response = _invoke_deepagent_json(
        prompt,
        config,
        frontier_state=frontier_state,
        repo_root=repo_root,
        session=session,
    )

    ids = response.get("ordered_ids")
    if not isinstance(ids, list):
        raise AgentExecutionError("deepagents ranking response missing ordered_ids list")
    ordered_ids = [str(x).strip() for x in ids if isinstance(x, (str, int, float)) and str(x).strip()]
    if not ordered_ids:
        raise AgentExecutionError("deepagents ranking response returned no ordered_ids")

    position = {cid: idx for idx, cid in enumerate(ordered_ids)}
    ranked = sorted(
        ranked,
        key=lambda c: position.get(c.candidate_id, len(ranked) + c.line),
    )
    trace = {
        "engine": "deepagents",
        "ordered_ids": [c.candidate_id for c in ranked],
        "notes": response.get("notes", []),
        "hypotheses": response.get("hypotheses", []),
        "failed_paths": response.get("failed_paths", []),
    }
    return ranked, trace


def skeptic_refine_with_deepagents(
    candidates: list[Candidate],
    config: PadvConfig,
    frontier_state: dict[str, Any] | None = None,
    repo_root: str | None = None,
    session: AgentSession | None = None,
    failure_analysis: FailureAnalysis | None = None,
) -> tuple[list[Candidate], dict[str, Any]]:
    frontier_state = frontier_state or {}
    if not candidates:
        return [], {"engine": "deepagents", "reason": "no-candidates"}

    patterns = failure_analysis.patterns if isinstance(failure_analysis, FailureAnalysis) else []
    payload = []
    for c in candidates[: min(150, len(candidates))]:
        penalty = failure_penalty(
            candidate_vuln_class=c.vuln_class,
            candidate_provenance=c.provenance,
            candidate_confidence=c.confidence,
            patterns=patterns,
        )
        payload.append(
            {
                "candidate_id": c.candidate_id,
                "vuln_class": c.vuln_class,
                "file_path": c.file_path,
                "line": c.line,
                "confidence": c.confidence,
                "provenance": c.provenance,
                "web_path_hints": c.web_path_hints[:20],
                "failure_penalty": round(penalty, 4),
                "historically_fragile": penalty > 0.7,
            }
        )
    analysis_summary: dict[str, Any] = {}
    if isinstance(failure_analysis, FailureAnalysis):
        analysis_summary = {
            "total_runs_analyzed": failure_analysis.total_runs_analyzed,
            "total_failures": failure_analysis.total_failures,
            "pattern_count": len(failure_analysis.patterns),
        }
    prompt = (
        "Act as a skeptic agent. Aggressively falsify weak exploit hypotheses. "
        "Drop candidates lacking corroboration, unreachable contexts, implausible exploitation paths, or historically fragile profiles. "
        'Return JSON: {"drop_ids":[...], "confidence_overrides":{"id":0.0}, "notes":[...], "failed_paths":[...]}. '
        f"Failure analysis summary: {json.dumps(analysis_summary, ensure_ascii=True)}. "
        f"Frontier state: {json.dumps(frontier_state, ensure_ascii=True)}. "
        f"Candidates: {json.dumps(payload, ensure_ascii=True)}"
    )
    response = _invoke_deepagent_json(
        prompt,
        config,
        frontier_state=frontier_state,
        repo_root=repo_root,
        session=session,
    )

    drop_ids = {str(x) for x in response.get("drop_ids", []) if str(x).strip()}
    overrides = response.get("confidence_overrides", {})
    if not isinstance(overrides, dict):
        raise AgentExecutionError("deepagents skeptic response has invalid confidence_overrides")

    refined: list[Candidate] = []
    for cand in candidates:
        if cand.candidate_id in drop_ids:
            continue
        override = overrides.get(cand.candidate_id)
        if isinstance(override, (float, int)):
            cand.confidence = max(0.0, min(1.0, float(override)))
        refined.append(cand)

    trace = {
        "engine": "deepagents",
        "dropped": sorted(drop_ids),
        "notes": response.get("notes", []),
        "failed_paths": response.get("failed_paths", []),
    }
    return refined, trace


def schedule_actions_with_deepagents(
    candidates: list[Candidate],
    config: PadvConfig,
    max_candidates: int,
    frontier_state: dict[str, Any] | None = None,
    repo_root: str | None = None,
    session: AgentSession | None = None,
) -> tuple[list[Candidate], dict[str, float], dict[str, Any]]:
    if not candidates:
        return [], {}, {"engine": "deepagents", "reason": "no-candidates"}

    frontier_state = frontier_state or {}
    payload = [
        {
            "candidate_id": c.candidate_id,
            "vuln_class": c.vuln_class,
            "file_path": c.file_path,
            "line": c.line,
            "confidence": c.confidence,
            "provenance": c.provenance,
            "web_path_hints": c.web_path_hints[:20],
            "expected_intercepts": c.expected_intercepts[:20],
        }
        for c in candidates[: min(200, len(candidates))]
    ]
    prompt = (
        "Choose the next validation actions to maximize expected information gain. "
        "You must prioritize novelty against coverage deltas and avoid repeating failed paths. "
        'Return JSON: {"actions":[{"candidate_id":"...","action":"validate","expected_info_gain":0.0,"rationale":"..."}],'
        '"notes":[...]} '
        f"Max candidates to schedule: {max_candidates}. "
        f"Frontier state: {json.dumps(frontier_state, ensure_ascii=True)}. "
        f"Candidates: {json.dumps(payload, ensure_ascii=True)}"
    )
    response = _invoke_deepagent_json(
        prompt,
        config,
        frontier_state=frontier_state,
        repo_root=repo_root,
        session=session,
    )
    raw_actions = response.get("actions")
    if not isinstance(raw_actions, list):
        raise AgentExecutionError("deepagents scheduler response missing actions list")

    by_id = {c.candidate_id: c for c in candidates}
    selected_scores: dict[str, float] = {}
    actions: list[dict[str, Any]] = []
    for item in raw_actions:
        if not isinstance(item, dict):
            continue
        candidate_id = item.get("candidate_id")
        if not isinstance(candidate_id, str) or candidate_id not in by_id:
            continue
        score = item.get("expected_info_gain")
        if isinstance(score, bool) or not isinstance(score, (int, float)):
            continue
        normalized_score = float(score)
        if candidate_id in selected_scores:
            selected_scores[candidate_id] = max(selected_scores[candidate_id], normalized_score)
        else:
            selected_scores[candidate_id] = normalized_score
        actions.append(
            {
                "candidate_id": candidate_id,
                "action": str(item.get("action", "validate")).strip() or "validate",
                "expected_info_gain": normalized_score,
                "rationale": str(item.get("rationale", "")).strip(),
            }
        )

    if not selected_scores:
        raise AgentExecutionError("deepagents scheduler produced no valid candidate actions")

    ranked_ids = sorted(
        selected_scores.keys(),
        key=lambda cid: (-selected_scores[cid], -by_id[cid].confidence, by_id[cid].file_path, by_id[cid].line),
    )
    selected = [by_id[cid] for cid in ranked_ids[:max(1, max_candidates)]]
    limited_ids = {c.candidate_id for c in selected}
    trace = {
        "engine": "deepagents",
        "selected": [c.candidate_id for c in selected],
        "scores": {cid: round(selected_scores[cid], 4) for cid in limited_ids},
        "actions": [a for a in actions if a["candidate_id"] in limited_ids],
        "notes": response.get("notes", []),
    }
    selected_objective_scores = {cid: selected_scores[cid] for cid in limited_ids}
    return selected, selected_objective_scores, trace


def make_validation_plan_with_deepagents(
    candidate: Candidate,
    config: PadvConfig,
    repo_root: str | None = None,
    session: AgentSession | None = None,
) -> tuple[ValidationPlan, dict[str, Any]]:
    default_plan = _default_plan(candidate, config)
    class_hint = (
        "Class-specific objective: "
        "xss_output_boundary => force reflected canary in response body; "
        "debug_output_leak/information_disclosure => provoke verbose output with canary; "
        "broken_access_control/auth_and_session_failures => include auth-required paths and expect anon access probe; "
        "idor_invariant_missing => include id parameter mutations; "
        "csrf_invariant_missing => include state-changing request without csrf token; "
        "session_fixation_invariant => include auth/session transition path."
    )
    prompt = (
        "Create a strict HTTP validation plan for this PHP candidate. "
        "Need exactly 3 positive and at least 1 negative request, deterministic canary injection, and compact intercept set. "
        "Prioritize reachable paths from web_path_hints and exploit-relevant parameters. "
        'Return JSON: {"intercepts":[...], "positive_requests":[...], "negative_requests":[...], '
        '"strategy":"...", "negative_control_strategy":"...", "plan_notes":[...]} '
        f"{class_hint} "
        f"Candidate: {json.dumps(candidate.to_dict(), ensure_ascii=True)} "
        f"Canary parameter: {config.canary.parameter_name}"
    )
    response = _invoke_deepagent_json(
        prompt,
        config,
        repo_root=repo_root,
        session=session,
    )

    intercepts = response.get("intercepts")
    pos = response.get("positive_requests")
    neg = response.get("negative_requests")
    if not isinstance(intercepts, list) or not isinstance(pos, list) or not isinstance(neg, list):
        raise AgentExecutionError("deepagents plan response missing required list fields")

    normalized_intercepts = sorted({str(x) for x in intercepts if str(x).strip()})
    if not normalized_intercepts:
        raise AgentExecutionError("deepagents plan response produced empty intercept set")
    canary = default_plan.canary

    def _inject_canary(req: dict[str, Any], canary_value: str) -> dict[str, Any]:
        enriched = dict(req)
        query = enriched.get("query")
        if isinstance(query, dict):
            q = {str(k): str(v) for k, v in query.items()}
        else:
            q = {}
        q[config.canary.parameter_name] = canary_value
        enriched["query"] = q
        if "method" not in enriched:
            enriched["method"] = "GET"
        return enriched

    positive_requests = [
        _inject_canary(req, canary) for req in pos[:3] if isinstance(req, dict)
    ]
    while len(positive_requests) < 3:
        positive_requests.append(_inject_canary({"method": "GET", "path": "/"}, canary))

    negative_requests = [
        _inject_canary(req, "padv-negative-control") for req in neg[:3] if isinstance(req, dict)
    ]
    if not negative_requests:
        negative_requests = [_inject_canary({"method": "GET", "path": "/"}, "padv-negative-control")]

    plan = ValidationPlan(
        candidate_id=candidate.candidate_id,
        intercepts=normalized_intercepts,
        positive_requests=positive_requests,
        negative_requests=negative_requests,
        canary=canary,
        strategy=str(response.get("strategy", "deepagents-plan")),
        negative_control_strategy=str(response.get("negative_control_strategy", "canary-mismatch")),
        plan_notes=[str(x) for x in response.get("plan_notes", []) if str(x).strip()],
    )
    trace = {
        "engine": "deepagents",
        "candidate_id": candidate.candidate_id,
        "session_thread_id": getattr(session, "thread_id", None),
        "response": response,
    }
    return plan, trace

from __future__ import annotations

import json
import os
import re
import threading
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from padv.analytics.failure_patterns import failure_penalty
from padv.config.schema import PadvConfig
from padv.models import Candidate, FailureAnalysis, ValidationPlan


_JSON_BLOCK_RE = re.compile(r"\{.*\}", re.DOTALL)
_SEMANTIC_SIGNALS = frozenset({"joern", "scip"})


class AgentExecutionError(RuntimeError):
    pass


@dataclass(slots=True)
class AgentSession:
    agent: Any
    thread_id: str
    model: str
    repo_root: str | None


def _default_rank(candidates: list[Candidate], mode: str) -> list[Candidate]:
    def _semantic_signal_count(candidate: Candidate) -> int:
        return len(
            {
                signal.strip().lower()
                for signal in candidate.provenance
                if isinstance(signal, str) and signal.strip().lower() in _SEMANTIC_SIGNALS
            }
        )

    runtime_first = sorted(
        candidates,
        key=lambda c: (
            len(c.expected_intercepts) == 0,
            -_semantic_signal_count(c),
            -c.confidence,
            c.file_path,
            c.line,
        ),
    )
    if mode == "delta":
        return [c for c in runtime_first if "vendor/" not in c.file_path]
    return runtime_first


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
    timeout_seconds = max(1, int(config.llm.timeout_seconds))
    max_attempts = 2
    last_error: Exception | None = None

    for _attempt in range(1, max_attempts + 1):
        def _invoke() -> Any:
            return active_session.agent.invoke(
                {"messages": [{"role": "user", "content": prompt}]},
                config={"configurable": {"thread_id": active_session.thread_id}},
            )

        result_box: dict[str, Any] = {}
        error_box: dict[str, BaseException] = {}

        def _runner() -> None:
            try:
                result_box["value"] = _invoke()
            except BaseException as exc:  # pragma: no cover - defensive for third-party stack
                error_box["error"] = exc

        thread = threading.Thread(target=_runner, daemon=True, name="padv-deepagent-invoke")
        thread.start()
        thread.join(timeout_seconds)

        try:
            if thread.is_alive():
                raise TimeoutError(f"deepagents invocation timed out after {timeout_seconds}s")
            if "error" in error_box:
                raise error_box["error"]
            result = result_box.get("value")
            content = _extract_text(result if isinstance(result, dict) else {})
            parsed = _extract_json(content)
            if parsed is None:
                raise AgentExecutionError("deepagents returned non-JSON response")
            return parsed
        except TimeoutError as exc:
            last_error = AgentExecutionError(str(exc))
        except Exception as exc:
            last_error = AgentExecutionError(f"deepagents invocation failed: {exc}")

    if last_error is not None:
        raise last_error
    raise AgentExecutionError("deepagents invocation failed")


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

    # Keep the planning set bounded deterministically and require complete ordering
    # for that set from the agent response (no silent reordering path).
    planning_limit = min(max(1, int(config.budgets.max_candidates)), 25)
    ranked = ranked[:planning_limit]

    payload = [
        {
            "candidate_id": c.candidate_id,
            "vuln_class": c.vuln_class,
            "file_path": c.file_path,
            "line": c.line,
            "confidence": c.confidence,
            "provenance": c.provenance,
            "expected_intercepts": c.expected_intercepts[:8],
            "web_path_hints": c.web_path_hints[:8],
        }
        for c in ranked
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
    candidate_ids = {c.candidate_id for c in ranked}
    response_ids = set(ordered_ids)
    missing = sorted(candidate_ids - response_ids)
    if missing:
        raise AgentExecutionError(
            f"deepagents ranking response omitted candidate ids: {', '.join(missing[:25])}"
        )

    position = {cid: idx for idx, cid in enumerate(ordered_ids)}
    ranked = sorted(
        ranked,
        key=lambda c: position[c.candidate_id],
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
    penalized: list[str] = []
    for cand in candidates:
        if cand.candidate_id in drop_ids:
            # Keep candidate in the frontier but down-rank aggressively instead of
            # hard-dropping the entire queue.
            cand.confidence = max(0.01, min(1.0, cand.confidence * 0.35))
            penalized.append(cand.candidate_id)
        override = overrides.get(cand.candidate_id)
        if isinstance(override, (float, int)):
            cand.confidence = max(0.0, min(1.0, float(override)))
        refined.append(cand)

    trace = {
        "engine": "deepagents",
        "dropped": [],
        "proposed_drops": sorted(drop_ids),
        "penalized": sorted(penalized),
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
    candidate_id_pattern = re.compile(r"(?:cand|scip)-\d+", re.IGNORECASE)
    trailing_num_pattern = re.compile(r"(?:cand|scip)-0*([0-9]+)$", re.IGNORECASE)
    numeric_suffix_map: dict[int, list[str]] = {}
    for cid in by_id:
        match = trailing_num_pattern.search(cid)
        if not match:
            continue
        num = int(match.group(1))
        numeric_suffix_map.setdefault(num, []).append(cid)

    def _resolve_candidate_id(raw: Any) -> str | None:
        value = str(raw).strip()
        if not value:
            return None
        if value in by_id:
            return value
        for known_id in sorted(by_id.keys(), key=len, reverse=True):
            if known_id in value:
                return known_id
        match = candidate_id_pattern.search(value)
        if match:
            token = match.group(0)
            if token in by_id:
                return token
            num_match = trailing_num_pattern.search(token)
            if num_match:
                num = int(num_match.group(1))
                numeric_ids = numeric_suffix_map.get(num, [])
                if len(numeric_ids) == 1:
                    return numeric_ids[0]
        return None

    def _parse_score(raw: Any) -> float | None:
        if isinstance(raw, bool):
            return None
        if isinstance(raw, (int, float)):
            return float(raw)
        if isinstance(raw, str):
            token = raw.strip()
            if not token:
                return None
            try:
                return float(token)
            except ValueError:
                match = re.search(r"[-+]?\d+(?:\.\d+)?", token)
                if match:
                    try:
                        return float(match.group(0))
                    except ValueError:
                        return None
                return None
        return None

    selected_scores: dict[str, float] = {}
    actions: list[dict[str, Any]] = []
    for item in raw_actions:
        if not isinstance(item, dict):
            continue
        candidate_id = _resolve_candidate_id(item.get("candidate_id"))
        if candidate_id is None:
            continue
        score = _parse_score(item.get("expected_info_gain"))
        if score is None:
            continue
        normalized_score = score
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

    coverage = frontier_state.get("coverage", {}) if isinstance(frontier_state, dict) else {}
    seen_files = {
        str(x).strip()
        for x in coverage.get("files", [])
        if isinstance(x, str) and str(x).strip()
    } if isinstance(coverage, dict) else set()
    seen_classes = {
        str(x).strip()
        for x in coverage.get("classes", [])
        if isinstance(x, str) and str(x).strip()
    } if isinstance(coverage, dict) else set()

    def _semantic_signal_count(candidate: Candidate) -> int:
        return len(
            {
                signal.strip().lower()
                for signal in candidate.provenance
                if isinstance(signal, str) and signal.strip().lower() in _SEMANTIC_SIGNALS
            }
        )

    def _base_priority(candidate: Candidate) -> float:
        score = max(0.0, min(1.0, float(candidate.confidence)))
        if candidate.vuln_class not in seen_classes:
            score += 0.30
        if candidate.file_path not in seen_files:
            score += 0.20
        score += 0.08 * _semantic_signal_count(candidate)
        if candidate.web_path_hints:
            score += 0.04
        if candidate.expected_intercepts:
            score += 0.03
        return score

    combined_scores: dict[str, float] = {}
    for cid, candidate in by_id.items():
        score = _base_priority(candidate)
        if cid in selected_scores:
            score = max(score, 1.0 + selected_scores[cid])
        combined_scores[cid] = score

    ranked_ids = sorted(
        combined_scores.keys(),
        key=lambda cid: (-combined_scores[cid], -by_id[cid].confidence, by_id[cid].file_path, by_id[cid].line),
    )
    limit = max(1, max_candidates)
    selected_ids: list[str] = []
    class_selected: set[str] = set()

    # Pass 1: keep at least one candidate per class when possible.
    for cid in ranked_ids:
        candidate = by_id[cid]
        if candidate.vuln_class in class_selected:
            continue
        selected_ids.append(cid)
        class_selected.add(candidate.vuln_class)
        if len(selected_ids) >= limit:
            break

    # Pass 2: fill remaining slots by priority.
    if len(selected_ids) < limit:
        for cid in ranked_ids:
            if cid in selected_ids:
                continue
            selected_ids.append(cid)
            if len(selected_ids) >= limit:
                break

    selected = [by_id[cid] for cid in selected_ids]
    limited_ids = {c.candidate_id for c in selected}
    trace = {
        "engine": "deepagents",
        "selected": [c.candidate_id for c in selected],
        "scores": {cid: round(combined_scores[cid], 4) for cid in limited_ids},
        "agent_scores": {cid: round(selected_scores[cid], 4) for cid in limited_ids if cid in selected_scores},
        "actions": [a for a in actions if a["candidate_id"] in limited_ids],
        "notes": response.get("notes", []),
        "selection_strategy": "class_quota_priority",
        "agent_action_count": len(actions),
        "reason": "agent-priority" if selected_scores else "deterministic-priority",
    }
    selected_objective_scores = {cid: combined_scores[cid] for cid in limited_ids}
    return selected, selected_objective_scores, trace


def _normalize_validation_plan_response(
    candidate: Candidate,
    response: dict[str, Any],
    config: PadvConfig,
) -> ValidationPlan:
    intercepts = response.get("intercepts")
    pos = response.get("positive_requests")
    neg = response.get("negative_requests")
    if not isinstance(intercepts, list) or not isinstance(pos, list) or not isinstance(neg, list):
        raise AgentExecutionError("deepagents plan response missing required list fields")

    normalized_intercepts = sorted({str(x) for x in intercepts if str(x).strip()})
    if not normalized_intercepts:
        normalized_intercepts = sorted(
            {
                str(x)
                for x in (
                    candidate.expected_intercepts
                    or ([candidate.sink] if candidate.sink else [])
                )
                if str(x).strip()
            }
        )
    if not normalized_intercepts:
        normalized_intercepts = ["unknown"]
    canary = f"padv-{candidate.candidate_id}-{uuid.uuid4().hex[:10]}"

    allowed_methods = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}

    def _normalize_request(req: dict[str, Any], canary_value: str) -> dict[str, Any]:
        method_raw = req.get("method")
        method = str(method_raw).strip().upper() if method_raw is not None else "GET"
        if method not in allowed_methods:
            method = "GET"

        path_raw = req.get("path")
        path = str(path_raw).strip() if path_raw is not None else ""
        if not path:
            path = "/"
        if not path.startswith("/"):
            path = "/" + path

        query = req.get("query")
        if isinstance(query, dict):
            q = {str(k): str(v) for k, v in query.items()}
        else:
            q = {}
        q[config.canary.parameter_name] = canary_value

        body = req.get("body")
        normalized: dict[str, Any] = {"method": method, "path": path, "query": q}
        if body is not None:
            if isinstance(body, dict):
                normalized["body"] = {str(k): str(v) for k, v in body.items()}
            elif isinstance(body, str):
                parsed: object | None = None
                try:
                    parsed = json.loads(body)
                except json.JSONDecodeError:
                    parsed = None
                if isinstance(parsed, dict):
                    normalized["body"] = {str(k): str(v) for k, v in parsed.items()}
                else:
                    normalized["body"] = {"value": body}
            else:
                normalized["body"] = {"value": str(body)}
        return normalized

    positive_requests = [_normalize_request(req, canary) for req in pos if isinstance(req, dict)]
    if not positive_requests:
        positive_requests = [{"method": "GET", "path": "/", "query": {config.canary.parameter_name: canary}}]
    while len(positive_requests) < 3:
        clone = dict(positive_requests[-1])
        clone_query = dict(clone.get("query", {}))
        clone_query[f"{config.canary.parameter_name}_step"] = str(len(positive_requests) + 1)
        clone["query"] = clone_query
        positive_requests.append(clone)
    positive_requests = positive_requests[:3]

    negative_requests = [_normalize_request(req, "padv-negative-control") for req in neg if isinstance(req, dict)]
    if not negative_requests:
        negative_requests = [
            {
                "method": "GET",
                "path": "/",
                "query": {config.canary.parameter_name: "padv-negative-control"},
            }
        ]

    return ValidationPlan(
        candidate_id=candidate.candidate_id,
        intercepts=normalized_intercepts,
        positive_requests=positive_requests,
        negative_requests=negative_requests,
        canary=canary,
        strategy=str(response.get("strategy", "deepagents-plan")),
        negative_control_strategy=str(response.get("negative_control_strategy", "canary-mismatch")),
        plan_notes=[str(x) for x in response.get("plan_notes", []) if str(x).strip()],
    )


def make_validation_plan_with_deepagents(
    candidate: Candidate,
    config: PadvConfig,
    repo_root: str | None = None,
    session: AgentSession | None = None,
) -> tuple[ValidationPlan, dict[str, Any]]:
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
    plan = _normalize_validation_plan_response(candidate, response, config)
    trace = {
        "engine": "deepagents",
        "candidate_id": candidate.candidate_id,
        "session_thread_id": getattr(session, "thread_id", None),
        "response": response,
    }
    return plan, trace


def make_validation_plans_with_deepagents(
    candidates: list[Candidate],
    config: PadvConfig,
    *,
    repo_root: str | None = None,
    session: AgentSession | None = None,
    batch_size: int = 4,
) -> tuple[dict[str, ValidationPlan], dict[str, Any]]:
    if not candidates:
        return {}, {"engine": "deepagents", "reason": "no-candidates", "batches": []}

    class_hint = (
        "Class-specific objective: "
        "xss_output_boundary => force reflected canary in response body; "
        "debug_output_leak/information_disclosure => provoke verbose output with canary; "
        "broken_access_control/auth_and_session_failures => include auth-required paths and expect anon access probe; "
        "idor_invariant_missing => include id parameter mutations; "
        "csrf_invariant_missing => include state-changing request without csrf token; "
        "session_fixation_invariant => include auth/session transition path."
    )
    plans: dict[str, ValidationPlan] = {}
    batches_trace: list[dict[str, Any]] = []
    step = max(1, int(batch_size))

    for index in range(0, len(candidates), step):
        batch = candidates[index : index + step]
        payload = [cand.to_dict() for cand in batch]
        prompt = (
            "Create strict HTTP validation plans for each listed PHP web-security candidate. "
            "Each plan needs exactly 3 positive and at least 1 negative request, deterministic canary injection, "
            "and compact intercept set. "
            "Prioritize reachable paths from web_path_hints and exploit-relevant parameters. "
            'Return JSON: {"plans":[{"candidate_id":"...","intercepts":[...],"positive_requests":[...],'
            '"negative_requests":[...],"strategy":"...","negative_control_strategy":"...","plan_notes":[...]}],'
            '"notes":[...]}. '
            f"{class_hint} "
            f"Canary parameter: {config.canary.parameter_name}. "
            f"Candidates: {json.dumps(payload, ensure_ascii=True)}"
        )
        response = _invoke_deepagent_json(
            prompt,
            config,
            repo_root=repo_root,
            session=session,
        )
        raw_plans = response.get("plans")
        if not isinstance(raw_plans, list):
            raise AgentExecutionError("deepagents batch plan response missing plans list")

        by_id: dict[str, dict[str, Any]] = {}
        for item in raw_plans:
            if not isinstance(item, dict):
                continue
            cid = item.get("candidate_id")
            if isinstance(cid, str) and cid.strip():
                by_id[cid.strip()] = item

        missing_ids: list[str] = []
        for candidate in batch:
            raw = by_id.get(candidate.candidate_id)
            if isinstance(raw, dict):
                plans[candidate.candidate_id] = _normalize_validation_plan_response(candidate, raw, config)
                continue
            missing_ids.append(candidate.candidate_id)
        if missing_ids:
            raise AgentExecutionError(
                f"deepagents batch planner omitted candidate ids: {', '.join(sorted(missing_ids))}"
            )

        batches_trace.append(
            {
                "batch_index": (index // step) + 1,
                "batch_size": len(batch),
                "returned_plan_ids": sorted(by_id.keys()),
                "missing_ids": missing_ids,
                "notes": response.get("notes", []),
            }
        )

    trace = {
        "engine": "deepagents",
        "batch_size": step,
        "planned": len(plans),
        "batches": batches_trace,
    }
    return plans, trace

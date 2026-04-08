from __future__ import annotations

import copy
import hashlib
import inspect
import json
import os
import re
import shlex
import sqlite3
import subprocess
import threading
import traceback
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from padv import __version__ as PADV_VERSION
from padv.agents.checkpoints import FileBackedMemorySaver
from padv.analytics.failure_patterns import failure_penalty
from padv.config.schema import PadvConfig
from padv.models import (
    CanaryMatchRule,
    Candidate,
    ExperimentAttempt,
    FailureAnalysis,
    Hypothesis,
    HttpExpectations,
    HttpStep,
    NegativeControl,
    ObjectiveScore,
    OracleSpec,
    PlanBudget,
    Refutation,
    ResearchFinding,
    ResearchTask,
    ValidationPlan,
    WitnessBundle,
)
from padv.validation.contracts import apply_validation_profile, profile_for_vuln_class
from padv.validation.preconditions import (
    GatePreconditions,
    ensure_no_legacy_preconditions,
    merge_gate_preconditions,
    migrate_legacy_preconditions,
)

try:
    from langchain.agents.middleware.types import AgentMiddleware  # type: ignore[import-not-found]
except Exception:  # pragma: no cover - optional at import time
    AgentMiddleware = object  # type: ignore[assignment,misc]


_JSON_BLOCK_RE = re.compile(r"\{.*\}", re.DOTALL)
_JSON_FENCE_RE = re.compile(r"```(?:json)?\s*(\{[^\}]*\})\s*```", re.DOTALL | re.IGNORECASE)
_SEMANTIC_SIGNALS = frozenset({"joern", "scip"})
_SKEPTIC_FOCUS = "exploit-invalidating objections only"
_TRIAGE_FIELDS = (
    "reproducibility_gap",
    "legitimacy_gap",
    "impact_gap",
    "missing_witness",
)
_PLAN_CANARY_PLACEHOLDER = "__PADV_CANARY__"


class AgentExecutionError(RuntimeError):
    pass


class AgentSoftYield(RuntimeError):
    def __init__(
        self,
        message: str,
        *,
        role: str,
        category: str,
        turn: int,
        handoff_ref: str,
        progress_ref: str = "",
        response_ref: str = "",
        last_response: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.role = str(role)
        self.category = str(category)
        self.turn = int(turn)
        self.handoff_ref = str(handoff_ref)
        self.progress_ref = str(progress_ref)
        self.response_ref = str(response_ref)
        self.last_response = dict(last_response or {})


_INFLIGHT_HANDOFFS: dict[str, dict[str, Any]] = {}
_INFLIGHT_HANDOFFS_LOCK = threading.Lock()
_HANDOFF_CACHE_TTL_SECONDS = 3600
_HANDOFF_CACHE_PROMPT_VERSION = "2026-04-06"
_HANDOFF_CODE_SIGNATURE_CACHE: tuple[tuple[tuple[str, int, int], ...], str] | None = None
_HANDOFF_CODE_SIGNATURE_LOCK = threading.Lock()
_RUN_SCOPED_HANDOFF_CATEGORIES = frozenset(
    {
        "orient",
        "select_objective",
        "continue_or_stop",
        "hypothesis_synthesis",
        "skeptic_challenge",
        "experiment_plan",
    }
)


@dataclass(slots=True)
class AgentSession:
    agent: Any
    thread_id: str
    model: str
    repo_root: str | None
    checkpoint_dir: str | None = None
    role: str = "agent"
    invoke_lock: threading.Lock = field(default_factory=threading.Lock)


@dataclass(slots=True)
class AgentRuntime:
    root: AgentSession
    subagents: dict[str, AgentSession]
    shared_context: dict[str, Any]
    checkpoint_dir: str
    workspace_dir: str
    model: str
    repo_root: str | None
    store: Any | None = None
    prompts: dict[str, str] = field(default_factory=dict)


class TaskDelegationTraceMiddleware(AgentMiddleware):
    def __init__(self, *, shared_context: dict[str, Any], checkpoint_dir: str) -> None:
        self._shared_context = shared_context
        self._checkpoint_dir = checkpoint_dir

    @property
    def name(self) -> str:
        return self.__class__.__name__

    def wrap_tool_call(self, request: Any, handler: Any) -> Any:
        result = handler(request)
        tool_call = getattr(request, "tool_call", {}) or {}
        if str(tool_call.get("name", "")).strip() != "task":
            return result

        args = tool_call.get("args", {})
        if not isinstance(args, dict):
            args = {}
        payload = {
            "role": "root",
            "tool": "task",
            "tool_call_id": str(tool_call.get("id", "")),
            "subagent_type": str(args.get("subagent_type", "")),
            "description": str(args.get("description", ""))[:2000],
            "prompt": str(args.get("prompt", ""))[:4000],
            "result_excerpt": str(getattr(result, "content", ""))[:2000],
        }
        self._record(payload)
        return result

    def _record(self, payload: dict[str, Any]) -> None:
        artifact_id = uuid.uuid4().hex[:12]
        path = _workspace_artifact_path(
            self._checkpoint_dir,
            role="root",
            category="delegations",
            artifact_id=artifact_id,
        )
        path.write_text(json.dumps(payload, indent=2, ensure_ascii=True), encoding="utf-8")
        relative = str(path.relative_to(_workspace_root(self._checkpoint_dir)))

        _append_workspace_index_ref(self._shared_context, role="root", category="delegations", relative=relative)
        _append_shared_context_list_item(self._shared_context, key="delegations", payload={"ref": relative, **payload})
        subagent_type = str(payload.get("subagent_type", "")).strip() or "unknown"
        _emit_shared_progress(
            self._shared_context,
            role="root",
            status="delegated",
            detail=f"task -> {subagent_type}",
            artifact_ref=relative,
            tool="task",
            subagent_type=subagent_type,
        )


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


def _extract_text_from_message(msg: Any) -> str:
    """Return the first non-empty text from a single message object."""
    content = getattr(msg, "content", None)
    if isinstance(content, str) and content.strip():
        return content
    if not isinstance(msg, dict):
        return ""
    raw = msg.get("content")
    if isinstance(raw, str) and raw.strip():
        return raw
    if isinstance(raw, list):
        chunks = [part.get("text", "") for part in raw if isinstance(part, dict)]
        joined = "\n".join(x for x in chunks if x)
        if joined.strip():
            return joined
    return ""


def _extract_text(result: dict[str, Any]) -> str:
    messages = result.get("messages")
    if not isinstance(messages, list):
        return ""
    for msg in reversed(messages):
        text = _extract_text_from_message(msg)
        if text:
            return text
    return ""


def _count_trailing_backslashes(payload: str, pos: int) -> int:
    """Count consecutive backslashes immediately before *pos* in *payload*."""
    count = 0
    j = pos - 1
    while j >= 0 and payload[j] == "\\":
        count += 1
        j -= 1
    return count


def _repair_json_escape_at(payload: str, i: int, out: list[str]) -> int:
    """Handle a backslash-escape inside a JSON string, returning the new index."""
    nxt = payload[i + 1]
    if nxt in '"\\/bfnrtu':
        out.append("\\")
        out.append(nxt)
    elif nxt == "'":
        out.append("'")
    else:
        out.append("\\\\")
        out.append(nxt)
    return i + 2


def _repair_json_like_string(payload: str) -> str:
    """Fix non-standard escape sequences in a JSON-like string from LLM output."""
    out: list[str] = []
    in_string = False
    i = 0
    while i < len(payload):
        char = payload[i]
        if char == '"':
            if _count_trailing_backslashes(payload, i) % 2 == 0:
                in_string = not in_string
            out.append(char)
            i += 1
            continue
        if in_string and char == "\\" and i + 1 < len(payload):
            i = _repair_json_escape_at(payload, i, out)
            continue
        out.append(char)
        i += 1
    return "".join(out)


def _try_json_loads_as_dict(payload: str) -> dict[str, Any] | None:
    """Try to parse *payload* as JSON; return the dict or ``None``."""
    try:
        data = json.loads(payload)
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


def _try_raw_decode_dict(decoder: json.JSONDecoder, source: str) -> dict[str, Any] | None:
    """Attempt ``raw_decode`` on *source* and return the dict or ``None``."""
    try:
        data, _end = decoder.raw_decode(source)
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


def _attempt_json_parse(candidate: str) -> dict[str, Any] | None:
    """Try multiple strategies to extract a JSON dict from *candidate*."""
    payload = str(candidate or "").strip()
    if not payload:
        return None

    result = _try_json_loads_as_dict(payload)
    if result is not None:
        return result

    # LLMs often emit JSON-looking payloads with markdown fences and
    # non-JSON escapes like \' inside otherwise valid JSON strings.
    repaired = _repair_json_like_string(payload)
    if repaired != payload:
        result = _try_json_loads_as_dict(repaired)
        if result is not None:
            return result

    return _scan_for_json_object(payload, repaired)


def _scan_for_json_object(payload: str, repaired: str) -> dict[str, Any] | None:
    """Walk *payload* looking for the first ``{`` that decodes to a dict."""
    decoder = json.JSONDecoder()
    sources_differ = repaired != payload
    for idx, char in enumerate(payload):
        if char != "{":
            continue
        result = _try_raw_decode_dict(decoder, payload[idx:])
        if result is not None:
            return result
        if sources_differ:
            result = _try_raw_decode_dict(decoder, repaired[idx:])
            if result is not None:
                return result
    return None


def _extract_json(text: str) -> dict[str, Any] | None:
    body = str(text or "").strip()
    if not body:
        return None
    for candidate in [body, *[match.group(1) for match in _JSON_FENCE_RE.finditer(body)]]:
        data = _attempt_json_parse(candidate)
        if isinstance(data, dict):
            return data
    return None


def _normalize_triage_entry(raw: Any) -> dict[str, str]:
    if not isinstance(raw, dict):
        return dict.fromkeys(_TRIAGE_FIELDS, "")
    normalized: dict[str, str] = {}
    for triage_field in _TRIAGE_FIELDS:
        value = raw.get(triage_field, "")
        text = str(value).strip() if value is not None else ""
        normalized[triage_field] = text
    return normalized


def _normalize_triage_from_dict(raw: dict[str, Any], candidate_ids: set[str]) -> dict[str, dict[str, str]]:
    out: dict[str, dict[str, str]] = {}
    for candidate_id, entry in raw.items():
        cid = str(candidate_id).strip()
        if not cid or cid not in candidate_ids:
            continue
        out[cid] = _normalize_triage_entry(entry)
    return out


def _normalize_triage_from_list(raw: list[Any], candidate_ids: set[str]) -> dict[str, dict[str, str]]:
    out: dict[str, dict[str, str]] = {}
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        cid = str(entry.get("candidate_id", "")).strip()
        if not cid or cid not in candidate_ids:
            continue
        out[cid] = _normalize_triage_entry(entry)
    return out


def _normalize_triage_by_candidate(raw: Any, candidate_ids: set[str]) -> dict[str, dict[str, str]]:
    if isinstance(raw, dict):
        return _normalize_triage_from_dict(raw, candidate_ids)
    if isinstance(raw, list):
        return _normalize_triage_from_list(raw, candidate_ids)
    return {}


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


def _anthropic_prompt_caching_middleware(config: PadvConfig) -> Any | None:
    if str(config.llm.provider).strip().lower() != "anthropic":
        return None
    middleware_cls = None
    try:
        from langchain_anthropic import AnthropicPromptCachingMiddleware  # type: ignore[import-not-found]

        middleware_cls = AnthropicPromptCachingMiddleware
    except Exception:
        try:
            from langchain_anthropic.middleware import AnthropicPromptCachingMiddleware  # type: ignore[import-not-found]

            middleware_cls = AnthropicPromptCachingMiddleware
        except Exception:
            return None
    try:
        return middleware_cls()
    except Exception:
        return None


def _checkpoint_path(checkpoint_dir: str | Path, role: str, thread_id: str) -> Path:
    base = Path(checkpoint_dir)
    base.mkdir(parents=True, exist_ok=True)
    return base / role / f"{thread_id}.pkl"


def _workspace_root(checkpoint_dir: str | Path) -> Path:
    root = Path(checkpoint_dir) / "workspace"
    root.mkdir(parents=True, exist_ok=True)
    return root


def _workspace_artifact_path(
    checkpoint_dir: str | Path,
    *,
    role: str,
    category: str,
    artifact_id: str,
) -> Path:
    root = _workspace_root(checkpoint_dir)
    path = root / role / category / f"{artifact_id}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def _persist_raw_agent_output(session: AgentSession, *, content: str, kind: str) -> str | None:
    checkpoint_dir = str(session.checkpoint_dir or "").strip()
    if not checkpoint_dir:
        return None
    path = _workspace_artifact_path(
        checkpoint_dir,
        role=session.role,
        category="raw_outputs",
        artifact_id=uuid.uuid4().hex[:12],
    )
    payload = {
        "role": session.role,
        "thread_id": session.thread_id,
        "kind": kind,
        "captured_at": datetime.now(tz=timezone.utc).isoformat(),
        "content": str(content or "")[:24000],
    }
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=True), encoding="utf-8")
    return str(path.relative_to(_workspace_root(checkpoint_dir)))


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
    checkpointer = FileBackedMemorySaver(_checkpoint_path(Path(".padv") / "langgraph", "legacy", thread_id))
    middleware: list[Any] = []
    try:
        agent = create_deep_agent(
            model=model,
            tools=tools,
            system_prompt=system_prompt,
            checkpointer=checkpointer,
            middleware=middleware,
        )
    except Exception as exc:
        raise AgentExecutionError(f"deepagents agent creation failed: {exc}") from exc

    if isinstance(frontier_state, dict):
        frontier_state["agent_thread_id"] = thread_id
    return AgentSession(agent=agent, thread_id=thread_id, model=model, repo_root=repo_root)


def _run_repo_command(repo_root: str | None, command: str) -> str:
    if not repo_root:
        return "repo root unavailable"
    try:
        proc = subprocess.run(
            shlex.split(command),
            cwd=repo_root,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except Exception as exc:
        return f"command failed: {exc}"
    output = (proc.stdout or proc.stderr or "").strip()
    return output[:12000]


def _parse_json_list(raw: str | None) -> list[str]:
    text = str(raw or "").strip()
    if not text:
        return []
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return [text]
    if isinstance(parsed, list):
        return [str(item).strip() for item in parsed if str(item).strip()]
    return [str(parsed).strip()] if str(parsed).strip() else []


def _workspace_index_refs(shared_context: dict[str, Any], *, role: str, category: str) -> list[str]:
    workspace_index = _shared_context_snapshot(shared_context, "workspace_index", {})
    if not isinstance(workspace_index, dict):
        return []
    role_index = workspace_index.get(role, {})
    if not isinstance(role_index, dict):
        return []
    refs = role_index.get(category, [])
    if not isinstance(refs, list):
        return []
    return [str(item) for item in refs if isinstance(item, str)]


def _tool_usage_entries(shared_context: dict[str, Any], *, role: str) -> list[dict[str, Any]]:
    tool_usage = _shared_context_snapshot(shared_context, "tool_usage", {})
    if not isinstance(tool_usage, dict):
        return []
    entries = tool_usage.get(role, [])
    if not isinstance(entries, list):
        return []
    return [item for item in entries if isinstance(item, dict)]


def _shared_context_lock(shared_context: dict[str, Any]) -> threading.RLock:
    lock = shared_context.get("__lock__")
    if lock is not None:
        return lock
    new_lock: threading.RLock = threading.RLock()
    shared_context["__lock__"] = new_lock
    return new_lock


def _now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def _progress_callback(shared_context: dict[str, Any]) -> Any:
    callback = shared_context.get("__progress_callback__")
    return callback if callable(callback) else None


def _active_progress_step(shared_context: dict[str, Any], *, role: str) -> str:
    active = shared_context.get("__active_categories__")
    if isinstance(active, dict):
        category = str(active.get(role, "")).strip()
        if category:
            return category
    return f"{role}_agent"


def _set_active_progress_category(shared_context: dict[str, Any], *, role: str, category: str | None) -> str | None:
    with _shared_context_lock(shared_context):
        active = shared_context.setdefault("__active_categories__", {})
        if not isinstance(active, dict):
            return None
        previous_raw = active.get(role)
        previous = str(previous_raw).strip() if isinstance(previous_raw, str) and str(previous_raw).strip() else None
        if category:
            active[role] = str(category).strip()
        else:
            active.pop(role, None)
        return previous


def _emit_shared_progress(
    shared_context: dict[str, Any],
    *,
    role: str,
    status: str,
    detail: str | None = None,
    step: str | None = None,
    **extra: Any,
) -> None:
    callback = _progress_callback(shared_context)
    if callback is None:
        return
    payload: dict[str, Any] = {
        "ts": _now_iso(),
        "step": step or _active_progress_step(shared_context, role=role),
        "status": status,
        "role": role,
    }
    if detail:
        payload["detail"] = detail
    for key, value in extra.items():
        if value is None:
            continue
        payload[key] = value
    try:
        callback(payload)
    except Exception:
        return


def _handoff_cache_db_path(checkpoint_dir: str | None) -> Path | None:
    path = str(checkpoint_dir or "").strip()
    if not path:
        return None
    root = Path(path)
    if root.name.startswith(("analyze-", "run-", "validate-")) and root.parent:
        root = root.parent
    root.mkdir(parents=True, exist_ok=True)
    return root / "handoff_cache.sqlite"


def _ensure_handoff_cache_db(db_path: Path) -> None:
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS handoff_exact_cache (
                cache_key TEXT PRIMARY KEY,
                response_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.commit()


_CACHE_KEY_SKIP_KEYS = frozenset({"agent_threads", "__lock__", "thread_id", "updated_at", "created_at"})


def _normalize_cache_value(value: Any) -> Any:
    """Recursively strip volatile keys from a value for stable cache hashing."""
    if isinstance(value, dict):
        return {
            key: _normalize_cache_value(item)
            for key, item in value.items()
            if key not in _CACHE_KEY_SKIP_KEYS
        }
    if isinstance(value, list):
        return [_normalize_cache_value(item) for item in value]
    return value


def _handoff_cache_key(
    session: AgentSession,
    *,
    config: PadvConfig,
    category: str,
    envelope: dict[str, Any],
    response_contract: str,
    workspace_role: str,
    delegated_role: str | None,
) -> str:
    payload = {
        "role": session.role,
        "model": session.model,
        "repo_root": str(session.repo_root or ""),
        "category": category,
        "workspace_role": workspace_role,
        "delegated_role": delegated_role or "",
        "response_contract": response_contract,
        "config_signature": _handoff_config_signature(config),
        "code_signature": _handoff_code_signature(),
        "prompt_version": _handoff_prompt_version(category),
        "run_scope": _handoff_cache_run_scope(session, category),
        "envelope": _normalize_cache_value(envelope),
    }
    serialized = json.dumps(payload, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def _handoff_config_signature(config: PadvConfig) -> str:
    payload = asdict(config)
    serialized = json.dumps(payload, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()[:16]


def _handoff_code_signature_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _handoff_code_signature() -> str:
    global _HANDOFF_CODE_SIGNATURE_CACHE
    root = _handoff_code_signature_root()
    paths = [root / "padv.toml", *sorted((root / "padv").rglob("*.py"))]
    snapshot: list[tuple[str, int, int]] = []
    for path in paths:
        if not path.exists():
            continue
        stat = path.stat()
        snapshot.append((str(path.relative_to(root)), int(stat.st_mtime_ns), int(stat.st_size)))
    snapshot_key = tuple(snapshot)
    with _HANDOFF_CODE_SIGNATURE_LOCK:
        cached = _HANDOFF_CODE_SIGNATURE_CACHE
        if cached is not None and cached[0] == snapshot_key:
            return cached[1]
    hasher = hashlib.sha256()
    hasher.update(PADV_VERSION.encode("utf-8"))
    hasher.update(b"\0")
    for relative_path, _mtime_ns, _size in snapshot_key:
        hasher.update(relative_path.encode("utf-8"))
        hasher.update(b"\0")
        hasher.update((root / relative_path).read_bytes())
        hasher.update(b"\0")
    signature = hasher.hexdigest()[:16]
    with _HANDOFF_CODE_SIGNATURE_LOCK:
        _HANDOFF_CODE_SIGNATURE_CACHE = (snapshot_key, signature)
    return signature


_HANDOFF_CACHE_PROMPT_VERSIONS = {
    "proposer": "2026-04-06-proposer",
    "skeptic": "2026-04-06-skeptic",
    "auth": "2026-04-06-auth",
    "planner": "2026-04-06-planner",
}

def _handoff_prompt_version(category: str) -> str:
    for prefix, version in _HANDOFF_CACHE_PROMPT_VERSIONS.items():
        if prefix in category:
            return version
    return _HANDOFF_CACHE_PROMPT_VERSIONS["planner"]


def _handoff_cache_run_scope(session: AgentSession, category: str) -> str:
    if category not in _RUN_SCOPED_HANDOFF_CATEGORIES:
        return ""
    checkpoint_dir = str(session.checkpoint_dir or "").strip()
    if not checkpoint_dir:
        return ""
    return Path(checkpoint_dir).name


def _load_handoff_cache(checkpoint_dir: str | None, cache_key: str) -> dict[str, Any] | None:
    db_path = _handoff_cache_db_path(checkpoint_dir)
    if db_path is None or not db_path.exists():
        return None
    _ensure_handoff_cache_db(db_path)
    with sqlite3.connect(db_path) as conn:
        row = conn.execute(
            "SELECT response_json, created_at FROM handoff_exact_cache WHERE cache_key = ?",
            (cache_key,),
        ).fetchone()
        if row is None:
            return None
        created_at = _parse_cache_created_at(row[1])
        if created_at is None or _cache_entry_expired(created_at):
            conn.execute("DELETE FROM handoff_exact_cache WHERE cache_key = ?", (cache_key,))
            conn.commit()
            return None
    try:
        payload = json.loads(str(row[0]))
    except Exception:
        return None
    return payload if isinstance(payload, dict) else None


def _parse_cache_created_at(raw: Any) -> datetime | None:
    if not isinstance(raw, str) or not raw.strip():
        return None
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed


def _cache_entry_expired(created_at: datetime) -> bool:
    age = (datetime.now(tz=timezone.utc) - created_at).total_seconds()
    return age > float(_HANDOFF_CACHE_TTL_SECONDS)


def _handoff_cache_enabled(config: PadvConfig) -> bool:
    return not bool(getattr(config.agent, "deterministic_mode", False))


def _store_handoff_cache(checkpoint_dir: str | None, cache_key: str, payload: dict[str, Any]) -> None:
    db_path = _handoff_cache_db_path(checkpoint_dir)
    if db_path is None:
        return
    _ensure_handoff_cache_db(db_path)
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO handoff_exact_cache (cache_key, response_json, created_at)
            VALUES (?, ?, ?)
            ON CONFLICT(cache_key) DO UPDATE SET
                response_json = excluded.response_json,
                created_at = excluded.created_at
            """,
            (
                cache_key,
                json.dumps(payload, ensure_ascii=True, sort_keys=True),
                datetime.now(tz=timezone.utc).isoformat(),
            ),
        )
        conn.commit()


def _acquire_inflight_handoff(cache_key: str) -> tuple[dict[str, Any], bool]:
    with _INFLIGHT_HANDOFFS_LOCK:
        entry = _INFLIGHT_HANDOFFS.get(cache_key)
        if entry is not None:
            return entry, False
        entry = {"event": threading.Event(), "result": None, "error": None}
        _INFLIGHT_HANDOFFS[cache_key] = entry
        return entry, True


def _resolve_inflight_handoff(cache_key: str, *, result: dict[str, Any] | None = None, error: Exception | None = None) -> None:
    with _INFLIGHT_HANDOFFS_LOCK:
        entry = _INFLIGHT_HANDOFFS.pop(cache_key, None)
    if entry is None:
        return
    entry["result"] = result
    entry["error"] = error
    entry["event"].set()


def _shared_context_snapshot(shared_context: dict[str, Any], key: str, default: Any) -> Any:
    with _shared_context_lock(shared_context):
        value = shared_context.get(key, default)
        try:
            return copy.deepcopy(value)
        except Exception:
            return value


def _clone_shared_context(shared_context: dict[str, Any]) -> dict[str, Any]:
    with _shared_context_lock(shared_context):
        cloned: dict[str, Any] = {}
        for key, value in shared_context.items():
            if key == "__lock__":
                continue
            try:
                cloned[key] = copy.deepcopy(value)
            except Exception:
                cloned[key] = value
    cloned["__lock__"] = threading.RLock()
    return cloned


def _append_workspace_index_ref(shared_context: dict[str, Any], *, role: str, category: str, relative: str) -> None:
    with _shared_context_lock(shared_context):
        workspace_index = shared_context.setdefault("workspace_index", {})
        if not isinstance(workspace_index, dict):
            return
        workspace_index.setdefault(role, {})
        role_index = workspace_index.get(role)
        if not isinstance(role_index, dict):
            return
        role_index.setdefault(category, [])
        refs = role_index.get(category)
        if isinstance(refs, list):
            refs.append(relative)


def _append_shared_context_entry(shared_context: dict[str, Any], *, key: str, role: str, payload: dict[str, Any]) -> None:
    with _shared_context_lock(shared_context):
        mapping = shared_context.setdefault(key, {})
        if not isinstance(mapping, dict):
            return
        mapping.setdefault(role, [])
        entries = mapping.get(role)
        if isinstance(entries, list):
            entries.append(payload)


def _append_shared_context_list_item(shared_context: dict[str, Any], *, key: str, payload: dict[str, Any]) -> None:
    with _shared_context_lock(shared_context):
        entries = shared_context.setdefault(key, [])
        if isinstance(entries, list):
            entries.append(payload)


def _research_context_delta(shared_context: dict[str, Any], *, role: str) -> dict[str, Any]:
    workspace_index = _shared_context_snapshot(shared_context, "workspace_index", {})
    tool_usage = _shared_context_snapshot(shared_context, "tool_usage", {})
    worklog = _shared_context_snapshot(shared_context, "worklog", {})
    workspace_role = workspace_index.get(role, {}) if isinstance(workspace_index, dict) else {}
    tool_role = tool_usage.get(role, []) if isinstance(tool_usage, dict) else []
    worklog_role = worklog.get(role, []) if isinstance(worklog, dict) else []
    return {
        "workspace_index": {
            role: workspace_role,
        },
        "tool_usage": {
            role: tool_role,
        },
        "worklog": {
            role: worklog_role,
        },
    }


def _merge_workspace_index_category_refs(target_refs: list[str], refs: list[Any]) -> None:
    """Append unique non-empty string refs from *refs* into *target_refs*."""
    for ref in refs:
        text = str(ref).strip()
        if text and text not in target_refs:
            target_refs.append(text)


def _merge_workspace_index_role(role_index: dict[str, Any], categories: dict[str, Any]) -> None:
    """Merge category-level ref lists from *categories* into *role_index*."""
    for category, refs in categories.items():
        if not isinstance(refs, list):
            continue
        role_index.setdefault(category, [])
        target_refs = role_index.get(category)
        if not isinstance(target_refs, list):
            continue
        _merge_workspace_index_category_refs(target_refs, refs)


def _merge_workspace_index_delta(context: dict[str, Any], workspace_index_delta: dict[str, Any]) -> None:
    """Merge *workspace_index_delta* into *context*'s workspace_index."""
    workspace_index = context.setdefault("workspace_index", {})
    if not isinstance(workspace_index, dict):
        return
    for role, categories in workspace_index_delta.items():
        if not isinstance(categories, dict):
            continue
        workspace_index.setdefault(role, {})
        role_index = workspace_index.get(role)
        if not isinstance(role_index, dict):
            continue
        _merge_workspace_index_role(role_index, categories)


def _merge_keyed_entries_delta(context: dict[str, Any], key: str, key_delta: dict[str, Any]) -> None:
    """Merge tool_usage or worklog delta entries into *context[key]*, deduplicating by ref."""
    target = context.setdefault(key, {})
    if not isinstance(target, dict):
        return
    for role, entries in key_delta.items():
        if not isinstance(entries, list):
            continue
        target.setdefault(role, [])
        dest = target.get(role)
        if not isinstance(dest, list):
            continue
        _append_deduplicated_entries(dest, entries)


def _append_deduplicated_entries(dest: list[dict[str, Any]], entries: list[Any]) -> None:
    """Append entries to *dest*, skipping duplicates by ref."""
    seen_refs: set[str] = {
        str(item.get("ref", "")).strip()
        for item in dest
        if isinstance(item, dict)
    }
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        ref = str(entry.get("ref", "")).strip()
        if ref and ref in seen_refs:
            continue
        dest.append(entry)
        if ref:
            seen_refs.add(ref)


def merge_agent_runtime_context_delta(runtime: AgentRuntime, delta: dict[str, Any]) -> None:
    if not isinstance(delta, dict) or not delta:
        return
    with _shared_context_lock(runtime.shared_context):
        workspace_index_delta = delta.get("workspace_index", {})
        if isinstance(workspace_index_delta, dict):
            _merge_workspace_index_delta(runtime.shared_context, workspace_index_delta)

        for key in ("tool_usage", "worklog"):
            key_delta = delta.get(key, {})
            if not isinstance(key_delta, dict):
                continue
            _merge_keyed_entries_delta(runtime.shared_context, key, key_delta)


def clone_runtime_for_parallel_role(runtime: AgentRuntime, config: PadvConfig, *, role: str) -> AgentRuntime:
    prompts = getattr(runtime, "prompts", {})
    if not isinstance(prompts, dict) or role not in prompts:
        return runtime
    shared_context = _clone_shared_context(runtime.shared_context)
    shared_context["__delta__"] = {}
    session = _create_agent_session(
        config,
        role=role,
        system_prompt=prompts[role],
        repo_root=runtime.repo_root,
        shared_context=shared_context,
        frontier_state=None,
        checkpoint_dir=runtime.checkpoint_dir,
        store=runtime.store,
        backend=_build_backend_factory(runtime.repo_root, runtime.workspace_dir),
        name=f"padv-{role}-subagent",
    )
    return AgentRuntime(
        root=runtime.root,
        subagents={role: session},
        shared_context=shared_context,
        checkpoint_dir=runtime.checkpoint_dir,
        workspace_dir=runtime.workspace_dir,
        model=runtime.model,
        repo_root=runtime.repo_root,
        store=runtime.store,
        prompts=prompts,
    )


def finalize_parallel_role_runtime(runtime: AgentRuntime, *, role: str) -> dict[str, Any]:
    if not isinstance(getattr(runtime, "shared_context", None), dict):
        return {}
    delta = _research_context_delta(runtime.shared_context, role=role)
    runtime.shared_context["__delta__"] = delta
    return delta


def _compact_failed_paths(items: Any, limit: int, max_reason: int) -> list[dict[str, Any]]:
    """Compact failed path entries to the last *limit* items with truncated reasons."""
    if not isinstance(items, list):
        return []
    compact: list[dict[str, Any]] = []
    for item in items[-limit:]:
        if not isinstance(item, dict):
            continue
        reason = str(item.get("reason", "")).strip()
        if len(reason) > max_reason:
            reason = reason[: max_reason - 3].rstrip() + "..."
        compact.append(
            {
                "path": str(item.get("path", "")).strip(),
                "iteration": int(item.get("iteration", 0) or 0),
                "reason": reason,
            }
        )
    return compact


def _safe_list_len(state: dict[str, Any], key: str) -> int:
    """Return the length of *state[key]* if it is a list, else 0."""
    value = state.get(key, [])
    return len(value) if isinstance(value, list) else 0


def _safe_dict_len(state: dict[str, Any], key: str) -> int:
    """Return the length of *state[key]* if it is a dict, else 0."""
    value = state.get(key, {})
    return len(value) if isinstance(value, dict) else 0


def _compact_coverage(raw: Any, tail: int) -> dict[str, list[Any]]:
    """Extract and tail-truncate coverage sub-keys from *raw*."""
    if not isinstance(raw, dict):
        return {"files": [], "classes": [], "signals": [], "sinks": [], "web_paths": []}
    return {
        key: list(raw.get(key, []))[-tail:]
        for key in ("files", "classes", "signals", "sinks", "web_paths")
    }


def _compact_runtime_coverage(raw: Any, tail: int) -> dict[str, list[Any]]:
    """Extract and tail-truncate runtime_coverage sub-keys from *raw*."""
    if not isinstance(raw, dict):
        return {"flags": [], "classes": []}
    return {
        key: list(raw.get(key, []))[-tail:]
        for key in ("flags", "classes")
    }


def _compact_frontier_state(frontier_state: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(frontier_state, dict):
        return {}

    return {
        "version": int(frontier_state.get("version", 0) or 0),
        "updated_at": str(frontier_state.get("updated_at", "")),
        "iteration": int(frontier_state.get("iteration", 0) or 0),
        "stagnation_rounds": int(frontier_state.get("stagnation_rounds", 0) or 0),
        "failed_paths_count": _safe_list_len(frontier_state, "failed_paths"),
        "coverage": _compact_coverage(frontier_state.get("coverage", {}), 10),
        "runtime_coverage": _compact_runtime_coverage(frontier_state.get("runtime_coverage", {}), 10),
        "failed_paths": _compact_failed_paths(frontier_state.get("failed_paths", []), 8, 240),
        "hypotheses_count": _safe_list_len(frontier_state, "hypotheses"),
        "history_count": _safe_list_len(frontier_state, "history"),
        "attempt_history_count": _safe_list_len(frontier_state, "attempt_history"),
        "candidate_resume_size": _safe_dict_len(frontier_state, "candidate_resume"),
    }


def _compact_research_frontier_state(frontier_state: dict[str, Any] | None) -> dict[str, Any]:
    compact = _compact_frontier_state(frontier_state)
    if not compact:
        return {}
    compact.pop("failed_paths", None)
    compact.pop("history_count", None)
    compact.pop("attempt_history_count", None)
    compact.pop("candidate_resume_size", None)
    coverage = compact.get("coverage")
    if isinstance(coverage, dict):
        compact["coverage"] = {
            "files": list(coverage.get("files", []))[-6:],
            "classes": list(coverage.get("classes", []))[-6:],
            "signals": list(coverage.get("signals", []))[-6:],
            "sinks": list(coverage.get("sinks", []))[-4:],
            "web_paths": list(coverage.get("web_paths", []))[-6:],
        }
    runtime_coverage = compact.get("runtime_coverage")
    if isinstance(runtime_coverage, dict):
        compact["runtime_coverage"] = {
            "flags": list(runtime_coverage.get("flags", []))[-6:],
            "classes": list(runtime_coverage.get("classes", []))[-6:],
        }
    return compact


def _compact_research_findings(findings: list[ResearchFinding], *, limit: int = 12) -> list[dict[str, Any]]:
    compact: list[dict[str, Any]] = []
    for item in findings[:limit]:
        compact.append(
            {
                "finding_id": item.finding_id,
                "objective_id": item.objective_id,
                "channel": item.channel,
                "title": item.title[:140],
                "summary": item.summary[:400],
                "evidence_refs": list(item.evidence_refs)[:6],
                "file_refs": list(item.file_refs)[:4],
                "web_paths": list(item.web_paths)[:4],
                "params": list(item.params)[:4],
                "sink_refs": list(item.sink_refs)[:4],
                "metadata_keys": sorted(item.metadata.keys())[:6] if isinstance(item.metadata, dict) else [],
            }
        )
    return compact


def _compact_hypotheses(hypotheses: list[Hypothesis], *, limit: int = 6) -> list[dict[str, Any]]:
    compact: list[dict[str, Any]] = []
    for item in hypotheses[:limit]:
        compact.append(
            {
                "hypothesis_id": item.hypothesis_id,
                "objective_id": item.objective_id,
                "vuln_class": item.vuln_class,
                "title": item.title[:140],
                "rationale": item.rationale[:160],
                "evidence_refs": list(item.evidence_refs)[:4],
                "confidence": item.confidence,
                "status": item.status,
                "gate_preconditions": item.gate_preconditions.to_dict(),
                "auth_requirements": list(item.auth_requirements)[:3],
                "web_path_hints": list(item.web_path_hints)[:3],
                "preconditions": list(item.preconditions)[:3],
                "candidate": {
                    "candidate_id": item.candidate.candidate_id,
                    "vuln_class": item.candidate.vuln_class,
                    "title": item.candidate.title[:140],
                    "file_path": item.candidate.file_path,
                    "line": item.candidate.line,
                    "sink": item.candidate.sink[:180],
                    "confidence": item.candidate.confidence,
                    "expected_intercepts": list(item.candidate.expected_intercepts)[:4],
                    "evidence_refs": list(item.candidate.evidence_refs)[:4],
                },
            }
        )
    return compact


_ENVIRONMENTAL_SKEPTIC_TOKENS = (
    "security_level",
    "security level",
    "auth-state-known",
    "default configuration",
    "deployment configuration",
    ".htaccess",
    "rfc1918",
    "localhost",
    "internal network",
    "network barrier",
    "network access",
    "session state",
    "php session",
)


def _is_environmental_skeptic_text(value: str) -> bool:
    text = str(value or "").strip().lower()
    if not text:
        return False
    return any(token in text for token in _ENVIRONMENTAL_SKEPTIC_TOKENS)


def _compact_hypotheses_for_skeptic(hypotheses: list[Hypothesis], *, limit: int = 3) -> list[dict[str, Any]]:
    compact = _compact_hypotheses(hypotheses, limit=limit)
    for item in compact:
        auth_requirements = [
            value for value in item.get("auth_requirements", []) if not _is_environmental_skeptic_text(str(value))
        ]
        preconditions = [
            value for value in item.get("preconditions", []) if not _is_environmental_skeptic_text(str(value))
        ]
        item["auth_requirements"] = auth_requirements[:2]
        item["preconditions"] = preconditions[:2]
        item["environment_constraints_tracked_elsewhere"] = True
        item["skeptic_focus"] = _SKEPTIC_FOCUS
    return compact


def _handoff_work_guidance(role: str, category: str) -> str:
    if category in {"source_research", "graph_research", "web_research"}:
        return (
            f"Your role is {role} research. Inspect repo/shared context, record concrete intermediate findings with "
            "`write_agent_worklog`. Do not jump straight to a summary without first externalizing your intermediate work. "
            "When you finalize, return only the strongest few executable findings; do not spend tokens on a long task ledger."
        )
    if category == "skeptic_challenge":
        return (
            "Actively try to disprove the current hypotheses, but keep the scope tight. Focus on exploit-invalidating "
            "objections grounded in sanitization, parser behavior, request shaping, sink reachability, or authorization "
            "logic. Do not spend the turn re-checking deployment or environment preconditions such as security level, "
            "network placement, default configuration, or session setup; runtime and gates track those separately unless "
            "they make every exploit variant impossible. Record the strongest objections with `write_agent_worklog`, and "
            "then finalize. Return at most 3 material refutations; do not write one note per hypothesis if the weaker "
            "claims add little information. If the remaining hypotheses have no strong objection, finalize with fewer or "
            "zero refutations instead of continuing."
        )
    if category == "experiment_plan":
        return (
            "Build the runtime plan incrementally, but keep the scope tight. Focus on the strongest 2-3 surviving "
            "hypotheses, persist planning checkpoints with `write_agent_worklog`, and then finalize. Return at most 3 "
            "concrete validation plans with explicit positive/negative controls; do not spend turns on a general "
            "strategy essay once the requests and witness goals are clear."
        )
    if category == "orient":
        return (
            "Use the shared objective/frontier tools to justify the next move. Start from the aggregate discovery "
            "summary tools before drilling into raw candidate or evidence records. Prefer a backlog that spans "
            "materially distinct vulnerability families present in discovery instead of collapsing to a top-4 shortlist. "
            "The graph owns stop/continue decisions, not this turn. If this orient handoff is called, you must return at "
            "least one objective and never return an empty objectives list. If information gain is diminishing, keep the "
            "strongest remaining objective and explain the diminishing returns in notes instead of stopping. "
            "Deterministic backfill will preserve wider coverage after your ranking. Do not block orient on unresolved "
            "deployment/reachability questions; capture those uncertainties in the objective rationale and let later "
            "research/skeptic phases test them explicitly. Persist a short worklog note if you change direction."
        )
    if category in {"select_objective", "continue_or_stop"}:
        return (
            "Use the shared objective/frontier tools to justify the next move. Start from the aggregate discovery "
            "summary tools before drilling into raw candidate or evidence records. Prefer a backlog that spans "
            "materially distinct vulnerability families present in discovery instead of collapsing to a top-4 shortlist. "
            "Return only the strongest primary objectives you can defend; deterministic backfill will preserve wider "
            "coverage after your ranking. Do not block orient or selection on unresolved deployment/reachability "
            "questions; capture those uncertainties in the objective rationale and let later research/skeptic phases "
            "test them explicitly. Persist a short worklog note if you change direction or stop due to lack of "
            "information gain."
        )
    return "Use the workspace and shared-state tools before concluding, and persist meaningful intermediate work."


def _handoff_turn_checklist(category: str, turn: int) -> list[str]:
    if category in {"source_research", "graph_research", "web_research"}:
        if turn == 1:
            return [
                "inspect candidate seeds and semantic evidence",
                "persist at least one worklog note for a concrete lead",
                "continue if a sink/path question remains open",
            ]
        return [
            "review the latest worklog and unresolved questions",
            "tighten findings to executable/request-relevant evidence",
            "finalize only if at least one concrete finding is ready",
        ]
    if category == "skeptic_challenge":
        if turn == 1:
            return [
                "inspect current hypotheses and prior refutations",
                "persist only the strongest 1-3 objections in the worklog",
                "finalize once the strongest objections are explicit",
            ]
        return [
            "review only unresolved high-value objections",
            "drop low-value objections that do not materially change exploitability",
            "finalize after explicit refutation reasoning for the strongest objections",
        ]
    if category == "experiment_plan":
        if turn == 1:
            return [
                "review only the strongest 2-3 surviving hypotheses and runtime history",
                "persist a worklog checkpoint for the strongest witness strategies",
                "finalize once positive and negative controls are explicit for the strongest plans",
            ]
        return [
            "drop lower-value plans that do not materially improve validation coverage",
            "ensure requests, oracle functions, and witness goals align for the remaining plans",
            "finalize with the strongest 1-3 concrete plans",
        ]
    if category == "orient":
        if turn == 1:
            return [
                "review objectives/frontier state",
                "persist a supervisor worklog checkpoint with the current decision framing",
                "continue if competing priorities remain unresolved",
            ]
        return [
            "review the prior supervisor worklog checkpoint",
            "justify the next objective backlog against frontier history and expected information gain",
            "encode unresolved deployment or reachability questions in the rationale instead of stalling",
            "finalize only after at least one objective is explicit and externally inspectable",
        ]
    if category in {"select_objective", "continue_or_stop"}:
        if turn == 1:
            return [
                "review objectives/frontier state",
                "persist a supervisor worklog checkpoint with the current decision framing",
                "continue if competing priorities or stop conditions remain unresolved",
            ]
        return [
            "review the prior supervisor worklog checkpoint",
            "justify the next decision against frontier history and expected information gain",
            "encode unresolved deployment or reachability questions in the rationale instead of stalling",
            "finalize only after the decision rationale is explicit and externally inspectable",
        ]
    return ["review latest context", "use tools before concluding"]


def _filter_shared_list_by_selector(
    items: list[Any],
    token: str,
    *,
    haystack_keys: list[str] | None = None,
    limit: int = 100,
) -> list[Any]:
    """Filter a list of dicts by a case-insensitive substring match."""
    filtered = []
    for item in items:
        if not isinstance(item, dict):
            continue
        if token:
            if haystack_keys:
                haystack = " ".join(str(item.get(k, "")) for k in haystack_keys).lower()
            else:
                haystack = json.dumps(item, ensure_ascii=True).lower()
            if token not in haystack:
                continue
        filtered.append(item)
    return filtered[:limit]


def _filter_dict_payload_by_selector(payload: dict[str, Any], token: str) -> dict[str, Any]:
    """Narrow a dict payload to entries whose JSON or key matches token."""
    if not token:
        return payload
    narrowed: dict[str, Any] = {}
    for key, value in payload.items():
        text = json.dumps(value, ensure_ascii=True).lower()
        if token in text or token in key.lower():
            narrowed[key] = value
    return narrowed


def _append_bucket_sample(bucket: dict[str, Any], key: str, value: str, limit: int = 5) -> None:
    """Add value to bucket[key] list if unique and under limit."""
    if value and value not in bucket[key] and len(bucket[key]) < limit:
        bucket[key].append(value)


def _summarize_evidence_by_class(evidence: list[Any]) -> dict[str, Any]:
    by_class: dict[str, dict[str, Any]] = {}
    total = 0
    for item in evidence:
        if not isinstance(item, dict):
            continue
        total += 1
        query_id = str(item.get("query_id", "")).strip()
        vuln_class = query_id.split("::", 1)[-1] if "::" in query_id else query_id or "unknown"
        bucket = by_class.setdefault(
            vuln_class,
            {"count": 0, "query_ids": [], "sample_files": [], "sample_candidate_ids": []},
        )
        bucket["count"] += 1
        _append_bucket_sample(bucket, "query_ids", query_id)
        _append_bucket_sample(bucket, "sample_files", str(item.get("file_path", "")).strip())
        _append_bucket_sample(bucket, "sample_candidate_ids", str(item.get("candidate_id", "")).strip())
    return {"total": total, "classes": {key: by_class[key] for key in sorted(by_class.keys())}, "_class_count": len(by_class)}


def _summarize_candidates_by_class(candidates: list[Any]) -> dict[str, Any]:
    by_class: dict[str, dict[str, Any]] = {}
    total = 0
    for item in candidates:
        if not isinstance(item, dict):
            continue
        total += 1
        vuln_class = str(item.get("vuln_class", "")).strip() or "unknown"
        bucket = by_class.setdefault(
            vuln_class,
            {"count": 0, "sample_candidate_ids": [], "sample_files": [], "sample_sinks": []},
        )
        bucket["count"] += 1
        _append_bucket_sample(bucket, "sample_candidate_ids", str(item.get("candidate_id", "")).strip())
        _append_bucket_sample(bucket, "sample_files", str(item.get("file_path", "")).strip())
        _append_bucket_sample(bucket, "sample_sinks", str(item.get("sink", "")).strip())
    return {"total": total, "classes": {key: by_class[key] for key in sorted(by_class.keys())}, "_class_count": len(by_class)}


def _build_tool_use_detail(tool_name: str, **metadata: Any) -> str:
    detail = f"tool {tool_name}"
    summary_bits: list[str] = []
    for key in ("count", "selector", "prefix", "path"):
        if key not in metadata:
            continue
        val = str(metadata[key]).strip() if key != "count" else str(metadata[key])
        if key == "count" or val:
            summary_bits.append(f"{key}={val[:80]}")
    if summary_bits:
        detail += " | " + ", ".join(summary_bits)
    return detail


@dataclass
class _ToolCtx:
    """Shared state passed to tool-builder sub-functions."""

    shared_context: dict[str, Any]
    role: str
    workspace_dir: Path | None
    repo_root: str | None

    def safe_workspace_path(self, rel_path: str) -> Path | None:
        if self.workspace_dir is None:
            return None
        try:
            candidate = (self.workspace_dir / rel_path).resolve()
        except Exception:
            return None
        if self.workspace_dir == candidate or self.workspace_dir in candidate.parents:
            return candidate
        return None

    def list_workspace(self, prefix: str = "") -> str:
        if self.workspace_dir is None or not self.workspace_dir.exists():
            return "[]"
        base = self.safe_workspace_path(prefix.strip()) if prefix.strip() else self.workspace_dir
        if base is None or not base.exists():
            return "[]"
        if base.is_file():
            return json.dumps([str(base.relative_to(self.workspace_dir))], ensure_ascii=True)
        items = sorted(str(p.relative_to(self.workspace_dir)) for p in base.rglob("*.json"))
        return json.dumps(items[:500], ensure_ascii=True)

    def write_role_workspace(self, category: str, payload: dict[str, Any]) -> str:
        if self.workspace_dir is None:
            return "workspace unavailable"
        artifact_id = uuid.uuid4().hex[:12]
        path = self.workspace_dir / self.role / category / f"{artifact_id}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2, ensure_ascii=True), encoding="utf-8")
        relative = str(path.relative_to(self.workspace_dir))
        _append_workspace_index_ref(self.shared_context, role=self.role, category=category, relative=relative)
        return relative

    def record_tool_use(self, tool_name: str, **metadata: Any) -> None:
        payload = {"role": self.role, "tool": str(tool_name), **metadata}
        relative = self.write_role_workspace("tool_calls", payload)
        _append_shared_context_entry(self.shared_context, key="tool_usage", role=self.role, payload={"ref": relative, **payload})
        detail = _build_tool_use_detail(tool_name, **metadata)
        _emit_shared_progress(self.shared_context, role=self.role, status="activity", detail=detail, artifact_ref=relative, tool=tool_name)


def _query_filtered_shared_list(ctx: _ToolCtx, context_key: str, tool_name: str, selector: str) -> str:
    items = _shared_context_snapshot(ctx.shared_context, context_key, [])
    if not isinstance(items, list):
        return "[]"
    token = str(selector or "").strip().lower()
    filtered = _filter_shared_list_by_selector(items, token)
    ctx.record_tool_use(tool_name, selector=token[:120], count=len(filtered))
    return json.dumps(filtered, ensure_ascii=True)


def _build_query_tools(ctx: _ToolCtx, tool: Any) -> list[Any]:
    """Build context-query tools (objectives, findings, hypotheses, etc.)."""

    @tool("search_repo_text")
    def search_repo_text(pattern: str) -> str:
        """Search the repo with ripgrep and return matching lines."""
        token = str(pattern or "").strip()
        if not token or not ctx.repo_root:
            return "search unavailable"
        ctx.record_tool_use("search_repo_text", pattern=token[:240])
        return _run_repo_command(ctx.repo_root, f"rg -n --hidden --glob '!vendor' --glob '!node_modules' {shlex.quote(token)} .")

    @tool("list_objectives")
    def list_objectives(_: str = "") -> str:
        """List current objective queue."""
        payload = _shared_context_snapshot(ctx.shared_context, "objective_queue", [])
        ctx.record_tool_use("list_objectives", count=min(len(payload), 50) if isinstance(payload, list) else 0)
        return json.dumps(payload[:50], ensure_ascii=True)

    @tool("list_research_findings")
    def list_research_findings(channel: str = "") -> str:
        """List current research findings, optionally filtered by channel."""
        findings = _shared_context_snapshot(ctx.shared_context, "research_findings", [])
        if not isinstance(findings, list):
            return "[]"
        wanted = str(channel or "").strip().lower()
        filtered = [
            item for item in findings
            if isinstance(item, dict) and (not wanted or str(item.get("channel", "")).strip().lower() == wanted)
        ]
        ctx.record_tool_use("list_research_findings", channel=wanted, count=min(len(filtered), 100))
        return json.dumps(filtered[:100], ensure_ascii=True)

    @tool("list_hypotheses")
    def list_hypotheses(selector: str = "") -> str:
        """List current hypotheses filtered by objective, class, candidate or text selector."""
        return _query_filtered_shared_list(ctx, "hypotheses", "list_hypotheses", selector)

    @tool("list_refutations")
    def list_refutations(selector: str = "") -> str:
        """List current refutations filtered by hypothesis, severity or text selector."""
        return _query_filtered_shared_list(ctx, "refutations", "list_refutations", selector)

    @tool("list_experiment_attempts")
    def list_experiment_attempts(selector: str = "") -> str:
        """List current planned experiment attempts filtered by hypothesis or text selector."""
        return _query_filtered_shared_list(ctx, "experiment_board", "list_experiment_attempts", selector)

    @tool("list_task_delegations")
    def list_task_delegations(selector: str = "") -> str:
        """List recorded root task delegations filtered by subagent type or text selector."""
        return _query_filtered_shared_list(ctx, "delegations", "list_task_delegations", selector)

    result = [
        list_objectives, list_research_findings, list_hypotheses,
        list_refutations, list_experiment_attempts, list_task_delegations,
    ]
    if ctx.role != "root":
        result = [search_repo_text, *result]
    return result


def _build_evidence_tools(ctx: _ToolCtx, tool: Any) -> list[Any]:
    """Build evidence and candidate lookup/summarize tools."""

    @tool("lookup_semantic_evidence")
    def lookup_semantic_evidence(selector: str = "") -> str:
        """Return semantic evidence refs and snippets for SCIP/Joern selectors."""
        token = str(selector or "").strip().lower()
        evidence = _shared_context_snapshot(ctx.shared_context, "static_evidence", [])
        if not isinstance(evidence, list):
            return "[]"
        filtered = _filter_shared_list_by_selector(
            evidence, token, haystack_keys=["candidate_id", "query_id", "file_path", "snippet"],
        )
        ctx.record_tool_use("lookup_semantic_evidence", selector=token[:120], count=len(filtered))
        return json.dumps(filtered, ensure_ascii=True)

    @tool("summarize_semantic_evidence")
    def summarize_semantic_evidence(_: str = "") -> str:
        """Return aggregate counts and representative samples across all semantic evidence."""
        evidence = _shared_context_snapshot(ctx.shared_context, "static_evidence", [])
        if not isinstance(evidence, list):
            return "{}"
        summary = _summarize_evidence_by_class(evidence)
        ctx.record_tool_use("summarize_semantic_evidence", class_count=summary.pop("_class_count", 0), total=summary["total"])
        return json.dumps(summary, ensure_ascii=True)

    @tool("lookup_candidate_seeds")
    def lookup_candidate_seeds(selector: str = "") -> str:
        """Return candidate seed records filtered by selector."""
        token = str(selector or "").strip().lower()
        candidates = _shared_context_snapshot(ctx.shared_context, "candidate_seeds", [])
        if not isinstance(candidates, list):
            return "[]"
        filtered = _filter_shared_list_by_selector(
            candidates, token, haystack_keys=["candidate_id", "vuln_class", "file_path", "sink"],
        )
        ctx.record_tool_use("lookup_candidate_seeds", selector=token[:120], count=len(filtered))
        return json.dumps(filtered, ensure_ascii=True)

    @tool("summarize_candidate_seeds")
    def summarize_candidate_seeds(_: str = "") -> str:
        """Return aggregate counts and representative samples across all candidate seeds."""
        candidates = _shared_context_snapshot(ctx.shared_context, "candidate_seeds", [])
        if not isinstance(candidates, list):
            return "{}"
        summary = _summarize_candidates_by_class(candidates)
        ctx.record_tool_use("summarize_candidate_seeds", class_count=summary.pop("_class_count", 0), total=summary["total"])
        return json.dumps(summary, ensure_ascii=True)

    return [lookup_semantic_evidence, summarize_semantic_evidence, lookup_candidate_seeds, summarize_candidate_seeds]


def _build_state_tools(ctx: _ToolCtx, tool: Any) -> list[Any]:
    """Build web-state, playwright-artifact, and runtime-history lookup tools."""

    @tool("lookup_web_state")
    def lookup_web_state(selector: str = "") -> str:
        """Return Playwright-derived web artifacts, hints, auth contexts and discovery artifacts."""
        token = str(selector or "").strip().lower()
        payload = {
            "web_hints": _shared_context_snapshot(ctx.shared_context, "web_hints", {}),
            "web_artifacts": _shared_context_snapshot(ctx.shared_context, "web_artifacts", {}),
            "auth_contexts": _shared_context_snapshot(ctx.shared_context, "auth_contexts", {}),
            "artifact_index": _shared_context_snapshot(ctx.shared_context, "artifact_index", {}),
        }
        result = _filter_dict_payload_by_selector(payload, token)
        ctx.record_tool_use("lookup_web_state", selector=token[:120], keys=sorted(result.keys()))
        return json.dumps(result, ensure_ascii=True)

    @tool("lookup_playwright_artifacts")
    def lookup_playwright_artifacts(selector: str = "") -> str:
        """Return persisted Playwright-discovered pages and requests filtered by selector."""
        token = str(selector or "").strip().lower()
        artifacts = _shared_context_snapshot(ctx.shared_context, "web_artifacts", {})
        if not isinstance(artifacts, dict):
            return "{}"
        payload = {
            "pages": artifacts.get("pages", []),
            "requests": artifacts.get("requests", []),
            "visited_urls": artifacts.get("visited_urls", []),
            "errors": artifacts.get("errors", []),
        }
        result = _filter_dict_payload_by_selector(payload, token)
        ctx.record_tool_use("lookup_playwright_artifacts", selector=token[:120], keys=sorted(result.keys()))
        return json.dumps(result, ensure_ascii=True)

    @tool("lookup_runtime_history")
    def lookup_runtime_history(selector: str = "") -> str:
        """Return runtime history and witness bundles."""
        token = str(selector or "").strip().lower()
        payload = {
            "runtime_history": _shared_context_snapshot(ctx.shared_context, "runtime_history", []),
            "witness_bundles": _shared_context_snapshot(ctx.shared_context, "witness_bundles", []),
            "gate_history": _shared_context_snapshot(ctx.shared_context, "gate_history", []),
        }
        result = _filter_dict_payload_by_selector(payload, token)
        ctx.record_tool_use("lookup_runtime_history", selector=token[:120], keys=sorted(result.keys()))
        return json.dumps(result, ensure_ascii=True)

    return [lookup_web_state, lookup_playwright_artifacts, lookup_runtime_history]


def _build_workspace_tools(ctx: _ToolCtx, tool: Any) -> list[Any]:
    """Build workspace management tools (list, read, write)."""

    @tool("list_agent_workspace")
    def list_agent_workspace(prefix: str = "") -> str:
        """List persisted agent workspace artifacts by relative prefix."""
        ctx.record_tool_use("list_agent_workspace", prefix=str(prefix or "")[:240])
        return ctx.list_workspace(prefix)

    @tool("read_agent_workspace")
    def read_agent_workspace(path: str) -> str:
        """Read a persisted agent workspace artifact by relative path."""
        ctx.record_tool_use("read_agent_workspace", path=str(path or "")[:240])
        target = ctx.safe_workspace_path(path)
        if target is None or not target.exists() or not target.is_file():
            return "invalid workspace path"
        try:
            return target.read_text(encoding="utf-8", errors="ignore")[:24000]
        except OSError:
            return "workspace read failed"

    @tool("list_role_workspace")
    def list_role_workspace(category: str = "") -> str:
        """List persisted workspace artifacts for the current agent role."""
        prefix = ctx.role if not str(category or "").strip() else f"{ctx.role}/{str(category).strip().strip('/')}"
        ctx.record_tool_use("list_role_workspace", category=str(category or "")[:120], prefix=prefix[:240])
        return ctx.list_workspace(prefix)

    @tool("write_agent_worklog")
    def write_agent_worklog(category: str, summary: str, details: str = "", refs_json: str = "[]") -> str:
        """Persist a role-local worklog note with optional evidence refs."""
        note_category = str(category or "").strip() or "general"
        payload = {
            "role": ctx.role,
            "category": note_category,
            "summary": str(summary or "").strip(),
            "details": str(details or "").strip(),
            "refs": _parse_json_list(refs_json),
        }
        relative = ctx.write_role_workspace("worklog", payload)
        _append_shared_context_entry(ctx.shared_context, key="worklog", role=ctx.role, payload={"ref": relative, **payload})
        summary_text = str(payload.get("summary", "")).strip()
        _emit_shared_progress(
            ctx.shared_context,
            role=ctx.role,
            status="worklog",
            detail=f"{note_category}: {summary_text[:120]}".strip(": "),
            artifact_ref=relative,
            category=note_category,
        )
        return relative

    return [list_agent_workspace, read_agent_workspace, list_role_workspace, write_agent_worklog]


def _build_shared_context_tools(shared_context: dict[str, Any], repo_root: str | None, *, role: str) -> list[Any]:
    try:
        from langchain_core.tools import tool  # type: ignore[import-not-found]
    except Exception as exc:
        raise AgentExecutionError(f"langchain_core tools import failed: {exc}") from exc

    fs_tools = _build_filesystem_tools(repo_root) if repo_root and role != "root" else []
    workspace_dir = Path(str(shared_context.get("workspace_dir") or "")).resolve() if shared_context.get("workspace_dir") else None
    ctx = _ToolCtx(shared_context=shared_context, role=role, workspace_dir=workspace_dir, repo_root=repo_root)

    return (
        fs_tools
        + _build_query_tools(ctx, tool)
        + _build_evidence_tools(ctx, tool)
        + _build_state_tools(ctx, tool)
        + _build_workspace_tools(ctx, tool)
    )


def _agent_thread_id(frontier_state: dict[str, Any] | None, *, role: str, prefix: str) -> str:
    threads = frontier_state.get("agent_threads", {}) if isinstance(frontier_state, dict) else {}
    if isinstance(threads, dict):
        existing = threads.get(role)
        if isinstance(existing, str) and existing.strip():
            return existing.strip()
    return f"{prefix}-{role}-{uuid.uuid4().hex[:10]}"


def _persist_agent_thread_id(frontier_state: dict[str, Any] | None, *, role: str, thread_id: str) -> None:
    if not isinstance(frontier_state, dict):
        return
    threads = frontier_state.setdefault("agent_threads", {})
    if isinstance(threads, dict):
        threads[role] = thread_id


def _shared_backend_root(repo_root: str | None, workspace_dir: str | None) -> str | None:
    paths = [str(Path(path).resolve()) for path in (repo_root, workspace_dir) if isinstance(path, str) and path.strip()]
    if not paths:
        return None
    try:
        return str(Path(os.path.commonpath(paths)))
    except ValueError:
        return str(Path(paths[0]))


def _memory_store_namespace() -> tuple[str, ...]:
    return ("padv", "deepagents", "memories")



def _build_backend_factory(repo_root: str | None, workspace_dir: str | None):
    try:
        from deepagents.backends import CompositeBackend, FilesystemBackend, StoreBackend  # type: ignore[import-not-found]
    except Exception as exc:
        raise AgentExecutionError(f"deepagents backend import failed: {exc}") from exc

    backend_root = _shared_backend_root(repo_root, workspace_dir) or str(Path.cwd())

    def _factory(runtime: Any) -> Any:
        return CompositeBackend(
            default=FilesystemBackend(root_dir=backend_root, virtual_mode=True),
            routes={
                "/memories/": StoreBackend(
                    runtime,
                    namespace=lambda _ctx: _memory_store_namespace(),
                )
            },
        )

    return _factory


def _build_workspace_backend_factory(workspace_dir: str | None):
    try:
        from deepagents.backends import CompositeBackend, FilesystemBackend, StoreBackend  # type: ignore[import-not-found]
    except Exception as exc:
        raise AgentExecutionError(f"deepagents backend import failed: {exc}") from exc

    backend_root = str(Path(workspace_dir).resolve()) if isinstance(workspace_dir, str) and workspace_dir.strip() else str(Path.cwd())

    def _factory(runtime: Any) -> Any:
        return CompositeBackend(
            default=FilesystemBackend(root_dir=backend_root, virtual_mode=True),
            routes={
                "/memories/": StoreBackend(
                    runtime,
                    namespace=lambda _ctx: _memory_store_namespace(),
                )
            },
        )

    return _factory


def _create_persistent_store(checkpoint_dir: str) -> Any:
    try:
        from langgraph.store.sqlite import SqliteStore  # type: ignore[import-not-found]
    except Exception as exc:
        raise AgentExecutionError(f"langgraph sqlite store import failed: {exc}") from exc

    db_path = Path(checkpoint_dir) / "memories.sqlite"
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(
        str(db_path),
        check_same_thread=False,
        isolation_level=None,
    )
    store = SqliteStore(conn)
    store.setup()
    return store


def _memory_sources_for_role(role: str) -> list[str]:
    safe_role = re.sub(r"[^a-z0-9_-]+", "-", str(role).strip().lower()) or "agent"
    return [
        "/memories/padv/shared.md",
        f"/memories/padv/{safe_role}.md",
    ]


def _subagent_descriptions() -> dict[str, str]:
    return {
        "source": "Investigate source files, entrypoints, request variables, routes, and executable PHP paths.",
        "graph": "Investigate SCIP and Joern evidence, callsites, dataflow relationships, and authorization gates.",
        "web": "Investigate reachable web flows, forms, sessions, and parameter propagation using discovered browser state.",
        "exploit": "Synthesize exploit hypotheses, witness expectations, and runtime preconditions from combined evidence.",
        "skeptic": "Actively refute exploit hypotheses with sanitization, reachability, and auth-barrier objections.",
        "experiment": "Turn surviving hypotheses into deterministic runtime experiments with positive and negative controls.",
    }



def _memory_store_put(store: Any, *, path: str, content: str) -> None:
    namespace = _memory_store_namespace()
    payload = {
        "content": str(content).splitlines(),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "modified_at": datetime.now(timezone.utc).isoformat(),
    }
    existing = store.get(namespace, path)
    if existing is not None and isinstance(getattr(existing, "value", None), dict):
        created_at = existing.value.get("created_at")
        if isinstance(created_at, str) and created_at.strip():
            payload["created_at"] = created_at
    store.put(namespace, path, payload)



def _render_shared_memory(*, repo_root: str | None, workspace_dir: str | None) -> str:
    lines = [
        "# padv Shared Memory",
        "",
        "This agent run analyzes PHP web applications using LangGraph + DeepAgents.",
        "Use filesystem, SCIP/Joern, web, and runtime tools instead of guessing.",
        "Deterministic validation decisions come only from the external gate engine.",
        "",
        f"Repository root: {repo_root or '(unavailable)'}",
        f"Workspace dir: {workspace_dir or '(unavailable)'}",
    ]
    return "\n".join(lines).strip() + "\n"



def _render_role_memory(*, role: str, system_prompt: str) -> str:
    lines = [
        f"# padv Role Memory: {role}",
        "",
        f"Role: {role}",
        "Prefer tool use and persisted artifacts over unsupported assumptions.",
        "Keep outputs compact and evidence-linked.",
        "",
        "System prompt:",
        system_prompt.strip(),
    ]
    return "\n".join(lines).strip() + "\n"



def _seed_agent_memories(
    store: Any,
    *,
    repo_root: str | None,
    workspace_dir: str | None,
    prompts: dict[str, str],
) -> None:
    _memory_store_put(
        store,
        path="/memories/padv/shared.md",
        content=_render_shared_memory(repo_root=repo_root, workspace_dir=workspace_dir),
    )
    for role, prompt in prompts.items():
        safe_role = re.sub(r"[^a-z0-9_-]+", "-", str(role).strip().lower()) or "agent"
        _memory_store_put(
            store,
            path=f"/memories/padv/{safe_role}.md",
            content=_render_role_memory(role=role, system_prompt=prompt),
        )


def _subagent_specs(
    *,
    prompts: dict[str, str],
    shared_context: dict[str, Any],
    repo_root: str | None,
    model: str,
) -> list[dict[str, Any]]:
    descriptions = _subagent_descriptions()
    specs: list[dict[str, Any]] = []
    for role, description in descriptions.items():
        specs.append(
            {
                "name": role,
                "description": description,
                "system_prompt": prompts[role],
                "tools": _build_shared_context_tools(shared_context, repo_root, role=role),
                "model": model,
            }
        )
    return specs


def _compiled_subagent_sessions(
    config: PadvConfig,
    *,
    prompts: dict[str, str],
    shared_context: dict[str, Any],
    repo_root: str | None,
    store: Any,
    workspace_dir: str,
    checkpoint_dir: str,
) -> dict[str, AgentSession]:
    backend_factory = _build_backend_factory(repo_root, workspace_dir)
    sessions: dict[str, AgentSession] = {}
    for role in _subagent_descriptions():
        sessions[role] = _create_agent_session(
            config,
            role=role,
            system_prompt=prompts[role],
            repo_root=repo_root,
            shared_context=shared_context,
            frontier_state=None,
            checkpoint_dir=checkpoint_dir,
            store=store,
            backend=backend_factory,
            name=f"padv-{role}-subagent",
        )
    return sessions


def _runtime_subagent_specs(sessions: dict[str, AgentSession]) -> list[dict[str, Any]]:
    descriptions = _subagent_descriptions()
    specs: list[dict[str, Any]] = []
    for role, description in descriptions.items():
        session = sessions.get(role)
        if session is None:
            continue
        specs.append(
            {
                "name": role,
                "description": description,
                "runnable": session.agent,
            }
        )
    return specs


def _agent_middleware_for_role(
    *,
    config: PadvConfig,
    role: str,
    shared_context: dict[str, Any],
    checkpoint_dir: str,
) -> list[Any]:
    del config
    middleware: list[Any] = []
    if role == "root":
        middleware.append(TaskDelegationTraceMiddleware(shared_context=shared_context, checkpoint_dir=checkpoint_dir))
    return middleware


def _create_agent_session(
    config: PadvConfig,
    *,
    role: str,
    system_prompt: str,
    repo_root: str | None,
    shared_context: dict[str, Any],
    frontier_state: dict[str, Any] | None,
    checkpoint_dir: str,
    store: Any | None = None,
    backend: Any | None = None,
    subagents: list[dict[str, Any]] | None = None,
    name: str | None = None,
) -> AgentSession:
    api_key = os.environ.get(config.llm.api_key_env)
    if not api_key:
        raise AgentExecutionError(f"missing API key env var: {config.llm.api_key_env}")
    try:
        from deepagents import create_deep_agent  # type: ignore[import-not-found]
    except Exception as exc:
        raise AgentExecutionError(f"deepagents/langgraph import failed: {exc}") from exc

    model = _resolve_model(config)
    thread_id = _agent_thread_id(frontier_state, role=role, prefix=config.agent.thread_prefix)
    tools = _build_shared_context_tools(shared_context, repo_root, role=role)
    checkpointer = FileBackedMemorySaver(_checkpoint_path(checkpoint_dir, role, thread_id))
    middleware = _agent_middleware_for_role(
        config=config,
        role=role,
        shared_context=shared_context,
        checkpoint_dir=checkpoint_dir,
    )
    try:
        agent = create_deep_agent(
            model=model,
            tools=tools,
            system_prompt=system_prompt,
            checkpointer=checkpointer,
            middleware=middleware,
            store=store,
            backend=backend,
            subagents=subagents,
            memory=_memory_sources_for_role(role),
            name=name or f"padv-{role}",
        )
    except Exception as exc:
        raise AgentExecutionError(f"deepagents agent creation failed: {exc}") from exc
    _persist_agent_thread_id(frontier_state, role=role, thread_id=thread_id)
    return AgentSession(
        agent=agent,
        thread_id=thread_id,
        model=model,
        repo_root=repo_root,
        checkpoint_dir=checkpoint_dir,
        role=role,
    )


def ensure_agent_runtime(
    config: PadvConfig,
    *,
    frontier_state: dict[str, Any] | None = None,
    repo_root: str | None = None,
    checkpoint_dir: str = "",
    runtime: AgentRuntime | None = None,
) -> AgentRuntime:
    if runtime is not None:
        return runtime

    shared_context: dict[str, Any] = {
        "__lock__": threading.RLock(),
        "__active_categories__": {},
        "objective_queue": [],
        "research_findings": [],
        "hypotheses": [],
        "refutations": [],
        "experiment_board": [],
        "static_evidence": [],
        "candidate_seeds": [],
        "web_hints": {},
        "web_artifacts": {},
        "auth_contexts": {},
        "artifact_index": {},
        "worklog": {},
        "delegations": [],
        "runtime_history": [],
        "witness_bundles": [],
        "gate_history": [],
    }
    prompts = {
        "root": (
            "You are the root agent for a PHP web exploit discovery system. "
            "Drive objectives, delegate to subagents, and reason over persistent frontier state. "
            "Use tools before concluding. Return strict JSON only."
        ),
        "source": (
            "You are the source research subagent. Reconstruct executable entrypoints, request variables, "
            "routes, and code-level context from the repository. Use tools extensively and return strict JSON only."
        ),
        "graph": (
            "You are the graph research subagent. Investigate SCIP and Joern evidence, callsites, dataflows, "
            "and authorization gates. Use tools and return strict JSON only."
        ),
        "web": (
            "You are the web research subagent. Investigate reachable flows, forms, session transitions, "
            "parameters, and request behavior using persisted Playwright-derived pages, forms, and request artifacts. "
            "Use those artifacts directly instead of inferring flows only from source code. Return strict JSON only."
        ),
        "exploit": (
            "You are the exploit research subagent. Combine evidence into exploit hypotheses with concrete witnesses, "
            "preconditions and runtime expectations. Use tools when needed. Return strict JSON only."
        ),
        "skeptic": (
            "You are the skeptic subagent. Actively refute exploit hypotheses using exploit-invalidating alternate "
            "explanations grounded in code, parsing, sanitization, request structure, reachability of the vulnerable sink, "
            "or authorization logic. Do not spend the turn re-litigating environment/setup constraints like security level, "
            "session initialization, network placement, or default deployment configuration unless they prove the exploit is "
            "impossible across all realistic runtime states. Use tools before concluding. Return strict JSON only."
        ),
        "experiment": (
            "You are the experiment subagent. Convert surviving hypotheses into deterministic runtime plans with "
            "positive requests, negative controls and witness goals. Use tools when needed. Return strict JSON only."
        ),
    }
    resolved_checkpoint_dir = checkpoint_dir or str(Path(".padv") / "langgraph")
    workspace_dir = str(_workspace_root(resolved_checkpoint_dir))
    shared_context["workspace_dir"] = workspace_dir
    shared_context["workspace_index"] = {}
    memory_store = _create_persistent_store(resolved_checkpoint_dir)
    _seed_agent_memories(
        memory_store,
        repo_root=repo_root,
        workspace_dir=workspace_dir,
        prompts=prompts,
    )
    workspace_backend_factory = _build_workspace_backend_factory(workspace_dir)
    subagent_sessions = _compiled_subagent_sessions(
        config,
        prompts=prompts,
        shared_context=shared_context,
        repo_root=repo_root,
        store=memory_store,
        workspace_dir=workspace_dir,
        checkpoint_dir=resolved_checkpoint_dir,
    )
    root_subagents = _runtime_subagent_specs(subagent_sessions)
    root_session = _create_agent_session(
        config,
        role="root",
        system_prompt=prompts["root"],
        repo_root=repo_root,
        shared_context=shared_context,
        frontier_state=frontier_state,
        checkpoint_dir=resolved_checkpoint_dir,
        store=memory_store,
        backend=workspace_backend_factory,
        subagents=root_subagents,
        name="padv-root",
    )
    return AgentRuntime(
        root=root_session,
        subagents=subagent_sessions,
        shared_context=shared_context,
        checkpoint_dir=resolved_checkpoint_dir,
        workspace_dir=workspace_dir,
        model=root_session.model,
        repo_root=repo_root,
        store=memory_store,
        prompts=prompts,
    )


def update_agent_runtime_context(runtime: AgentRuntime, **payload: Any) -> None:
    with _shared_context_lock(runtime.shared_context):
        for key, value in payload.items():
            try:
                runtime.shared_context[key] = copy.deepcopy(value)
            except Exception:
                runtime.shared_context[key] = value


def _write_workspace_json(runtime: AgentRuntime, *, role: str, category: str, payload: dict[str, Any]) -> str:
    artifact_id = uuid.uuid4().hex[:12]
    path = _workspace_artifact_path(
        runtime.checkpoint_dir,
        role=role,
        category=category,
        artifact_id=artifact_id,
    )
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=True), encoding="utf-8")
    relative = str(path.relative_to(Path(runtime.workspace_dir)))
    _append_workspace_index_ref(runtime.shared_context, role=role, category=category, relative=relative)
    return relative


def _build_handoff_prompt(
    session: AgentSession,
    artifact_role: str,
    delegated_role: str | None,
    handoff_ref: str,
    category_guidance: str,
    response_contract: str,
    recent_worklog_refs: list[str],
    recent_tool_refs: list[str],
) -> str:
    if delegated_role:
        return (
            "You are the root supervisor. "
            f"You must delegate this task via the task tool using subagent_type='{delegated_role}'. "
            "Do not solve it directly from the root context. "
            f"Tell the delegated subagent to inspect the handoff artifact at '{handoff_ref}'. "
            f"The delegated subagent owns workspace role '{artifact_role}'. "
            f"Recent worklog refs for delegated role '{artifact_role}': {json.dumps(recent_worklog_refs, ensure_ascii=True)}. "
            f"Recent tool-call refs for delegated role '{artifact_role}': {json.dumps(recent_tool_refs, ensure_ascii=True)}. "
            f"{category_guidance} "
            f"Return only the delegated subagent's strict JSON matching this response contract: {response_contract}"
        )
    return (
        f"You are continuing the durable {session.role} agent workspace. "
        f"Use the workspace tools to inspect the handoff artifact at '{handoff_ref}'. "
        f"Recent worklog refs for your role: {json.dumps(recent_worklog_refs, ensure_ascii=True)}. "
        f"Recent tool-call refs for your role: {json.dumps(recent_tool_refs, ensure_ascii=True)}. "
        f"{category_guidance} "
        "Use repo and shared-state tools before concluding. "
        f"Return strict JSON matching this response contract: {response_contract}"
    )


def _build_handoff_success_meta(
    handoff_ref: str,
    response_ref: str,
    session: AgentSession,
    artifact_role: str,
    delegated_role: str | None,
    cache_key: str,
    runtime: AgentRuntime,
) -> dict[str, Any]:
    return {
        "handoff_ref": handoff_ref,
        "response_ref": response_ref,
        "response_refs": [response_ref],
        "progress_refs": [],
        "turns": 1,
        "invocation_role": session.role,
        "workspace_role": artifact_role,
        "delegated_role": delegated_role,
        "worklog_refs": _workspace_index_refs(runtime.shared_context, role=artifact_role, category="worklog"),
        "tool_refs": _workspace_index_refs(runtime.shared_context, role=artifact_role, category="tool_calls"),
        "delegation_refs": _workspace_index_refs(runtime.shared_context, role="root", category="delegations"),
        "cache_hit": False,
        "cache_source": "",
        "cache_key": cache_key,
    }


def _invoke_agent_handoff(
    runtime: AgentRuntime,
    session: AgentSession,
    config: PadvConfig,
    *,
    category: str,
    envelope: dict[str, Any],
    response_contract: str,
    workspace_role: str | None = None,
    delegated_role: str | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    artifact_role = workspace_role or session.role
    cache_enabled = _handoff_cache_enabled(config)
    cache_key = _handoff_cache_key(
        session,
        config=config,
        category=category,
        envelope=envelope,
        response_contract=response_contract,
        workspace_role=artifact_role,
        delegated_role=delegated_role,
    )
    handoff_payload = {
        "role": artifact_role,
        "invocation_role": session.role,
        "delegated_role": delegated_role,
        "thread_id": session.thread_id,
        "category": category,
        "response_contract": response_contract,
        "envelope": envelope,
    }
    handoff_ref = _write_workspace_json(runtime, role=artifact_role, category="handoffs", payload=handoff_payload)
    category_guidance = _handoff_work_guidance(artifact_role, category)
    handoff_timeout_seconds = _handoff_timeout_seconds(category, config)

    def _cached_return(parsed: dict[str, Any], *, cache_source: str) -> tuple[dict[str, Any], dict[str, Any]]:
        response_ref = _write_workspace_json(
            runtime,
            role=artifact_role,
            category="responses",
            payload={
                "handoff_ref": handoff_ref,
                "category": category,
                "turn": 0,
                "invocation_role": session.role,
                "delegated_role": delegated_role,
                "cache_key": cache_key,
                "cache_hit": True,
                "cache_source": cache_source,
                "response": parsed,
            },
        )
        return parsed, {
            "handoff_ref": handoff_ref,
            "response_ref": response_ref,
            "response_refs": [response_ref],
            "progress_refs": [],
            "turns": 1,
            "invocation_role": session.role,
            "workspace_role": artifact_role,
            "delegated_role": delegated_role,
            "worklog_refs": _workspace_index_refs(runtime.shared_context, role=artifact_role, category="worklog"),
            "tool_refs": _workspace_index_refs(runtime.shared_context, role=artifact_role, category="tool_calls"),
            "delegation_refs": _workspace_index_refs(runtime.shared_context, role="root", category="delegations"),
            "cache_hit": True,
            "cache_source": cache_source,
            "cache_key": cache_key,
        }

    inflight_entry: dict[str, Any] | None = None
    if cache_enabled:
        cached = _load_handoff_cache(runtime.checkpoint_dir, cache_key)
        if cached is not None:
            _emit_shared_progress(
                runtime.shared_context,
                role=artifact_role,
                status="cache_hit",
                detail=f"{category} sqlite-exact",
                step=category,
                handoff_ref=handoff_ref,
                cache_source="sqlite-exact",
            )
            return _cached_return(cached, cache_source="sqlite-exact")

        inflight_entry, is_leader = _acquire_inflight_handoff(cache_key)
        if not is_leader:
            inflight_entry["event"].wait()
            if inflight_entry.get("error") is not None:
                error = inflight_entry["error"]
                if isinstance(error, Exception):
                    raise error
                raise AgentExecutionError(str(error))
            result = inflight_entry.get("result")
            if isinstance(result, dict):
                return _cached_return(result, cache_source="inflight-dedup")
            raise AgentExecutionError(f"{session.role} identical handoff dedup wait ended without result")

    previous_active_category = _set_active_progress_category(runtime.shared_context, role=artifact_role, category=category)
    try:
        _emit_shared_progress(
            runtime.shared_context,
            role=artifact_role,
            status="start",
            detail=f"handoff {category}",
            step=category,
            handoff_ref=handoff_ref,
            invocation_role=session.role,
            delegated_role=delegated_role,
        )
        recent_worklog_refs = _workspace_index_refs(runtime.shared_context, role=artifact_role, category="worklog")[-5:]
        recent_tool_refs = _workspace_index_refs(runtime.shared_context, role=artifact_role, category="tool_calls")[-5:]
        prompt = _build_handoff_prompt(
            session, artifact_role, delegated_role, handoff_ref, category_guidance,
            response_contract, recent_worklog_refs, recent_tool_refs,
        )
        parsed = _invoke_agent_session_with_timeout(
            session,
            prompt,
            config,
            timeout_seconds=handoff_timeout_seconds,
        )
        response_ref = _write_workspace_json(
            runtime,
            role=artifact_role,
            category="responses",
            payload={
                "handoff_ref": handoff_ref,
                "category": category,
                "turn": 1,
                "invocation_role": session.role,
                "delegated_role": delegated_role,
                "cache_key": cache_key,
                "cache_hit": False,
                "response": parsed,
            },
        )
        status = str(parsed.get("status", "")).strip().lower()
        if status == "continue":
            raise AgentExecutionError(
                f"{session.role} returned non-final continue response for {category}; "
                "DeepAgents handoffs must return a final structured result"
            )
        _emit_shared_progress(
            runtime.shared_context,
            role=artifact_role,
            status="response",
            detail="turn=1 final",
            step=category,
            handoff_ref=handoff_ref,
            response_ref=response_ref,
            turn=1,
            invocation_role=session.role,
            delegated_role=delegated_role,
        )
        if cache_enabled:
            _store_handoff_cache(runtime.checkpoint_dir, cache_key, parsed)
        meta = _build_handoff_success_meta(handoff_ref, response_ref, session, artifact_role, delegated_role, cache_key, runtime)
        if cache_enabled:
            _resolve_inflight_handoff(cache_key, result=parsed)
        return parsed, meta
    except Exception as exc:
        _emit_shared_progress(
            runtime.shared_context,
            role=artifact_role,
            status="error",
            detail=str(exc),
            step=category,
            handoff_ref=handoff_ref,
            invocation_role=session.role,
            delegated_role=delegated_role,
        )
        if cache_enabled:
            _resolve_inflight_handoff(cache_key, error=exc if isinstance(exc, Exception) else AgentExecutionError(str(exc)))
        raise
    finally:
        _set_active_progress_category(runtime.shared_context, role=artifact_role, category=previous_active_category)


def _handoff_timeout_seconds(category: str, config: PadvConfig) -> int | None:
    del category, config
    return None


def _invoke_agent_session_with_timeout(
    session: AgentSession,
    prompt: str,
    config: PadvConfig,
    *,
    timeout_seconds: int | None,
) -> dict[str, Any]:
    fn = invoke_agent_session_json
    try:
        parameters = inspect.signature(fn).parameters
    except (TypeError, ValueError):  # pragma: no cover - defensive for mocks
        parameters = {}
    if "timeout_seconds" in parameters:
        return fn(session, prompt, config, timeout_seconds=timeout_seconds)
    return fn(session, prompt, config)


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
    max_attempts = 2
    last_error: Exception | None = None

    for _attempt in range(1, max_attempts + 1):
        try:
            invoke_lock = getattr(active_session, "invoke_lock", None)
            if invoke_lock is None:
                result = active_session.agent.invoke(
                    {"messages": [{"role": "user", "content": prompt}]},
                    config={"configurable": {"thread_id": active_session.thread_id}},
                )
            else:
                with invoke_lock:
                    result = active_session.agent.invoke(
                        {"messages": [{"role": "user", "content": prompt}]},
                        config={"configurable": {"thread_id": active_session.thread_id}},
                    )
            content = _extract_text(result if isinstance(result, dict) else {})
            parsed = _extract_json(content)
            if parsed is None:
                raw_ref = _persist_raw_agent_output(active_session, content=content, kind="non_json_response")
                detail = "deepagents returned non-JSON response"
                if raw_ref:
                    detail += f" (raw_ref={raw_ref})"
                raise AgentExecutionError(detail)
            return parsed
        except Exception as exc:
            last_error = AgentExecutionError(f"deepagents invocation failed: {exc}")

    if last_error is not None:
        raise last_error
    raise AgentExecutionError("deepagents invocation failed")


def _persist_invoke_exception(session: AgentSession, exc: Exception) -> str | None:
    return _persist_raw_agent_output(
        session,
        content=json.dumps(
            {
                "role": session.role,
                "error_type": type(exc).__name__,
                "error": str(exc),
                "traceback": traceback.format_exc()[:24000],
            },
            ensure_ascii=True,
            indent=2,
        ),
        kind="invoke_exception",
    )


def _invoke_session_once(session: AgentSession, prompt: str) -> dict[str, Any]:
    with session.invoke_lock:
        result = session.agent.invoke(
            {"messages": [{"role": "user", "content": prompt}]},
            config={"configurable": {"thread_id": session.thread_id}},
        )
    content = _extract_text(result if isinstance(result, dict) else {})
    parsed = _extract_json(content)
    if parsed is None:
        raw_ref = _persist_raw_agent_output(session, content=content, kind="non_json_response")
        detail = f"{session.role} returned non-JSON response"
        if raw_ref:
            detail += f" (raw_ref={raw_ref})"
        raise AgentExecutionError(detail)
    return parsed


def invoke_agent_session_json(
    session: AgentSession,
    prompt: str,
    config: PadvConfig,
    timeout_seconds: int | None = None,
) -> dict[str, Any]:
    del timeout_seconds
    max_attempts = 2
    last_error: Exception | None = None

    for _attempt in range(1, max_attempts + 1):
        try:
            return _invoke_session_once(session, prompt)
        except TimeoutError as exc:
            last_error = AgentExecutionError(str(exc))
        except AgentExecutionError as exc:
            last_error = exc
            continue
        except Exception as exc:
            raw_ref = _persist_invoke_exception(session, exc)
            detail = f"{session.role} invocation failed: {exc}"
            if raw_ref:
                detail += f" (raw_ref={raw_ref})"
            last_error = AgentExecutionError(detail)
    if last_error is not None:
        raise last_error
    raise AgentExecutionError(f"{session.role} invocation failed")


def _normalize_objectives(raw: Any) -> list[ObjectiveScore]:
    if not isinstance(raw, list):
        return []
    out: list[ObjectiveScore] = []
    for idx, item in enumerate(raw, start=1):
        if not isinstance(item, dict):
            continue
        objective_id = str(item.get("objective_id", "")).strip() or f"obj-{idx:03d}"
        title = str(item.get("title", "")).strip() or objective_id
        rationale = str(item.get("rationale", "")).strip() or "agent objective"
        score = item.get("expected_info_gain")
        priority = item.get("priority", score)
        try:
            expected_info_gain = float(score) if score is not None else 0.0
        except Exception:
            expected_info_gain = 0.0
        try:
            normalized_priority = float(priority) if priority is not None else expected_info_gain
        except Exception:
            normalized_priority = expected_info_gain
        channels = [
            str(x).strip()
            for x in item.get("channels", [])
            if isinstance(x, (str, int, float)) and str(x).strip()
        ]
        related_ids = [
            str(x).strip()
            for x in item.get("related_hypothesis_ids", [])
            if isinstance(x, (str, int, float)) and str(x).strip()
        ]
        out.append(
            ObjectiveScore(
                objective_id=objective_id,
                title=title,
                rationale=rationale,
                expected_info_gain=expected_info_gain,
                priority=normalized_priority,
                channels=channels,
                related_hypothesis_ids=related_ids,
            )
        )
    return out


def _limit_primary_objectives(objectives: list[ObjectiveScore], limit: int = 6) -> list[ObjectiveScore]:
    if limit <= 0 or len(objectives) <= limit:
        return objectives
    ranked = sorted(
        objectives,
        key=lambda item: (-float(item.priority), -float(item.expected_info_gain), item.objective_id),
    )
    return ranked[:limit]


def _normalize_research_tasks(raw: Any, *, objective_id: str, channel: str) -> list[ResearchTask]:
    if not isinstance(raw, list):
        return []
    out: list[ResearchTask] = []
    for idx, item in enumerate(raw, start=1):
        if not isinstance(item, dict):
            continue
        out.append(
            ResearchTask(
                task_id=str(item.get("task_id", "")).strip() or f"{channel}-task-{objective_id}-{idx:03d}",
                objective_id=objective_id,
                channel=channel,
                target_ref=str(item.get("target_ref", "")).strip() or str(item.get("file_path", "")).strip() or objective_id,
                prompt=str(item.get("prompt", "")).strip() or str(item.get("summary", "")).strip() or "research task",
                status=str(item.get("status", "")).strip() or "done",
                metadata={k: v for k, v in item.items() if k not in {"task_id", "target_ref", "prompt", "status"}},
            )
        )
    return out


def _normalize_research_findings(raw: Any, *, objective_id: str, channel: str) -> list[ResearchFinding]:
    if not isinstance(raw, list):
        return []
    out: list[ResearchFinding] = []
    for idx, item in enumerate(raw, start=1):
        if not isinstance(item, dict):
            continue
        evidence_refs = [
            str(x).strip()
            for x in item.get("evidence_refs", [])
            if isinstance(x, (str, int, float)) and str(x).strip()
        ]
        file_refs = [
            str(x).strip()
            for x in item.get("file_refs", [])
            if isinstance(x, (str, int, float)) and str(x).strip()
        ]
        web_paths = [
            str(x).strip()
            for x in item.get("web_paths", [])
            if isinstance(x, (str, int, float)) and str(x).strip()
        ]
        params = [
            str(x).strip()
            for x in item.get("params", [])
            if isinstance(x, (str, int, float)) and str(x).strip()
        ]
        sink_refs = [
            str(x).strip()
            for x in item.get("sink_refs", [])
            if isinstance(x, (str, int, float)) and str(x).strip()
        ]
        out.append(
            ResearchFinding(
                finding_id=str(item.get("finding_id", "")).strip() or f"{channel}-finding-{objective_id}-{idx:03d}",
                objective_id=objective_id,
                channel=channel,
                title=str(item.get("title", "")).strip() or f"{channel} finding",
                summary=str(item.get("summary", "")).strip() or str(item.get("title", "")).strip() or "research finding",
                evidence_refs=evidence_refs,
                file_refs=file_refs,
                web_paths=web_paths,
                params=params,
                sink_refs=sink_refs,
                metadata={k: v for k, v in item.items() if k not in {"finding_id", "title", "summary", "evidence_refs", "file_refs", "web_paths", "params", "sink_refs"}},
            )
        )
    return out


def _normalize_stringish_list(raw: Any) -> list[str]:
    if not isinstance(raw, list):
        return []
    out: list[str] = []
    seen: set[str] = set()
    for item in raw:
        if isinstance(item, (str, int, float)):
            value = str(item).strip()
        elif isinstance(item, (dict, list)):
            try:
                value = json.dumps(item, ensure_ascii=True, sort_keys=True)
            except Exception:
                value = str(item).strip()
        else:
            continue
        if not value or value in seen:
            continue
        seen.add(value)
        out.append(value)
    return out


def _canonical_candidate_id(current_id: str, refs: list[str]) -> str:
    token = str(current_id).strip()
    ref_ids = [
        str(ref).strip()
        for ref in refs
        if isinstance(ref, (str, int, float)) and re.match(r"^(cand|scip)-[A-Za-z0-9]+(?:-[A-Za-z0-9]+)?$", str(ref).strip())
    ]
    if not token:
        return ref_ids[0] if ref_ids else token
    if token in ref_ids:
        return token
    for ref_id in ref_ids:
        if token.startswith(f"{ref_id}-"):
            return ref_id
    return ref_ids[0] if ref_ids else token


def _candidate_from_payload(item: dict[str, Any]) -> Candidate | None:
    candidate_payload = item.get("candidate")
    if not isinstance(candidate_payload, dict):
        return None
    try:
        candidate = Candidate(**candidate_payload)
        candidate.expected_intercepts = _normalize_stringish_list(candidate.expected_intercepts)
        candidate.provenance = _normalize_stringish_list(candidate.provenance)
        candidate.evidence_refs = _normalize_stringish_list(candidate.evidence_refs)
        candidate.auth_requirements = _normalize_stringish_list(candidate.auth_requirements)
        candidate.web_path_hints = _normalize_stringish_list(candidate.web_path_hints)
        candidate.preconditions = _normalize_stringish_list(candidate.preconditions)
        candidate.candidate_id = _canonical_candidate_id(candidate.candidate_id, candidate.evidence_refs)
        return candidate
    except TypeError:
        return None


def _safe_int(value: Any, default: int = 1) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except Exception:
        return default


def _candidate_from_hypothesis_item(item: dict[str, Any], idx: int) -> Candidate:
    from_payload = _candidate_from_payload(item)
    if from_payload is not None:
        return from_payload

    candidate_id = str(item.get("candidate_id", "")).strip() or f"cand-{idx:05d}"
    vuln_class = str(item.get("vuln_class", "")).strip() or "unknown"
    sink = str(item.get("sink", "")).strip() or "unknown"
    expected_intercepts = [
        *_normalize_stringish_list(item.get("expected_intercepts", []))
    ] or ([sink] if sink else [])
    evidence_refs = _normalize_stringish_list(item.get("evidence_refs", []))
    return Candidate(
        candidate_id=_canonical_candidate_id(candidate_id, evidence_refs),
        vuln_class=vuln_class,
        title=str(item.get("title", "")).strip() or vuln_class,
        file_path=str(item.get("file_path", "")).strip() or "unknown.php",
        line=_safe_int(item.get("line", 1)),
        sink=sink,
        expected_intercepts=expected_intercepts,
        notes=str(item.get("notes", "")).strip(),
        provenance=_normalize_stringish_list(item.get("provenance", [])),
        evidence_refs=evidence_refs,
        confidence=_safe_float(item.get("confidence", 0.0)),
        auth_requirements=_normalize_stringish_list(item.get("auth_requirements", [])),
        web_path_hints=_normalize_stringish_list(item.get("web_path_hints", [])),
        preconditions=_normalize_stringish_list(item.get("preconditions", [])),
    )


def _unwrap_hypotheses_input(raw: Any) -> list[Any] | None:
    if isinstance(raw, dict):
        if isinstance(raw.get("hypotheses"), list):
            return raw.get("hypotheses")
        if isinstance(raw.get("hypothesis"), dict):
            return [raw.get("hypothesis")]
        if {"hypothesis_id", "objective_id", "vuln_class", "title", "rationale"} & set(raw.keys()):
            return [raw]
        return None
    if isinstance(raw, list):
        return raw
    return None


def _hypothesis_metadata(item: dict[str, Any]) -> dict[str, Any]:
    excluded = {"hypothesis_id", "objective_id", "vuln_class", "title", "rationale", "evidence_refs", "candidate", "candidate_id", "status", "confidence"}
    return {k: v for k, v in item.items() if k not in excluded}


def _normalize_hypotheses(raw: Any) -> list[Hypothesis]:
    items = _unwrap_hypotheses_input(raw)
    if items is None:
        return []
    out: list[Hypothesis] = []
    for idx, item in enumerate(items, start=1):
        if not isinstance(item, dict):
            continue
        candidate = _candidate_from_hypothesis_item(item, idx)
        out.append(
            Hypothesis(
                hypothesis_id=str(item.get("hypothesis_id", "")).strip() or f"hyp-{idx:05d}",
                objective_id=str(item.get("objective_id", "")).strip() or "objective-unknown",
                vuln_class=str(item.get("vuln_class", "")).strip() or candidate.vuln_class,
                title=str(item.get("title", "")).strip() or candidate.title,
                rationale=str(item.get("rationale", "")).strip() or "agentic hypothesis",
                evidence_refs=_normalize_stringish_list(item.get("evidence_refs", [])) or list(candidate.evidence_refs),
                candidate=candidate,
                status=str(item.get("status", "")).strip() or "active",
                confidence=float(item.get("confidence", candidate.confidence or 0.0)),
                auth_requirements=list(candidate.auth_requirements),
                preconditions=list(candidate.preconditions),
                gate_preconditions=merge_gate_preconditions(
                    candidate.gate_preconditions,
                    item.get("gate_preconditions"),
                ),
                web_path_hints=list(candidate.web_path_hints),
                metadata=_hypothesis_metadata(item),
            )
        )
    return out


def _normalize_refutations(raw: Any) -> list[Refutation]:
    if not isinstance(raw, list):
        return []
    out: list[Refutation] = []
    for idx, item in enumerate(raw, start=1):
        if not isinstance(item, dict):
            continue
        out.append(
            Refutation(
                refutation_id=str(item.get("refutation_id", "")).strip() or f"ref-{idx:05d}",
                hypothesis_id=str(item.get("hypothesis_id", "")).strip() or "unknown",
                title=str(item.get("title", "")).strip() or "refutation",
                summary=str(item.get("summary", "")).strip() or "skeptic refutation",
                evidence_refs=[
                    str(x).strip()
                    for x in item.get("evidence_refs", [])
                    if isinstance(x, (str, int, float)) and str(x).strip()
                ],
                severity=str(item.get("severity", "")).strip() or "medium",
                metadata={k: v for k, v in item.items() if k not in {"refutation_id", "hypothesis_id", "title", "summary", "evidence_refs", "severity"}},
            )
        )
    return out


def _unwrap_experiment_attempts_input(raw: Any) -> list[Any] | None:
    if isinstance(raw, dict):
        if isinstance(raw.get("plans"), list):
            return raw.get("plans")
        if {"candidate_id", "vuln_class", "title", "file_path", "sink"} & set(raw.keys()):
            return [raw]
        return None
    if isinstance(raw, list):
        return raw
    return None


def _normalize_experiment_attempts(raw: Any, config: PadvConfig) -> tuple[dict[str, ValidationPlan], list[ExperimentAttempt]]:
    plans: dict[str, ValidationPlan] = {}
    attempts: list[ExperimentAttempt] = []
    items = _unwrap_experiment_attempts_input(raw)
    if items is None:
        return plans, attempts
    for idx, item in enumerate(items, start=1):
        if not isinstance(item, dict):
            continue
        candidate = _candidate_from_hypothesis_item(item, idx)
        plan = _normalize_validation_plan_response(candidate, item, config)
        plans[candidate.candidate_id] = plan
        attempts.append(
            ExperimentAttempt(
                attempt_id=str(item.get("attempt_id", "")).strip() or f"exp-{idx:05d}",
                hypothesis_id=str(item.get("hypothesis_id", "")).strip() or candidate.candidate_id,
                plan_id=str(item.get("plan_id", "")).strip() or plan.candidate_id,
                request_refs=[
                    str(x).strip()
                    for x in item.get("request_refs", [])
                    if isinstance(x, (str, int, float)) and str(x).strip()
                ],
                witness_goal=str(item.get("witness_goal", "")).strip() or plan.strategy,
                status=str(item.get("status", "")).strip() or "planned",
                analysis_flags=[
                    str(x).strip()
                    for x in item.get("analysis_flags", [])
                    if isinstance(x, (str, int, float)) and str(x).strip()
                ],
                metadata={k: v for k, v in item.items() if k not in {"attempt_id", "hypothesis_id", "plan_id", "request_refs", "witness_goal", "status", "analysis_flags"}},
            )
        )
    return plans, attempts


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
        'Return JSON: {"drop_ids":[...], "confidence_overrides":{"id":0.0}, '
        '"triage_by_candidate":{"id":{"reproducibility_gap":"...","legitimacy_gap":"...",'
        '"impact_gap":"...","missing_witness":"..."}}, "notes":[...], "failed_paths":[...]}. '
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
    triage_by_candidate = _normalize_triage_by_candidate(
        response.get("triage_by_candidate"),
        {cand.candidate_id for cand in candidates},
    )
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
        "triage_by_candidate": triage_by_candidate,
    }
    return refined, trace


def _resolve_candidate_id(
    raw: Any,
    by_id: dict[str, Candidate],
    candidate_id_pattern: re.Pattern[str],
    trailing_num_pattern: re.Pattern[str],
    numeric_suffix_map: dict[int, list[str]],
) -> str | None:
    value = str(raw).strip()
    if not value:
        return None
    if value in by_id:
        return value
    for known_id in sorted(by_id.keys(), key=len, reverse=True):
        if known_id in value:
            return known_id
    match = candidate_id_pattern.search(value)
    if not match:
        return None
    token = match.group(0)
    if token in by_id:
        return token
    num_match = trailing_num_pattern.search(token)
    if not num_match:
        return None
    num = int(num_match.group(1))
    numeric_ids = numeric_suffix_map.get(num, [])
    if len(numeric_ids) == 1:
        return numeric_ids[0]
    return None


def _parse_info_gain_score(raw: Any) -> float | None:
    if isinstance(raw, bool):
        return None
    if isinstance(raw, (int, float)):
        return float(raw)
    if not isinstance(raw, str):
        return None
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


def _build_numeric_suffix_map(by_id: dict[str, Candidate]) -> dict[int, list[str]]:
    trailing_num_pattern = re.compile(r"(?:cand|scip)-0*(\d+)$", re.IGNORECASE)
    numeric_suffix_map: dict[int, list[str]] = {}
    for cid in by_id:
        match = trailing_num_pattern.search(cid)
        if not match:
            continue
        num = int(match.group(1))
        numeric_suffix_map.setdefault(num, []).append(cid)
    return numeric_suffix_map


def _parse_agent_actions(
    raw_actions: list[Any],
    by_id: dict[str, Candidate],
) -> tuple[dict[str, float], list[dict[str, Any]]]:
    candidate_id_pattern = re.compile(r"(?:cand|scip)-\d+", re.IGNORECASE)
    trailing_num_pattern = re.compile(r"(?:cand|scip)-0*(\d+)$", re.IGNORECASE)
    numeric_suffix_map = _build_numeric_suffix_map(by_id)

    selected_scores: dict[str, float] = {}
    actions: list[dict[str, Any]] = []
    for item in raw_actions:
        if not isinstance(item, dict):
            continue
        candidate_id = _resolve_candidate_id(
            item.get("candidate_id"), by_id, candidate_id_pattern, trailing_num_pattern, numeric_suffix_map,
        )
        if candidate_id is None:
            continue
        score = _parse_info_gain_score(item.get("expected_info_gain"))
        if score is None:
            continue
        if candidate_id in selected_scores:
            selected_scores[candidate_id] = max(selected_scores[candidate_id], score)
        else:
            selected_scores[candidate_id] = score
        actions.append(
            {
                "candidate_id": candidate_id,
                "action": str(item.get("action", "validate")).strip() or "validate",
                "expected_info_gain": score,
                "rationale": str(item.get("rationale", "")).strip(),
            }
        )
    return selected_scores, actions


def _compute_base_priority(candidate: Candidate, seen_classes: set[str], seen_files: set[str]) -> float:
    score = max(0.0, min(1.0, float(candidate.confidence)))
    if candidate.vuln_class not in seen_classes:
        score += 0.30
    if candidate.file_path not in seen_files:
        score += 0.20
    semantic_count = len(
        {
            signal.strip().lower()
            for signal in candidate.provenance
            if isinstance(signal, str) and signal.strip().lower() in _SEMANTIC_SIGNALS
        }
    )
    score += 0.08 * semantic_count
    if candidate.web_path_hints:
        score += 0.04
    if candidate.expected_intercepts:
        score += 0.03
    return score


def _extract_coverage_sets(frontier_state: dict[str, Any]) -> tuple[set[str], set[str]]:
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
    return seen_files, seen_classes


def _select_candidates_by_class_quota(
    ranked_ids: list[str],
    by_id: dict[str, Candidate],
    limit: int,
) -> list[str]:
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
            return selected_ids

    # Pass 2: fill remaining slots by priority.
    for cid in ranked_ids:
        if cid in selected_ids:
            continue
        selected_ids.append(cid)
        if len(selected_ids) >= limit:
            break
    return selected_ids


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
        '"skip_reasons":[{"candidate_id":"...","reproducibility_gap":"...","legitimacy_gap":"...",'
        '"impact_gap":"...","missing_witness":"..."}],"notes":[...]} '
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
    triage_by_candidate = _normalize_triage_by_candidate(
        response.get("skip_reasons"),
        set(by_id.keys()),
    )
    if not raw_actions:
        return [], {}, {
            "engine": "deepagents",
            "selected": [],
            "scores": {},
            "agent_scores": {},
            "actions": [],
            "notes": response.get("notes", []),
            "triage_by_candidate": triage_by_candidate,
            "selection_strategy": "agent-empty-selection",
            "agent_action_count": 0,
            "reason": "agent-no-actions",
        }

    selected_scores, actions = _parse_agent_actions(raw_actions, by_id)

    seen_files, seen_classes = _extract_coverage_sets(frontier_state)

    combined_scores: dict[str, float] = {}
    for cid, candidate in by_id.items():
        score = _compute_base_priority(candidate, seen_classes, seen_files)
        if cid in selected_scores:
            score = max(score, 1.0 + selected_scores[cid])
        combined_scores[cid] = score

    ranked_ids = sorted(
        combined_scores.keys(),
        key=lambda cid: (-combined_scores[cid], -by_id[cid].confidence, by_id[cid].file_path, by_id[cid].line),
    )
    limit = max(1, max_candidates)
    selected_ids = _select_candidates_by_class_quota(ranked_ids, by_id, limit)

    selected = [by_id[cid] for cid in selected_ids]
    limited_ids = {c.candidate_id for c in selected}
    trace = {
        "engine": "deepagents",
        "selected": [c.candidate_id for c in selected],
        "scores": {cid: round(combined_scores[cid], 4) for cid in limited_ids},
        "agent_scores": {cid: round(selected_scores[cid], 4) for cid in limited_ids if cid in selected_scores},
        "actions": [a for a in actions if a["candidate_id"] in limited_ids],
        "notes": response.get("notes", []),
        "triage_by_candidate": triage_by_candidate,
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
    candidate = apply_validation_profile(candidate)
    profile = profile_for_vuln_class(candidate.canonical_class or candidate.vuln_class)
    canary = f"padv-{candidate.candidate_id}-{uuid.uuid4().hex[:10]}"
    steps_raw = response.get("steps")
    oracle_spec_raw = response.get("oracle_spec")
    negative_controls_raw = response.get("negative_controls")
    budgets_raw = response.get("budgets")
    if not isinstance(steps_raw, list) or not isinstance(oracle_spec_raw, dict) or not isinstance(negative_controls_raw, list) or not isinstance(budgets_raw, dict):
        raise AgentExecutionError("deepagents plan response must include steps, oracle_spec, negative_controls, and budgets")

    def _replace_placeholder(value: Any, replacement: str) -> Any:
        if isinstance(value, str):
            return value.replace(_PLAN_CANARY_PLACEHOLDER, replacement)
        if isinstance(value, list):
            return [_replace_placeholder(item, replacement) for item in value]
        if isinstance(value, dict):
            return {key: _replace_placeholder(item, replacement) for key, item in value.items()}
        return value

    def _build_step(item: Any, *, field_name: str, idx: int) -> HttpStep:
        if not isinstance(item, dict):
            raise AgentExecutionError(f"deepagents plan {field_name}[{idx}] must be an object")
        method = str(item.get("method", "")).strip().upper()
        path = str(item.get("path", "")).strip()
        url = str(item.get("url", "")).strip()
        if not method or (not path and not url):
            raise AgentExecutionError(f"deepagents plan {field_name}[{idx}] must define method and path/url")
        expectations_raw = item.get("expectations", {})
        if expectations_raw is None:
            expectations_raw = {}
        if not isinstance(expectations_raw, dict):
            raise AgentExecutionError(f"deepagents plan {field_name}[{idx}].expectations must be an object")
        body_type = str(item.get("body_type", "")).strip().casefold() or "none"
        body = item.get("body")
        if body_type in {"text", "xml"} and body is not None and not isinstance(body, str):
            raise AgentExecutionError(f"deepagents plan {field_name}[{idx}].body must be a string for {body_type}")
        return HttpStep(
            method=method,
            path=path,
            url=url,
            headers=item.get("headers", {}),
            query=item.get("query", {}),
            body_type=body_type,
            body=body,
            body_ref=item.get("body_ref", ""),
            cookies=item.get("cookies", {}),
            expectations=HttpExpectations(**expectations_raw),
        )

    steps = [
        _build_step(_replace_placeholder(item, canary), field_name="steps", idx=idx)
        for idx, item in enumerate(steps_raw)
    ]
    if not steps:
        raise AgentExecutionError("deepagents plan response must include at least one validation step")

    oracle_functions = [
        str(item).strip()
        for item in oracle_spec_raw.get("oracle_functions", [])
        if isinstance(item, (str, int, float)) and str(item).strip()
    ]
    if not oracle_functions:
        raise AgentExecutionError("deepagents plan oracle_spec.oracle_functions must be a non-empty list")
    canary_rules_raw = oracle_spec_raw.get("canary_rules", [])
    if not isinstance(canary_rules_raw, list):
        raise AgentExecutionError("deepagents plan oracle_spec.canary_rules must be a list")
    oracle_spec = OracleSpec(
        intercept_profile=str(oracle_spec_raw.get("intercept_profile", "default")).strip() or "default",
        oracle_functions=oracle_functions,
        canary_rules=[
            CanaryMatchRule(**item)
            for item in _replace_placeholder(canary_rules_raw, canary)
            if isinstance(item, dict)
        ],
    )

    negative_controls: list[NegativeControl] = []
    for idx, item in enumerate(negative_controls_raw):
        if not isinstance(item, dict):
            raise AgentExecutionError(f"deepagents plan negative_controls[{idx}] must be an object")
        raw_step = item.get("step") if isinstance(item.get("step"), dict) else item
        negative_controls.append(
            NegativeControl(
                label=str(item.get("label", "")).strip() or f"control-{idx}",
                step=_build_step(
                    _replace_placeholder(raw_step, f"{canary}-control-{idx}"),
                    field_name="negative_controls",
                    idx=idx,
                ),
                expect_clean=bool(item.get("expect_clean", True)),
            )
        )

    max_requests = budgets_raw.get("max_requests")
    max_time_s = budgets_raw.get("max_time_s")
    if not isinstance(max_requests, int) or max_requests <= 0 or not isinstance(max_time_s, int) or max_time_s <= 0:
        raise AgentExecutionError("deepagents plan budgets must include positive integer max_requests and max_time_s")
    budgets = PlanBudget(max_requests=max_requests, max_time_s=max_time_s)

    gate_preconditions = merge_gate_preconditions(
        candidate.gate_preconditions,
        response.get("gate_preconditions"),
    )
    if gate_preconditions.is_empty():
        gate_preconditions = migrate_legacy_preconditions(
            preconditions=candidate.preconditions,
            auth_requirements=candidate.auth_requirements,
        )
    environment_requirements = []
    if gate_preconditions.requires_auth:
        environment_requirements.append("requires_auth")
    if gate_preconditions.requires_session:
        environment_requirements.append("requires_session")
    if gate_preconditions.requires_csrf_token:
        environment_requirements.append("requires_csrf_token")
    if gate_preconditions.requires_upload:
        environment_requirements.append("requires_upload")
    if gate_preconditions.requires_seed:
        environment_requirements.append("requires_seed")
    environment_requirements.extend(f"requires_header:{item}" for item in gate_preconditions.requires_specific_header)
    environment_requirements.extend(f"unknown_blocker:{item}" for item in gate_preconditions.unknown_blockers)

    return ValidationPlan(
        candidate_id=candidate.candidate_id,
        intercepts=list(oracle_spec.oracle_functions),
        positive_requests=[step.to_request_spec() for step in steps],
        negative_requests=[control.step.to_request_spec() for control in negative_controls],
        validation_mode=profile.validation_mode,
        canonical_class=profile.canonical_class,
        class_contract_id=profile.class_contract_id,
        gate_preconditions=gate_preconditions,
        environment_requirements=environment_requirements,
        requests=[step.to_request_spec() for step in steps],
        negative_controls=negative_controls,
        canary=canary,
        oracle_functions=list(oracle_spec.oracle_functions),
        strategy=str(response.get("strategy", "deepagents-plan")),
        negative_control_strategy=str(response.get("negative_control_strategy", "canary-mismatch")),
        plan_notes=[str(x) for x in response.get("plan_notes", []) if str(x).strip()],
        steps=steps,
        oracle_spec=oracle_spec,
        budgets=budgets,
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
        "Return only structured JSON with no prose-derived request fields. "
        "Use the literal placeholder __PADV_CANARY__ inside positive steps and oracle canary rules when a dynamic canary is needed. "
        "Prioritize reachable paths from web_path_hints and exploit-relevant parameters. "
        'Return JSON: {"candidate_id":"...","steps":[{"method":"GET","path":"/...","headers":{},"query":{},"body_type":"none","body":null,"expectations":{"status_codes":[200],"body_must_contain":[],"body_must_not_contain":[],"header_must_include":{}}}],"oracle_spec":{"intercept_profile":"default","oracle_functions":["..."],"canary_rules":[{"location":"response_body","match_type":"contains","value":"__PADV_CANARY__"}]},"negative_controls":[{"label":"control-0","step":{"method":"GET","path":"/...","headers":{},"query":{},"body_type":"none","body":null,"expectations":{"status_codes":[200],"body_must_contain":[],"body_must_not_contain":[],"header_must_include":{}}},"expect_clean":true}],"budgets":{"max_requests":4,"max_time_s":15},"strategy":"...","negative_control_strategy":"...","plan_notes":[...]} '
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


def _process_validation_plan_batch(
    batch: list[Candidate],
    config: PadvConfig,
    class_hint: str,
    *,
    repo_root: str | None,
    session: AgentSession | None,
) -> tuple[dict[str, ValidationPlan], dict[str, dict[str, Any]]]:
    payload = [cand.to_dict() for cand in batch]
    prompt = (
        "Create strict HTTP validation plans for each listed PHP web-security candidate. "
        "Return only structured JSON with no prose-derived request fields. "
        "Use the literal placeholder __PADV_CANARY__ inside positive steps and oracle canary rules when a dynamic canary is needed. "
        "Prioritize reachable paths from web_path_hints and exploit-relevant parameters. "
        'Return JSON: {"plans":[{"candidate_id":"...","steps":[{"method":"GET","path":"/...","headers":{},"query":{},"body_type":"none","body":null,"expectations":{"status_codes":[200],"body_must_contain":[],"body_must_not_contain":[],"header_must_include":{}}}],"oracle_spec":{"intercept_profile":"default","oracle_functions":["..."],"canary_rules":[{"location":"response_body","match_type":"contains","value":"__PADV_CANARY__"}]},"negative_controls":[{"label":"control-0","step":{"method":"GET","path":"/...","headers":{},"query":{},"body_type":"none","body":null,"expectations":{"status_codes":[200],"body_must_contain":[],"body_must_not_contain":[],"header_must_include":{}}},"expect_clean":true}],"budgets":{"max_requests":4,"max_time_s":15},"strategy":"...","negative_control_strategy":"...","plan_notes":[...]}],'
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

    by_id = _index_raw_plans_by_candidate_id(raw_plans)
    plans: dict[str, ValidationPlan] = {}
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
    return plans, by_id


def _index_raw_plans_by_candidate_id(raw_plans: list[Any]) -> dict[str, dict[str, Any]]:
    by_id: dict[str, dict[str, Any]] = {}
    for item in raw_plans:
        if not isinstance(item, dict):
            continue
        cid = item.get("candidate_id")
        if isinstance(cid, str) and cid.strip():
            by_id[cid.strip()] = item
    return by_id


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
        batch_plans, by_id = _process_validation_plan_batch(
            batch, config, class_hint, repo_root=repo_root, session=session,
        )
        plans.update(batch_plans)
        batches_trace.append(
            {
                "batch_index": (index // step) + 1,
                "batch_size": len(batch),
                "returned_plan_ids": sorted(by_id.keys()),
                "missing_ids": [],
                "notes": [],
            }
        )

    trace = {
        "engine": "deepagents",
        "batch_size": step,
        "planned": len(plans),
        "batches": batches_trace,
    }
    return plans, trace


def orient_root_agent(
    runtime: AgentRuntime,
    config: PadvConfig,
    *,
    frontier_state: dict[str, Any],
    discovery_trace: dict[str, Any],
    run_validation: bool,
    objective_queue: list[ObjectiveScore] | None = None,
) -> tuple[list[ObjectiveScore], dict[str, Any]]:
    remaining_objectives = [item.to_dict() for item in (objective_queue or [])]
    parsed, handoff_meta = _invoke_agent_handoff(
        runtime,
        runtime.root,
        config,
        category="orient",
        envelope={
            "run_validation": bool(run_validation),
            "discovery_trace": discovery_trace,
            "frontier_state": _compact_frontier_state(frontier_state),
            "remaining_objectives": remaining_objectives,
        },
        response_contract='{"objectives":[{"objective_id":"...","title":"...","rationale":"...","expected_info_gain":0.0,"priority":0.0,"channels":["source","graph","web"],"related_hypothesis_ids":[...]}],"notes":[...]}',
    )
    objectives = _limit_primary_objectives(_normalize_objectives(parsed.get("objectives", [])))
    if not objectives:
        fallback = _limit_primary_objectives(list(objective_queue or []))
        if not fallback:
            raise AgentExecutionError("root agent returned zero objectives")
        objectives = fallback
        notes = [
            *[str(item).strip() for item in parsed.get("notes", []) if str(item).strip()],
            "empty orient response replaced with remaining objective queue fallback",
        ]
        trace = {
            "engine": "deepagents",
            "notes": notes,
            "objective_ids": [o.objective_id for o in objectives],
            "fallback_used": True,
            **handoff_meta,
        }
        return objectives, trace
    return objectives, {"engine": "deepagents", "notes": parsed.get("notes", []), "objective_ids": [o.objective_id for o in objectives], "fallback_used": False, **handoff_meta}


def select_objective_with_root_agent(
    runtime: AgentRuntime,
    config: PadvConfig,
    *,
    objective_queue: list[ObjectiveScore],
    frontier_state: dict[str, Any],
) -> tuple[ObjectiveScore, dict[str, Any]]:
    parsed, handoff_meta = _invoke_agent_handoff(
        runtime,
        runtime.root,
        config,
        category="select_objective",
        envelope={
            "objective_queue": [o.to_dict() for o in objective_queue],
            "frontier_state": _compact_frontier_state(frontier_state),
        },
        response_contract='{"objective_id":"...","notes":[...]}',
    )
    selected_id = str(parsed.get("objective_id", "")).strip()
    selected = next((item for item in objective_queue if item.objective_id == selected_id), None)
    if selected is None:
        raise AgentExecutionError(f"root agent selected unknown objective: {selected_id}")
    return selected, {"engine": "deepagents", "selected_objective_id": selected.objective_id, "notes": parsed.get("notes", []), **handoff_meta}


def run_research_subagent(
    runtime: AgentRuntime,
    role: str,
    config: PadvConfig,
    *,
    objective: ObjectiveScore,
    frontier_state: dict[str, Any],
) -> tuple[list[ResearchTask], list[ResearchFinding], dict[str, Any]]:
    session = runtime.subagents.get(role, runtime.root)
    parsed, handoff_meta = _invoke_agent_handoff(
        runtime,
        session,
        config,
        category=f"{role}_research",
        envelope={
            "objective": objective.to_dict(),
            "frontier_state": _compact_research_frontier_state(frontier_state),
        },
        response_contract='{"findings":[{"finding_id":"...","title":"...","summary":"...","evidence_refs":[...],"file_refs":[...],"web_paths":[...],"params":[...],"sink_refs":[...]}],"notes":[...]}',
        workspace_role=role,
    )
    tasks = _normalize_research_tasks(parsed.get("tasks", []), objective_id=objective.objective_id, channel=role)
    findings = _normalize_research_findings(parsed.get("findings", []), objective_id=objective.objective_id, channel=role)
    return tasks, findings, {"engine": "deepagents", "role": role, "notes": parsed.get("notes", []), "task_ids": [t.task_id for t in tasks], "finding_ids": [f.finding_id for f in findings], **handoff_meta}


def synthesize_hypotheses_with_subagent(
    runtime: AgentRuntime,
    config: PadvConfig,
    *,
    objective: ObjectiveScore,
    findings: list[ResearchFinding],
    frontier_state: dict[str, Any],
) -> tuple[list[Hypothesis], dict[str, Any]]:
    if not findings:
        return [], {"engine": "deepagents", "reason": "no-findings", "hypothesis_ids": []}
    parsed, handoff_meta = _invoke_agent_handoff(
        runtime,
        runtime.subagents.get("exploit", runtime.root),
        config,
        category="hypothesis_synthesis",
        envelope={
            "objective": objective.to_dict(),
            "research_findings": _compact_research_findings(findings),
            "frontier_state": _compact_frontier_state(frontier_state),
        },
        response_contract='{"hypotheses":[{"hypothesis_id":"...","objective_id":"...","vuln_class":"...","title":"...","rationale":"...","evidence_refs":[...],"candidate":{"candidate_id":"...","vuln_class":"...","title":"...","file_path":"...","line":1,"sink":"...","expected_intercepts":[...],"notes":"...","provenance":[...],"evidence_refs":[...],"confidence":0.0,"auth_requirements":[...],"web_path_hints":[...],"preconditions":[...]},"confidence":0.0,"status":"active"}],"notes":[...]}',
        workspace_role="exploit",
    )
    hypotheses = _normalize_hypotheses(parsed.get("hypotheses", []))
    if findings and not hypotheses:
        import sys
        print("WARNING: exploit subagent returned zero hypotheses for objective; skipping", file=sys.stderr)
    return hypotheses, {"engine": "deepagents", "notes": parsed.get("notes", []), "hypothesis_ids": [h.hypothesis_id for h in hypotheses], **handoff_meta}


def challenge_hypotheses_with_subagent(
    runtime: AgentRuntime,
    config: PadvConfig,
    *,
    hypotheses: list[Hypothesis],
) -> tuple[list[Refutation], dict[str, Any]]:
    prioritized_hypotheses = sorted(
        hypotheses,
        key=lambda item: float(item.confidence or 0.0),
        reverse=True,
    )[:3]
    if not prioritized_hypotheses:
        return [], {"engine": "deepagents", "reason": "no-hypotheses", "refutation_ids": []}
    try:
        parsed, handoff_meta = _invoke_agent_handoff(
            runtime,
            runtime.subagents.get("skeptic", runtime.root),
            config,
            category="skeptic_challenge",
            envelope={
                "hypotheses": _compact_hypotheses_for_skeptic(prioritized_hypotheses, limit=3),
                "skeptic_scope": {
                    "focus": _SKEPTIC_FOCUS,
                    "defer_environmental_constraints": True,
                },
            },
            response_contract='{"refutations":[{"refutation_id":"...","hypothesis_id":"...","title":"...","summary":"...","evidence_refs":[...],"severity":"low|medium|high"}],"notes":[...]}',
            workspace_role="skeptic",
        )
        refutations = [
            item
            for item in _normalize_refutations(parsed.get("refutations", []))
            if not _is_environmental_skeptic_text(f"{item.title} {item.summary}")
        ]
        return refutations, {"engine": "deepagents", "notes": parsed.get("notes", []), "refutation_ids": [r.refutation_id for r in refutations], **handoff_meta}
    except AgentExecutionError as exc:
        return [], {
            "engine": "deepagents-fallback",
            "notes": [],
            "refutation_ids": [],
            "fallback_error": str(exc),
            "fallback_reason": "skeptic-timeout-or-agent-error",
            "hypothesis_ids": [item.hypothesis_id for item in prioritized_hypotheses],
        }


def _collect_fallback_candidates(
    prioritized_hypotheses: list[Hypothesis],
) -> tuple[list[Candidate], dict[str, Hypothesis]]:
    fallback_candidates: list[Candidate] = []
    candidate_to_hypothesis: dict[str, Hypothesis] = {}
    for item in prioritized_hypotheses:
        candidate = item.candidate
        if candidate.candidate_id in candidate_to_hypothesis:
            continue
        candidate_to_hypothesis[candidate.candidate_id] = item
        fallback_candidates.append(candidate)
    return fallback_candidates, candidate_to_hypothesis


def _build_experiment_fallback_attempts(
    fallback_candidates: list[Candidate],
    candidate_to_hypothesis: dict[str, Hypothesis],
    plans: dict[str, ValidationPlan],
    exc: Exception,
) -> list[ExperimentAttempt]:
    attempts: list[ExperimentAttempt] = []
    for idx, candidate in enumerate(fallback_candidates, start=1):
        plan = plans.get(candidate.candidate_id)
        hypothesis = candidate_to_hypothesis.get(candidate.candidate_id)
        if plan is None or hypothesis is None:
            continue
        attempts.append(
            ExperimentAttempt(
                attempt_id=f"fallback-attempt-{idx:04d}",
                hypothesis_id=hypothesis.hypothesis_id,
                plan_id=f"fallback-plan-{idx:04d}",
                request_refs=[],
                witness_goal=hypothesis.vuln_class,
                status="planned",
                analysis_flags=["fallback-plan"],
                metadata={"fallback_error": str(exc)},
            )
        )
    return attempts


def _plan_experiments_primary(
    runtime: AgentRuntime,
    config: PadvConfig,
    hypotheses: list[Hypothesis],
    prioritized_hypotheses: list[Hypothesis],
) -> tuple[dict[str, ValidationPlan], list[ExperimentAttempt], dict[str, Any]]:
    parsed, handoff_meta = _invoke_agent_handoff(
        runtime,
        runtime.subagents.get("experiment", runtime.root),
        config,
        category="experiment_plan",
        envelope={
            "hypotheses": _compact_hypotheses_for_skeptic(prioritized_hypotheses, limit=3),
            "skeptic_scope": {
                "focus": _SKEPTIC_FOCUS,
                "defer_environmental_constraints": True,
            },
        },
        response_contract='{"plans":[{"hypothesis_id":"...","candidate":{"candidate_id":"...","vuln_class":"...","title":"...","file_path":"...","line":1,"sink":"...","expected_intercepts":[...],"notes":"...","provenance":[...],"evidence_refs":[...],"confidence":0.0},"steps":[{"method":"GET","path":"/...","headers":{},"query":{},"body_type":"none","body":null,"expectations":{"status_codes":[200],"body_must_contain":[],"body_must_not_contain":[],"header_must_include":{}}}],"oracle_spec":{"intercept_profile":"default","oracle_functions":["..."],"canary_rules":[{"location":"response_body","match_type":"contains","value":"__PADV_CANARY__"}]},"negative_controls":[{"label":"control-0","step":{"method":"GET","path":"/...","headers":{},"query":{},"body_type":"none","body":null,"expectations":{"status_codes":[200],"body_must_contain":[],"body_must_not_contain":[],"header_must_include":{}}},"expect_clean":true}],"budgets":{"max_requests":4,"max_time_s":15},"strategy":"...","negative_control_strategy":"...","plan_notes":[...],"attempt_id":"...","plan_id":"...","request_refs":[...],"witness_goal":"...","status":"planned","analysis_flags":[...]}],"notes":[...]}',
        workspace_role="experiment",
    )
    plans, attempts = _normalize_experiment_attempts(parsed.get("plans", parsed), config)
    if hypotheses and not plans:
        raise AgentExecutionError("experiment subagent returned zero plans")
    return plans, attempts, {"engine": "deepagents", "notes": parsed.get("notes", []), "planned_candidate_ids": sorted(plans.keys()), **handoff_meta}


def _plan_experiments_fallback(
    runtime: AgentRuntime,
    config: PadvConfig,
    hypotheses: list[Hypothesis],
    prioritized_hypotheses: list[Hypothesis],
    exc: AgentExecutionError,
) -> tuple[dict[str, ValidationPlan], list[ExperimentAttempt], dict[str, Any]]:
    fallback_candidates, candidate_to_hypothesis = _collect_fallback_candidates(prioritized_hypotheses)
    if not fallback_candidates:
        raise exc
    plans, fallback_trace = make_validation_plans_with_deepagents(
        fallback_candidates,
        config,
        repo_root=runtime.repo_root,
        session=runtime.subagents.get("experiment", runtime.root),
        batch_size=2,
    )
    attempts = _build_experiment_fallback_attempts(fallback_candidates, candidate_to_hypothesis, plans, exc)
    if hypotheses and not plans:
        raise exc
    return plans, attempts, {
        "engine": "deepagents-fallback",
        "notes": [],
        "planned_candidate_ids": sorted(plans.keys()),
        "fallback_error": str(exc),
        "fallback_trace": fallback_trace,
    }


def plan_experiments_with_subagent(
    runtime: AgentRuntime,
    config: PadvConfig,
    *,
    hypotheses: list[Hypothesis],
) -> tuple[dict[str, ValidationPlan], list[ExperimentAttempt], dict[str, Any]]:
    # NOTE: config.agent.max_parallel_experiments is defined but not yet
    # wired. Experiment planning currently runs sequentially. When parallel
    # experiment execution is implemented, this value should cap the number
    # of concurrent experiment subagent invocations.
    # Similarly, config.agent.max_parallel_research and
    # config.agent.max_parallel_skeptic are reserved for future parallelism.
    prioritized_hypotheses = sorted(
        hypotheses,
        key=lambda item: float(item.confidence or 0.0),
        reverse=True,
    )[:3]
    if not prioritized_hypotheses:
        return {}, [], {"engine": "deepagents", "reason": "no-hypotheses", "planned_candidate_ids": []}
    try:
        return _plan_experiments_primary(runtime, config, hypotheses, prioritized_hypotheses)
    except AgentExecutionError as exc:
        return _plan_experiments_fallback(runtime, config, hypotheses, prioritized_hypotheses, exc)


def decide_continue_with_root_agent(
    runtime: AgentRuntime,
    config: PadvConfig,
    *,
    iteration: int,
    objective_queue: list[ObjectiveScore],
    hypotheses: list[Hypothesis],
    refutations: list[Refutation],
    witness_bundles: list[WitnessBundle],
    max_iterations: int,
) -> tuple[bool, dict[str, Any]]:
    parsed, handoff_meta = _invoke_agent_handoff(
        runtime,
        runtime.root,
        config,
        category="continue_or_stop",
        envelope={
            "iteration": iteration,
            "max_iterations": max_iterations,
            "objective_queue": [o.to_dict() for o in objective_queue],
            "hypotheses": [h.to_dict() for h in hypotheses],
            "refutations": [r.to_dict() for r in refutations],
            "witness_bundles": [w.to_dict() for w in witness_bundles],
            "frontier_state": _compact_frontier_state(runtime.shared_context.get("frontier_state")),
        },
        response_contract='{"continue":true,"reason":"...","notes":[...]}',
    )
    should_continue = bool(parsed.get("continue")) and iteration < max_iterations
    return should_continue, {"engine": "deepagents", "reason": str(parsed.get("reason", "")).strip(), "notes": parsed.get("notes", []), **handoff_meta}

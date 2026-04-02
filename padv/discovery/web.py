from __future__ import annotations

import asyncio
import json
import re
import urllib.parse
from collections.abc import Awaitable, Callable
from typing import Any, TypedDict

from padv.config.schema import PadvConfig

_JSON_BLOCK_RE = re.compile(r"\{.*\}", re.DOTALL)


class _LLMState(TypedDict, total=False):
    prompt: str
    parsed: dict[str, Any]


class _WebState(TypedDict, total=False):
    queue: list[str]
    seen: list[str]
    visited: list[str]
    found: dict[str, list[str]]
    pages: list[dict[str, Any]]
    requests: list[dict[str, Any]]
    errors: list[str]
    steps: int
    current_url: str
    current_path: str
    candidate_urls: list[str]
    candidate_params: list[str]


def _normalize_path(url: str) -> tuple[str, list[str]]:
    parsed = urllib.parse.urlsplit(url)
    params = sorted(urllib.parse.parse_qs(parsed.query, keep_blank_values=True).keys())
    path = parsed.path or "/"
    return path, params


def _base_origin(url: str) -> tuple[str, str]:
    parsed = urllib.parse.urlsplit(url)
    return parsed.scheme, parsed.netloc


def _canonicalize_url(raw: str, *, base_url: str) -> str | None:
    value = str(raw or "").strip()
    if not value:
        return None
    if value.startswith(("javascript:", "mailto:", "tel:", "data:")):
        return None

    absolute = urllib.parse.urljoin(base_url, value)
    parsed = urllib.parse.urlsplit(absolute)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None

    base_scheme, base_netloc = _base_origin(base_url)
    if parsed.netloc != base_netloc:
        return None

    normalized_path = parsed.path or "/"
    cleaned = urllib.parse.urlunsplit((base_scheme or parsed.scheme, parsed.netloc, normalized_path, parsed.query, ""))
    return cleaned


def _extract_text_from_langchain_message(result: Any) -> str:
    content = getattr(result, "content", None)
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        chunks: list[str] = []
        for item in content:
            if isinstance(item, str):
                chunks.append(item)
                continue
            if isinstance(item, dict):
                text = item.get("text")
                if isinstance(text, str):
                    chunks.append(text)
        return "\n".join(chunks)
    if isinstance(result, str):
        return result
    return ""


def _extract_json_object(text: str) -> dict[str, Any] | None:
    body = text.strip()
    if not body:
        return None
    try:
        parsed = json.loads(body)
        if isinstance(parsed, dict):
            return parsed
    except json.JSONDecodeError:
        pass

    match = _JSON_BLOCK_RE.search(body)
    if not match:
        return None
    try:
        parsed = json.loads(match.group(0))
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


async def _safe_dismiss_dialog(dialog: Any) -> None:
    try:
        await dialog.dismiss()
    except Exception:
        # Some targets open dialogs while the page is already tearing down.
        return


def _install_dialog_guards(context: Any, page: Any) -> None:
    def _wire_dialog_handler(target_page: Any) -> None:
        target_page.on("dialog", lambda dialog: asyncio.create_task(_safe_dismiss_dialog(dialog)))

    _wire_dialog_handler(page)
    context.on("page", _wire_dialog_handler)


def _build_llm(config: PadvConfig):
    from langchain_anthropic import ChatAnthropic  # type: ignore[import-not-found]

    api_key = __import__("os").environ.get(config.llm.api_key_env)
    if not api_key:
        raise RuntimeError(f"missing API key env var: {config.llm.api_key_env}")
    if config.llm.provider != "anthropic":
        raise RuntimeError(f"unsupported llm provider for web discovery: {config.llm.provider}")

    return ChatAnthropic(
        model=config.llm.model,
        anthropic_api_key=api_key,
        timeout=float(config.llm.timeout_seconds),
        max_tokens=config.llm.max_tokens,
        temperature=config.llm.temperature,
        max_retries=2,
    )


def _add_found(found: dict[str, list[str]], path: str, params: list[str]) -> dict[str, list[str]]:
    normalized_path = path or "/"
    existing = found.get(normalized_path, [])
    filtered = [p for p in params if isinstance(p, str) and p.strip()]
    found[normalized_path] = sorted(set(existing).union(filtered))
    return found


async def _invoke_llm_json_via_langgraph(config: PadvConfig, prompt: str) -> dict[str, Any]:
    from langgraph.graph import END, START, StateGraph  # type: ignore[import-not-found]

    llm = _build_llm(config)

    async def _node_infer(state: _LLMState) -> _LLMState:
        response = await llm.ainvoke(state.get("prompt", ""))
        parsed = _extract_json_object(_extract_text_from_langchain_message(response))
        if parsed is None:
            raise RuntimeError("web discovery llm returned non-JSON response")
        return {"parsed": parsed}

    builder = StateGraph(_LLMState)
    builder.add_node("infer", _node_infer)
    builder.add_edge(START, "infer")
    builder.add_edge("infer", END)
    graph = builder.compile()

    result = await graph.ainvoke({"prompt": prompt})
    parsed = result.get("parsed") if isinstance(result, dict) else None
    if not isinstance(parsed, dict):
        raise RuntimeError("web discovery llm graph returned invalid result")
    return parsed


async def _llm_select_next_urls(
    config: PadvConfig,
    *,
    current_url: str,
    visited_urls: list[str],
    candidate_urls: list[str],
    candidate_params: list[str],
    remaining_budget: int,
) -> tuple[list[str], list[str]]:
    if not candidate_urls and not candidate_params:
        return [], []

    prompt = (
        "You are a web security discovery planner for a PHP target. "
        "Select next URLs to visit for maximum information gain and likely exploitability. "
        "Avoid logout/signout and already-visited URLs. "
        "Return strict JSON only with this schema: "
        '{"next_urls":["..."],"likely_params":["..."]}. '
        f"Current URL: {current_url}\n"
        f"Already visited URLs: {json.dumps(visited_urls[-120:], ensure_ascii=True)}\n"
        f"Candidate URLs: {json.dumps(candidate_urls[:120], ensure_ascii=True)}\n"
        f"Candidate params: {json.dumps(candidate_params[:120], ensure_ascii=True)}\n"
        f"Remaining URL budget: {remaining_budget}\n"
        "Keep next_urls short and focused."
    )

    parsed = await _invoke_llm_json_via_langgraph(config, prompt)

    raw_urls = parsed.get("next_urls", [])
    raw_params = parsed.get("likely_params", [])

    next_urls = [str(x).strip() for x in raw_urls if isinstance(x, (str, int, float)) and str(x).strip()]
    likely_params = [
        str(x).strip()
        for x in raw_params
        if isinstance(x, (str, int, float)) and str(x).strip() and re.fullmatch(r"[A-Za-z0-9_\-]{1,64}", str(x).strip())
    ]
    return next_urls, likely_params


async def _llm_select_login_selectors(config: PadvConfig, form_meta: Any) -> tuple[str, str, str]:
    prompt = (
        "Choose CSS selectors for login fields from this form metadata. "
        "Return JSON only: "
        '{"username_selector":"...","password_selector":"...","submit_selector":"..."}. '
        f"Metadata: {json.dumps(form_meta, ensure_ascii=True)}"
    )
    parsed = await _invoke_llm_json_via_langgraph(config, prompt)

    u_sel = parsed.get("username_selector")
    p_sel = parsed.get("password_selector")
    s_sel = parsed.get("submit_selector")
    username_selector = u_sel.strip() if isinstance(u_sel, str) else ""
    password_selector = p_sel.strip() if isinstance(p_sel, str) else ""
    submit_selector = s_sel.strip() if isinstance(s_sel, str) else ""
    return username_selector, password_selector, submit_selector


async def _extract_page_observations(page: Any) -> dict[str, Any]:
    result = await page.evaluate(
        """
        () => {
          const urls = [];
          for (const a of document.querySelectorAll('a[href]')) {
            if (a && a.href) urls.push(a.href);
          }
          for (const f of document.querySelectorAll('form[action]')) {
            const action = f.getAttribute('action') || '';
            if (action) {
              try {
                urls.push(new URL(action, window.location.href).toString());
              } catch (_) {}
            }
          }

          const params = [];
          for (const el of document.querySelectorAll('input[name], select[name], textarea[name]')) {
            const name = (el.getAttribute('name') || '').trim();
            if (name) params.push(name);
          }
          for (const u of urls) {
            try {
              const parsed = new URL(u);
              for (const key of parsed.searchParams.keys()) params.push(key);
            } catch (_) {}
          }

          const title = document.title || '';
          const h1 = Array.from(document.querySelectorAll('h1, h2')).map(x => (x.textContent || '').trim()).filter(Boolean).slice(0, 6);
          const forms = [];
          for (const f of document.querySelectorAll('form')) {
            const inputs = [];
            for (const i of f.querySelectorAll('input,select,textarea')) {
              inputs.push({
                name: i.getAttribute('name') || '',
                id: i.id || '',
                type: i.getAttribute('type') || i.tagName.toLowerCase(),
                required: i.hasAttribute('required'),
              });
            }
            forms.push({
              action: f.getAttribute('action') || '',
              method: (f.getAttribute('method') || 'get').toLowerCase(),
              inputs,
            });
          }
          return {
            urls,
            params,
            summary: `${title}\n${h1.join(' | ')}`.trim(),
            title,
            headings: h1,
            forms,
          };
        }
        """
    )

    if not isinstance(result, dict):
        return {"urls": [], "params": [], "summary": "", "title": "", "headings": [], "forms": []}
    urls = [str(x).strip() for x in result.get("urls", []) if isinstance(x, str) and x.strip()]
    params = [str(x).strip() for x in result.get("params", []) if isinstance(x, str) and x.strip()]
    headings = [str(x).strip() for x in result.get("headings", []) if isinstance(x, str) and x.strip()]
    forms: list[dict[str, Any]] = []
    for item in result.get("forms", []):
        if not isinstance(item, dict):
            continue
        action = str(item.get("action", "")).strip()
        method = str(item.get("method", "get")).strip().lower() or "get"
        inputs: list[dict[str, Any]] = []
        for raw in item.get("inputs", []):
            if not isinstance(raw, dict):
                continue
            inputs.append(
                {
                    "name": str(raw.get("name", "")).strip(),
                    "id": str(raw.get("id", "")).strip(),
                    "type": str(raw.get("type", "")).strip().lower(),
                    "required": bool(raw.get("required", False)),
                }
            )
        forms.append({"action": action, "method": method, "inputs": inputs})
    summary = str(result.get("summary", "")).strip()
    return {
        "urls": urls,
        "params": params,
        "summary": summary,
        "title": str(result.get("title", "")).strip(),
        "headings": headings,
        "forms": forms,
    }


def _cookie_origin_fields(base_url: str) -> tuple[str, str, bool]:
    parsed = urllib.parse.urlsplit(base_url)
    scheme = parsed.scheme or "http"
    host = parsed.hostname or ""
    secure = scheme == "https"
    return scheme, host, secure


def _build_initial_url_lists(
    base_url: str,
    seed_urls: list[str] | None,
) -> tuple[list[str], list[str]]:
    initial_queue: list[str] = []
    initial_seen: list[str] = []
    for raw in [base_url] + list(seed_urls or []):
        normalized = _canonicalize_url(raw, base_url=base_url)
        if not normalized or normalized in initial_seen:
            continue
        initial_seen.append(normalized)
        initial_queue.append(normalized)
    return initial_queue, initial_seen


async def _inject_cookies(context: Any, auth_state: dict[str, Any] | None, base_url: str) -> None:
    cookie_map = auth_state.get("cookies", {}) if isinstance(auth_state, dict) else {}
    if not isinstance(cookie_map, dict) or not cookie_map:
        return
    scheme, host, secure = _cookie_origin_fields(base_url)
    cookies_payload = [
        {
            "name": str(name),
            "value": str(value),
            "domain": host,
            "path": "/",
            "httpOnly": False,
            "secure": secure,
            "sameSite": "Lax",
            "url": f"{scheme}://{host}/",
        }
        for name, value in cookie_map.items()
        if str(name).strip()
    ]
    if cookies_payload:
        await context.add_cookies(cookies_payload)


def _make_request_recorder(requests: list[dict[str, Any]], base_url: str) -> Callable[[Any], None]:
    def _record_request(request: Any) -> None:
        try:
            candidate = _canonicalize_url(request.url, base_url=base_url)
            if not candidate:
                return
            path, params = _normalize_path(candidate)
            requests.append(
                {
                    "url": candidate,
                    "path": path,
                    "method": str(getattr(request, "method", "") or "").upper(),
                    "resource_type": str(getattr(request, "resource_type", "") or ""),
                    "params": params,
                }
            )
        except Exception:
            return
    return _record_request


def _pop_next_unvisited(queue: list[str], visited: list[str]) -> str:
    while queue:
        candidate = queue.pop(0)
        if candidate not in visited:
            return candidate
    return ""


def _seed_urls_into_queue(
    candidate_urls: list[str],
    seen: list[str],
    visited: list[str],
    queue: list[str],
    seed_cap: int,
) -> None:
    for url in candidate_urls[:8]:
        if url in seen or url in visited:
            continue
        if len(seen) >= seed_cap:
            break
        seen.append(url)
        queue.append(url)


def _enqueue_llm_urls(
    llm_urls: list[str],
    base_url: str,
    seen: list[str],
    visited: list[str],
    queue: list[str],
    queue_cap: int,
) -> None:
    for raw in llm_urls:
        normalized = _canonicalize_url(raw, base_url=base_url)
        if not normalized or normalized in seen or normalized in visited:
            continue
        if len(seen) >= queue_cap:
            break
        seen.append(normalized)
        queue.append(normalized)


def _normalize_found_results(found: dict[str, list[str]]) -> dict[str, list[str]]:
    normalized: dict[str, list[str]] = {}
    for path, params in found.items():
        if not isinstance(path, str):
            continue
        if isinstance(params, list):
            normalized[path] = sorted({str(x).strip() for x in params if str(x).strip()})
        else:
            normalized[path] = []
    return normalized


def _build_discovery_artifacts(
    result: dict[str, Any],
    initial_queue: list[str],
) -> dict[str, Any]:
    pages = result.get("pages", []) if isinstance(result, dict) else []
    requests_payload = result.get("requests", []) if isinstance(result, dict) else []
    errors = result.get("errors", []) if isinstance(result, dict) else []
    visited_urls = result.get("visited", []) if isinstance(result, dict) else []
    return {
        "seed_urls": initial_queue,
        "visited_urls": [str(x).strip() for x in visited_urls if isinstance(x, str) and str(x).strip()],
        "pages": [item for item in pages if isinstance(item, dict)],
        "requests": [item for item in requests_payload if isinstance(item, dict)][:200],
        "errors": [str(x).strip() for x in errors if isinstance(x, str) and str(x).strip()],
    }


def _empty_discovery_result(initial_queue: list[str] | None = None) -> dict[str, Any]:
    return {"hints": {}, "artifacts": {"seed_urls": list(initial_queue or []), "visited_urls": [], "pages": [], "requests": [], "errors": []}}


def _collect_candidate_urls(observation: dict[str, Any], base_url: str) -> list[str]:
    candidate_urls: list[str] = []
    for raw in observation.get("urls", []):
        normalized = _canonicalize_url(raw, base_url=base_url)
        if normalized:
            candidate_urls.append(normalized)
    return candidate_urls


def _build_page_record(
    canonical_url: str,
    current_path: str,
    observation: dict[str, Any],
    raw_params: list[str],
    candidate_urls: list[str],
) -> dict[str, Any]:
    return {
        "url": canonical_url, "path": current_path,
        "summary": str(observation.get("summary", "")).strip(),
        "title": str(observation.get("title", "")).strip(),
        "headings": list(observation.get("headings", []))[:12],
        "params": raw_params[:64],
        "candidate_urls": candidate_urls[:24],
        "forms": list(observation.get("forms", []))[:12],
    }


async def _navigate_and_extract_page(
    page: Any,
    current: str,
    base_url: str,
    timeout_ms: int,
) -> tuple[str, str, list[str], list[str], dict[str, Any]]:
    """Navigate to *current* and return (canonical_url, path, params, urls, observation)."""
    await page.goto(current, wait_until="domcontentloaded", timeout=timeout_ms)
    live_url = page.url or current
    canonical = _canonicalize_url(live_url, base_url=base_url) or current
    path, query_params = _normalize_path(canonical)
    observation = await _extract_page_observations(page)
    raw_params = list(observation.get("params", []))
    candidate_urls = _collect_candidate_urls(observation, base_url)
    return canonical, path, query_params + raw_params, candidate_urls, observation


async def _discover_with_playwright_async(
    config: PadvConfig,
    seed_urls: list[str] | None = None,
    auth_state: dict[str, Any] | None = None,
) -> dict[str, Any]:
    from langgraph.graph import END, START, StateGraph  # type: ignore[import-not-found]
    from playwright.async_api import async_playwright  # type: ignore[import-not-found]

    base_url = config.target.base_url
    initial_queue, initial_seen = _build_initial_url_lists(base_url, seed_urls)

    if not initial_queue:
        return _empty_discovery_result()

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=config.web.headless)
        context = await browser.new_context(ignore_https_errors=True)
        await _inject_cookies(context, auth_state, base_url)
        page = await context.new_page()
        _install_dialog_guards(context, page)
        requests: list[dict[str, Any]] = []
        page.on("request", _make_request_recorder(requests, base_url))

        timeout_ms = max(1, int(config.web.request_timeout_seconds)) * 1000

        def _unpack_navigate_state(state: _WebState) -> tuple[list, list, list, dict, list, list, int]:
            return (
                list(state.get("queue", [])),
                list(state.get("seen", [])),
                list(state.get("visited", [])),
                dict(state.get("found", {})),
                list(state.get("pages", [])),
                list(state.get("errors", [])),
                int(state.get("steps", 0)),
            )

        def _build_navigate_result(
            queue: list, seen: list, visited: list, found: dict,
            pages_list: list, errors: list, steps: int,
            current_url: str, current_path: str,
            candidate_urls: list[str], candidate_params: list[str],
        ) -> _WebState:
            return {
                "queue": queue, "seen": seen, "visited": visited,
                "found": found, "pages": pages_list, "requests": list(requests),
                "errors": errors, "steps": steps, "current_url": current_url,
                "current_path": current_path, "candidate_urls": candidate_urls,
                "candidate_params": candidate_params,
            }

        async def _node_navigate_extract(state: _WebState) -> _WebState:
            queue, seen, visited, found, pages_list, errors, steps = _unpack_navigate_state(state)

            current = _pop_next_unvisited(queue, visited)
            if not current:
                return _build_navigate_result(queue, seen, visited, found, pages_list, errors, steps, "", "", [], [])

            steps += 1
            canonical_current = current
            current_path = _normalize_path(current)[0]
            candidate_urls: list[str] = []
            candidate_params: list[str] = []

            try:
                canonical_current, current_path, all_params, candidate_urls, obs = (
                    await _navigate_and_extract_page(page, current, base_url, timeout_ms)
                )
                candidate_params = list(obs.get("params", []))
                found = _add_found(found, current_path, all_params)
                _seed_urls_into_queue(candidate_urls, seen, visited, queue, max(config.web.max_pages * 6, 64))
                pages_list.append(_build_page_record(canonical_current, current_path, obs, candidate_params, candidate_urls))
            except Exception:
                errors.append(f"navigation_failed:{current}")

            if canonical_current not in visited:
                visited.append(canonical_current)

            return _build_navigate_result(
                queue, seen, visited, found, pages_list, errors, steps,
                canonical_current, current_path, candidate_urls, candidate_params,
            )

        async def _node_llm_plan(state: _WebState) -> _WebState:
            queue = list(state.get("queue", []))
            seen = list(state.get("seen", []))
            visited = list(state.get("visited", []))
            found = dict(state.get("found", {}))

            current_url = str(state.get("current_url", "")).strip()
            current_path = str(state.get("current_path", "")).strip() or "/"

            remaining = max(0, config.web.max_pages - len(visited))
            if not current_url or remaining <= 0:
                return {"queue": queue, "seen": seen, "visited": visited, "found": found}

            llm_urls, llm_params = await _llm_select_next_urls(
                config,
                current_url=current_url,
                visited_urls=visited,
                candidate_urls=list(state.get("candidate_urls", [])),
                candidate_params=list(state.get("candidate_params", [])),
                remaining_budget=remaining,
            )

            found = _add_found(found, current_path, llm_params)
            _enqueue_llm_urls(llm_urls, base_url, seen, visited, queue, max(config.web.max_pages * 8, 96))

            return {
                "queue": queue, "seen": seen, "visited": visited, "found": found,
                "pages": list(state.get("pages", [])),
                "requests": list(requests),
                "errors": list(state.get("errors", [])),
            }

        def _route_continue(state: _WebState) -> str:
            if int(state.get("steps", 0)) >= config.web.max_actions:
                return "done"
            if len(state.get("visited", [])) >= config.web.max_pages:
                return "done"
            if not state.get("queue"):
                return "done"
            return "again"

        result = await _run_crawl_graph(
            _node_navigate_extract, _node_llm_plan, _route_continue,
            initial_queue, initial_seen,
        )

        await context.close()
        await browser.close()

    return _finalize_discovery(result, initial_queue)


async def _run_crawl_graph(
    navigate_node: Any, llm_node: Any, route_fn: Any,
    initial_queue: list[str], initial_seen: list[str],
) -> dict[str, Any]:
    from langgraph.graph import END, START, StateGraph  # type: ignore[import-not-found]
    builder = StateGraph(_WebState)
    builder.add_node("navigate_extract", navigate_node)
    builder.add_node("llm_plan", llm_node)
    builder.add_edge(START, "navigate_extract")
    builder.add_edge("navigate_extract", "llm_plan")
    builder.add_conditional_edges("llm_plan", route_fn, {"again": "navigate_extract", "done": END})
    graph = builder.compile()
    return await graph.ainvoke({
        "queue": initial_queue, "seen": initial_seen, "visited": [],
        "found": {}, "pages": [], "requests": [], "errors": [], "steps": 0,
    })


def _finalize_discovery(result: Any, initial_queue: list[str]) -> dict[str, Any]:
    found = result.get("found") if isinstance(result, dict) else None
    if not isinstance(found, dict):
        return _empty_discovery_result(initial_queue)
    normalized_found = _normalize_found_results(found)
    artifacts = _build_discovery_artifacts(result, initial_queue)
    return {"hints": normalized_found, "artifacts": artifacts}


async def _extract_cookies_from_playwright_context(context: Any) -> dict[str, str]:
    try:
        raw = await context.cookies()
    except Exception:
        return {}
    if not isinstance(raw, list):
        return {}
    out: dict[str, str] = {}
    for item in raw:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name", "")).strip()
        value = str(item.get("value", "")).strip()
        if name:
            out[name] = value
    return out


def _selector_for_name(name: str) -> str:
    esc = re.sub(r'(["\\])', r"\\\\\1", name)
    return f'input[name="{esc}"]'


def _validate_auth_config(config: PadvConfig) -> None:
    if not config.auth.login_url:
        raise RuntimeError("auth.enabled=true but auth.login_url is empty")
    if not config.auth.username:
        raise RuntimeError("auth.enabled=true but auth.username is empty")
    if not config.auth.password:
        raise RuntimeError("auth.enabled=true but auth.password is empty")


def _collect_form_input_candidates(form_meta: Any) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    if not isinstance(form_meta, list):
        return candidates
    for form in form_meta:
        if not isinstance(form, dict):
            continue
        for inp in form.get("inputs", []):
            if isinstance(inp, dict):
                candidates.append(inp)
    return candidates


def _heuristic_selectors_from_inputs(
    input_candidates: list[dict[str, Any]],
) -> tuple[str, str]:
    username_selector = ""
    password_selector = ""
    for inp in input_candidates:
        name = str(inp.get("name", "")).strip()
        inp_type = str(inp.get("type", "")).strip().lower()
        if not password_selector and inp_type == "password" and name:
            password_selector = _selector_for_name(name)
        if not username_selector and name and re.search(r"user|login|email|name", name, re.IGNORECASE):
            username_selector = _selector_for_name(name)
    return username_selector, password_selector


async def _resolve_login_selectors(
    config: PadvConfig,
    form_meta: Any,
    input_candidates: list[dict[str, Any]],
) -> tuple[str, str, str]:
    username_selector, password_selector = _heuristic_selectors_from_inputs(input_candidates)
    llm_u, llm_p, llm_s = await _llm_select_login_selectors(config, form_meta)
    if llm_u:
        username_selector = llm_u
    if llm_p:
        password_selector = llm_p
    submit_selector = llm_s or ""
    if not password_selector:
        password_selector = "input[type='password']"
    if not username_selector:
        username_selector = "input[type='email'], input[type='text']"
    return username_selector, password_selector, submit_selector


async def _submit_login_form(page: Any, submit_selector: str) -> None:
    if submit_selector:
        await page.click(submit_selector)
        return
    submit = page.locator("form button[type='submit'], form input[type='submit']").first
    if await submit.count() > 0:
        await submit.click()
    else:
        await page.keyboard.press("Enter")


async def _auth_with_playwright_async(config: PadvConfig) -> dict[str, Any]:
    from playwright.async_api import async_playwright  # type: ignore[import-not-found]

    if not config.auth.enabled:
        return {"cookies": {}, "auth_enabled": False}
    _validate_auth_config(config)

    timeout_ms = max(1, int(config.web.request_timeout_seconds)) * 1000

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=config.web.headless)
        context = await browser.new_context(ignore_https_errors=True)
        page = await context.new_page()
        _install_dialog_guards(context, page)

        await page.goto(config.auth.login_url, wait_until="domcontentloaded", timeout=timeout_ms)

        form_meta = await page.evaluate(
            """
            () => {
              const forms = [];
              for (const f of document.querySelectorAll('form')) {
                const inputs = [];
                for (const i of f.querySelectorAll('input,select,textarea')) {
                  inputs.push({
                    name: i.getAttribute('name') || '',
                    id: i.id || '',
                    type: i.getAttribute('type') || i.tagName.toLowerCase(),
                    placeholder: i.getAttribute('placeholder') || '',
                  });
                }
                forms.push({
                  action: f.getAttribute('action') || '',
                  method: (f.getAttribute('method') || 'get').toLowerCase(),
                  inputs,
                });
              }
              return forms;
            }
            """
        )

        input_candidates = _collect_form_input_candidates(form_meta)
        username_selector, password_selector, submit_selector = await _resolve_login_selectors(
            config, form_meta, input_candidates,
        )

        await page.fill(username_selector, config.auth.username)
        await page.fill(password_selector, config.auth.password)
        await _submit_login_form(page, submit_selector)

        try:
            await page.wait_for_load_state("networkidle", timeout=timeout_ms)
        except Exception:
            pass

        try:
            await page.goto(config.target.base_url, wait_until="domcontentloaded", timeout=timeout_ms)
        except Exception:
            pass

        cookies = await _extract_cookies_from_playwright_context(context)
        await context.close()
        await browser.close()

    if not cookies:
        raise RuntimeError("playwright auth flow produced no session cookies")

    return {
        "auth_enabled": True,
        "login_url": config.auth.login_url,
        "username": config.auth.username,
        "cookies": cookies,
        "summary": "playwright-auth-ok",
    }


def _run_async(coro_factory: Callable[[], Awaitable[Any]]) -> Any:
    try:
        return asyncio.run(coro_factory())
    except RuntimeError:
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(coro_factory())
        finally:
            loop.close()


def discover_web_hints(config: PadvConfig, seed_urls: list[str] | None = None) -> tuple[dict[str, list[str]], str | None]:
    try:
        payload = _run_async(lambda: _discover_with_playwright_async(config, seed_urls=seed_urls))
        if not isinstance(payload, dict):
            return {}, None
        if payload and all(isinstance(k, str) and isinstance(v, list) for k, v in payload.items()):
            return payload, None
        hints = payload.get("hints", {})
        return hints if isinstance(hints, dict) else {}, None
    except Exception as exc:
        raise RuntimeError(f"playwright_discovery_error:{exc}") from exc


def discover_web_inventory(
    config: PadvConfig,
    seed_urls: list[str] | None = None,
    auth_state: dict[str, Any] | None = None,
) -> tuple[dict[str, list[str]], dict[str, Any], str | None]:
    try:
        payload = _run_async(lambda: _discover_with_playwright_async(config, seed_urls=seed_urls, auth_state=auth_state))
        if not isinstance(payload, dict):
            return {}, {"seed_urls": list(seed_urls or []), "visited_urls": [], "pages": [], "requests": [], "errors": []}, None
        if payload and all(isinstance(k, str) and isinstance(v, list) for k, v in payload.items()):
            return payload, {"seed_urls": list(seed_urls or []), "visited_urls": [], "pages": [], "requests": [], "errors": []}, None
        hints = payload.get("hints", {})
        artifacts = payload.get("artifacts", {})
        normalized_hints = hints if isinstance(hints, dict) else {}
        normalized_artifacts = artifacts if isinstance(artifacts, dict) else {}
        return normalized_hints, normalized_artifacts, None
    except Exception as exc:
        raise RuntimeError(f"playwright_discovery_error:{exc}") from exc


def establish_auth_state(config: PadvConfig) -> dict[str, Any]:
    try:
        return _run_async(lambda: _auth_with_playwright_async(config))
    except Exception as exc:
        raise RuntimeError(f"playwright_auth_error:{exc}") from exc

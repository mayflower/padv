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


async def _extract_page_observations(page: Any) -> tuple[list[str], list[str], str]:
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
          return {
            urls,
            params,
            summary: `${title}\n${h1.join(' | ')}`.trim(),
          };
        }
        """
    )

    if not isinstance(result, dict):
        return [], [], ""
    urls = [str(x).strip() for x in result.get("urls", []) if isinstance(x, str) and x.strip()]
    params = [str(x).strip() for x in result.get("params", []) if isinstance(x, str) and x.strip()]
    summary = str(result.get("summary", "")).strip()
    return urls, params, summary


async def _discover_with_playwright_async(config: PadvConfig, seed_urls: list[str] | None = None) -> dict[str, list[str]]:
    from langgraph.graph import END, START, StateGraph  # type: ignore[import-not-found]
    from playwright.async_api import async_playwright  # type: ignore[import-not-found]

    base_url = config.target.base_url
    initial_queue: list[str] = []
    initial_seen: list[str] = []

    for raw in [base_url] + list(seed_urls or []):
        normalized = _canonicalize_url(raw, base_url=base_url)
        if not normalized:
            continue
        if normalized in initial_seen:
            continue
        initial_seen.append(normalized)
        initial_queue.append(normalized)

    if not initial_queue:
        return {}

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=config.web.headless)
        context = await browser.new_context(ignore_https_errors=True)
        page = await context.new_page()

        timeout_ms = max(1, int(config.web.request_timeout_seconds)) * 1000

        async def _node_navigate_extract(state: _WebState) -> _WebState:
            queue = list(state.get("queue", []))
            seen = list(state.get("seen", []))
            visited = list(state.get("visited", []))
            found = dict(state.get("found", {}))
            steps = int(state.get("steps", 0))

            current = ""
            while queue:
                candidate = queue.pop(0)
                if candidate in visited:
                    continue
                current = candidate
                break

            if not current:
                return {
                    "queue": queue,
                    "seen": seen,
                    "visited": visited,
                    "found": found,
                    "steps": steps,
                    "current_url": "",
                    "current_path": "",
                    "candidate_urls": [],
                    "candidate_params": [],
                }

            steps += 1
            candidate_urls: list[str] = []
            candidate_params: list[str] = []
            canonical_current = current
            current_path = _normalize_path(current)[0]

            try:
                await page.goto(current, wait_until="domcontentloaded", timeout=timeout_ms)
                live_url = page.url or current
                canonical_current = _canonicalize_url(live_url, base_url=base_url) or current
                current_path, query_params = _normalize_path(canonical_current)
                found = _add_found(found, current_path, query_params)

                raw_urls, raw_params, _summary = await _extract_page_observations(page)
                candidate_params = raw_params
                found = _add_found(found, current_path, raw_params)

                for raw in raw_urls:
                    normalized = _canonicalize_url(raw, base_url=base_url)
                    if normalized:
                        candidate_urls.append(normalized)

                seed_cap = max(config.web.max_pages * 6, 64)
                for url in candidate_urls[:8]:
                    if url in seen or url in visited:
                        continue
                    if len(seen) >= seed_cap:
                        break
                    seen.append(url)
                    queue.append(url)
            except Exception:
                pass

            if canonical_current not in visited:
                visited.append(canonical_current)

            return {
                "queue": queue,
                "seen": seen,
                "visited": visited,
                "found": found,
                "steps": steps,
                "current_url": canonical_current,
                "current_path": current_path,
                "candidate_urls": candidate_urls,
                "candidate_params": candidate_params,
            }

        async def _node_llm_plan(state: _WebState) -> _WebState:
            queue = list(state.get("queue", []))
            seen = list(state.get("seen", []))
            visited = list(state.get("visited", []))
            found = dict(state.get("found", {}))

            current_url = str(state.get("current_url", "")).strip()
            current_path = str(state.get("current_path", "")).strip() or "/"
            candidate_urls = list(state.get("candidate_urls", []))
            candidate_params = list(state.get("candidate_params", []))

            remaining = max(0, config.web.max_pages - len(visited))
            if not current_url or remaining <= 0:
                return {"queue": queue, "seen": seen, "visited": visited, "found": found}

            llm_urls, llm_params = await _llm_select_next_urls(
                config,
                current_url=current_url,
                visited_urls=visited,
                candidate_urls=candidate_urls,
                candidate_params=candidate_params,
                remaining_budget=remaining,
            )

            found = _add_found(found, current_path, llm_params)

            queue_cap = max(config.web.max_pages * 8, 96)
            for raw in llm_urls:
                normalized = _canonicalize_url(raw, base_url=base_url)
                if not normalized or normalized in seen or normalized in visited:
                    continue
                if len(seen) >= queue_cap:
                    break
                seen.append(normalized)
                queue.append(normalized)

            return {
                "queue": queue,
                "seen": seen,
                "visited": visited,
                "found": found,
            }

        def _route_continue(state: _WebState) -> str:
            steps = int(state.get("steps", 0))
            visited = list(state.get("visited", []))
            queue = list(state.get("queue", []))
            if steps >= config.web.max_actions:
                return "done"
            if len(visited) >= config.web.max_pages:
                return "done"
            if not queue:
                return "done"
            return "again"

        builder = StateGraph(_WebState)
        builder.add_node("navigate_extract", _node_navigate_extract)
        builder.add_node("llm_plan", _node_llm_plan)
        builder.add_edge(START, "navigate_extract")
        builder.add_edge("navigate_extract", "llm_plan")
        builder.add_conditional_edges("llm_plan", _route_continue, {"again": "navigate_extract", "done": END})

        graph = builder.compile()
        result = await graph.ainvoke(
            {
                "queue": initial_queue,
                "seen": initial_seen,
                "visited": [],
                "found": {},
                "steps": 0,
            }
        )

        await context.close()
        await browser.close()

    found = result.get("found") if isinstance(result, dict) else None
    if not isinstance(found, dict):
        return {}
    normalized_found: dict[str, list[str]] = {}
    for path, params in found.items():
        if not isinstance(path, str):
            continue
        if isinstance(params, list):
            normalized_found[path] = sorted({str(x).strip() for x in params if str(x).strip()})
        else:
            normalized_found[path] = []
    return normalized_found


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


async def _auth_with_playwright_async(config: PadvConfig) -> dict[str, Any]:
    from playwright.async_api import async_playwright  # type: ignore[import-not-found]

    if not config.auth.enabled:
        return {"cookies": {}, "auth_enabled": False}
    if not config.auth.login_url:
        raise RuntimeError("auth.enabled=true but auth.login_url is empty")
    if not config.auth.username:
        raise RuntimeError("auth.enabled=true but auth.username is empty")
    if not config.auth.password:
        raise RuntimeError("auth.enabled=true but auth.password is empty")

    timeout_ms = max(1, int(config.web.request_timeout_seconds)) * 1000

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=config.web.headless)
        context = await browser.new_context(ignore_https_errors=True)
        page = await context.new_page()

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

        username_selector = ""
        password_selector = ""
        submit_selector = ""

        candidates = []
        if isinstance(form_meta, list):
            for form in form_meta:
                if not isinstance(form, dict):
                    continue
                for inp in form.get("inputs", []):
                    if isinstance(inp, dict):
                        candidates.append(inp)

        for inp in candidates:
            name = str(inp.get("name", "")).strip()
            inp_type = str(inp.get("type", "")).strip().lower()
            if not password_selector and inp_type == "password" and name:
                password_selector = _selector_for_name(name)
            if not username_selector and name and re.search(r"user|login|email|name", name, re.IGNORECASE):
                username_selector = _selector_for_name(name)

        llm_u, llm_p, llm_s = await _llm_select_login_selectors(config, form_meta)
        if llm_u:
            username_selector = llm_u
        if llm_p:
            password_selector = llm_p
        if llm_s:
            submit_selector = llm_s

        if not password_selector:
            password_selector = "input[type='password']"
        if not username_selector:
            username_selector = "input[type='email'], input[type='text']"

        await page.fill(username_selector, config.auth.username)
        await page.fill(password_selector, config.auth.password)

        if submit_selector:
            await page.click(submit_selector)
        else:
            submit = page.locator("form button[type='submit'], form input[type='submit']").first
            if await submit.count() > 0:
                await submit.click()
            else:
                await page.keyboard.press("Enter")

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
        return _run_async(lambda: _discover_with_playwright_async(config, seed_urls=seed_urls)), None
    except Exception as exc:
        raise RuntimeError(f"playwright_discovery_error:{exc}") from exc


def establish_auth_state(config: PadvConfig) -> dict[str, Any]:
    try:
        return _run_async(lambda: _auth_with_playwright_async(config))
    except Exception as exc:
        raise RuntimeError(f"playwright_auth_error:{exc}") from exc

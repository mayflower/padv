from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import tomllib


class ConfigError(ValueError):
    pass


@dataclass(slots=True)
class TargetConfig:
    base_url: str
    request_timeout_seconds: int


@dataclass(slots=True)
class OracleConfig:
    request_key_header: str
    request_intercept_header: str
    request_correlation_header: str
    response_result_header: str
    response_status_header: str
    response_call_count_header: str
    response_overflow_header: str
    response_arg_truncated_header: str
    response_result_truncated_header: str
    response_correlation_header: str
    result_encoding: str
    max_result_b64_len: int
    api_key: str


@dataclass(slots=True)
class CanaryConfig:
    parameter_name: str
    allow_casefold: bool
    allow_url_decode: bool


@dataclass(slots=True)
class BudgetConfig:
    max_candidates: int
    max_requests: int
    max_seconds_per_candidate: int
    max_run_seconds: int


@dataclass(slots=True)
class SandboxConfig:
    deploy_cmd: str
    reset_cmd: str
    status_cmd: str
    logs_cmd: str


@dataclass(slots=True)
class StoreConfig:
    root: str
    store_raw_reports: bool


@dataclass(slots=True)
class AuthConfig:
    enabled: bool
    login_url: str
    username: str
    password: str
    profile_path: str


@dataclass(slots=True)
class JoernConfig:
    enabled: bool
    query_profile: str
    command: str
    parse_command: str
    parse_language: str
    use_http_api: bool
    server_url: str
    script_path: str
    timeout_seconds: int
    fallback_to_regex: bool


@dataclass(slots=True)
class LLMConfig:
    provider: str
    model: str
    api_key_env: str
    temperature: float
    max_tokens: int
    timeout_seconds: int


@dataclass(slots=True)
class AgentConfig:
    use_deepagents: bool
    hard_fail: bool
    require_langgraph: bool
    max_iterations: int
    improvement_patience: int
    skeptic_rounds: int
    thread_prefix: str


@dataclass(slots=True)
class ScipConfig:
    enabled: bool
    command: str
    print_command: str
    artifact_dir: str
    timeout_seconds: int
    hard_fail: bool


@dataclass(slots=True)
class WebConfig:
    enabled: bool
    use_browser_use: bool
    headless: bool
    max_pages: int
    max_actions: int
    request_timeout_seconds: int


@dataclass(slots=True)
class DifferentialConfig:
    enabled: bool
    auth_levels: list[str]
    body_length_tolerance: float


@dataclass(slots=True)
class PadvConfig:
    target: TargetConfig
    oracle: OracleConfig
    canary: CanaryConfig
    budgets: BudgetConfig
    sandbox: SandboxConfig
    store: StoreConfig
    auth: AuthConfig
    joern: JoernConfig
    llm: LLMConfig
    agent: AgentConfig
    scip: ScipConfig
    web: WebConfig
    differential: DifferentialConfig


def _require_section(data: dict[str, Any], key: str) -> dict[str, Any]:
    value = data.get(key)
    if not isinstance(value, dict):
        raise ConfigError(f"missing or invalid section: {key}")
    return value


def _get_str(section: dict[str, Any], key: str) -> str:
    value = section.get(key)
    if not isinstance(value, str) or not value:
        raise ConfigError(f"missing or invalid string: {key}")
    return value


def _get_int(section: dict[str, Any], key: str, min_value: int = 0) -> int:
    value = section.get(key)
    if not isinstance(value, int) or value < min_value:
        raise ConfigError(f"missing or invalid int: {key}")
    return value


def _get_bool(section: dict[str, Any], key: str) -> bool:
    value = section.get(key)
    if not isinstance(value, bool):
        raise ConfigError(f"missing or invalid bool: {key}")
    return value


def _get_float(section: dict[str, Any], key: str, min_value: float | None = None) -> float:
    value = section.get(key)
    if isinstance(value, int):
        value = float(value)
    if not isinstance(value, float):
        raise ConfigError(f"missing or invalid float: {key}")
    if min_value is not None and value < min_value:
        raise ConfigError(f"missing or invalid float: {key}")
    return value


def _get_optional_str(section: dict[str, Any], key: str, default: str = "") -> str:
    value = section.get(key, default)
    if value is None:
        return default
    if not isinstance(value, str):
        raise ConfigError(f"missing or invalid string: {key}")
    return value


def _get_optional_int(section: dict[str, Any], key: str, default: int, min_value: int = 0) -> int:
    value = section.get(key, default)
    if not isinstance(value, int) or value < min_value:
        raise ConfigError(f"missing or invalid int: {key}")
    return value


def _get_optional_bool(section: dict[str, Any], key: str, default: bool) -> bool:
    value = section.get(key, default)
    if not isinstance(value, bool):
        raise ConfigError(f"missing or invalid bool: {key}")
    return value


def _get_optional_float(
    section: dict[str, Any],
    key: str,
    default: float,
    min_value: float | None = None,
) -> float:
    value = section.get(key, default)
    if isinstance(value, int):
        value = float(value)
    if not isinstance(value, float):
        raise ConfigError(f"missing or invalid float: {key}")
    if min_value is not None and value < min_value:
        raise ConfigError(f"missing or invalid float: {key}")
    return value


def _get_optional_str_list(section: dict[str, Any], key: str, default: list[str]) -> list[str]:
    value = section.get(key, default)
    if not isinstance(value, list):
        raise ConfigError(f"missing or invalid list: {key}")
    result: list[str] = []
    for item in value:
        if not isinstance(item, str):
            raise ConfigError(f"missing or invalid list: {key}")
        text = item.strip()
        if text:
            result.append(text)
    return result if result else list(default)


def _require_true(section: dict[str, Any], key: str, *, default: bool, reason: str) -> bool:
    value = _get_optional_bool(section, key, default)
    if not value:
        raise ConfigError(reason)
    return True


def load_config(path: str | Path) -> PadvConfig:
    config_path = Path(path)
    if not config_path.exists():
        raise ConfigError(f"config not found: {config_path}")

    with config_path.open("rb") as f:
        data = tomllib.load(f)

    target = _require_section(data, "target")
    oracle = _require_section(data, "oracle")
    canary = _require_section(data, "canary")
    budgets = _require_section(data, "budgets")
    sandbox = _require_section(data, "sandbox")
    store = _require_section(data, "store")
    auth = _require_section(data, "auth")
    joern = _require_section(data, "joern")
    llm = data.get("llm", {})
    agent = data.get("agent", {})
    scip = data.get("scip", {})
    web = data.get("web", {})
    differential = data.get("differential", {})
    if not isinstance(llm, dict):
        raise ConfigError("invalid section: llm")
    if not isinstance(agent, dict):
        raise ConfigError("invalid section: agent")
    if not isinstance(scip, dict):
        raise ConfigError("invalid section: scip")
    if not isinstance(web, dict):
        raise ConfigError("invalid section: web")
    if not isinstance(differential, dict):
        raise ConfigError("invalid section: differential")

    # Strict cutover: these switches are always-on and cannot be disabled.
    agent_use_deepagents = _require_true(
        agent,
        "use_deepagents",
        default=True,
        reason="agent.use_deepagents must be true",
    )
    agent_require_langgraph = _require_true(
        agent,
        "require_langgraph",
        default=True,
        reason="agent.require_langgraph must be true",
    )
    web_enabled = _require_true(
        web,
        "enabled",
        default=True,
        reason="web.enabled must be true",
    )
    web_use_browser_use = _require_true(
        web,
        "use_browser_use",
        default=True,
        reason="web.use_browser_use must be true",
    )
    agent_hard_fail = _require_true(
        agent,
        "hard_fail",
        default=True,
        reason="agent.hard_fail must be true",
    )
    joern_enabled = _require_true(
        joern,
        "enabled",
        default=True,
        reason="joern.enabled must be true",
    )
    joern_no_regex_fallback = not _get_optional_bool(joern, "fallback_to_regex", False)
    if not joern_no_regex_fallback:
        raise ConfigError("joern.fallback_to_regex must be false")
    scip_enabled = _require_true(
        scip,
        "enabled",
        default=True,
        reason="scip.enabled must be true",
    )
    scip_hard_fail = _require_true(
        scip,
        "hard_fail",
        default=True,
        reason="scip.hard_fail must be true",
    )

    parsed = PadvConfig(
        target=TargetConfig(
            base_url=_get_str(target, "base_url"),
            request_timeout_seconds=_get_int(target, "request_timeout_seconds", min_value=1),
        ),
        oracle=OracleConfig(
            request_key_header=_get_str(oracle, "request_key_header"),
            request_intercept_header=_get_str(oracle, "request_intercept_header"),
            request_correlation_header=_get_str(oracle, "request_correlation_header"),
            response_result_header=_get_str(oracle, "response_result_header"),
            response_status_header=_get_str(oracle, "response_status_header"),
            response_call_count_header=_get_str(oracle, "response_call_count_header"),
            response_overflow_header=_get_str(oracle, "response_overflow_header"),
            response_arg_truncated_header=_get_str(oracle, "response_arg_truncated_header"),
            response_result_truncated_header=_get_str(oracle, "response_result_truncated_header"),
            response_correlation_header=_get_str(oracle, "response_correlation_header"),
            result_encoding=_get_str(oracle, "result_encoding"),
            max_result_b64_len=_get_int(oracle, "max_result_b64_len", min_value=1),
            api_key=_get_str(oracle, "api_key"),
        ),
        canary=CanaryConfig(
            parameter_name=_get_str(canary, "parameter_name"),
            allow_casefold=_get_bool(canary, "allow_casefold"),
            allow_url_decode=_get_bool(canary, "allow_url_decode"),
        ),
        budgets=BudgetConfig(
            max_candidates=_get_int(budgets, "max_candidates", min_value=1),
            max_requests=_get_int(budgets, "max_requests", min_value=1),
            max_seconds_per_candidate=_get_int(budgets, "max_seconds_per_candidate", min_value=1),
            max_run_seconds=_get_int(budgets, "max_run_seconds", min_value=1),
        ),
        sandbox=SandboxConfig(
            deploy_cmd=_get_optional_str(sandbox, "deploy_cmd"),
            reset_cmd=_get_optional_str(sandbox, "reset_cmd"),
            status_cmd=_get_optional_str(sandbox, "status_cmd"),
            logs_cmd=_get_optional_str(sandbox, "logs_cmd"),
        ),
        store=StoreConfig(
            root=_get_str(store, "root"),
            store_raw_reports=_get_bool(store, "store_raw_reports"),
        ),
        auth=AuthConfig(
            enabled=_get_bool(auth, "enabled"),
            login_url=_get_optional_str(auth, "login_url"),
            username=_get_optional_str(auth, "username"),
            password=_get_optional_str(auth, "password"),
            profile_path=_get_optional_str(auth, "profile_path"),
        ),
        joern=JoernConfig(
            enabled=joern_enabled,
            query_profile=_get_str(joern, "query_profile"),
            command=_get_optional_str(joern, "command", "joern"),
            parse_command=_get_optional_str(joern, "parse_command", "joern-parse"),
            parse_language=_get_optional_str(joern, "parse_language", "PHP"),
            use_http_api=_get_bool(joern, "use_http_api") if "use_http_api" in joern else False,
            server_url=_get_optional_str(joern, "server_url", "http://127.0.0.1:8080"),
            script_path=_get_optional_str(joern, "script_path", ""),
            timeout_seconds=_get_int(joern, "timeout_seconds", min_value=1) if "timeout_seconds" in joern else 600,
            fallback_to_regex=False,
        ),
        llm=LLMConfig(
            provider=_get_optional_str(llm, "provider", "anthropic"),
            model=_get_optional_str(llm, "model", "claude-sonnet-4-5-20250929"),
            api_key_env=_get_optional_str(llm, "api_key_env", "ANTHROPIC_API_KEY"),
            temperature=_get_optional_float(llm, "temperature", 0.0, min_value=0.0),
            max_tokens=_get_optional_int(llm, "max_tokens", 4096, min_value=1),
            timeout_seconds=_get_optional_int(llm, "timeout_seconds", 120, min_value=1),
        ),
        agent=AgentConfig(
            use_deepagents=agent_use_deepagents,
            hard_fail=agent_hard_fail,
            require_langgraph=agent_require_langgraph,
            max_iterations=_get_optional_int(agent, "max_iterations", 3, min_value=1),
            improvement_patience=_get_optional_int(agent, "improvement_patience", 1, min_value=0),
            skeptic_rounds=_get_optional_int(agent, "skeptic_rounds", 1, min_value=0),
            thread_prefix=_get_optional_str(agent, "thread_prefix", "padv"),
        ),
        scip=ScipConfig(
            enabled=scip_enabled,
            command=_get_optional_str(scip, "command", "scip-php"),
            print_command=_get_optional_str(scip, "print_command", "scip print"),
            artifact_dir=_get_optional_str(scip, "artifact_dir", ".padv/scip"),
            timeout_seconds=_get_optional_int(scip, "timeout_seconds", 300, min_value=1),
            hard_fail=scip_hard_fail,
        ),
        web=WebConfig(
            enabled=web_enabled,
            use_browser_use=web_use_browser_use,
            headless=_get_optional_bool(web, "headless", True),
            max_pages=_get_optional_int(web, "max_pages", 8, min_value=1),
            max_actions=_get_optional_int(web, "max_actions", 30, min_value=1),
            request_timeout_seconds=_get_optional_int(web, "request_timeout_seconds", 15, min_value=1),
        ),
        differential=DifferentialConfig(
            enabled=_get_optional_bool(differential, "enabled", True),
            auth_levels=_get_optional_str_list(differential, "auth_levels", ["anonymous"]),
            body_length_tolerance=_get_optional_float(differential, "body_length_tolerance", 0.10, min_value=0.0),
        ),
    )

    if parsed.oracle.result_encoding not in {"base64-json", "json"}:
        raise ConfigError("oracle.result_encoding must be one of: base64-json, json")

    if parsed.llm.provider != "anthropic":
        raise ConfigError("llm.provider must be anthropic for browser-use agentic runs")
    if parsed.differential.body_length_tolerance > 1.0:
        raise ConfigError("differential.body_length_tolerance must be <= 1.0")

    return parsed

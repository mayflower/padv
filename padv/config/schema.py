from __future__ import annotations

import urllib.parse
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
    shared_session: bool = False


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
    deterministic_mode: bool
    max_iterations: int
    max_agent_turns: int
    improvement_patience: int
    skeptic_rounds: int
    thread_prefix: str
    checkpoint_dir: str
    max_parallel_research: int
    max_parallel_skeptic: int
    max_parallel_experiments: int


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


def _require_true(section: dict[str, Any], key: str, *, reason: str) -> bool:
    value = _get_bool(section, key)
    if not value:
        raise ConfigError(reason)
    return True


def _reject_unknown_keys(section_name: str, section: dict[str, Any], allowed: set[str]) -> None:
    unknown = sorted(k for k in section.keys() if k not in allowed)
    if unknown:
        joined = ", ".join(unknown)
        raise ConfigError(f"unknown keys in [{section_name}]: {joined}")


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
    llm = _require_section(data, "llm")
    agent = _require_section(data, "agent")
    scip = _require_section(data, "scip")
    web = _require_section(data, "web")
    differential = _require_section(data, "differential")

    _reject_unknown_keys("target", target, {"base_url", "request_timeout_seconds"})
    _reject_unknown_keys(
        "oracle",
        oracle,
        {
            "request_key_header",
            "request_intercept_header",
            "request_correlation_header",
            "response_result_header",
            "response_status_header",
            "response_call_count_header",
            "response_overflow_header",
            "response_arg_truncated_header",
            "response_result_truncated_header",
            "response_correlation_header",
            "result_encoding",
            "max_result_b64_len",
            "api_key",
        },
    )
    _reject_unknown_keys("canary", canary, {"parameter_name", "allow_casefold", "allow_url_decode"})
    _reject_unknown_keys(
        "budgets",
        budgets,
        {"max_candidates", "max_requests", "max_seconds_per_candidate", "max_run_seconds"},
    )
    _reject_unknown_keys("sandbox", sandbox, {"deploy_cmd", "reset_cmd", "status_cmd", "logs_cmd"})
    _reject_unknown_keys("store", store, {"root", "store_raw_reports"})
    _reject_unknown_keys("auth", auth, {"enabled", "login_url", "username", "password", "profile_path"})
    _reject_unknown_keys(
        "joern",
        joern,
        {
            "enabled",
            "query_profile",
            "command",
            "parse_command",
            "parse_language",
            "use_http_api",
            "server_url",
            "script_path",
            "timeout_seconds",
        },
    )
    _reject_unknown_keys(
        "llm",
        llm,
        {"provider", "model", "api_key_env", "temperature", "max_tokens", "timeout_seconds"},
    )
    _reject_unknown_keys(
        "agent",
        agent,
        {
            "use_deepagents",
            "hard_fail",
            "require_langgraph",
            "deterministic_mode",
            "max_iterations",
            "max_agent_turns",
            "improvement_patience",
            "skeptic_rounds",
            "thread_prefix",
            "checkpoint_dir",
            "max_parallel_research",
            "max_parallel_skeptic",
            "max_parallel_experiments",
        },
    )
    _reject_unknown_keys(
        "scip",
        scip,
        {"enabled", "command", "print_command", "artifact_dir", "timeout_seconds", "hard_fail"},
    )
    _reject_unknown_keys(
        "web",
        web,
        {"enabled", "use_browser_use", "headless", "max_pages", "max_actions", "request_timeout_seconds"},
    )
    _reject_unknown_keys("differential", differential, {"enabled", "auth_levels", "body_length_tolerance"})

    # Strict cutover: these switches are always-on and cannot be disabled.
    agent_use_deepagents = _require_true(
        agent,
        "use_deepagents",
        reason="agent.use_deepagents must be true",
    )
    agent_require_langgraph = _require_true(
        agent,
        "require_langgraph",
        reason="agent.require_langgraph must be true",
    )
    web_enabled = _require_true(
        web,
        "enabled",
        reason="web.enabled must be true",
    )
    web_use_browser_use = _require_true(
        web,
        "use_browser_use",
        reason="web.use_browser_use must be true",
    )
    agent_hard_fail = _require_true(
        agent,
        "hard_fail",
        reason="agent.hard_fail must be true",
    )
    joern_enabled = _require_true(
        joern,
        "enabled",
        reason="joern.enabled must be true",
    )
    scip_enabled = _require_true(
        scip,
        "enabled",
        reason="scip.enabled must be true",
    )
    scip_hard_fail = _require_true(
        scip,
        "hard_fail",
        reason="scip.hard_fail must be true",
    )

    parsed = PadvConfig(
        target=TargetConfig(
            base_url=_get_str(target, "base_url"),
            request_timeout_seconds=_get_int(target, "request_timeout_seconds", min_value=1),
            shared_session=_get_optional_bool(target, "shared_session", default=False),
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
            command=_get_str(joern, "command"),
            parse_command=_get_optional_str(joern, "parse_command"),
            parse_language=_get_str(joern, "parse_language"),
            use_http_api=_get_bool(joern, "use_http_api"),
            server_url=_get_str(joern, "server_url"),
            script_path=_get_optional_str(joern, "script_path", ""),
            timeout_seconds=_get_int(joern, "timeout_seconds", min_value=1),
        ),
        llm=LLMConfig(
            provider=_get_str(llm, "provider"),
            model=_get_str(llm, "model"),
            api_key_env=_get_str(llm, "api_key_env"),
            temperature=_get_float(llm, "temperature", min_value=0.0),
            max_tokens=_get_int(llm, "max_tokens", min_value=1),
            timeout_seconds=_get_int(llm, "timeout_seconds", min_value=1),
        ),
        agent=AgentConfig(
            use_deepagents=agent_use_deepagents,
            hard_fail=agent_hard_fail,
            require_langgraph=agent_require_langgraph,
            deterministic_mode=_get_optional_bool(agent, "deterministic_mode", False),
            max_iterations=_get_int(agent, "max_iterations", min_value=1),
            max_agent_turns=_get_optional_int(agent, "max_agent_turns", 3, min_value=1),
            improvement_patience=_get_int(agent, "improvement_patience", min_value=0),
            skeptic_rounds=_get_int(agent, "skeptic_rounds", min_value=0),
            thread_prefix=_get_str(agent, "thread_prefix"),
            checkpoint_dir=_get_optional_str(agent, "checkpoint_dir", ""),
            max_parallel_research=_get_optional_int(agent, "max_parallel_research", 3, min_value=1),
            max_parallel_skeptic=_get_optional_int(agent, "max_parallel_skeptic", 3, min_value=1),
            max_parallel_experiments=_get_optional_int(agent, "max_parallel_experiments", 3, min_value=1),
        ),
        scip=ScipConfig(
            enabled=scip_enabled,
            command=_get_str(scip, "command"),
            print_command=_get_str(scip, "print_command"),
            artifact_dir=_get_str(scip, "artifact_dir"),
            timeout_seconds=_get_int(scip, "timeout_seconds", min_value=1),
            hard_fail=scip_hard_fail,
        ),
        web=WebConfig(
            enabled=web_enabled,
            use_browser_use=web_use_browser_use,
            headless=_get_bool(web, "headless"),
            max_pages=_get_int(web, "max_pages", min_value=1),
            max_actions=_get_int(web, "max_actions", min_value=1),
            request_timeout_seconds=_get_int(web, "request_timeout_seconds", min_value=1),
        ),
        differential=DifferentialConfig(
            enabled=_get_bool(differential, "enabled"),
            auth_levels=_get_optional_str_list(differential, "auth_levels", ["anonymous"]),
            body_length_tolerance=_get_float(differential, "body_length_tolerance", min_value=0.0),
        ),
    )

    if parsed.oracle.result_encoding not in {"base64-json", "json"}:
        raise ConfigError("oracle.result_encoding must be one of: base64-json, json")

    if parsed.llm.provider != "anthropic":
        raise ConfigError("llm.provider must be anthropic for browser-use agentic runs")
    if parsed.differential.body_length_tolerance > 1.0:
        raise ConfigError("differential.body_length_tolerance must be <= 1.0")
    if parsed.differential.body_length_tolerance < 0.0:
        raise ConfigError("differential.body_length_tolerance must be >= 0.0")

    # Validate auth fields when auth is enabled
    if parsed.auth.enabled:
        if not parsed.auth.login_url:
            raise ConfigError("auth.login_url is required when auth.enabled is true")
        if not parsed.auth.username:
            raise ConfigError("auth.username is required when auth.enabled is true")
        if not parsed.auth.password:
            raise ConfigError("auth.password is required when auth.enabled is true")

    # Validate URL format for key URL fields
    _validate_url("target.base_url", parsed.target.base_url)
    if parsed.auth.enabled and parsed.auth.login_url:
        _validate_url("auth.login_url", parsed.auth.login_url)
    if parsed.joern.use_http_api:
        _validate_url("joern.server_url", parsed.joern.server_url)

    return parsed


def _validate_url(field_name: str, value: str) -> None:
    """Validate that *value* is a well-formed HTTP(S) URL."""
    parsed = urllib.parse.urlparse(value)
    if parsed.scheme not in ("http", "https"):
        raise ConfigError(f"{field_name} must start with http:// or https://")
    if not parsed.netloc:
        raise ConfigError(f"{field_name} is not a valid URL (missing host)")

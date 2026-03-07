from __future__ import annotations

from pathlib import Path

import pytest

from padv.config.schema import ConfigError, load_config


def _strict_config_text() -> str:
    return """
[target]
base_url = "http://127.0.0.1:8080/index.php"
request_timeout_seconds = 10

[oracle]
request_key_header = "Morcilla-Key"
request_intercept_header = "Morcilla-Intercept"
request_correlation_header = "Morcilla-Correlation"
response_result_header = "X-Morcilla-Result"
response_status_header = "X-Morcilla-Status"
response_call_count_header = "X-Morcilla-Call-Count"
response_overflow_header = "X-Morcilla-Overflow"
response_arg_truncated_header = "X-Morcilla-Arg-Truncated"
response_result_truncated_header = "X-Morcilla-Result-Truncated"
response_correlation_header = "X-Morcilla-Correlation"
result_encoding = "base64-json"
max_result_b64_len = 8192
api_key = "test-key"

[canary]
parameter_name = "padv_canary"
allow_casefold = false
allow_url_decode = true

[budgets]
max_candidates = 20
max_requests = 50
max_seconds_per_candidate = 60
max_run_seconds = 600

[sandbox]
deploy_cmd = ""
reset_cmd = ""
status_cmd = ""
logs_cmd = ""

[store]
root = ".padv"
store_raw_reports = false

[auth]
enabled = false
login_url = ""
username = ""
password = ""
profile_path = ""

[joern]
enabled = true
query_profile = "default"
command = "joern"
parse_command = "joern-parse"
parse_language = "PHP"
use_http_api = false
server_url = "http://127.0.0.1:8080"
script_path = ""
timeout_seconds = 600

[llm]
provider = "anthropic"
model = "claude-sonnet-4-5-20250929"
api_key_env = "ANTHROPIC_API_KEY"
temperature = 0.0
max_tokens = 4096
timeout_seconds = 120

[agent]
use_deepagents = true
hard_fail = true
require_langgraph = true
max_iterations = 3
improvement_patience = 1
skeptic_rounds = 1
thread_prefix = "padv"

[scip]
enabled = true
command = "scip-php"
print_command = "scip print"
artifact_dir = ".padv/scip"
timeout_seconds = 300
hard_fail = true

[web]
enabled = true
use_browser_use = true
headless = true
max_pages = 8
max_actions = 30
request_timeout_seconds = 15

[differential]
enabled = true
auth_levels = ["anonymous"]
body_length_tolerance = 0.10
""".strip()


def _write_config(tmp_path: Path, text: str, filename: str = "cfg.toml") -> Path:
    path = tmp_path / filename
    path.write_text(text + "\n", encoding="utf-8")
    return path


def test_load_config_success() -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    assert config.target.base_url.startswith("http://")
    assert config.budgets.max_candidates > 0
    assert config.oracle.result_encoding == "base64-json"
    assert config.joern.parse_command == "joern-parse"
    assert config.joern.parse_language == "PHP"
    assert config.joern.use_http_api is False
    assert config.joern.enabled is True
    assert config.llm.provider == "anthropic"
    assert config.llm.model.startswith("claude-")
    assert config.agent.use_deepagents is True
    assert config.agent.hard_fail is True
    assert config.agent.require_langgraph is True
    assert config.scip.enabled is True
    assert config.scip.hard_fail is True
    assert config.web.enabled is True
    assert config.web.use_browser_use is True
    assert config.differential.enabled is True
    assert config.differential.auth_levels == ["anonymous"]
    assert config.differential.body_length_tolerance == 0.10


def test_load_config_requires_strict_sections(tmp_path: Path) -> None:
    text = _strict_config_text()
    text = text.replace(
        """
[llm]
provider = "anthropic"
model = "claude-sonnet-4-5-20250929"
api_key_env = "ANTHROPIC_API_KEY"
temperature = 0.0
max_tokens = 4096
timeout_seconds = 120
""".strip()
        + "\n",
        "",
    )
    path = _write_config(tmp_path, text, "missing-llm.toml")
    with pytest.raises(ConfigError, match="missing or invalid section: llm"):
        load_config(path)


def test_load_config_rejects_unknown_joern_key(tmp_path: Path) -> None:
    text = _strict_config_text().replace(
        "timeout_seconds = 600",
        "timeout_seconds = 600\nfallback_to_regex = true",
    )
    path = _write_config(tmp_path, text, "unknown-joern-key.toml")
    with pytest.raises(ConfigError, match=r"unknown keys in \[joern\]: fallback_to_regex"):
        load_config(path)


def test_load_config_rejects_disabled_always_on_flags(tmp_path: Path) -> None:
    text = _strict_config_text().replace("[joern]\nenabled = true", "[joern]\nenabled = false")
    path = _write_config(tmp_path, text, "invalid-flags.toml")
    with pytest.raises(ConfigError, match="joern.enabled must be true"):
        load_config(path)


def test_load_config_rejects_agent_hard_fail_false(tmp_path: Path) -> None:
    text = _strict_config_text().replace("hard_fail = true", "hard_fail = false", 1)
    path = _write_config(tmp_path, text, "invalid-hard-fail.toml")
    with pytest.raises(ConfigError, match="agent.hard_fail must be true"):
        load_config(path)


def test_load_config_rejects_non_anthropic_provider(tmp_path: Path) -> None:
    text = _strict_config_text()
    text = text.replace('provider = "anthropic"', 'provider = "openai"')
    path = _write_config(tmp_path, text, "invalid-provider.toml")
    with pytest.raises(ConfigError, match="llm.provider must be anthropic"):
        load_config(path)

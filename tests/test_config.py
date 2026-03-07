from __future__ import annotations

from pathlib import Path

import pytest

from padv.config.schema import ConfigError, load_config


def test_load_config_success() -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    assert config.target.base_url.startswith("http://")
    assert config.budgets.max_candidates > 0
    assert config.oracle.result_encoding == "base64-json"
    assert config.joern.parse_command == "joern-parse"
    assert config.joern.parse_language == "PHP"
    assert config.joern.use_http_api is False
    assert config.joern.enabled is True
    assert config.joern.fallback_to_regex is False
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


def test_load_config_backward_compatible_without_new_sections(tmp_path: Path) -> None:
    config_text = """
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
fallback_to_regex = false
"""
    path = tmp_path / "legacy.toml"
    path.write_text(config_text.strip() + "\n", encoding="utf-8")

    config = load_config(path)
    assert config.llm.provider == "anthropic"
    assert config.agent.use_deepagents is True
    assert config.agent.hard_fail is True
    assert config.agent.require_langgraph is True
    assert config.joern.enabled is True
    assert config.joern.fallback_to_regex is False
    assert config.scip.enabled is True
    assert config.web.enabled is True
    assert config.web.use_browser_use is True
    assert config.scip.hard_fail is True
    assert config.differential.enabled is True
    assert config.differential.auth_levels == ["anonymous"]
    assert config.differential.body_length_tolerance == 0.10


def test_load_config_rejects_disabled_always_on_flags(tmp_path: Path) -> None:
    config_text = """
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

[joern]
enabled = false
query_profile = "default"
command = "joern"
parse_command = "joern-parse"
parse_language = "PHP"
use_http_api = false
server_url = "http://127.0.0.1:8080"
script_path = ""
timeout_seconds = 600
fallback_to_regex = true

[agent]
use_deepagents = false
require_langgraph = false

[web]
enabled = false
use_browser_use = false
"""
    path = tmp_path / "invalid-flags.toml"
    path.write_text(config_text.strip() + "\n", encoding="utf-8")

    with pytest.raises(ConfigError):
        load_config(path)


def test_load_config_rejects_agent_hard_fail_false(tmp_path: Path) -> None:
    config_text = """
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
fallback_to_regex = false

[agent]
use_deepagents = true
hard_fail = false
require_langgraph = true

[web]
enabled = true
use_browser_use = true
"""
    path = tmp_path / "invalid-hard-fail.toml"
    path.write_text(config_text.strip() + "\n", encoding="utf-8")

    with pytest.raises(ConfigError, match="agent.hard_fail must be true"):
        load_config(path)


def test_load_config_rejects_non_anthropic_provider(tmp_path: Path) -> None:
    config_text = """
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
fallback_to_regex = false

[agent]
use_deepagents = true
hard_fail = true
require_langgraph = true

[llm]
provider = "openai"
model = "gpt-4.1"
api_key_env = "OPENAI_API_KEY"
temperature = 0.0
max_tokens = 1024
timeout_seconds = 60

[web]
enabled = true
use_browser_use = true
"""
    path = tmp_path / "invalid-provider.toml"
    path.write_text(config_text.strip() + "\n", encoding="utf-8")

    with pytest.raises(ConfigError, match="llm.provider must be anthropic"):
        load_config(path)

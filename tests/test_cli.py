from __future__ import annotations

import json
from pathlib import Path

from padv.cli.main import main
from padv.models import RunSummary
from padv.store.evidence_store import EvidenceStore


def _config_text(store_root: Path) -> str:
    return f"""
[target]
base_url = "http://127.0.0.1:8080/index.php"
request_timeout_seconds = 10
shared_session = false

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
root = "{store_root}"
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


def test_show_run_id_emits_json_by_default(tmp_path: Path, capsys) -> None:
    store = EvidenceStore(tmp_path / ".padv")
    store.save_run_summary(
        RunSummary(
            run_id="run-1234",
            mode="variant",
            started_at="2026-04-05T10:00:00+00:00",
            completed_at="2026-04-05T10:05:00+00:00",
            total_candidates=2,
            decisions={"CONFIRMED_ANALYSIS_FINDING": 1},
            bundle_ids=["bundle-1"],
            status="completed",
            stop_rule="budget",
            stop_reason="complete",
        )
    )
    config_path = tmp_path / "padv.toml"
    config_path.write_text(_config_text(store.root), encoding="utf-8")

    exit_code = main(["show", "--config", str(config_path), "--run-id", "run-1234"])

    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["run_id"] == "run-1234"
    assert payload["status"] == "completed"
    assert payload["bundle_ids"] == ["bundle-1"]

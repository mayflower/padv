from __future__ import annotations

import base64
import json
from pathlib import Path

from padv.config.schema import load_config
from padv.oracle.morcilla import parse_intercept_report, parse_response_headers


def test_parse_morcilla_headers() -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    payload = base64.b64encode(
        json.dumps(
            [
                {
                    "function": "mysqli_query",
                    "file": "app.php",
                    "line": 12,
                    "args": ['"select * from t where id=padv-abc"'],
                }
            ]
        ).encode("utf-8")
    ).decode("ascii")

    headers = {
        "X-Morcilla-Status": "active_hits",
        "X-Morcilla-Call-Count": "1",
        "X-Morcilla-Overflow": "0",
        "X-Morcilla-Arg-Truncated": "0",
        "X-Morcilla-Result-Truncated": "0",
        "X-Morcilla-Correlation": "req-1",
        "X-Morcilla-Result": payload,
    }

    runtime = parse_response_headers("req-1", headers, config.oracle)
    assert runtime.status == "active_hits"
    assert runtime.call_count == 1
    assert len(runtime.calls) == 1
    assert runtime.calls[0].function == "mysqli_query"


def test_parse_intercept_report_returns_typed_calls_deterministically() -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    payload = base64.b64encode(
        json.dumps(
            [
                {
                    "function": "mysqli_query",
                    "file": "app.php",
                    "line": 12,
                    "args": ['"select * from t where id=padv-abc"'],
                },
                {
                    "function": "printf",
                    "file": "view.php",
                    "line": 18,
                    "args": ["safe"],
                },
            ]
        ).encode("utf-8")
    ).decode("ascii")
    headers = {
        "X-Morcilla-Status": "active_hits",
        "X-Morcilla-Call-Count": "2",
        "X-Morcilla-Overflow": "0",
        "X-Morcilla-Arg-Truncated": "0",
        "X-Morcilla-Result-Truncated": "0",
        "X-Morcilla-Correlation": "req-typed",
        "X-Morcilla-Result": payload,
    }

    report = parse_intercept_report(headers, config.oracle)

    assert report.status == "active_hits"
    assert report.call_count == 2
    assert report.correlation_id == "req-typed"
    assert report.truncated is False
    assert [item.function for item in report.calls] == ["mysqli_query", "printf"]
    assert report.calls[0].args == ['"select * from t where id=padv-abc"']


def test_parse_intercept_report_detects_truncation_and_runtime_becomes_insufficient_evidence() -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    payload = base64.b64encode(
        json.dumps(
            [
                {
                    "function": "mysqli_query",
                    "file": "app.php",
                    "line": 12,
                    "args": ["padv-abc"],
                }
            ]
        ).encode("utf-8")
    ).decode("ascii")
    headers = {
        "X-Morcilla-Status": "active_hits",
        "X-Morcilla-Call-Count": "1",
        "X-Morcilla-Overflow": "0",
        "X-Morcilla-Arg-Truncated": "0",
        "X-Morcilla-Result-Truncated": "1",
        "X-Morcilla-Correlation": "req-trunc",
        "X-Morcilla-Result": payload,
    }

    report = parse_intercept_report(headers, config.oracle)
    runtime = parse_response_headers("req-trunc", headers, config.oracle)

    assert report.truncated is True
    assert report.truncation_reason == "result_truncated"
    assert runtime.status == "insufficient_evidence"
    assert runtime.result_truncated is True
    assert runtime.aux["truncation_reason"] == "result_truncated"

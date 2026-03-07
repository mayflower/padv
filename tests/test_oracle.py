from __future__ import annotations

import base64
import json
from pathlib import Path

from padv.config.schema import load_config
from padv.oracle.morcilla import parse_response_headers


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

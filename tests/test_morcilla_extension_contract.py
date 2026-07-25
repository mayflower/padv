"""Contract test between the real morcilla PHP extension and PADV's oracle parser.

Every other runtime test in this suite feeds synthetic response headers into
``parse_intercept_report``. That proves the parser works; it proves nothing about
whether the extension actually emits those headers. This module builds the real
extension, issues real requests and asserts the contract end to end, up to and
including the V0 scope gate.

Marked ``integration``: it needs docker and the morcilla source checkout.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterator
from pathlib import Path

import pytest
from padv.config.schema import load_config
from padv.gates.engine import _evaluate_v0_scope
from padv.oracle.morcilla import parse_intercept_report, parse_response_headers

pytestmark = pytest.mark.integration

REPO_ROOT = Path(__file__).resolve().parents[1]
PROBE_DIR = REPO_ROOT / "tests" / "fixtures" / "effectiveness" / "morcilla_probe"
CONFIG_PATH = REPO_ROOT / "padv.mutillidae.strict.toml"

IMAGE_TAG = "padv-morcilla-contract:test"
CONTAINER_NAME = "padv-morcilla-contract"
HOST_PORT = 18099
API_KEY = "test-key"


def _morcilla_src() -> Path:
    configured = os.environ.get("MORCILLA_SRC_DIR", "").strip()
    candidate = Path(configured) if configured else REPO_ROOT.parent / "morcilla"
    return candidate


def _docker(*args: str, timeout: int = 900) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", *args],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


@pytest.fixture(scope="module")
def probe_url(tmp_path_factory) -> Iterator[str]:
    if shutil.which("docker") is None:
        pytest.skip("docker is not available")

    src = _morcilla_src()
    if not (src / "morcilla.c").is_file():
        pytest.skip(f"morcilla extension source not found at {src}; set MORCILLA_SRC_DIR")

    context = tmp_path_factory.mktemp("morcilla-context")
    shutil.copytree(src, context / "ext" / "morcilla", ignore=shutil.ignore_patterns(".git"))
    shutil.copy(PROBE_DIR / "Dockerfile", context / "Dockerfile")
    shutil.copy(PROBE_DIR / "probe.php", context / "probe.php")

    build = _docker("build", "-q", "-t", IMAGE_TAG, str(context))
    if build.returncode != 0:
        pytest.skip(f"could not build morcilla probe image: {build.stderr.strip()[:400]}")

    _docker("rm", "-f", CONTAINER_NAME, timeout=60)
    run = _docker(
        "run", "-d", "--name", CONTAINER_NAME, "-p", f"{HOST_PORT}:80", IMAGE_TAG, timeout=120
    )
    if run.returncode != 0:
        pytest.skip(f"could not start morcilla probe container: {run.stderr.strip()[:400]}")

    url = f"http://127.0.0.1:{HOST_PORT}/probe.php"
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2):
                break
        except (urllib.error.URLError, OSError):
            time.sleep(0.5)
    else:  # pragma: no cover - only on a broken docker host
        _docker("rm", "-f", CONTAINER_NAME, timeout=60)
        pytest.skip("morcilla probe container did not become ready")

    yield url

    _docker("rm", "-f", CONTAINER_NAME, timeout=60)


def _request(
    probe_url: str,
    *,
    key: str | None = API_KEY,
    intercept: str | None = "probe::query",
    correlation: str | None = None,
    query: str = "padv-canary-abc123",
    repeat: int = 1,
) -> dict[str, str]:
    url = f"{probe_url}?q={urllib.parse.quote(query)}&repeat={repeat}"
    request = urllib.request.Request(url)
    if key is not None:
        request.add_header("Morcilla-Key", key)
    if intercept is not None:
        request.add_header("Morcilla-Intercept", intercept)
    if correlation is not None:
        request.add_header("Morcilla-Correlation", correlation)
    with urllib.request.urlopen(request, timeout=15) as response:
        return dict(response.headers.items())


def _oracle():
    return load_config(CONFIG_PATH).oracle


def test_active_hits_reports_full_contract(probe_url: str) -> None:
    """The headline case: a real intercept must survive PADV's V0 scope gate."""
    correlation = "padv-corr-active-hits"
    headers = _request(probe_url, correlation=correlation)

    report = parse_intercept_report(headers, _oracle())
    assert report.status == "active_hits"
    assert report.call_count == 1
    assert report.correlation_id == correlation
    assert report.overflow is False
    assert report.arg_truncated is False
    assert report.result_truncated is False
    assert report.truncated is False

    assert len(report.calls) == 1
    call = report.calls[0]
    assert call.function == "Probe::query"
    assert call.file.endswith("/probe.php")
    assert "padv-canary-abc123" in call.args[0]

    evidence = parse_response_headers("req-1", headers, _oracle())
    _pos, _neg, v0_failure = _evaluate_v0_scope([evidence, evidence], [evidence])
    assert v0_failure is None, f"V0 rejected a real morcilla run: {v0_failure}"


def test_call_count_header_matches_payload(probe_url: str) -> None:
    headers = _request(probe_url, repeat=3)
    report = parse_intercept_report(headers, _oracle())
    assert report.call_count == 3
    assert len(report.calls) == 3


def test_active_no_hits_when_nothing_matches(probe_url: str) -> None:
    """Zero interceptions is a valid observation, not an absent oracle."""
    headers = _request(probe_url, intercept="some::function_that_is_never_called")
    report = parse_intercept_report(headers, _oracle())
    assert report.status == "active_no_hits"
    assert report.call_count == 0
    assert report.calls == []


def test_wrong_key_reports_auth_failed(probe_url: str) -> None:
    headers = _request(probe_url, key="wrong-key")
    report = parse_intercept_report(headers, _oracle())
    assert report.status == "auth_failed"


def test_missing_intercept_list_is_reported(probe_url: str) -> None:
    headers = _request(probe_url, intercept=None)
    report = parse_intercept_report(headers, _oracle())
    assert report.status == "missing_intercept"


def test_no_morcilla_headers_without_key(probe_url: str) -> None:
    """A request PADV did not send must stay completely unmarked."""
    headers = _request(probe_url, key=None, intercept=None)
    assert not [name for name in headers if name.lower().startswith("x-morcilla")]


def test_argument_truncation_is_signalled(probe_url: str) -> None:
    """Truncation must reach PADV as a header, not only as an in-band '...'."""
    headers = _request(probe_url, query="A" * 600)
    report = parse_intercept_report(headers, _oracle())
    assert report.status == "active_hits"
    assert report.arg_truncated is True
    assert report.truncated is True

    evidence = parse_response_headers("req-trunc", headers, _oracle())
    assert evidence.status == "insufficient_evidence"


def test_correlation_is_echoed_verbatim(probe_url: str) -> None:
    for correlation in ("padv-corr-0001", "padv-corr-0002"):
        headers = _request(probe_url, correlation=correlation)
        report = parse_intercept_report(headers, _oracle())
        assert report.correlation_id == correlation


def test_result_payload_is_valid_base64_json(probe_url: str) -> None:
    import base64

    headers = _request(probe_url)
    raw = {k.lower(): v for k, v in headers.items()}["x-morcilla-result"]
    decoded = json.loads(base64.b64decode(raw, validate=True))
    assert isinstance(decoded, list)
    assert decoded[0]["function"] == "Probe::query"
    assert isinstance(decoded[0]["line"], int)

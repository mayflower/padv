"""How the runtime binds the XSS execution oracle into the gate decision.

These do not launch a browser. They exercise the wiring: a candidate whose
oracle is unavailable is SKIPPED_PRECONDITION (requires_browser), and a fake
oracle that confirms execution feeds xss_execution_witness into the flags the
gate consumes.
"""

from __future__ import annotations

from pathlib import Path

from padv.config.schema import load_config
from padv.dynamic.browser.oracle import ProbeResult
from padv.models import Candidate, RuntimeCall, RuntimeEvidence, ValidationPlan
from padv.orchestrator import runtime as rt
from padv.validation.preconditions import GatePreconditions

CONFIG_PATH = Path(__file__).resolve().parents[1] / "padv.toml"


def _xss_candidate() -> Candidate:
    return Candidate(
        candidate_id="cand-xss",
        vuln_class="xss_output_boundary",
        title="Reflected XSS",
        file_path="src/dns-lookup.php",
        line=151,
        sink="echo",
        expected_intercepts=["echo"],
        canonical_class="xss_output_boundary",
    )


def _plan(canary: str = "padv-canary") -> ValidationPlan:
    return ValidationPlan(
        candidate_id="cand-xss",
        intercepts=["echo"],
        positive_requests=[{"path": "/index.php", "method": "GET", "query": {"page": "dns-lookup.php", "target_host": canary}}],
        negative_requests=[],
        canary=canary,
        canonical_class="xss_output_boundary",
    )


def _positive_run() -> RuntimeEvidence:
    return RuntimeEvidence(
        request_id="p1",
        status="http_observed",
        call_count=0,
        overflow=False,
        arg_truncated=False,
        result_truncated=False,
        correlation="p1",
        calls=[RuntimeCall(function="echo", file="dns-lookup.php", line=151, args=["padv-canary"])],
        raw_headers={},
    )


class _Target:
    """Minimal stand-in for _PreparedValidationTarget for the helper under test."""

    def __init__(self, candidate: Candidate) -> None:
        self.candidate = candidate
        self.preconditions = GatePreconditions()


def _ctx(browser_oracle) -> rt._ValidationContext:
    return rt._ValidationContext(
        config=load_config(CONFIG_PATH),
        store=None,  # type: ignore[arg-type]
        run_id="run-x",
        cookie_jar={},
        auth_state={},
        planner_trace={},
        discovery_trace={},
        artifact_refs=[],
        browser_oracle=browser_oracle,
    )


def test_injection_param_is_the_key_carrying_the_canary() -> None:
    assert rt._xss_injection_param(_plan()) == "target_host"


def test_missing_oracle_marks_requires_browser() -> None:
    target = _Target(_xss_candidate())
    runs = [_positive_run()]
    rt._apply_xss_execution_oracle(_ctx(None), target, target.candidate, _plan(), runs)

    assert target.preconditions.requires_browser is True
    # no execution witness was fabricated
    assert all("xss_execution_witness" not in r.analysis_flags for r in runs)


def test_confirmed_execution_feeds_the_witness_flag() -> None:
    class _FakeOracle:
        def probe(self, **_kwargs):
            return ProbeResult(
                executed=True,
                positive_flags={"xss_execution_witness", "xss_dom_witness"},
                callback_token="tok",
                callback_hits={"/cb/tok/script_tag"},
                firing_variant="script_tag",
                dom_execution_context="script_text",
            )

    target = _Target(_xss_candidate())
    runs = [_positive_run()]
    rt._apply_xss_execution_oracle(_ctx(_FakeOracle()), target, target.candidate, _plan(), runs)

    assert target.preconditions.requires_browser is False
    assert all("xss_execution_witness" in r.analysis_flags for r in runs)


def test_oracle_that_finds_no_execution_leaves_flags_clean() -> None:
    class _QuietOracle:
        def probe(self, **_kwargs):
            return ProbeResult(executed=False, detail="nothing executed")

    target = _Target(_xss_candidate())
    runs = [_positive_run()]
    rt._apply_xss_execution_oracle(_ctx(_QuietOracle()), target, target.candidate, _plan(), runs)

    # No witness, but also not a precondition skip: the experiment ran and the
    # payload simply did not execute, which the gate should treat as REFUTED.
    assert target.preconditions.requires_browser is False
    assert all("xss_execution_witness" not in r.analysis_flags for r in runs)


def test_non_xss_candidate_is_untouched() -> None:
    sqli = Candidate(
        candidate_id="cand-sql",
        vuln_class="sql_injection_boundary",
        title="SQLi",
        file_path="src/a.php",
        line=1,
        sink="mysqli::query",
        expected_intercepts=["mysqli::query"],
        canonical_class="sql_injection_boundary",
    )
    target = _Target(sqli)
    runs = [_positive_run()]
    rt._apply_xss_execution_oracle(_ctx(None), target, sqli, _plan(), runs)
    assert target.preconditions.requires_browser is False

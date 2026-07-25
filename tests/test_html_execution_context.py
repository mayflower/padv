"""The XSS witness must depend on where the canary lands, not on what else is on the page.

The previous rule was "raw canary somewhere in the body AND the substring
'<script' somewhere in the body". Almost every real page loads a script, so that
reduced to "the canary was reflected at all" — which is not execution.
"""

from __future__ import annotations

import pytest
from padv.validation.html_context import canary_execution_context

CANARY = "padv-canary-abc123"


def _page(body: str) -> str:
    """A realistic page: it loads a script, like nearly every application does."""
    return (
        "<!doctype html><html><head>"
        '<script src="/js/jquery.min.js"></script>'
        "</head><body>" + body + "</body></html>"
    )


# --- the false positive this replaces -----------------------------------


def test_reflection_into_plain_text_is_not_execution() -> None:
    body = _page(f"<p>No results for {CANARY}</p>")
    assert canary_execution_context(body, CANARY) is None


def test_reflection_into_a_non_handler_attribute_is_not_execution() -> None:
    body = _page(f'<input type="text" name="q" value="{CANARY}">')
    assert canary_execution_context(body, CANARY) is None


def test_reflection_into_a_normal_href_is_not_execution() -> None:
    body = _page(f'<a href="/search?q={CANARY}">retry</a>')
    assert canary_execution_context(body, CANARY) is None


def test_absent_canary_is_not_execution() -> None:
    assert canary_execution_context(_page("<p>nothing here</p>"), CANARY) is None


def test_html_comment_is_not_execution() -> None:
    body = _page(f"<!-- debug: {CANARY} -->")
    assert canary_execution_context(body, CANARY) is None


# --- genuine executable contexts ----------------------------------------


def test_canary_inside_script_text_is_execution() -> None:
    body = _page(f"<script>var q = '{CANARY}';</script>")
    assert canary_execution_context(body, CANARY) == "script_text"


def test_canary_in_event_handler_attribute_is_execution() -> None:
    body = _page(f'<img src="x" onerror="{CANARY}">')
    assert canary_execution_context(body, CANARY) == "event_handler"


@pytest.mark.parametrize("handler", ["onload", "onclick", "onmouseover", "onfocus"])
def test_any_event_handler_attribute_counts(handler: str) -> None:
    body = _page(f'<div {handler}="{CANARY}">x</div>')
    assert canary_execution_context(body, CANARY) == "event_handler"


def test_javascript_url_is_execution() -> None:
    body = _page(f'<a href="javascript:{CANARY}">click</a>')
    assert canary_execution_context(body, CANARY) == "javascript_url"


def test_canary_that_closes_a_tag_and_opens_a_script_is_execution() -> None:
    """The classic breakout: the reflection itself introduces the script element."""
    body = _page(f'<input value="x"><script>{CANARY}</script>')
    assert canary_execution_context(body, CANARY) == "script_text"


# --- robustness ---------------------------------------------------------


def test_malformed_markup_does_not_raise() -> None:
    body = f"<div><span onerror='{CANARY}'</div><script>"
    assert canary_execution_context(body, CANARY) in {"event_handler", "script_text", None}


def test_empty_inputs_are_safe() -> None:
    assert canary_execution_context("", CANARY) is None
    assert canary_execution_context(_page("x"), "") is None


def test_style_element_is_not_script_context() -> None:
    body = _page(f"<style>body {{ background: url({CANARY}) }}</style>")
    assert canary_execution_context(body, CANARY) is None


# --- the runtime flag deriver ------------------------------------------


def test_derived_flags_do_not_mark_a_plain_reflection_as_dom_witness() -> None:
    from padv.orchestrator.runtime import _derive_body_canary_flags

    body = _page(f"<p>No results for {CANARY}</p>")
    flags, has_raw = _derive_body_canary_flags(body, CANARY)

    assert has_raw is True
    assert "xss_raw_canary" in flags
    assert "xss_dom_witness" not in flags


def test_derived_flags_record_the_context_that_justified_the_witness() -> None:
    from padv.orchestrator.runtime import _derive_body_canary_flags

    flags, _ = _derive_body_canary_flags(_page(f"<script>x='{CANARY}'</script>"), CANARY)
    assert "xss_dom_witness" in flags
    assert "xss_context_script_text" in flags


def test_escaped_reflection_yields_no_xss_flags() -> None:
    from padv.orchestrator.runtime import _derive_body_canary_flags

    body = _page(f"<p>&lt;b&gt;{CANARY}&lt;/b&gt;</p><script>var a=1;</script>")
    flags, _ = _derive_body_canary_flags(body, CANARY)
    assert "xss_dom_witness" not in flags

"""Decide whether a canary landed somewhere a browser would execute it.

Substring checks over a whole response cannot answer that question: nearly every
page contains a ``<script>`` tag, so "the canary is present and a script tag is
present" is true for any reflection at all. This parses the document instead and
reports the position of the canary relative to the parse tree.

It answers where the canary ended up, not whether a browser did execute it. A
real execution oracle still needs a browser; this only stops a plain reflection
from being reported as one.
"""

from __future__ import annotations

from html.parser import HTMLParser

# Contexts, in the order they are preferred when a canary occurs more than once.
SCRIPT_TEXT = "script_text"
EVENT_HANDLER = "event_handler"
JAVASCRIPT_URL = "javascript_url"

_URL_ATTRIBUTES = frozenset({"href", "src", "action", "formaction", "data", "poster"})
_SCRIPTABLE_URL_SCHEMES = ("javascript:", "data:text/html")


class _CanaryContextParser(HTMLParser):
    def __init__(self, canary: str) -> None:
        super().__init__(convert_charrefs=False)
        self._canary = canary
        self._script_depth = 0
        self.contexts: set[str] = set()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "script":
            self._script_depth += 1
        self._inspect_attrs(attrs)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._inspect_attrs(attrs)

    def handle_endtag(self, tag: str) -> None:
        if tag == "script" and self._script_depth > 0:
            self._script_depth -= 1

    def handle_data(self, data: str) -> None:
        if self._script_depth > 0 and self._canary in data:
            self.contexts.add(SCRIPT_TEXT)

    def _inspect_attrs(self, attrs: list[tuple[str, str | None]]) -> None:
        for raw_name, raw_value in attrs:
            value = raw_value or ""
            if self._canary not in value:
                continue
            name = (raw_name or "").strip().casefold()
            if name.startswith("on") and len(name) > 2:
                self.contexts.add(EVENT_HANDLER)
                continue
            if name in _URL_ATTRIBUTES:
                stripped = value.strip().casefold().replace(" ", "").replace("\t", "")
                if stripped.startswith(_SCRIPTABLE_URL_SCHEMES):
                    self.contexts.add(JAVASCRIPT_URL)


def canary_execution_context(body: str, canary: str) -> str | None:
    """Return the executable context the canary occupies, or None.

    ``None`` covers both "not reflected" and "reflected somewhere inert", since
    neither is evidence of execution.
    """
    if not body or not canary:
        return None
    if canary not in body:
        return None

    parser = _CanaryContextParser(canary)
    try:
        parser.feed(body)
        parser.close()
    except Exception:
        # Malformed markup is common in error pages. Whatever the parser managed
        # to classify before giving up still stands; nothing is assumed beyond it.
        pass

    for context in (SCRIPT_TEXT, EVENT_HANDLER, JAVASCRIPT_URL):
        if context in parser.contexts:
            return context
    return None

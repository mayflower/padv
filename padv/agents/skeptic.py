from __future__ import annotations

from padv.models import Candidate


def minimize_intercepts(candidate: Candidate) -> list[str]:
    if candidate.expected_intercepts:
        return sorted(set(candidate.expected_intercepts))
    if candidate.sink:
        return [candidate.sink.replace("(", "").replace("->", "::")]
    return []


def required_preconditions(candidate: Candidate) -> list[str]:
    return candidate.preconditions

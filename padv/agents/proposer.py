from __future__ import annotations

from padv.models import Candidate


def rank_candidates(candidates: list[Candidate], mode: str) -> list[Candidate]:
    runtime_first = sorted(
        candidates,
        key=lambda c: (len(c.expected_intercepts) == 0, -c.confidence, c.file_path, c.line),
    )
    if mode == "delta":
        return [c for c in runtime_first if "vendor/" not in c.file_path]
    return runtime_first

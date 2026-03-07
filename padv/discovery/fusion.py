from __future__ import annotations

from dataclasses import replace

from padv.config.schema import PadvConfig
from padv.models import Candidate, StaticEvidence


def _merge_lists(a: list[str], b: list[str]) -> list[str]:
    out = list(a)
    seen = set(a)
    for item in b:
        if item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def fuse_candidates(
    candidates: list[Candidate],
    static_evidence: list[StaticEvidence],
    config: PadvConfig,
) -> tuple[list[Candidate], list[StaticEvidence]]:
    if not candidates:
        return [], []

    key_by_old_id: dict[str, tuple[str, str, int, str]] = {}
    merged: dict[tuple[str, str, int, str], Candidate] = {}
    for cand in candidates:
        key = (cand.vuln_class, cand.file_path, cand.line, cand.sink)
        key_by_old_id[cand.candidate_id] = key
        current = merged.get(key)
        if current is None:
            merged[key] = replace(cand)
            continue
        current.provenance = _merge_lists(current.provenance, cand.provenance)
        current.evidence_refs = _merge_lists(current.evidence_refs, cand.evidence_refs)
        current.expected_intercepts = _merge_lists(current.expected_intercepts, cand.expected_intercepts)
        current.preconditions = _merge_lists(current.preconditions, cand.preconditions)
        current.auth_requirements = _merge_lists(current.auth_requirements, cand.auth_requirements)
        current.web_path_hints = _merge_lists(current.web_path_hints, cand.web_path_hints)
        if cand.confidence > current.confidence:
            current.confidence = cand.confidence
        if not current.entrypoint_hint and cand.entrypoint_hint:
            current.entrypoint_hint = cand.entrypoint_hint
        if cand.notes and cand.notes not in current.notes:
            current.notes = f"{current.notes}; {cand.notes}".strip("; ")

    merged_list = sorted(
        merged.items(),
        key=lambda item: (-item[1].confidence, item[1].file_path, item[1].line, item[1].vuln_class),
    )
    merged_list = merged_list[: config.budgets.max_candidates]

    new_candidates: list[Candidate] = []
    remap: dict[tuple[str, str, int, str], str] = {}
    for idx, (key, cand) in enumerate(merged_list, start=1):
        new_id = f"cand-{idx:05d}"
        remap[key] = new_id
        cand.candidate_id = new_id
        new_candidates.append(cand)

    new_static: list[StaticEvidence] = []
    seen_hashes: set[tuple[str, str]] = set()
    for item in static_evidence:
        key = key_by_old_id.get(item.candidate_id)
        if key is None:
            continue
        candidate_id = remap.get(key)
        if not candidate_id:
            continue
        dedup_key = (candidate_id, item.hash)
        if dedup_key in seen_hashes:
            continue
        seen_hashes.add(dedup_key)
        new_static.append(
            StaticEvidence(
                candidate_id=candidate_id,
                query_profile=item.query_profile,
                query_id=item.query_id,
                file_path=item.file_path,
                line=item.line,
                snippet=item.snippet,
                hash=item.hash,
            )
        )

    return new_candidates, new_static

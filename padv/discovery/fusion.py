from __future__ import annotations

from dataclasses import dataclass
from dataclasses import replace

from padv.config.schema import PadvConfig
from padv.models import Candidate, StaticEvidence

_SEMANTIC_SIGNALS = frozenset({"joern", "scip"})


@dataclass(slots=True)
class FusionMeta:
    input_candidates: int
    fused_candidates: int
    dual_signal_candidates: int
    dropped_nonsemantic_candidates: int
    evidence_graph: dict[str, dict[str, object]]


def _merge_lists(a: list[str], b: list[str]) -> list[str]:
    out = list(a)
    seen = set(a)
    for item in b:
        if item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def _semantic_signals(candidate: Candidate) -> set[str]:
    return {
        signal
        for signal in candidate.provenance
        if isinstance(signal, str) and signal.strip().lower() in _SEMANTIC_SIGNALS
    }


def _semantic_score(candidate: Candidate) -> int:
    return len(_semantic_signals(candidate))


def _merge_candidate_fields(target: Candidate, incoming: Candidate) -> None:
    target.provenance = _merge_lists(target.provenance, incoming.provenance)
    target.evidence_refs = _merge_lists(target.evidence_refs, incoming.evidence_refs)
    target.expected_intercepts = _merge_lists(target.expected_intercepts, incoming.expected_intercepts)
    target.preconditions = _merge_lists(target.preconditions, incoming.preconditions)
    target.auth_requirements = _merge_lists(target.auth_requirements, incoming.auth_requirements)
    target.web_path_hints = _merge_lists(target.web_path_hints, incoming.web_path_hints)

    # Prefer the stronger semantic signal candidate as primary sink/position anchor.
    target_score = (_semantic_score(target), target.confidence)
    incoming_score = (_semantic_score(incoming), incoming.confidence)
    if incoming_score > target_score and incoming.sink:
        target.sink = incoming.sink
        target.line = incoming.line

    if incoming.confidence > target.confidence:
        target.confidence = incoming.confidence
    if not target.entrypoint_hint and incoming.entrypoint_hint:
        target.entrypoint_hint = incoming.entrypoint_hint
    if incoming.notes and incoming.notes not in target.notes:
        target.notes = f"{target.notes}; {incoming.notes}".strip("; ")


def _merge_candidates_by_key(
    candidates: list[Candidate],
) -> tuple[dict[str, tuple[str, str, int]], dict[tuple[str, str, int], Candidate], int]:
    key_by_old_id: dict[str, tuple[str, str, int]] = {}
    merged: dict[tuple[str, str, int], Candidate] = {}
    dropped_nonsemantic = 0
    for cand in candidates:
        key = (cand.vuln_class, cand.file_path, cand.line)
        key_by_old_id[cand.candidate_id] = key
        if _semantic_score(cand) == 0:
            dropped_nonsemantic += 1
            continue
        current = merged.get(key)
        if current is None:
            merged[key] = replace(cand)
            continue
        _merge_candidate_fields(current, cand)
    return key_by_old_id, merged, dropped_nonsemantic


def _assign_ids_and_boost(
    merged: dict[tuple[str, str, int], Candidate],
    max_candidates: int,
) -> tuple[list[Candidate], dict[tuple[str, str, int], str], int]:
    merged_list = sorted(
        merged.items(),
        key=lambda item: (
            -_semantic_score(item[1]),
            -item[1].confidence,
            item[1].file_path,
            item[1].line,
            item[1].vuln_class,
        ),
    )[:max_candidates]

    new_candidates: list[Candidate] = []
    remap: dict[tuple[str, str, int], str] = {}
    dual_signal_candidates = 0
    for idx, (key, cand) in enumerate(merged_list, start=1):
        new_id = f"cand-{idx:05d}"
        remap[key] = new_id
        cand.candidate_id = new_id
        if _semantic_score(cand) >= 2:
            dual_signal_candidates += 1
            cand.confidence = min(1.0, cand.confidence + 0.1)
            if "multi-signal-semantic" not in cand.notes:
                cand.notes = f"{cand.notes}; multi-signal-semantic".strip("; ")
        new_candidates.append(cand)
    return new_candidates, remap, dual_signal_candidates


def _remap_static_evidence(
    static_evidence: list[StaticEvidence],
    key_by_old_id: dict[str, tuple[str, str, int]],
    remap: dict[tuple[str, str, int], str],
) -> list[StaticEvidence]:
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
    return new_static


def _build_evidence_graph(
    new_candidates: list[Candidate],
    new_static: list[StaticEvidence],
) -> dict[str, dict[str, object]]:
    static_refs: dict[str, list[str]] = {}
    for item in new_static:
        static_refs.setdefault(item.candidate_id, []).append(item.query_id)

    evidence_graph: dict[str, dict[str, object]] = {}
    for cand in new_candidates:
        semantic = sorted(_semantic_signals(cand))
        evidence_graph[cand.candidate_id] = {
            "semantic_signals": semantic,
            "semantic_signal_count": len(semantic),
            "provenance": list(cand.provenance),
            "evidence_refs": list(cand.evidence_refs),
            "static_query_ids": sorted(static_refs.get(cand.candidate_id, [])),
            "has_dual_signal": len(semantic) >= 2,
        }
    return evidence_graph


def fuse_candidates_with_meta(
    candidates: list[Candidate],
    static_evidence: list[StaticEvidence],
    config: PadvConfig,
) -> tuple[list[Candidate], list[StaticEvidence], FusionMeta]:
    if not candidates:
        return [], [], FusionMeta(0, 0, 0, 0, {})

    key_by_old_id, merged, dropped_nonsemantic = _merge_candidates_by_key(candidates)
    new_candidates, remap, dual_signal_candidates = _assign_ids_and_boost(merged, config.budgets.max_candidates)
    new_static = _remap_static_evidence(static_evidence, key_by_old_id, remap)
    evidence_graph = _build_evidence_graph(new_candidates, new_static)

    meta = FusionMeta(
        input_candidates=len(candidates),
        fused_candidates=len(new_candidates),
        dual_signal_candidates=dual_signal_candidates,
        dropped_nonsemantic_candidates=dropped_nonsemantic,
        evidence_graph=evidence_graph,
    )
    return new_candidates, new_static, meta


def fuse_candidates(
    candidates: list[Candidate],
    static_evidence: list[StaticEvidence],
    config: PadvConfig,
) -> tuple[list[Candidate], list[StaticEvidence]]:
    merged_candidates, merged_static, _meta = fuse_candidates_with_meta(candidates, static_evidence, config)
    return merged_candidates, merged_static

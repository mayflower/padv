from __future__ import annotations

from dataclasses import dataclass
from dataclasses import replace

from padv.config.schema import PadvConfig
from padv.identity import (
    candidate_sink_signature_for_fields,
    candidate_slice_signature_for_fields,
    candidate_uid_for_fields,
)
from padv.models import Candidate, StaticEvidence

_SEMANTIC_SIGNALS = frozenset({"joern", "scip"})
_PROVENANCE_PRIORITY = {"joern": 0, "scip": 1}


@dataclass(slots=True)
class FusionMeta:
    input_candidates: int
    fused_candidates: int
    dual_signal_candidates: int
    dropped_nonsemantic_candidates: int
    evidence_graph: dict[str, dict[str, object]]


def _merge_lists(a: list[str], b: list[str]) -> list[str]:
    merged = {
        str(item).strip()
        for item in [*a, *b]
        if isinstance(item, str) and str(item).strip()
    }
    return sorted(merged, key=lambda item: (item.casefold(), item))


def _merge_notes(a: str, b: str) -> str:
    parts = {
        segment.strip()
        for value in (a, b)
        for segment in str(value or "").split(";")
        if segment.strip()
    }
    return "; ".join(sorted(parts, key=lambda item: (item.casefold(), item)))


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

    if incoming.confidence > target.confidence:
        target.confidence = incoming.confidence
    if not target.entrypoint_hint and incoming.entrypoint_hint:
        target.entrypoint_hint = incoming.entrypoint_hint
    target.notes = _merge_notes(target.notes, incoming.notes)


def _provenance_priority(candidate: Candidate) -> tuple[int, ...]:
    semantic = _semantic_signals(candidate)
    if not semantic:
        return (len(_PROVENANCE_PRIORITY) + 1,)
    return tuple(sorted(_PROVENANCE_PRIORITY.get(signal.casefold(), len(_PROVENANCE_PRIORITY) + 1) for signal in semantic))


def _primary_candidate_rank(candidate: Candidate) -> tuple[int, tuple[int, ...], float, str, str]:
    return (
        -_semantic_score(candidate),
        _provenance_priority(candidate),
        -float(candidate.confidence),
        str(candidate.candidate_uid or "").strip(),
        str(candidate.candidate_id or "").strip(),
    )


def _sink_signature(candidate: Candidate) -> str:
    return candidate_sink_signature_for_fields(
        sink=candidate.sink,
        expected_intercepts=candidate.expected_intercepts,
    )


def _slice_signature(candidate: Candidate) -> str:
    return candidate_slice_signature_for_fields(entrypoint_hint=candidate.entrypoint_hint)


def _merge_key(candidate: Candidate) -> tuple[str, str, int, str, str]:
    return (
        str(candidate.vuln_class).strip(),
        str(candidate.file_path).strip(),
        int(candidate.line),
        _sink_signature(candidate),
        _slice_signature(candidate),
    )


def _merge_candidates_by_key(
    candidates: list[Candidate],
) -> tuple[dict[str, tuple[str, str, int, str, str]], dict[str, tuple[str, str, int, str, str]], dict[tuple[str, str, int, str, str], Candidate], int]:
    key_by_old_id: dict[str, tuple[str, str, int, str, str]] = {}
    key_by_old_uid: dict[str, tuple[str, str, int, str, str]] = {}
    merged: dict[tuple[str, str, int, str, str], Candidate] = {}
    dropped_nonsemantic = 0
    for cand in candidates:
        key = _merge_key(cand)
        key_by_old_id[cand.candidate_id] = key
        key_by_old_uid[cand.candidate_uid] = key
        if _semantic_score(cand) == 0:
            dropped_nonsemantic += 1
            continue
        current = merged.get(key)
        if current is None:
            merged[key] = replace(cand)
            continue
        if _primary_candidate_rank(cand) < _primary_candidate_rank(current):
            replacement = replace(cand)
            _merge_candidate_fields(replacement, current)
            merged[key] = replacement
            continue
        _merge_candidate_fields(current, cand)
    return key_by_old_id, key_by_old_uid, merged, dropped_nonsemantic


def _assign_ids_and_boost(
    merged: dict[tuple[str, str, int, str, str], Candidate],
    max_candidates: int,
) -> tuple[list[Candidate], dict[tuple[str, str, int, str, str], tuple[str, str]], int]:
    for cand in merged.values():
        cand.candidate_uid = candidate_uid_for_fields(
            vuln_class=cand.vuln_class,
            file_path=cand.file_path,
            line=cand.line,
            sink=cand.sink,
            expected_intercepts=cand.expected_intercepts,
            entrypoint_hint=cand.entrypoint_hint,
            provenance=cand.provenance,
        )
    merged_list = sorted(
        merged.items(),
        key=lambda item: (
            _primary_candidate_rank(item[1]),
            item[0],
            item[1].file_path,
            item[1].line,
            item[1].vuln_class,
            item[1].candidate_uid,
            item[1].candidate_id,
        ),
    )[:max_candidates]

    new_candidates: list[Candidate] = []
    remap: dict[tuple[str, str, int, str, str], tuple[str, str]] = {}
    dual_signal_candidates = 0
    for key, cand in merged_list:
        remap[key] = (cand.candidate_id, cand.candidate_uid)
        if _semantic_score(cand) >= 2:
            dual_signal_candidates += 1
            cand.confidence = min(1.0, cand.confidence + 0.1)
            cand.notes = _merge_notes(cand.notes, "multi-signal-semantic")
        new_candidates.append(cand)
    return new_candidates, remap, dual_signal_candidates


def _remap_static_evidence(
    static_evidence: list[StaticEvidence],
    key_by_old_id: dict[str, tuple[str, str, int, str, str]],
    key_by_old_uid: dict[str, tuple[str, str, int, str, str]],
    remap: dict[tuple[str, str, int, str, str], tuple[str, str]],
) -> list[StaticEvidence]:
    new_static: list[StaticEvidence] = []
    seen_hashes: set[tuple[str, str]] = set()
    for item in static_evidence:
        key = key_by_old_uid.get(item.candidate_uid) if item.candidate_uid else None
        if key is None:
            key = key_by_old_id.get(item.candidate_id)
        if key is None:
            continue
        anchor = remap.get(key)
        if not anchor:
            continue
        candidate_id, candidate_uid = anchor
        dedup_key = (candidate_uid, item.hash)
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
                candidate_uid=candidate_uid,
            )
        )
    return sorted(
        new_static,
        key=lambda item: (
            str(item.candidate_uid or ""),
            str(item.file_path),
            int(item.line),
            str(item.query_id),
            str(item.hash),
        ),
    )


def _build_evidence_graph(
    new_candidates: list[Candidate],
    new_static: list[StaticEvidence],
) -> dict[str, dict[str, object]]:
    static_refs: dict[str, list[str]] = {}
    for item in new_static:
        static_refs.setdefault(item.candidate_uid or item.candidate_id, []).append(item.query_id)

    evidence_graph: dict[str, dict[str, object]] = {}
    for cand in new_candidates:
        semantic = sorted(_semantic_signals(cand))
        evidence_graph[cand.candidate_uid] = {
            "candidate_id": cand.candidate_id,
            "semantic_signals": semantic,
            "semantic_signal_count": len(semantic),
            "provenance": list(cand.provenance),
            "evidence_refs": list(cand.evidence_refs),
            "static_query_ids": sorted(static_refs.get(cand.candidate_uid, [])),
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

    key_by_old_id, key_by_old_uid, merged, dropped_nonsemantic = _merge_candidates_by_key(candidates)
    new_candidates, remap, dual_signal_candidates = _assign_ids_and_boost(merged, config.budgets.max_candidates)
    new_static = _remap_static_evidence(static_evidence, key_by_old_id, key_by_old_uid, remap)
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

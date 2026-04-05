from __future__ import annotations

from dataclasses import dataclass
from collections.abc import Iterable

from padv.models import Candidate, StaticEvidence


def _normalized_refs(values: Iterable[str]) -> set[str]:
    refs: set[str] = set()
    for value in values:
        if not isinstance(value, str):
            continue
        text = value.strip()
        if text:
            refs.add(text)
    return refs


def _stable_candidate_order(candidates: Iterable[Candidate]) -> list[Candidate]:
    out: list[Candidate] = []
    seen: set[str] = set()
    for candidate in candidates:
        candidate_id = str(candidate.candidate_id or "").strip()
        if not candidate_id or candidate_id in seen:
            continue
        seen.add(candidate_id)
        out.append(candidate)
    return out


def _static_evidence_ref(item: StaticEvidence) -> str:
    return f"{item.query_id}:{item.file_path}:{item.line}"


def _matches_file_line_ref(ref: str, file_path: str, line: int) -> bool:
    prefix, sep, suffix = ref.rpartition(":")
    if sep != ":" or prefix != file_path:
        return False
    if suffix.isdigit():
        return int(suffix) == line
    if "-" not in suffix:
        return False
    start_text, end_text = suffix.split("-", 1)
    if not start_text.isdigit() or not end_text.isdigit():
        return False
    start = int(start_text)
    end = int(end_text)
    if start > end:
        start, end = end, start
    return start <= line <= end


def candidate_link_refs(candidate: Candidate, *, extra_refs: Iterable[str] = ()) -> set[str]:
    refs = _normalized_refs(list(candidate.evidence_refs) + list(extra_refs))
    refs.add(str(candidate.candidate_id).strip())
    if candidate.file_path and candidate.line:
        refs.add(f"{candidate.file_path}:{candidate.line}")
    return {ref for ref in refs if ref}


def static_evidence_matches_candidate(
    item: StaticEvidence,
    candidate: Candidate,
    *,
    extra_refs: Iterable[str] = (),
) -> bool:
    if item.candidate_id == candidate.candidate_id:
        return True

    refs = candidate_link_refs(candidate, extra_refs=extra_refs)
    if not refs:
        return item.file_path == candidate.file_path and item.line == candidate.line

    aliases = {
        item.hash,
        item.query_id,
        _static_evidence_ref(item),
        f"{item.file_path}:{item.line}",
    }
    if refs & aliases:
        return True

    if item.file_path == candidate.file_path and item.line == candidate.line:
        return True

    return any(_matches_file_line_ref(ref, item.file_path, item.line) for ref in refs)


def candidate_matches_selection(
    candidate: Candidate,
    selected_ids: set[str],
    *,
    extra_refs: Iterable[str] = (),
) -> bool:
    if not selected_ids:
        return True
    return bool(candidate_link_refs(candidate, extra_refs=extra_refs) & selected_ids)


@dataclass(frozen=True)
class LinkedEvidenceSelection:
    candidates: list[Candidate]
    static_evidence: list[StaticEvidence]
    static_by_candidate: dict[str, list[StaticEvidence]]
    missing_candidate_ids: list[str]


def select_linked_evidence(
    candidates: list[Candidate],
    static_evidence: list[StaticEvidence],
    *,
    selected_candidate_ids: Iterable[str] = (),
    extra_refs_by_candidate: dict[str, Iterable[str]] | None = None,
) -> LinkedEvidenceSelection:
    extra_refs_by_candidate = extra_refs_by_candidate or {}
    ordered_candidates = _stable_candidate_order(candidates)
    selected_ids = _normalized_refs(selected_candidate_ids)

    if selected_ids:
        selected_candidates = [
            candidate
            for candidate in ordered_candidates
            if candidate_matches_selection(
                candidate,
                selected_ids,
                extra_refs=extra_refs_by_candidate.get(candidate.candidate_id, ()),
            )
        ]
    else:
        selected_candidates = ordered_candidates

    grouped = group_static_evidence_by_candidate(
        selected_candidates,
        static_evidence,
        extra_refs_by_candidate=extra_refs_by_candidate,
    )
    filtered: list[StaticEvidence] = []
    seen_static: set[tuple[str, str]] = set()
    matched_ids: set[str] = set()
    for candidate in selected_candidates:
        matched_ids.update(
            candidate_link_refs(
                candidate,
                extra_refs=extra_refs_by_candidate.get(candidate.candidate_id, ()),
            )
            & selected_ids
        )
        for item in grouped.get(candidate.candidate_id, []):
            key = (item.candidate_id, item.hash)
            if key in seen_static:
                continue
            seen_static.add(key)
            filtered.append(item)
    missing = sorted(selected_ids - matched_ids)

    return LinkedEvidenceSelection(
        candidates=selected_candidates,
        static_evidence=filtered,
        static_by_candidate=grouped,
        missing_candidate_ids=missing,
    )


def filter_static_evidence_for_candidates(
    candidates: list[Candidate],
    static_evidence: list[StaticEvidence],
    *,
    extra_refs_by_candidate: dict[str, Iterable[str]] | None = None,
) -> list[StaticEvidence]:
    if not candidates or not static_evidence:
        return []

    extra_refs_by_candidate = extra_refs_by_candidate or {}
    out: list[StaticEvidence] = []
    seen: set[tuple[str, str]] = set()
    for item in static_evidence:
        matches = any(
            static_evidence_matches_candidate(
                item,
                candidate,
                extra_refs=extra_refs_by_candidate.get(candidate.candidate_id, ()),
            )
            for candidate in candidates
        )
        if not matches:
            continue
        key = (item.candidate_id, item.hash)
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def group_static_evidence_by_candidate(
    candidates: list[Candidate],
    static_evidence: list[StaticEvidence],
    *,
    extra_refs_by_candidate: dict[str, Iterable[str]] | None = None,
) -> dict[str, list[StaticEvidence]]:
    grouped: dict[str, list[StaticEvidence]] = {candidate.candidate_id: [] for candidate in candidates}
    extra_refs_by_candidate = extra_refs_by_candidate or {}
    for candidate in candidates:
        seen: set[tuple[str, str]] = set()
        for item in static_evidence:
            if not static_evidence_matches_candidate(
                item,
                candidate,
                extra_refs=extra_refs_by_candidate.get(candidate.candidate_id, ()),
            ):
                continue
            key = (item.candidate_id, item.hash)
            if key in seen:
                continue
            seen.add(key)
            grouped[candidate.candidate_id].append(item)
    return grouped

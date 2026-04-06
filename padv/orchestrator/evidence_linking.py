from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass

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
        candidate_key = str(candidate.candidate_uid or candidate.candidate_id or "").strip()
        if not candidate_key or candidate_key in seen:
            continue
        seen.add(candidate_key)
        out.append(candidate)
    return out


def _static_evidence_ref(item: StaticEvidence) -> str:
    return f"{item.query_id}:{item.file_path}:{item.line}"


@dataclass(frozen=True)
class _StaticEvidenceIndex:
    typed_refs: dict[tuple[str, str], list[StaticEvidence]]
    by_file_path: dict[str, list[StaticEvidence]]
    source_order: dict[int, int]


def _index_ref_key(ref_type: str, value: str) -> tuple[str, str] | None:
    text = str(value).strip()
    if not text:
        return None
    return (ref_type, text)


def _build_static_evidence_index(static_evidence: list[StaticEvidence]) -> _StaticEvidenceIndex:
    typed_refs: dict[tuple[str, str], list[StaticEvidence]] = defaultdict(list)
    by_file_path: dict[str, list[StaticEvidence]] = defaultdict(list)
    source_order: dict[int, int] = {}

    for idx, item in enumerate(static_evidence):
        source_order[id(item)] = idx
        by_file_path[item.file_path].append(item)
        for ref_type, value in (
            ("candidate_uid", item.candidate_uid),
            ("candidate_id", item.candidate_id),
            ("hash", item.hash),
            ("query_id", item.query_id),
            ("static_ref", _static_evidence_ref(item)),
            ("file_line", f"{item.file_path}:{item.line}"),
        ):
            key = _index_ref_key(ref_type, value)
            if key is not None:
                typed_refs[key].append(item)

    return _StaticEvidenceIndex(dict(typed_refs), dict(by_file_path), source_order)


def _dedupe_static_evidence(items: Iterable[StaticEvidence], index: _StaticEvidenceIndex) -> list[StaticEvidence]:
    seen: set[tuple[str, str]] = set()
    out: list[StaticEvidence] = []
    for item in sorted(items, key=lambda evidence: index.source_order.get(id(evidence), 0)):
        key = (item.candidate_uid or item.candidate_id, item.hash)
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def _candidate_index_matches(
    candidate: Candidate,
    index: _StaticEvidenceIndex,
    *,
    extra_refs: Iterable[str] = (),
) -> list[StaticEvidence]:
    matched: list[StaticEvidence] = []

    direct_uid_key = _index_ref_key("candidate_uid", candidate.candidate_uid)
    if direct_uid_key is not None:
        direct_uid_matches = index.typed_refs.get(direct_uid_key, ())
        if direct_uid_matches:
            return _dedupe_static_evidence(direct_uid_matches, index)

    def _extend(ref_type: str, value: str) -> None:
        key = _index_ref_key(ref_type, value)
        if key is None:
            return
        matched.extend(index.typed_refs.get(key, ()))

    _extend("candidate_id", candidate.candidate_id)

    refs = candidate_link_refs(candidate, extra_refs=extra_refs)
    for ref in refs:
        for ref_type in ("candidate_uid", "candidate_id", "hash", "query_id", "static_ref", "file_line"):
            _extend(ref_type, ref)
        prefix, sep, suffix = ref.rpartition(":")
        if sep == ":" and prefix and suffix and not suffix.isdigit() and "-" in suffix:
            for item in index.by_file_path.get(prefix, ()):
                if _matches_file_line_ref(ref, item.file_path, item.line):
                    matched.append(item)

    return _dedupe_static_evidence(matched, index)


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
    refs.add(str(candidate.candidate_uid).strip())
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
    if item.candidate_uid and item.candidate_uid == candidate.candidate_uid:
        return True

    if item.candidate_uid and candidate.candidate_uid:
        return False

    if item.candidate_id == candidate.candidate_id:
        return True

    refs = candidate_link_refs(candidate, extra_refs=extra_refs)
    if not refs:
        return item.file_path == candidate.file_path and item.line == candidate.line

    aliases = {
        item.candidate_uid,
        item.candidate_id,
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
            key = (item.candidate_uid or item.candidate_id, item.hash)
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

    grouped = group_static_evidence_by_candidate(
        candidates,
        static_evidence,
        extra_refs_by_candidate=extra_refs_by_candidate,
    )
    index = _build_static_evidence_index(static_evidence)
    flattened: list[StaticEvidence] = []
    for candidate in candidates:
        flattened.extend(grouped.get(candidate.candidate_id, ()))
    return _dedupe_static_evidence(flattened, index)


def group_static_evidence_by_candidate(
    candidates: list[Candidate],
    static_evidence: list[StaticEvidence],
    *,
    extra_refs_by_candidate: dict[str, Iterable[str]] | None = None,
) -> dict[str, list[StaticEvidence]]:
    grouped: dict[str, list[StaticEvidence]] = {candidate.candidate_id: [] for candidate in candidates}
    extra_refs_by_candidate = extra_refs_by_candidate or {}
    index = _build_static_evidence_index(static_evidence)
    for candidate in candidates:
        grouped[candidate.candidate_id] = _candidate_index_matches(
            candidate,
            index,
            extra_refs=extra_refs_by_candidate.get(candidate.candidate_id, ()),
        )
    return grouped

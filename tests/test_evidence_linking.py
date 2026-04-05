from __future__ import annotations

from padv.models import Candidate, StaticEvidence
from padv.orchestrator.evidence_linking import select_linked_evidence


def _candidate() -> Candidate:
    candidate = Candidate(
        candidate_id="cand-derived",
        vuln_class="sql_injection_boundary",
        title="SQL boundary",
        file_path="src/a.php",
        line=12,
        sink="mysqli_query",
        expected_intercepts=["mysqli_query"],
        notes="test",
        provenance=["joern"],
        confidence=0.7,
    )
    candidate.evidence_refs = ["plan-alias", "joern::sql::1:src/a.php:12"]
    return candidate


def _evidence(candidate_id: str, query_id: str, *, file_path: str = "src/a.php", line: int = 12) -> StaticEvidence:
    return StaticEvidence(
        candidate_id=candidate_id,
        query_profile="default",
        query_id=query_id,
        file_path=file_path,
        line=line,
        snippet="mysqli_query($db, $q)",
        hash=f"h-{candidate_id}-{query_id}-{line}",
    )


def test_select_linked_evidence_matches_candidate_via_alias_refs() -> None:
    selection = select_linked_evidence(
        [_candidate()],
        [_evidence("cand-source", "joern::sql::1"), _evidence("cand-stale", "joern::sql::2", file_path="src/other.php", line=40)],
        selected_candidate_ids=["plan-alias"],
    )

    assert [item.candidate_id for item in selection.candidates] == ["cand-derived"]
    assert [item.candidate_id for item in selection.static_evidence] == ["cand-source"]
    assert selection.missing_candidate_ids == []


def test_select_linked_evidence_reports_unmatched_selected_ids() -> None:
    selection = select_linked_evidence(
        [_candidate()],
        [_evidence("cand-source", "joern::sql::1")],
        selected_candidate_ids=["missing-plan-id"],
    )

    assert selection.candidates == []
    assert selection.static_evidence == []
    assert selection.missing_candidate_ids == ["missing-plan-id"]

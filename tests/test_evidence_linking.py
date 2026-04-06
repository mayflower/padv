from __future__ import annotations

from pathlib import Path

from padv.config.schema import load_config
from padv.discovery.fusion import fuse_candidates
from padv.models import Candidate, StaticEvidence
from padv.orchestrator import evidence_linking as evidence_linking_mod
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


def test_select_linked_evidence_preserves_static_attachments_after_fusion_via_candidate_uid() -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    candidates = [
        Candidate(
            candidate_id="cand-joern",
            vuln_class="sql_injection_boundary",
            title="SQL boundary",
            file_path="src/a.php",
            line=12,
            sink="mysqli_query",
            expected_intercepts=["mysqli_query"],
            provenance=["joern"],
            evidence_refs=["joern::sql::1"],
            confidence=0.7,
        ),
        Candidate(
            candidate_id="cand-scip",
            vuln_class="sql_injection_boundary",
            title="SQL boundary",
            file_path="src/a.php",
            line=12,
            sink="mysqli_query",
            expected_intercepts=["mysqli_query"],
            provenance=["scip"],
            evidence_refs=["scip::sql::1"],
            confidence=0.6,
        ),
    ]
    static = [
        StaticEvidence(
            candidate_id="cand-joern",
            candidate_uid=candidates[0].candidate_uid,
            query_profile="default",
            query_id="joern::sql::1",
            file_path="src/a.php",
            line=12,
            snippet="mysqli_query($db, $q)",
            hash="hash-joern",
        ),
        StaticEvidence(
            candidate_id="cand-scip",
            candidate_uid=candidates[1].candidate_uid,
            query_profile="default",
            query_id="scip::sql::1",
            file_path="src/a.php",
            line=12,
            snippet="mysqli_query($db, $q)",
            hash="hash-scip",
        ),
    ]

    fused_candidates, fused_static = fuse_candidates(candidates, static, config)
    selection = select_linked_evidence(
        fused_candidates,
        fused_static,
        selected_candidate_ids=[fused_candidates[0].candidate_uid],
    )

    assert [candidate.candidate_id for candidate in selection.candidates] == ["cand-joern"]
    assert sorted(item.query_id for item in selection.static_evidence) == ["joern::sql::1", "scip::sql::1"]
    assert {item.candidate_uid for item in selection.static_evidence} == {fused_candidates[0].candidate_uid}


def test_select_linked_evidence_keeps_distinct_same_sink_slices_after_fusion() -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    candidates = [
        Candidate(
            candidate_id="cand-slice-a",
            vuln_class="sql_injection_boundary",
            title="SQL boundary A",
            file_path="src/a.php",
            line=12,
            sink="mysqli_query",
            expected_intercepts=["mysqli_query"],
            entrypoint_hint="GET /reports",
            provenance=["joern"],
            evidence_refs=["joern::sql::slice-a"],
            confidence=0.7,
        ),
        Candidate(
            candidate_id="cand-slice-b",
            vuln_class="sql_injection_boundary",
            title="SQL boundary B",
            file_path="src/a.php",
            line=12,
            sink="mysqli_query",
            expected_intercepts=["mysqli_query"],
            entrypoint_hint="POST /admin/search",
            provenance=["joern"],
            evidence_refs=["joern::sql::slice-b"],
            confidence=0.7,
        ),
    ]
    static = [
        StaticEvidence(
            candidate_id="cand-slice-a",
            candidate_uid=candidates[0].candidate_uid,
            query_profile="default",
            query_id="joern::sql::slice-a",
            file_path="src/a.php",
            line=12,
            snippet="mysqli_query($db, $q_a)",
            hash="hash-slice-a",
        ),
        StaticEvidence(
            candidate_id="cand-slice-b",
            candidate_uid=candidates[1].candidate_uid,
            query_profile="default",
            query_id="joern::sql::slice-b",
            file_path="src/a.php",
            line=12,
            snippet="mysqli_query($db, $q_b)",
            hash="hash-slice-b",
        ),
    ]

    fused_candidates, fused_static = fuse_candidates(candidates, static, config)
    selection = select_linked_evidence(fused_candidates, fused_static)

    assert sorted(candidate.candidate_id for candidate in selection.candidates) == ["cand-slice-a", "cand-slice-b"]
    assert sorted(item.query_id for item in selection.static_evidence) == ["joern::sql::slice-a", "joern::sql::slice-b"]
    assert {
        candidate_id: [item.query_id for item in items]
        for candidate_id, items in selection.static_by_candidate.items()
    } == {
        "cand-slice-a": ["joern::sql::slice-a"],
        "cand-slice-b": ["joern::sql::slice-b"],
    }
    assert len({candidate.candidate_uid for candidate in selection.candidates}) == 2


def test_select_linked_evidence_avoids_quadratic_candidate_scans_for_exact_uid_matches(
    monkeypatch,
) -> None:
    candidates = [
        Candidate(
            candidate_id=f"cand-{idx}",
            vuln_class="sql_injection_boundary",
            title=f"SQL boundary {idx}",
            file_path=f"src/{idx}.php",
            line=idx + 1,
            sink="mysqli_query",
            expected_intercepts=["mysqli_query"],
            provenance=["joern"],
            confidence=0.7,
        )
        for idx in range(250)
    ]
    static = [
        StaticEvidence(
            candidate_id=candidate.candidate_id,
            candidate_uid=candidate.candidate_uid,
            query_profile="default",
            query_id=f"joern::sql::{idx}",
            file_path=candidate.file_path,
            line=candidate.line,
            snippet="mysqli_query($db, $q)",
            hash=f"hash-{idx}",
        )
        for idx, candidate in enumerate(candidates)
    ]

    match_calls = {"count": 0}
    original = evidence_linking_mod.static_evidence_matches_candidate

    def _counting_match(item, candidate, *, extra_refs=()):
        match_calls["count"] += 1
        return original(item, candidate, extra_refs=extra_refs)

    monkeypatch.setattr(evidence_linking_mod, "static_evidence_matches_candidate", _counting_match)

    selection = select_linked_evidence(candidates, static)

    assert len(selection.candidates) == 250
    assert len(selection.static_evidence) == 250
    assert match_calls["count"] <= len(candidates)

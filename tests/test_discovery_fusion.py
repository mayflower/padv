from __future__ import annotations

from pathlib import Path

import pytest

from padv.agents.deepagents_harness import rank_candidates_with_deepagents
from padv.config.schema import load_config
from padv.discovery.fusion import fuse_candidates, fuse_candidates_with_meta
from padv.models import Candidate, StaticEvidence


def test_fuse_candidates_preserves_primary_identity_and_stable_candidate_uid() -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")

    candidates = [
        Candidate(
            candidate_id="a-1",
            vuln_class="sql_injection_boundary",
            title="A03 SQL boundary influence",
            file_path="src/a.php",
            line=10,
            sink="mysqli_query",
            expected_intercepts=["mysqli_query"],
            notes="joern",
            provenance=["joern"],
            evidence_refs=["joern::1"],
            confidence=0.6,
        ),
        Candidate(
            candidate_id="b-1",
            vuln_class="sql_injection_boundary",
            title="A03 SQL boundary influence",
            file_path="src/a.php",
            line=10,
            sink="mysqli_query",
            expected_intercepts=["mysqli_query"],
            notes="scip",
            provenance=["scip"],
            evidence_refs=["scip::1"],
            confidence=0.4,
        ),
    ]
    static = [
        StaticEvidence(
            candidate_id="a-1",
            query_profile="default",
            query_id="joern::sql",
            file_path="src/a.php",
            line=10,
            snippet="mysqli_query($db, $q)",
            hash="hash-a",
        ),
        StaticEvidence(
            candidate_id="b-1",
            query_profile="default",
            query_id="scip::sql",
            file_path="src/a.php",
            line=10,
            snippet="mysqli_query($db, $q)",
            hash="hash-b",
        ),
    ]

    merged_candidates, merged_static = fuse_candidates(candidates, static, config)
    merged_candidates_repeat, merged_static_repeat = fuse_candidates(candidates, static, config)

    assert len(merged_candidates) == 1
    assert merged_candidates[0].candidate_id == "a-1"
    assert set(merged_candidates[0].provenance) == {"joern", "scip"}
    assert merged_candidates[0].candidate_uid == merged_candidates_repeat[0].candidate_uid
    assert len(merged_static) == 2
    assert all(item.candidate_id == "a-1" for item in merged_static)
    assert {item.candidate_uid for item in merged_static} == {merged_candidates[0].candidate_uid}
    assert {item.candidate_uid for item in merged_static_repeat} == {merged_candidates_repeat[0].candidate_uid}


def test_fuse_candidates_is_permutation_invariant() -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    candidates = [
        Candidate(
            candidate_id="scip-1",
            vuln_class="sql_injection_boundary",
            title="SQL boundary",
            file_path="src/a.php",
            line=10,
            sink="mysqli_query",
            expected_intercepts=["mysqli_query"],
            notes="scip",
            provenance=["scip"],
            evidence_refs=["scip::1"],
            confidence=0.5,
        ),
        Candidate(
            candidate_id="joern-1",
            vuln_class="sql_injection_boundary",
            title="SQL boundary",
            file_path="src/a.php",
            line=10,
            sink="mysqli_query",
            expected_intercepts=["mysqli_query"],
            notes="joern",
            provenance=["joern"],
            evidence_refs=["joern::1"],
            confidence=0.5,
        ),
    ]
    static = [
        StaticEvidence(
            candidate_id="scip-1",
            query_profile="default",
            query_id="scip::sql",
            file_path="src/a.php",
            line=10,
            snippet="mysqli_query($db, $q)",
            hash="hash-s",
        ),
        StaticEvidence(
            candidate_id="joern-1",
            query_profile="default",
            query_id="joern::sql",
            file_path="src/a.php",
            line=10,
            snippet="mysqli_query($db, $q)",
            hash="hash-j",
        ),
    ]

    first_candidates, first_static = fuse_candidates(candidates, static, config)
    second_candidates, second_static = fuse_candidates(list(reversed(candidates)), list(reversed(static)), config)

    assert [(item.candidate_id, item.candidate_uid, item.sink, tuple(item.provenance)) for item in first_candidates] == [
        (item.candidate_id, item.candidate_uid, item.sink, tuple(item.provenance))
        for item in second_candidates
    ]
    assert [(item.candidate_id, item.candidate_uid, item.query_id) for item in first_static] == [
        (item.candidate_id, item.candidate_uid, item.query_id)
        for item in second_static
    ]


def test_fuse_candidates_selects_stable_primary_for_equal_rank_cluster() -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    candidates = [
        Candidate(
            candidate_id="cand-b",
            vuln_class="sql_injection_boundary",
            title="SQL boundary",
            file_path="src/a.php",
            line=10,
            sink="mysqli_query",
            expected_intercepts=["mysqli_query"],
            notes="cluster b",
            provenance=["joern"],
            evidence_refs=["joern::b"],
            confidence=0.5,
        ),
        Candidate(
            candidate_id="cand-a",
            vuln_class="sql_injection_boundary",
            title="SQL boundary",
            file_path="src/a.php",
            line=10,
            sink="mysqli_query",
            expected_intercepts=["mysqli_query"],
            notes="cluster a",
            provenance=["joern"],
            evidence_refs=["joern::a"],
            confidence=0.5,
        ),
    ]

    first_candidates, _first_static = fuse_candidates(candidates, [], config)
    second_candidates, _second_static = fuse_candidates(list(reversed(candidates)), [], config)

    assert len(first_candidates) == 1
    assert [candidate.candidate_id for candidate in first_candidates] == ["cand-a"]
    assert [candidate.candidate_id for candidate in second_candidates] == ["cand-a"]
    assert first_candidates[0].candidate_uid == second_candidates[0].candidate_uid
    assert sorted(first_candidates[0].evidence_refs) == ["joern::a", "joern::b"]


def test_fuse_candidates_with_meta_drops_nonsemantic_candidates() -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    candidates = [
        Candidate(
            candidate_id="m-1",
            vuln_class="vulnerable_components",
            title="A06 vulnerable components",
            file_path="composer.json",
            line=1,
            sink="composer_dependency",
            expected_intercepts=[],
            notes="manifest",
            provenance=["manifest"],
            evidence_refs=["manifest::1"],
            confidence=0.2,
        ),
        Candidate(
            candidate_id="j-1",
            vuln_class="sql_injection_boundary",
            title="A03 SQL boundary influence",
            file_path="src/a.php",
            line=7,
            sink="mysqli_query",
            expected_intercepts=["mysqli_query"],
            notes="joern",
            provenance=["joern"],
            evidence_refs=["joern::1"],
            confidence=0.5,
        ),
    ]
    static = [
        StaticEvidence(
            candidate_id="m-1",
            query_profile="default",
            query_id="manifest::vulnerable_components",
            file_path="composer.json",
            line=1,
            snippet="deps",
            hash="hash-m",
        ),
        StaticEvidence(
            candidate_id="j-1",
            query_profile="default",
            query_id="joern::sql",
            file_path="src/a.php",
            line=7,
            snippet="mysqli_query($db, $q)",
            hash="hash-j",
        ),
    ]

    merged_candidates, merged_static, meta = fuse_candidates_with_meta(candidates, static, config)
    assert len(merged_candidates) == 1
    assert merged_candidates[0].vuln_class == "sql_injection_boundary"
    assert len(merged_static) == 1
    assert meta.dropped_nonsemantic_candidates == 1
    assert meta.fused_candidates == 1


def test_fuse_candidates_with_meta_keeps_same_line_different_sink_separate() -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    candidates = [
        Candidate(
            candidate_id="j-1",
            vuln_class="xss_output_boundary",
            title="A03 XSS output",
            file_path="src/x.php",
            line=12,
            sink="echo",
            expected_intercepts=["echo"],
            notes="joern",
            provenance=["joern"],
            evidence_refs=["joern::xss"],
            confidence=0.5,
        ),
        Candidate(
            candidate_id="s-1",
            vuln_class="xss_output_boundary",
            title="A03 XSS output",
            file_path="src/x.php",
            line=12,
            sink="print",
            expected_intercepts=["print"],
            notes="scip",
            provenance=["scip"],
            evidence_refs=["scip::xss"],
            confidence=0.5,
        ),
    ]
    static = [
        StaticEvidence(
            candidate_id="j-1",
            query_profile="default",
            query_id="joern::xss",
            file_path="src/x.php",
            line=12,
            snippet="echo $x",
            hash="hash-j",
        ),
        StaticEvidence(
            candidate_id="s-1",
            query_profile="default",
            query_id="scip::xss",
            file_path="src/x.php",
            line=12,
            snippet="print $x",
            hash="hash-s",
        ),
    ]

    merged_candidates, merged_static, meta = fuse_candidates_with_meta(candidates, static, config)
    assert len(merged_candidates) == 2
    assert len(merged_static) == 2
    assert meta.dual_signal_candidates == 0
    assert {item.sink for item in merged_candidates} == {"echo", "print"}
    assert all(meta.evidence_graph[item.candidate_uid]["has_dual_signal"] is False for item in merged_candidates)


def test_fuse_candidates_is_permutation_invariant_for_same_sink_distinct_slices() -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    candidates = [
        Candidate(
            candidate_id="slice-a",
            vuln_class="sql_injection_boundary",
            title="SQL boundary slice A",
            file_path="src/a.php",
            line=10,
            sink="mysqli_query",
            expected_intercepts=["mysqli_query"],
            entrypoint_hint="GET /reports",
            provenance=["joern"],
            evidence_refs=["joern::slice-a"],
            confidence=0.5,
        ),
        Candidate(
            candidate_id="slice-b",
            vuln_class="sql_injection_boundary",
            title="SQL boundary slice B",
            file_path="src/a.php",
            line=10,
            sink="mysqli_query",
            expected_intercepts=["mysqli_query"],
            entrypoint_hint="POST /admin/search",
            provenance=["joern"],
            evidence_refs=["joern::slice-b"],
            confidence=0.5,
        ),
    ]
    static = [
        StaticEvidence(
            candidate_id="slice-a",
            query_profile="default",
            query_id="joern::slice-a",
            file_path="src/a.php",
            line=10,
            snippet="mysqli_query($db, $q_a)",
            hash="hash-slice-a",
            candidate_uid=candidates[0].candidate_uid,
        ),
        StaticEvidence(
            candidate_id="slice-b",
            query_profile="default",
            query_id="joern::slice-b",
            file_path="src/a.php",
            line=10,
            snippet="mysqli_query($db, $q_b)",
            hash="hash-slice-b",
            candidate_uid=candidates[1].candidate_uid,
        ),
    ]

    first_candidates, first_static = fuse_candidates(candidates, static, config)
    second_candidates, second_static = fuse_candidates(list(reversed(candidates)), list(reversed(static)), config)

    assert len(first_candidates) == 2
    assert len({candidate.candidate_uid for candidate in first_candidates}) == 2
    assert [
        (item.candidate_id, item.candidate_uid, item.entrypoint_hint, tuple(item.provenance))
        for item in first_candidates
    ] == [
        (item.candidate_id, item.candidate_uid, item.entrypoint_hint, tuple(item.provenance))
        for item in second_candidates
    ]
    assert [(item.candidate_id, item.candidate_uid, item.query_id) for item in first_static] == [
        (item.candidate_id, item.candidate_uid, item.query_id)
        for item in second_static
    ]


def test_rank_pass_preserves_candidate_uid(monkeypatch: pytest.MonkeyPatch) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    candidates = [
        Candidate(
            candidate_id="cand-a",
            vuln_class="sql_injection_boundary",
            title="SQL A",
            file_path="src/a.php",
            line=10,
            sink="mysqli_query",
            expected_intercepts=["mysqli_query"],
            provenance=["joern"],
            confidence=0.4,
        ),
        Candidate(
            candidate_id="cand-b",
            vuln_class="command_injection_boundary",
            title="CMD B",
            file_path="src/b.php",
            line=8,
            sink="shell_exec",
            expected_intercepts=["shell_exec"],
            provenance=["scip"],
            confidence=0.7,
        ),
    ]
    original_uids = {candidate.candidate_id: candidate.candidate_uid for candidate in candidates}

    monkeypatch.setattr(
        "padv.agents.deepagents_harness._invoke_deepagent_json",
        lambda *args, **kwargs: {"ordered_ids": ["cand-b", "cand-a"]},
    )

    ranked, _trace = rank_candidates_with_deepagents(candidates, "balanced", config)

    assert [candidate.candidate_id for candidate in ranked] == ["cand-b", "cand-a"]
    assert {candidate.candidate_id: candidate.candidate_uid for candidate in ranked} == original_uids

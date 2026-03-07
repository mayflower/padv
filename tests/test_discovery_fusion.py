from __future__ import annotations

from pathlib import Path

from padv.config.schema import load_config
from padv.discovery.fusion import fuse_candidates, fuse_candidates_with_meta
from padv.models import Candidate, StaticEvidence


def test_fuse_candidates_merges_provenance_and_rewrites_ids() -> None:
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
    assert len(merged_candidates) == 1
    assert merged_candidates[0].candidate_id == "cand-00001"
    assert set(merged_candidates[0].provenance) == {"joern", "scip"}
    assert len(merged_static) == 2
    assert all(item.candidate_id == "cand-00001" for item in merged_static)


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


def test_fuse_candidates_with_meta_merges_same_line_different_sink() -> None:
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
    assert len(merged_candidates) == 1
    assert len(merged_static) == 2
    assert meta.dual_signal_candidates == 1
    assert merged_candidates[0].confidence > 0.5
    assert meta.evidence_graph["cand-00001"]["has_dual_signal"] is True

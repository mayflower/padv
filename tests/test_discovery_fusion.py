from __future__ import annotations

from pathlib import Path

from padv.config.schema import load_config
from padv.discovery.fusion import fuse_candidates
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
            notes="source",
            provenance=["source"],
            evidence_refs=["source::1"],
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
            query_id="source::sql",
            file_path="src/a.php",
            line=10,
            snippet="mysqli_query($db, $q)",
            hash="hash-b",
        ),
    ]

    merged_candidates, merged_static = fuse_candidates(candidates, static, config)
    assert len(merged_candidates) == 1
    assert merged_candidates[0].candidate_id == "cand-00001"
    assert set(merged_candidates[0].provenance) == {"joern", "source"}
    assert len(merged_static) == 2
    assert all(item.candidate_id == "cand-00001" for item in merged_static)

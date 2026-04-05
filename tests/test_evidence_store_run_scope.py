from __future__ import annotations

from pathlib import Path

from padv.models import Candidate, EvidenceBundle, GateResult, RunSummary, StaticEvidence
from padv.store.evidence_store import CorruptStoreArtifactError, EvidenceStore


def _candidate(candidate_id: str, title: str) -> Candidate:
    return Candidate(
        candidate_id=candidate_id,
        vuln_class="sql_injection",
        title=title,
        file_path="src/example.php",
        line=12,
        sink="mysqli_query",
        expected_intercepts=["mysqli_query"],
        provenance=["scip"],
    )


def _static(candidate_id: str) -> StaticEvidence:
    return StaticEvidence(
        candidate_id=candidate_id,
        query_profile="default",
        query_id="query-1",
        file_path="src/example.php",
        line=12,
        snippet="$db->query($sql)",
        hash=f"hash-{candidate_id}",
    )


def _bundle(run_id: str, candidate: Candidate) -> EvidenceBundle:
    return EvidenceBundle(
        bundle_id=f"bundle-{run_id}-{candidate.candidate_id}",
        created_at="2026-04-05T10:00:00+00:00",
        candidate=candidate,
        static_evidence=[_static(candidate.candidate_id)],
        positive_runtime=[],
        negative_runtime=[],
        repro_run_ids=[run_id],
        gate_result=GateResult(
            decision="CONFIRMED_ANALYSIS_FINDING",
            passed_gates=["V0"],
            failed_gate="V1",
            reason="unit test fixture",
        ),
        limitations=[],
    )


def test_run_scoped_store_keeps_candidates_bundles_and_static_evidence_isolated(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path)

    run_a = store.for_run("run-a")
    run_b = store.for_run("run-b")

    cand_a = _candidate("cand-a", "SQL injection A")
    cand_b = _candidate("cand-b", "SQL injection B")

    run_a.save_candidates([cand_a])
    run_a.save_static_evidence([_static(cand_a.candidate_id)])
    run_a.save_bundle(_bundle("run-a", cand_a))

    run_b.save_candidates([cand_b])
    run_b.save_static_evidence([_static(cand_b.candidate_id)])
    run_b.save_bundle(_bundle("run-b", cand_b))

    assert [item.candidate_id for item in run_a.load_candidates()] == ["cand-a"]
    assert [item.candidate_id for item in run_b.load_candidates()] == ["cand-b"]
    assert [item.candidate_id for item in run_a.load_static_evidence()] == ["cand-a"]
    assert [item.candidate_id for item in run_b.load_static_evidence()] == ["cand-b"]
    assert run_a.list_bundle_ids() == ["bundle-run-a-cand-a"]
    assert run_b.list_bundle_ids() == ["bundle-run-b-cand-b"]
    assert run_a.load_bundle("bundle-run-b-cand-b") is None
    assert run_b.load_bundle("bundle-run-a-cand-a") is None


def test_run_scoped_store_reads_only_requested_run_not_newest_directory(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path)

    older = store.for_run("run-older")
    newer = store.for_run("run-newer")
    older.save_candidates([_candidate("cand-older", "Older run")])
    newer.save_candidates([_candidate("cand-newer", "Newer run")])

    store.save_run_summary(
        RunSummary(
            run_id="run-older",
            mode="variant",
            started_at="2026-04-05T10:00:00+00:00",
            completed_at="2026-04-05T10:05:00+00:00",
            total_candidates=1,
            decisions={},
            bundle_ids=[],
        )
    )
    store.save_run_summary(
        RunSummary(
            run_id="run-newer",
            mode="variant",
            started_at="2026-04-05T11:00:00+00:00",
            completed_at="2026-04-05T11:05:00+00:00",
            total_candidates=1,
            decisions={},
            bundle_ids=[],
        )
    )

    loaded = older.load_candidates()

    assert [item.candidate_id for item in loaded] == ["cand-older"]


def test_corrupt_run_scoped_candidates_raise_typed_error(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path)
    run = store.for_run("run-corrupt")
    run.save_candidates([_candidate("cand-a", "SQL injection A")])
    path = store.run_dir("run-corrupt") / "candidates.json"
    path.write_text('{"broken": ', encoding="utf-8")

    try:
        run.load_candidates()
        raise AssertionError("expected corrupt candidates file to raise")
    except CorruptStoreArtifactError as exc:
        assert exc.path == path
        assert exc.artifact_kind == "candidates"

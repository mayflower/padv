from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest


def _load_assess_module():
    root = Path(__file__).resolve().parents[1]
    module_path = root / "scripts" / "mutillidae_integration_assess.py"
    spec = importlib.util.spec_from_file_location("mutillidae_integration_assess_test", module_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_run_strict_run_stabilization_recovers_partial_timeout_state(monkeypatch, tmp_path: Path) -> None:
    assess = _load_assess_module()
    output_dir = tmp_path / "assessment"

    monkeypatch.setattr(
        assess,
        "_run",
        lambda *args, **kwargs: assess.CmdResult(
            name="run_attempt_1",
            cmd=["padv", "run"],
            returncode=124,
            stdout="",
            stderr="command timed out after 3600s",
            started_at="2026-04-05T10:00:00+00:00",
            ended_at="2026-04-05T11:00:00+00:00",
            duration_seconds=3600.0,
        ),
    )
    monkeypatch.setattr(
        assess,
        "_graph_progress_for_run",
        lambda run_id: {
            "run_id": "run-test123",
            "latest_stage": "continue_or_stop",
            "latest_stage_file": "/tmp/061-continue_or_stop.json",
            "completed": False,
            "candidates": 2,
            "static_evidence": 0,
            "bundle_count": 14,
            "counts": {"all_bundles": 14},
            "decisions": {"DROPPED": 2},
            "frontier": {"iteration": 10},
        }
        if run_id == "run-mutillidae-01"
        else None,
    )
    monkeypatch.setattr(
        assess,
        "_latest_graph_progress",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("latest scan should not run")),
    )

    out = assess.run_strict_run_stabilization(output_dir, max_attempts=1, run_timeout=3600)

    assert out["success"] is False
    assert out["final_output"]["run_id"] == "run-test123"
    assert out["attempts"][0]["failure_class"] == "timeout"
    assert out["attempts"][0]["parsed_output"]["latest_stage"] == "continue_or_stop"


def test_run_analyze_stabilization_accepts_recovered_completed_graph(monkeypatch, tmp_path: Path) -> None:
    assess = _load_assess_module()
    output_dir = tmp_path / "assessment"

    monkeypatch.setattr(
        assess,
        "_run",
        lambda *args, **kwargs: assess.CmdResult(
            name="analyze_attempt_1",
            cmd=["padv", "analyze"],
            returncode=124,
            stdout="",
            stderr="command timed out after 3600s",
            started_at="2026-04-05T10:00:00+00:00",
            ended_at="2026-04-05T11:00:00+00:00",
            duration_seconds=3600.0,
        ),
    )
    monkeypatch.setattr(
        assess,
        "_graph_progress_for_run",
        lambda run_id: {
            "run_id": "analyze-test123",
            "latest_stage": "persist",
            "latest_stage_file": "/tmp/057-persist.json",
            "completed": True,
            "candidates": 120,
            "static_evidence": 120,
            "bundle_count": 0,
            "counts": {"candidates": 120, "static_evidence": 120},
            "decisions": {},
            "frontier": {"iteration": 8},
        }
        if run_id == "analyze-mutillidae-01"
        else None,
    )
    monkeypatch.setattr(
        assess,
        "_latest_graph_progress",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("latest scan should not run")),
    )

    out = assess.run_analyze_stabilization(output_dir, max_attempts=1, analyze_timeout=3600)

    assert out["success"] is True
    assert out["final_output"]["run_id"] == "analyze-test123"
    assert out["attempts"][0]["ok"] is True


def test_graph_progress_for_run_ignores_newer_directory(monkeypatch, tmp_path: Path) -> None:
    assess = _load_assess_module()
    padv_store = tmp_path / ".padv"
    monkeypatch.setattr(assess, "PADV_STORE", padv_store)

    target_dir = padv_store / "langgraph" / "run-target"
    newer_dir = padv_store / "langgraph" / "run-newer"
    target_dir.mkdir(parents=True)
    newer_dir.mkdir(parents=True)

    (target_dir / "001-research.json").write_text(
        json.dumps({"run_id": "run-target", "counts": {"candidates": 1}, "decisions": {}, "frontier": {}}),
        encoding="utf-8",
    )
    (newer_dir / "999-persist.json").write_text(
        json.dumps({"run_id": "run-newer", "counts": {"candidates": 9}, "decisions": {}, "frontier": {}}),
        encoding="utf-8",
    )

    progress = assess._graph_progress_for_run("run-target")

    assert progress is not None
    assert progress["run_id"] == "run-target"
    assert progress["latest_stage"] == "research"


def test_run_phase_b_reads_only_requested_run_artifacts(monkeypatch, tmp_path: Path) -> None:
    assess = _load_assess_module()
    padv_store = tmp_path / ".padv"
    gap_catalog = tmp_path / "gap-catalog.json"
    output_dir = tmp_path / "assessment"

    monkeypatch.setattr(assess, "PADV_STORE", padv_store)
    monkeypatch.setattr(assess, "GAP_CATALOG_PATH", gap_catalog)

    (padv_store / "runs" / "run-a").mkdir(parents=True)
    (padv_store / "runs" / "run-b").mkdir(parents=True)
    (padv_store / "runs" / "run-a" / "bundles").mkdir(parents=True)
    (padv_store / "runs" / "run-b" / "bundles").mkdir(parents=True)

    (padv_store / "runs" / "run-a" / "candidates.json").write_text(
        json.dumps(
            [
                {
                    "candidate_id": "cand-a",
                    "vuln_class": "sql_injection",
                    "title": "SQL injection in run A",
                    "file_path": "src/a.php",
                    "sink": "mysqli_query",
                    "provenance": ["scip"],
                }
            ]
        ),
        encoding="utf-8",
    )
    (padv_store / "runs" / "run-a" / "bundles" / "bundle-run-a-cand-a.json").write_text(
        json.dumps(
            [
                {
                    "bundle_id": "bundle-run-a-cand-a",
                    "candidate": {
                        "candidate_id": "cand-a",
                        "vuln_class": "sql_injection",
                        "title": "SQL injection in run A",
                        "file_path": "src/a.php",
                        "sink": "mysqli_query",
                    },
                    "gate_result": {"decision": "VALIDATED"},
                }
            ][0]
        ),
        encoding="utf-8",
    )
    (padv_store / "runs" / "run-b" / "candidates.json").write_text(
        json.dumps(
            [
                {
                    "candidate_id": "cand-b",
                    "vuln_class": "cross_site_scripting",
                    "title": "XSS in run B",
                    "file_path": "src/b.php",
                    "sink": "echo",
                    "provenance": ["web"],
                }
            ]
        ),
        encoding="utf-8",
    )
    (padv_store / "runs" / "run-b" / "bundles" / "bundle-run-b-cand-b.json").write_text(
        json.dumps(
            {
                "bundle_id": "bundle-run-b-cand-b",
                "candidate": {
                    "candidate_id": "cand-b",
                    "vuln_class": "cross_site_scripting",
                    "title": "XSS in run B",
                    "file_path": "src/b.php",
                    "sink": "echo",
                },
                "gate_result": {"decision": "VALIDATED"},
            }
        ),
        encoding="utf-8",
    )
    gap_catalog.write_text(
        json.dumps(
            [
                {
                    "gap_id": "GAP-SQL",
                    "category": "sql_injection",
                    "runtime_validatable": True,
                }
            ]
        ),
        encoding="utf-8",
    )

    phase_a = {"a1": {"summary": {"all_passed": True}}, "a2": {"success": True}, "a3": {"success": True}}

    output = assess.run_phase_b(output_dir, run_id="run-a", phase_a=phase_a)

    sql_row = next(item for item in output["matrix"] if item["requirement_id"] == "GAP-SQL")
    observed = json.loads(sql_row["observed_result"])
    assert sql_row["status"] == "FULL"
    assert sql_row["evidence_path"].endswith("/runs/run-a/candidates.json")
    assert observed["outcome_counts"]["VALIDATED"] == 1
    assert observed["outcome_reasons"]["VALIDATED"]["validated"] == 1
    assert output["candidate_outcomes"]["VALIDATED"] == 1
    assert output["candidate_outcomes"]["REFUTED"] == 0


def test_run_phase_b_requires_explicit_run_id(monkeypatch, tmp_path: Path) -> None:
    assess = _load_assess_module()
    monkeypatch.setattr(assess, "PADV_STORE", tmp_path / ".padv")
    monkeypatch.setattr(assess, "GAP_CATALOG_PATH", tmp_path / "gap-catalog.json")

    with pytest.raises(ValueError, match="run_id is required"):
        assess.run_phase_b(
            tmp_path / "assessment",
            run_id="",
            phase_a={"a1": {"summary": {"all_passed": True}}, "a2": {"success": True}, "a3": {"success": True}},
        )


def test_main_phase_b_requires_run_id_argument(monkeypatch, tmp_path: Path) -> None:
    assess = _load_assess_module()
    monkeypatch.setattr(assess, "PADV_STORE", tmp_path / ".padv")
    monkeypatch.setattr(sys, "argv", ["mutillidae_integration_assess.py", "--phase", "b"])

    with pytest.raises(SystemExit) as exc_info:
        assess.main()

    assert exc_info.value.code == 2


def test_run_phase_b_dropped_runtime_bundle_does_not_count_as_full(monkeypatch, tmp_path: Path) -> None:
    assess = _load_assess_module()
    padv_store = tmp_path / ".padv"
    gap_catalog = tmp_path / "gap-catalog.json"
    output_dir = tmp_path / "assessment"

    monkeypatch.setattr(assess, "PADV_STORE", padv_store)
    monkeypatch.setattr(assess, "GAP_CATALOG_PATH", gap_catalog)

    run_root = padv_store / "runs" / "run-a"
    (run_root / "bundles").mkdir(parents=True)

    (run_root / "candidates.json").write_text(
        json.dumps(
            [
                {
                    "candidate_id": "cand-a",
                    "vuln_class": "sql_injection",
                    "title": "SQL injection in run A",
                    "file_path": "src/a.php",
                    "sink": "mysqli_query",
                    "provenance": ["scip"],
                }
            ]
        ),
        encoding="utf-8",
    )
    (run_root / "bundles" / "bundle-run-a-cand-a.json").write_text(
        json.dumps(
            {
                "bundle_id": "bundle-run-a-cand-a",
                "bundle_type": "dropped",
                "candidate": {
                    "candidate_id": "cand-a",
                    "vuln_class": "sql_injection",
                    "title": "SQL injection in run A",
                    "file_path": "src/a.php",
                    "sink": "mysqli_query",
                },
                "gate_result": {"decision": "DROPPED"},
            }
        ),
        encoding="utf-8",
    )
    gap_catalog.write_text(
        json.dumps(
            [
                {
                    "gap_id": "GAP-SQL",
                    "category": "sql_injection",
                    "runtime_validatable": True,
                }
            ]
        ),
        encoding="utf-8",
    )

    phase_a = {"a1": {"summary": {"all_passed": True}}, "a2": {"success": True}, "a3": {"success": True}}

    output = assess.run_phase_b(output_dir, run_id="run-a", phase_a=phase_a)

    sql_row = next(item for item in output["matrix"] if item["requirement_id"] == "GAP-SQL")
    observed = json.loads(sql_row["observed_result"])

    assert sql_row["status"] == "PARTIAL"
    assert observed["runtime_outcomes"] == ["REFUTED"]
    assert observed["strong_refutation_count"] == 0


def test_run_phase_b_skipped_runtime_bundle_does_not_count_as_full(monkeypatch, tmp_path: Path) -> None:
    assess = _load_assess_module()
    padv_store = tmp_path / ".padv"
    gap_catalog = tmp_path / "gap-catalog.json"
    output_dir = tmp_path / "assessment"

    monkeypatch.setattr(assess, "PADV_STORE", padv_store)
    monkeypatch.setattr(assess, "GAP_CATALOG_PATH", gap_catalog)

    run_root = padv_store / "runs" / "run-a"
    (run_root / "bundles").mkdir(parents=True)

    (run_root / "candidates.json").write_text(
        json.dumps(
            [
                {
                    "candidate_id": "cand-a",
                    "vuln_class": "sql_injection_boundary",
                    "title": "SQL injection in run A",
                    "file_path": "src/a.php",
                    "sink": "mysqli_query",
                    "provenance": ["scip"],
                }
            ]
        ),
        encoding="utf-8",
    )
    (run_root / "bundles" / "bundle-run-a-cand-a.json").write_text(
        json.dumps(
            {
                "bundle_id": "bundle-run-a-cand-a",
                "candidate_outcome": "SKIPPED_BUDGET",
                "candidate": {
                    "candidate_id": "cand-a",
                    "vuln_class": "sql_injection_boundary",
                    "title": "SQL injection in run A",
                    "file_path": "src/a.php",
                    "sink": "mysqli_query",
                },
                "gate_result": {"decision": "SKIPPED_BUDGET"},
            }
        ),
        encoding="utf-8",
    )
    gap_catalog.write_text(
        json.dumps(
            [
                {
                    "gap_id": "GAP-SQL",
                    "category": "sql_injection",
                    "runtime_validatable": True,
                }
            ]
        ),
        encoding="utf-8",
    )

    phase_a = {"a1": {"summary": {"all_passed": True}}, "a2": {"success": True}, "a3": {"success": True}}

    output = assess.run_phase_b(output_dir, run_id="run-a", phase_a=phase_a)

    sql_row = next(item for item in output["matrix"] if item["requirement_id"] == "GAP-SQL")
    observed = json.loads(sql_row["observed_result"])

    assert sql_row["status"] == "PARTIAL"
    assert observed["runtime_outcomes"] == ["SKIPPED"]
    assert observed["runtime_attempted"] is True


def test_run_phase_b_strong_refutation_counts_as_full(monkeypatch, tmp_path: Path) -> None:
    assess = _load_assess_module()
    padv_store = tmp_path / ".padv"
    gap_catalog = tmp_path / "gap-catalog.json"
    output_dir = tmp_path / "assessment"

    monkeypatch.setattr(assess, "PADV_STORE", padv_store)
    monkeypatch.setattr(assess, "GAP_CATALOG_PATH", gap_catalog)

    run_root = padv_store / "runs" / "run-a"
    (run_root / "bundles").mkdir(parents=True)

    (run_root / "candidates.json").write_text(
        json.dumps(
            [
                {
                    "candidate_id": "cand-a",
                    "vuln_class": "sql_injection_boundary",
                    "title": "SQL injection in run A",
                    "file_path": "src/a.php",
                    "sink": "mysqli_query",
                    "provenance": ["scip"],
                }
            ]
        ),
        encoding="utf-8",
    )
    (run_root / "bundles" / "bundle-run-a-cand-a.json").write_text(
        json.dumps(
            {
                "bundle_id": "bundle-run-a-cand-a",
                "candidate_outcome": "REFUTED",
                "candidate": {
                    "candidate_id": "cand-a",
                    "vuln_class": "sql_injection_boundary",
                    "title": "SQL injection in run A",
                    "file_path": "src/a.php",
                    "sink": "mysqli_query",
                },
                "gate_result": {"decision": "DROPPED"},
                "validation_contract": {
                    "witness_contract": {
                        "canonical_class": "sql_injection_boundary",
                        "required_all": ["sql_sink_oracle_witness"],
                        "required_any": ["sql_body_diff_witness"],
                        "negative_must_not_include": [],
                        "enforce_negative_clean": True,
                    },
                    "witness": {
                        "canonical_class": "sql_injection_boundary",
                        "positive_flags": ["sql_sink_oracle_witness", "sql_body_diff_witness"],
                        "negative_flags": [],
                    },
                },
            }
        ),
        encoding="utf-8",
    )
    gap_catalog.write_text(
        json.dumps(
            [
                {
                    "gap_id": "GAP-SQL",
                    "category": "sql_injection",
                    "runtime_validatable": True,
                }
            ]
        ),
        encoding="utf-8",
    )

    phase_a = {"a1": {"summary": {"all_passed": True}}, "a2": {"success": True}, "a3": {"success": True}}

    output = assess.run_phase_b(output_dir, run_id="run-a", phase_a=phase_a)

    sql_row = next(item for item in output["matrix"] if item["requirement_id"] == "GAP-SQL")
    observed = json.loads(sql_row["observed_result"])

    assert sql_row["status"] == "FULL"
    assert observed["runtime_outcomes"] == ["REFUTED"]
    assert observed["strong_refutation_count"] == 1


def test_run_phase_b_reports_none_when_requested_run_has_no_attempt_for_category(monkeypatch, tmp_path: Path) -> None:
    assess = _load_assess_module()
    padv_store = tmp_path / ".padv"
    gap_catalog = tmp_path / "gap-catalog.json"
    output_dir = tmp_path / "assessment"

    monkeypatch.setattr(assess, "PADV_STORE", padv_store)
    monkeypatch.setattr(assess, "GAP_CATALOG_PATH", gap_catalog)

    (padv_store / "runs" / "run-a" / "bundles").mkdir(parents=True)
    (padv_store / "runs" / "run-b" / "bundles").mkdir(parents=True)
    (padv_store / "runs" / "run-a" / "candidates.json").write_text(json.dumps([]), encoding="utf-8")
    (padv_store / "runs" / "run-b" / "candidates.json").write_text(
        json.dumps(
            [
                {
                    "candidate_id": "cand-b",
                    "vuln_class": "sql_injection_boundary",
                    "title": "SQL injection in run B",
                    "file_path": "src/b.php",
                    "sink": "mysqli_query",
                    "provenance": ["scip"],
                }
            ]
        ),
        encoding="utf-8",
    )
    (padv_store / "runs" / "run-b" / "bundles" / "bundle-run-b-cand-b.json").write_text(
        json.dumps(
            {
                "bundle_id": "bundle-run-b-cand-b",
                "candidate_outcome": "VALIDATED",
                "candidate": {
                    "candidate_id": "cand-b",
                    "vuln_class": "sql_injection_boundary",
                    "title": "SQL injection in run B",
                    "file_path": "src/b.php",
                    "sink": "mysqli_query",
                },
                "gate_result": {"decision": "VALIDATED"},
            }
        ),
        encoding="utf-8",
    )
    gap_catalog.write_text(
        json.dumps(
            [
                {
                    "gap_id": "GAP-SQL",
                    "category": "sql_injection",
                    "runtime_validatable": True,
                }
            ]
        ),
        encoding="utf-8",
    )

    phase_a = {"a1": {"summary": {"all_passed": True}}, "a2": {"success": True}, "a3": {"success": True}}

    output = assess.run_phase_b(output_dir, run_id="run-a", phase_a=phase_a)

    sql_row = next(item for item in output["matrix"] if item["requirement_id"] == "GAP-SQL")
    observed = json.loads(sql_row["observed_result"])

    assert sql_row["status"] == "NONE"
    assert observed["runtime_outcomes"] == []
    assert observed["runtime_attempted"] is False

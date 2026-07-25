from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any


def _load_assess_module():
    root = Path(__file__).resolve().parents[1]
    module_path = root / "scripts" / "mutillidae_integration_assess.py"
    spec = importlib.util.spec_from_file_location("mutillidae_instance_matching_test", module_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


PHASE_A_OK = {"a1": {"summary": {"all_passed": True}}, "a2": {"success": True}, "a3": {"success": True}}


def _candidate(**overrides) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "candidate_id": "cand-a",
        "vuln_class": "sql_injection_boundary",
        "title": "SQL injection",
        "file_path": "src/user-poll.php",
        "sink": "mysqli_query",
        "provenance": ["scip"],
        "web_path_hints": [],
    }
    payload.update(overrides)
    return payload


def _bundle(candidate: dict[str, Any], outcome: str, bundle_id: str = "bundle-a") -> dict[str, Any]:
    decision = {"VALIDATED": "VALIDATED", "REFUTED": "REFUTED", "ANALYSIS_FINDING": "CONFIRMED_ANALYSIS_FINDING"}.get(
        outcome, "INCONCLUSIVE"
    )
    return {
        "bundle_id": bundle_id,
        "candidate_outcome": outcome,
        "candidate": candidate,
        "gate_result": {"decision": decision},
    }


def _gap(**overrides) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "gap_id": "GAP-SQL",
        "category": "sql_injection",
        "runtime_validatable": True,
        "target_expectation": "must_find",
        "instances": [
            {
                "instance_id": "GAP-SQL-i01",
                "file": "targets/mutillidae/src/user-poll.php",
                "sink": "",
                "route": "",
                "expected_outcome": "VALIDATED",
            }
        ],
        "negative_controls": [],
    }
    payload.update(overrides)
    return payload


def _run_phase_b(
    monkeypatch,
    tmp_path: Path,
    *,
    gaps: list[dict[str, Any]],
    candidates: list[dict[str, Any]],
    bundles: list[dict[str, Any]],
) -> dict[str, Any]:
    assess = _load_assess_module()
    padv_store = tmp_path / ".padv"
    gap_catalog = tmp_path / "gap-catalog.json"
    monkeypatch.setattr(assess, "PADV_STORE", padv_store)
    monkeypatch.setattr(assess, "GAP_CATALOG_PATH", gap_catalog)

    run_root = padv_store / "runs" / "run-a"
    (run_root / "bundles").mkdir(parents=True)
    (run_root / "candidates.json").write_text(json.dumps(candidates), encoding="utf-8")
    for bundle in bundles:
        (run_root / "bundles" / f"{bundle['bundle_id']}.json").write_text(json.dumps(bundle), encoding="utf-8")
    gap_catalog.write_text(json.dumps(gaps), encoding="utf-8")

    return assess.run_phase_b(tmp_path / "assessment", run_id="run-a", phase_a=PHASE_A_OK)


def _row(output: dict[str, Any], requirement_id: str = "GAP-SQL") -> dict[str, Any]:
    return next(item for item in output["matrix"] if item["requirement_id"] == requirement_id)


# --- structural matching ------------------------------------------------


def test_validated_instance_counts_as_full(monkeypatch, tmp_path: Path) -> None:
    candidate = _candidate()
    output = _run_phase_b(
        monkeypatch,
        tmp_path,
        gaps=[_gap()],
        candidates=[candidate],
        bundles=[_bundle(candidate, "VALIDATED")],
    )
    assert _row(output)["status"] == "FULL"
    assert output["metrics"]["true_positives"] == 1
    assert output["metrics"]["false_negatives"] == 0


def test_same_class_in_other_file_does_not_prove_the_instance(monkeypatch, tmp_path: Path) -> None:
    """A SQL injection in some other file is a different finding."""
    candidate = _candidate(file_path="src/unrelated.php")
    output = _run_phase_b(
        monkeypatch,
        tmp_path,
        gaps=[_gap()],
        candidates=[candidate],
        bundles=[_bundle(candidate, "VALIDATED")],
    )
    assert _row(output)["status"] == "NONE"
    assert output["metrics"]["true_positives"] == 0
    assert output["metrics"]["false_negatives"] == 1
    assert output["metrics"]["false_positives"] == 1
    assert output["metrics"]["unmatched_validated"] == ["unmatched:bundle-a"]


def test_declared_sink_must_match(monkeypatch, tmp_path: Path) -> None:
    gap = _gap()
    gap["instances"][0]["sink"] = "mysqli_query"
    candidate = _candidate(sink="pg_query")
    output = _run_phase_b(
        monkeypatch,
        tmp_path,
        gaps=[gap],
        candidates=[candidate],
        bundles=[_bundle(candidate, "VALIDATED")],
    )
    assert _row(output)["status"] == "NONE"


def test_declared_route_must_match(monkeypatch, tmp_path: Path) -> None:
    gap = _gap()
    gap["instances"][0]["route"] = "/user-poll.php"
    candidate = _candidate(web_path_hints=["/index.php"])
    output = _run_phase_b(
        monkeypatch,
        tmp_path,
        gaps=[gap],
        candidates=[candidate],
        bundles=[_bundle(candidate, "VALIDATED")],
    )
    assert _row(output)["status"] == "NONE"

    candidate_ok = _candidate(web_path_hints=["/user-poll.php"])
    output_ok = _run_phase_b(
        monkeypatch,
        tmp_path / "ok",
        gaps=[gap],
        candidates=[candidate_ok],
        bundles=[_bundle(candidate_ok, "VALIDATED")],
    )
    assert _row(output_ok)["status"] == "FULL"


def test_path_suffix_match_tolerates_differing_repo_roots(monkeypatch, tmp_path: Path) -> None:
    candidate = _candidate(file_path="/workspace/targets/mutillidae/src/user-poll.php")
    output = _run_phase_b(
        monkeypatch,
        tmp_path,
        gaps=[_gap()],
        candidates=[candidate],
        bundles=[_bundle(candidate, "VALIDATED")],
    )
    assert _row(output)["status"] == "FULL"


# --- outcome requirements ----------------------------------------------


def test_refutation_never_counts_as_full(monkeypatch, tmp_path: Path) -> None:
    """A refuted candidate is a negative result, not evidence the gap was covered."""
    candidate = _candidate()
    output = _run_phase_b(
        monkeypatch,
        tmp_path,
        gaps=[_gap()],
        candidates=[candidate],
        bundles=[_bundle(candidate, "REFUTED")],
    )
    row = _row(output)
    assert row["status"] == "PARTIAL"
    assert output["metrics"]["true_positives"] == 0
    assert output["metrics"]["false_negatives"] == 1


def test_inconclusive_outcome_is_partial_not_full(monkeypatch, tmp_path: Path) -> None:
    candidate = _candidate()
    output = _run_phase_b(
        monkeypatch,
        tmp_path,
        gaps=[_gap()],
        candidates=[candidate],
        bundles=[_bundle(candidate, "INCONCLUSIVE")],
    )
    assert _row(output)["status"] == "PARTIAL"


def test_analysis_finding_does_not_satisfy_a_runtime_instance(monkeypatch, tmp_path: Path) -> None:
    candidate = _candidate()
    output = _run_phase_b(
        monkeypatch,
        tmp_path,
        gaps=[_gap()],
        candidates=[candidate],
        bundles=[_bundle(candidate, "ANALYSIS_FINDING")],
    )
    assert _row(output)["status"] == "PARTIAL"


def test_analysis_only_row_requires_an_analysis_finding(monkeypatch, tmp_path: Path) -> None:
    gap = _gap(runtime_validatable=False)
    gap["instances"][0]["expected_outcome"] = "ANALYSIS_FINDING"
    candidate = _candidate()

    without_bundle = _run_phase_b(
        monkeypatch,
        tmp_path,
        gaps=[gap],
        candidates=[candidate],
        bundles=[],
    )
    assert _row(without_bundle)["status"] == "NONE"

    with_finding = _run_phase_b(
        monkeypatch,
        tmp_path / "ok",
        gaps=[gap],
        candidates=[candidate],
        bundles=[_bundle(candidate, "ANALYSIS_FINDING")],
    )
    assert _row(with_finding)["status"] == "FULL"


def test_partial_when_only_some_instances_are_proven(monkeypatch, tmp_path: Path) -> None:
    gap = _gap()
    gap["instances"].append(
        {
            "instance_id": "GAP-SQL-i02",
            "file": "targets/mutillidae/src/user-info.php",
            "sink": "",
            "route": "",
            "expected_outcome": "VALIDATED",
        }
    )
    candidate = _candidate()
    output = _run_phase_b(
        monkeypatch,
        tmp_path,
        gaps=[gap],
        candidates=[candidate],
        bundles=[_bundle(candidate, "VALIDATED")],
    )
    row = _row(output)
    observed = json.loads(row["observed_result"])
    assert row["status"] == "PARTIAL"
    assert observed["instances_proven"] == 1
    assert observed["instances_expected"] == 2
    assert output["metrics"]["recall_by_category"]["sql_injection"] == [1, 2]


# --- metrics ------------------------------------------------------------


def test_metrics_report_precision_recall_and_macro_recall(monkeypatch, tmp_path: Path) -> None:
    sql_gap = _gap()
    xss_gap = _gap(
        gap_id="GAP-XSS",
        category="cross_site_scripting",
        instances=[
            {
                "instance_id": "GAP-XSS-i01",
                "file": "targets/mutillidae/src/index.php",
                "sink": "",
                "route": "",
                "expected_outcome": "VALIDATED",
            }
        ],
    )
    sql_candidate = _candidate()
    output = _run_phase_b(
        monkeypatch,
        tmp_path,
        gaps=[sql_gap, xss_gap],
        candidates=[sql_candidate],
        bundles=[_bundle(sql_candidate, "VALIDATED")],
    )
    metrics = output["metrics"]
    assert metrics["true_positives"] == 1
    assert metrics["false_negatives"] == 1
    assert metrics["false_positives"] == 0
    assert metrics["precision"] == 1.0
    assert metrics["recall"] == 0.5
    assert metrics["macro_recall"] == 0.5


def test_should_find_rows_do_not_count_against_recall(monkeypatch, tmp_path: Path) -> None:
    gap = _gap(target_expectation="should_find")
    output = _run_phase_b(monkeypatch, tmp_path, gaps=[gap], candidates=[], bundles=[])
    assert output["metrics"]["false_negatives"] == 0
    assert output["metrics"]["recall_by_category"] == {}


def test_validated_negative_control_is_reported_as_a_violation(monkeypatch, tmp_path: Path) -> None:
    gap = _gap()
    gap["negative_controls"] = [
        {
            "instance_id": "GAP-SQL-patched",
            "file": "targets/mutillidae/src/user-poll-patched.php",
            "sink": "",
            "route": "",
        }
    ]

    real = _candidate()
    patched = _candidate(candidate_id="cand-p", file_path="src/user-poll-patched.php")
    output = _run_phase_b(
        monkeypatch,
        tmp_path,
        gaps=[gap],
        candidates=[real, patched],
        bundles=[
            _bundle(real, "VALIDATED"),
            _bundle(patched, "VALIDATED", bundle_id="bundle-p"),
        ],
    )
    metrics = output["metrics"]
    assert metrics["control_violations"] == 1
    # The control is a known instance, so it is a false positive rather than an
    # unmatched claim, and it must not dilute the true positive.
    assert metrics["true_positives"] == 1
    assert metrics["false_positives"] == 1
    assert metrics["unmatched_validated"] == []


def test_clean_negative_control_reports_no_violation(monkeypatch, tmp_path: Path) -> None:
    gap = _gap()
    gap["negative_controls"] = [
        {
            "instance_id": "GAP-SQL-patched",
            "file": "targets/mutillidae/src/user-poll-patched.php",
            "sink": "",
            "route": "",
        }
    ]
    patched = _candidate(candidate_id="cand-p", file_path="src/user-poll-patched.php")
    output = _run_phase_b(
        monkeypatch,
        tmp_path,
        gaps=[gap],
        candidates=[patched],
        bundles=[_bundle(patched, "REFUTED", bundle_id="bundle-p")],
    )
    assert output["metrics"]["control_violations"] == 0
    assert output["metrics"]["false_positives"] == 0

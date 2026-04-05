from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


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
        "_latest_graph_progress",
        lambda prefix: {
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
        if prefix == "run"
        else None,
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
        "_latest_graph_progress",
        lambda prefix: {
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
        if prefix == "analyze"
        else None,
    )

    out = assess.run_analyze_stabilization(output_dir, max_attempts=1, analyze_timeout=3600)

    assert out["success"] is True
    assert out["final_output"]["run_id"] == "analyze-test123"
    assert out["attempts"][0]["ok"] is True

from __future__ import annotations

import json
from pathlib import Path

from padv.store.compaction import compact_store


def _write_bundle(path: Path, *, bundle_id: str, file_path: str, line: int, created_at: str, clean: bool) -> None:
    attempts = []
    if clean:
        attempts = [{"runtime_status": "ok"}]
    else:
        attempts = [{"runtime_status": "request_failed"}]
    payload = {
        "bundle_id": bundle_id,
        "created_at": created_at,
        "candidate": {
            "candidate_id": bundle_id.replace("bundle-", "cand-"),
            "vuln_class": "sql_injection_boundary",
            "file_path": file_path,
            "line": line,
            "sink": "mysqli_query",
        },
        "planner_trace": {"attempts": attempts},
    }
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=True), encoding="utf-8")


def test_compact_store_keeps_latest_clean_bundle_per_signature_and_rewrites_runs(tmp_path: Path) -> None:
    source_root = tmp_path / "source_store"
    bundles_dir = source_root / "bundles"
    runs_dir = source_root / "runs"
    bundles_dir.mkdir(parents=True)
    runs_dir.mkdir(parents=True)

    _write_bundle(
        bundles_dir / "bundle-sigA-clean.json",
        bundle_id="bundle-sigA-clean",
        file_path="src/a.php",
        line=10,
        created_at="2026-03-07T00:00:01+00:00",
        clean=True,
    )
    _write_bundle(
        bundles_dir / "bundle-sigA-dirty.json",
        bundle_id="bundle-sigA-dirty",
        file_path="src/a.php",
        line=10,
        created_at="2026-03-07T00:00:05+00:00",
        clean=False,
    )
    _write_bundle(
        bundles_dir / "bundle-sigB-dirty.json",
        bundle_id="bundle-sigB-dirty",
        file_path="src/b.php",
        line=20,
        created_at="2026-03-07T00:00:03+00:00",
        clean=False,
    )

    run_summary = {
        "run_id": "run-1",
        "bundle_ids": ["bundle-sigA-clean", "bundle-sigA-dirty", "bundle-sigB-dirty"],
    }
    (runs_dir / "run-1.json").write_text(json.dumps(run_summary, indent=2, ensure_ascii=True), encoding="utf-8")

    run_data_dir = runs_dir / "run-1"
    run_data_dir.mkdir()
    (run_data_dir / "candidate_run_map.jsonl").write_text(
        "\n".join(
            [
                json.dumps({"candidate_id": "cand-a", "bundle_id": "bundle-sigA-clean"}),
                json.dumps({"candidate_id": "cand-b", "bundle_id": "bundle-sigA-dirty"}),
            ]
        ),
        encoding="utf-8",
    )

    output_root = tmp_path / "clean_store"
    result = compact_store(source_root=source_root, output_root=output_root)

    remaining_bundles = sorted(p.stem for p in (output_root / "bundles").glob("*.json"))
    assert remaining_bundles == ["bundle-sigA-clean", "bundle-sigB-dirty"]

    rewritten_summary = json.loads((output_root / "runs" / "run-1.json").read_text(encoding="utf-8"))
    assert rewritten_summary["bundle_ids"] == ["bundle-sigA-clean", "bundle-sigB-dirty"]

    assert result["bundles_before"] == 3
    assert result["bundles_after"] == 2
    assert result["bundles_removed"] == 1
    assert any("candidate_map:" in issue and "bundle-sigA-dirty" in issue for issue in result["orphan_issues"])


def test_compact_store_reports_stage_dirs_without_summary(tmp_path: Path) -> None:
    source_root = tmp_path / "source_store"
    (source_root / "bundles").mkdir(parents=True)
    runs_dir = source_root / "runs"
    runs_dir.mkdir(parents=True)

    orphan_stage_dir = runs_dir / "run-orphan"
    orphan_stage_dir.mkdir(parents=True)
    (orphan_stage_dir / "candidate_run_map.jsonl").write_text("", encoding="utf-8")

    output_root = tmp_path / "clean_store"
    result = compact_store(source_root=source_root, output_root=output_root)
    assert "stages_without_summary:run-orphan" in result["orphan_issues"]

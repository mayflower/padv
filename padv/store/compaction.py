from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

_JSON_GLOB = "*.json"


def _candidate_signature(candidate: dict[str, Any]) -> str:
    vuln_class = str(candidate.get("vuln_class", "")).strip()
    file_path = str(candidate.get("file_path", "")).strip()
    line = int(candidate.get("line", 0) or 0)
    sink = str(candidate.get("sink", "")).strip()
    return f"{vuln_class}|{file_path}|{line}|{sink}"


def _bundle_is_clean(bundle: dict[str, Any]) -> bool:
    planner_trace = bundle.get("planner_trace")
    if not isinstance(planner_trace, dict):
        return False
    attempts = planner_trace.get("attempts")
    if not isinstance(attempts, list) or not attempts:
        return False
    for item in attempts:
        if not isinstance(item, dict):
            return False
        status = str(item.get("runtime_status", "")).strip().lower()
        if status in {"request_failed", "inactive", "missing_intercept"}:
            return False
    return True


def _bundle_sort_key(bundle: dict[str, Any]) -> tuple[int, str, str]:
    clean_rank = 1 if _bundle_is_clean(bundle) else 0
    created_at = str(bundle.get("created_at", "")).strip()
    bundle_id = str(bundle.get("bundle_id", "")).strip()
    return clean_rank, created_at, bundle_id


def _load_json(path: Path) -> dict[str, Any] | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    return data if isinstance(data, dict) else None


def _gather_bundles(
    bundles_dir: Path,
) -> tuple[dict[Path, dict[str, Any]], dict[str, list[tuple[Path, dict[str, Any]]]]]:
    bundles_by_path: dict[Path, dict[str, Any]] = {}
    grouped: dict[str, list[tuple[Path, dict[str, Any]]]] = {}
    for bundle_file in sorted(bundles_dir.glob(_JSON_GLOB)):
        payload = _load_json(bundle_file)
        if payload is None:
            continue
        candidate = payload.get("candidate")
        if not isinstance(candidate, dict):
            continue
        signature = _candidate_signature(candidate)
        bundles_by_path[bundle_file] = payload
        grouped.setdefault(signature, []).append((bundle_file, payload))
    return bundles_by_path, grouped


def _select_best_bundles(
    grouped: dict[str, list[tuple[Path, dict[str, Any]]]],
) -> set[Path]:
    keep_paths: set[Path] = set()
    for items in grouped.values():
        keep_paths.add(max(items, key=lambda item: _bundle_sort_key(item[1]))[0])
    return keep_paths


def _remove_duplicate_bundles(
    bundles_by_path: dict[Path, dict[str, Any]],
    keep_paths: set[Path],
) -> int:
    removed_count = 0
    for bundle_file in bundles_by_path:
        if bundle_file in keep_paths:
            continue
        bundle_file.unlink(missing_ok=True)
        removed_count += 1
    return removed_count


def _kept_ids(
    bundles_by_path: dict[Path, dict[str, Any]],
    keep_paths: set[Path],
) -> set[str]:
    return {
        str(payload.get("bundle_id", "")).strip()
        for path, payload in bundles_by_path.items()
        if path in keep_paths
    }


def _rewrite_run_summaries(run_dir: Path, kept_bundle_ids: set[str]) -> int:
    rewritten = 0
    for run_summary in sorted(run_dir.glob(_JSON_GLOB)):
        payload = _load_json(run_summary)
        if payload is None:
            continue
        bundle_ids = payload.get("bundle_ids")
        if not isinstance(bundle_ids, list):
            continue
        payload["bundle_ids"] = [
            str(bid) for bid in bundle_ids if str(bid).strip() in kept_bundle_ids
        ]
        run_summary.write_text(json.dumps(payload, indent=2, ensure_ascii=True), encoding="utf-8")
        rewritten += 1
    return rewritten


def _detect_orphan_run_refs(run_dir: Path, kept_bundle_ids: set[str]) -> list[str]:
    issues: list[str] = []
    for run_summary in sorted(run_dir.glob(_JSON_GLOB)):
        payload = _load_json(run_summary)
        if payload is None:
            continue
        for bundle_id in payload.get("bundle_ids", []):
            text = str(bundle_id).strip()
            if text and text not in kept_bundle_ids:
                issues.append(f"run:{run_summary.name}:missing_bundle:{text}")
    return issues


def _detect_orphan_stage_refs(run_dir: Path, kept_bundle_ids: set[str]) -> list[str]:
    issues: list[str] = []
    for stage_dir in sorted(p for p in run_dir.iterdir() if p.is_dir()):
        run_summary = run_dir / f"{stage_dir.name}.json"
        if not run_summary.exists():
            issues.append(f"stages_without_summary:{stage_dir.name}")
        issues.extend(_detect_mapping_orphans(stage_dir, kept_bundle_ids))
    return issues


def _detect_mapping_orphans(stage_dir: Path, kept_bundle_ids: set[str]) -> list[str]:
    issues: list[str] = []
    mapping_path = stage_dir / "candidate_run_map.jsonl"
    if not mapping_path.exists():
        return issues
    for raw_line in mapping_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except Exception:
            issues.append(f"invalid_mapping_json:{mapping_path}")
            continue
        bundle_id = str(record.get("bundle_id", "")).strip()
        if bundle_id and bundle_id not in kept_bundle_ids:
            issues.append(f"candidate_map:{mapping_path}:missing_bundle:{bundle_id}")
    return issues


def compact_store(source_root: Path, output_root: Path) -> dict[str, Any]:
    if not source_root.exists() or not source_root.is_dir():
        raise FileNotFoundError(f"store root does not exist: {source_root}")

    if output_root.exists():
        shutil.rmtree(output_root)
    shutil.copytree(source_root, output_root)

    bundles_dir = output_root / "bundles"
    run_dir = output_root / "runs"

    bundles_by_path, grouped = _gather_bundles(bundles_dir)
    keep_paths = _select_best_bundles(grouped)
    removed_count = _remove_duplicate_bundles(bundles_by_path, keep_paths)
    kept_bundle_ids = _kept_ids(bundles_by_path, keep_paths)
    rewritten_runs = _rewrite_run_summaries(run_dir, kept_bundle_ids)

    orphan_issues = _detect_orphan_run_refs(run_dir, kept_bundle_ids)
    orphan_issues.extend(_detect_orphan_stage_refs(run_dir, kept_bundle_ids))

    return {
        "source_root": str(source_root),
        "output_root": str(output_root),
        "bundles_before": len(bundles_by_path),
        "bundles_after": len(keep_paths),
        "bundles_removed": removed_count,
        "runs_rewritten": rewritten_runs,
        "orphan_issues": sorted(set(orphan_issues)),
    }

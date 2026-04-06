from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

from padv.config.schema import PadvConfig
from padv.models import Candidate, RunSummary, StaticEvidence
from padv.orchestrator.graphs import analyze_with_graph, run_with_graph, validate_with_graph
from padv.store.evidence_store import EvidenceStore, RunIdRequiredError


def analyze(
    config: PadvConfig,
    repo_root: str,
    store: EvidenceStore,
    mode: str,
    progress_callback: Callable[[dict[str, Any]], None] | None = None,
    resume_run_id: str | None = None,
    run_id: str | None = None,
) -> tuple[list[Candidate], list[StaticEvidence]]:
    candidates, static_evidence, _ = analyze_with_graph(
        config,
        repo_root,
        store,
        mode,
        progress_callback=progress_callback,
        resume_run_id=resume_run_id,
        run_id=run_id,
    )
    return candidates, static_evidence


def validate_candidates(
    config: PadvConfig,
    store: EvidenceStore,
    static_evidence: list[StaticEvidence],
    candidates: list[Candidate],
    run_id: str,
    repo_root: str | None = None,
    progress_callback: Callable[[dict[str, Any]], None] | None = None,
    resume_run_id: str | None = None,
) -> tuple[list[object], dict[str, int]]:
    bundles, decisions = validate_with_graph(
        config=config,
        store=store,
        static_evidence=static_evidence,
        candidates=candidates,
        run_id=run_id,
        repo_root=repo_root,
        progress_callback=progress_callback,
        resume_run_id=resume_run_id,
    )
    return bundles, decisions


def run_pipeline(
    config: PadvConfig,
    repo_root: str,
    store: EvidenceStore,
    mode: str,
    progress_callback: Callable[[dict[str, Any]], None] | None = None,
    resume_run_id: str | None = None,
    run_id: str | None = None,
) -> RunSummary:
    return run_with_graph(
        config=config,
        repo_root=repo_root,
        store=store,
        mode=mode,
        progress_callback=progress_callback,
        resume_run_id=resume_run_id,
        run_id=run_id,
    )


def export_bundle(store: EvidenceStore, bundle_id: str, output_path: str) -> Path:
    try:
        bundle = store.load_bundle(bundle_id)
    except RunIdRequiredError:
        bundle = store.load_bundle_legacy_lookup(bundle_id)
    if bundle is None:
        raise FileNotFoundError(f"bundle not found: {bundle_id}")
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(bundle, indent=2, ensure_ascii=True))
    return out

from __future__ import annotations

import argparse
import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

from padv.analytics.failure_patterns import analyze_failures, format_analysis_table
from padv.config.schema import ConfigError, load_config
from padv.dynamic.sandbox import adapter as sandbox_adapter
from padv.orchestrator.pipeline import analyze, export_bundle, run_pipeline, validate_candidates
from padv.store.evidence_store import EvidenceStore

_HELP_CONFIG_PATH = "Path to TOML config"
_HELP_NO_PROGRESS = "Disable live step updates on stderr"


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="padv", description="PHP Agentic Discovery & Validation CLI")

    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="Discovery + detection + validation")
    run.add_argument("--config", default=None, help=_HELP_CONFIG_PATH)
    run.add_argument("--repo-root", required=True)
    run.add_argument("--mode", default="variant", choices=["variant", "delta", "batch"])
    run.add_argument("--no-progress", action="store_true", help=_HELP_NO_PROGRESS)
    run.add_argument("--run-id", default=None, help="Explicit run id for persisted artifacts")
    run.add_argument("--resume", nargs="?", const="latest", default=None, help="Resume an interrupted run by run id or latest compatible run")

    analyze_cmd = sub.add_parser("analyze", help="Static discovery/detection only")
    analyze_cmd.add_argument("--config", default=None, help=_HELP_CONFIG_PATH)
    analyze_cmd.add_argument("--repo-root", required=True)
    analyze_cmd.add_argument("--mode", default="variant", choices=["variant", "delta", "batch"])
    analyze_cmd.add_argument("--no-progress", action="store_true", help=_HELP_NO_PROGRESS)
    analyze_cmd.add_argument("--run-id", default=None, help="Explicit run id for persisted artifacts")
    analyze_cmd.add_argument("--resume", nargs="?", const="latest", default=None, help="Resume an interrupted analyze run by run id or latest compatible run")

    analyze_failures_cmd = sub.add_parser("analyze-failures", help="Analyze historical failure patterns")
    analyze_failures_cmd.add_argument("--config", default=None, help=_HELP_CONFIG_PATH)
    analyze_failures_cmd.add_argument("--min-occurrences", type=int, default=3)
    analyze_failures_cmd.add_argument("--format", choices=["json", "table"], default="table")

    validate = sub.add_parser("validate", help="Validate selected candidates")
    validate.add_argument("--config", default=None, help=_HELP_CONFIG_PATH)
    validate.add_argument("--candidate-id", action="append", dest="candidate_ids", default=[])
    validate.add_argument("--repo-root", default=None)
    validate.add_argument("--mode", default="variant", choices=["variant", "delta", "batch"])
    validate.add_argument("--no-progress", action="store_true", help=_HELP_NO_PROGRESS)
    validate.add_argument("--run-id", default=None, help="Run id to load persisted candidates and evidence from")
    validate.add_argument("--resume", nargs="?", const="latest", default=None, help="Resume an interrupted validate run by run id or latest compatible run")

    sandbox = sub.add_parser("sandbox", help="Sandbox helper commands")
    sandbox.add_argument("--config", default=None, help=_HELP_CONFIG_PATH)
    sandbox.add_argument("action", choices=["deploy", "reset", "status", "logs"])

    list_cmd = sub.add_parser("list", help="List artifacts")
    list_cmd.add_argument("--config", default=None, help=_HELP_CONFIG_PATH)
    list_cmd.add_argument("--run-id", default=None, help="Run id to inspect")
    list_cmd.add_argument("kind", choices=["candidates", "bundles", "runs", "resumes"])

    show = sub.add_parser("show", help="Show artifact details")
    show.add_argument("--config", default=None, help=_HELP_CONFIG_PATH)
    show.add_argument("--scope-run-id", default=None, help="Run id to read scoped candidates or bundles from")
    show.add_argument("--bundle-id")
    show.add_argument("--run-id")
    show.add_argument("--candidate-id")

    export = sub.add_parser("export", help="Export bundle to a file")
    export.add_argument("--config", default=None, help=_HELP_CONFIG_PATH)
    export.add_argument("--run-id", default=None, help="Run id to read the bundle from")
    export.add_argument("--bundle-id", required=True)
    export.add_argument("--output", required=True)

    return parser


def _load_config_or_exit(path: str):
    try:
        return load_config(path)
    except ConfigError as exc:
        print(json.dumps({"error": str(exc)}))
        raise SystemExit(2) from exc


def _resolve_config_path(args: argparse.Namespace) -> str:
    command_level = getattr(args, "config", None)
    if command_level:
        return command_level
    return "padv.toml"


def _store_from_root(root: str) -> EvidenceStore:
    store = EvidenceStore(Path(root))
    store.ensure()
    return store


def _print_json(data):
    print(json.dumps(data, indent=2, ensure_ascii=True))


def _progress_callback(enabled: bool):
    if not enabled:
        return None

    def _emit(event: dict[str, object]) -> None:
        ts_raw = str(event.get("ts", "")).strip()
        if ts_raw:
            try:
                dt = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
                ts = dt.astimezone(timezone.utc).strftime("%H:%M:%S")
            except ValueError:
                ts = ts_raw
        else:
            ts = datetime.now(tz=timezone.utc).strftime("%H:%M:%S")
        step = str(event.get("step", "step"))
        status = str(event.get("status", "info"))
        detail = str(event.get("detail", "")).strip()
        line = f"[{ts}] {step:<20} {status}"
        if detail:
            line += f" | {detail}"
        print(line, file=sys.stderr, flush=True)

    return _emit


def _cmd_run(args: argparse.Namespace) -> int:
    try:
        config = _load_config_or_exit(_resolve_config_path(args))
        store = _store_from_root(config.store.root)
        summary = run_pipeline(
            config=config,
            repo_root=args.repo_root,
            store=store,
            mode=args.mode,
            progress_callback=_progress_callback(not args.no_progress),
            resume_run_id=args.resume,
            run_id=args.run_id,
        )
        _print_json(summary.to_dict())
        return 0
    except Exception as exc:
        _print_json({"error": str(exc)})
        return 1


def _cmd_analyze(args: argparse.Namespace) -> int:
    try:
        config = _load_config_or_exit(_resolve_config_path(args))
        store = _store_from_root(config.store.root)
        candidates, static_evidence = analyze(
            config=config,
            repo_root=args.repo_root,
            store=store,
            mode=args.mode,
            progress_callback=_progress_callback(not args.no_progress),
            resume_run_id=args.resume,
            run_id=args.run_id,
        )
        _print_json(
            {
                "candidates": len(candidates),
                "static_evidence": len(static_evidence),
                "candidate_ids": [c.candidate_id for c in candidates],
            }
        )
        return 0
    except Exception as exc:
        _print_json({"error": str(exc)})
        return 1


def _cmd_analyze_failures(args: argparse.Namespace) -> int:
    try:
        config = _load_config_or_exit(_resolve_config_path(args))
        store = _store_from_root(config.store.root)
        analysis = analyze_failures(store=store, min_occurrences=max(1, int(args.min_occurrences)))
        if args.format == "json":
            _print_json(analysis.to_dict())
        else:
            print(format_analysis_table(analysis))
        return 0
    except Exception as exc:
        _print_json({"error": str(exc)})
        return 1


def _cmd_validate(args: argparse.Namespace) -> int:
    try:
        config = _load_config_or_exit(_resolve_config_path(args))
        store = _store_from_root(config.store.root)
        progress_cb = _progress_callback(not args.no_progress)

        if args.repo_root:
            candidates, static_evidence = analyze(
                config=config,
                repo_root=args.repo_root,
                store=store,
                mode=args.mode,
                progress_callback=progress_cb,
                run_id=args.run_id,
            )
        else:
            source_store = store.for_run(args.run_id) if args.run_id else store
            candidates = source_store.load_candidates()
            static_evidence = source_store.load_static_evidence()

        selected = candidates
        if args.candidate_ids:
            wanted = set(args.candidate_ids)
            selected = [c for c in candidates if c.candidate_id in wanted]

        run_id = f"run-validate-{uuid.uuid4().hex[:8]}"
        bundles, decisions = validate_candidates(
            config=config,
            store=store,
            static_evidence=static_evidence,
            candidates=selected,
            run_id=run_id,
            repo_root=args.repo_root,
            progress_callback=progress_cb,
            resume_run_id=args.resume,
        )
        _print_json(
            {
                "run_id": run_id,
                "validated": decisions.get("VALIDATED", 0),
                "confirmed_analysis": decisions.get("CONFIRMED_ANALYSIS_FINDING", 0),
                "dropped": decisions.get("DROPPED", 0),
                "needs_human_setup": decisions.get("NEEDS_HUMAN_SETUP", 0),
                "skipped_budget": decisions.get("SKIPPED_BUDGET", 0),
                "error": decisions.get("ERROR", 0),
                "bundle_ids": [b.bundle_id for b in bundles],
            }
        )
        return 0
    except Exception as exc:
        _print_json({"error": str(exc)})
        return 1


def _cmd_sandbox(args: argparse.Namespace) -> int:
    config = _load_config_or_exit(_resolve_config_path(args))

    if args.action == "deploy":
        result = sandbox_adapter.deploy(config.sandbox)
    elif args.action == "reset":
        result = sandbox_adapter.reset(config.sandbox)
    elif args.action == "status":
        result = sandbox_adapter.status(config.sandbox)
    else:
        result = sandbox_adapter.logs(config.sandbox)

    _print_json({"ok": result.ok, "action": result.action, "output": result.output})
    return 0 if result.ok else 1


def _cmd_list(args: argparse.Namespace) -> int:
    config = _load_config_or_exit(_resolve_config_path(args))
    store = _store_from_root(config.store.root)
    scoped_store = store.for_run(args.run_id) if args.run_id else store

    if args.kind == "candidates":
        _print_json([c.to_dict() for c in scoped_store.load_candidates()])
    elif args.kind == "bundles":
        _print_json(scoped_store.list_bundle_ids())
    elif args.kind == "resumes":
        _print_json(store.list_resume_metadata())
    else:
        _print_json(store.list_run_ids())
    return 0


def _cmd_show(args: argparse.Namespace) -> int:
    config = _load_config_or_exit(_resolve_config_path(args))
    store = _store_from_root(config.store.root)

    requested = sum(bool(x) for x in [args.bundle_id, args.run_id, args.candidate_id])
    if requested != 1:
        _print_json({"error": "provide exactly one of --bundle-id, --run-id, --candidate-id"})
        return 2

    if args.bundle_id:
        bundle = store.for_run(args.scope_run_id).load_bundle(args.bundle_id) if args.scope_run_id else store.load_bundle(args.bundle_id)
        if bundle is None:
            _print_json({"error": f"bundle not found: {args.bundle_id}"})
            return 1
        _print_json(bundle)
        return 0

    if args.run_id:
        run = store.load_run_summary(args.run_id)
        if run is None:
            _print_json({"error": f"run not found: {args.run_id}"})
            return 1
        _print_json(run)
        return 0

    candidate_source = store.for_run(args.scope_run_id).load_candidates() if args.scope_run_id else store.load_candidates()
    for candidate in candidate_source:
        if candidate.candidate_id == args.candidate_id:
            _print_json(candidate.to_dict())
            return 0
    _print_json({"error": f"candidate not found: {args.candidate_id}"})
    return 1


def _cmd_export(args: argparse.Namespace) -> int:
    config = _load_config_or_exit(_resolve_config_path(args))
    store = _store_from_root(config.store.root)
    bundle_store = store.for_run(args.run_id) if args.run_id else store
    try:
        out = export_bundle(bundle_store, args.bundle_id, args.output)
    except FileNotFoundError as exc:
        _print_json({"error": str(exc)})
        return 1
    _print_json({"bundle_id": args.bundle_id, "output": str(out)})
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "run":
        return _cmd_run(args)
    if args.command == "analyze":
        return _cmd_analyze(args)
    if args.command == "analyze-failures":
        return _cmd_analyze_failures(args)
    if args.command == "validate":
        return _cmd_validate(args)
    if args.command == "sandbox":
        return _cmd_sandbox(args)
    if args.command == "list":
        return _cmd_list(args)
    if args.command == "show":
        return _cmd_show(args)
    if args.command == "export":
        return _cmd_export(args)

    parser.print_help()
    return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())

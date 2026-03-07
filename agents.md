# Agent Instructions

## Primary Spec
- Canonical implementation spec is [`prd.md`](./prd.md).
- If older docs conflict, `prd.md` wins.

## Scope locks
- Never add reporting/advisory generation or patching automation.
- Do not call external targets; sandbox-only execution.

## Architecture rules
- Keep deterministic gate logic in `padv/gates/engine.py`.
- Keep Morcilla contract handling in `padv/oracle/morcilla.py`.
- Do not preserve backward compatibility for known misimplementations.
- Enforce strict agentic cutover per `prd.md` phases.

## Delivery protocol
1. Update/confirm spec assumptions.
2. Add or update tests.
3. Implement.
4. Run local unit/integration checks.
5. Summarize gate-impacting changes.

## Progress Log
- 2026-03-07: `DONE` - Created new strict cutover spec in `prd.md` (v2.0).
- 2026-03-07: `DONE` - Phase 0 (part 1): removed legacy `discover_source_candidates` from orchestrator runtime path.
- 2026-03-07: `DONE` - Phase 0 (part 2): static discovery now hard-fails when semantic discovery (`joern+scip`) yields zero candidates.
- 2026-03-07: `DONE` - Updated graph orchestrator tests for semantic-only runtime path; test suite green (`83 passed`).
- 2026-03-07: `DONE` - Phase 0 (part 3): removed dormant string/regex discovery components (`padv/discovery/source.py`, joern adapter regex branch), kept semantic-only discovery path.
- 2026-03-07: `DONE` - Rebased tests to strict semantic mode; suite green (`79 passed`).
- 2026-03-07: `DONE` - Phase 1: added SCIP-first discovery metrics and persisted semantic discovery artifacts (`raw_scip_hits`, `mapped_scip_sinks`, `joern_findings`, `fused_candidates`) in graph trace + artifact store.
- 2026-03-07: `DONE` - Added meta-aware discovery adapters (`discover_scip_candidates_with_meta`, `discover_candidates_with_meta`) and regression tests; suite green (`81 passed`).
- 2026-03-07: `IN_PROGRESS` - Phase 2: enforced semantic-only candidate intake in graph static discovery (manifest-only candidates dropped), and persisted per-candidate fusion evidence refs (`semantic-fusion-*.json`).
- 2026-03-07: `DONE` - Phase 2: implemented semantic evidence graph fusion (`fuse_candidates_with_meta`) with semantic-only intake, dual-signal preference (`joern+scip`), and persisted fusion graph artifacts.
- 2026-03-07: `IN_PROGRESS` - Phase 3: added runtime attempt telemetry per candidate (hypotheses + request/action + outcome delta flags) into bundle `planner_trace`.
- 2026-03-07: `DONE` - Added regression coverage for semantic fusion behavior and runtime planner trace telemetry; suite green (`85 passed`).
- 2026-03-07: `IN_PROGRESS` - Phase 3: switched run-mode loop to true per-iteration `plan -> execute -> analyze` (validation nodes execute each iteration before frontier update).
- 2026-03-07: `DONE` - Frontier now persists runtime attempt history and runtime-coverage deltas across iterations (`attempt_history`, `runtime_coverage`); regression tests green (`86 passed`).
- 2026-03-07: `IN_PROGRESS` - Phase 4: removed runtime-class fallback acceptance for runtime-validatable classes; deterministic gates now require class-specific witness rules and enforce negative-control cleanliness per class.
- 2026-03-07: `DONE` - Added SQL witness regressions (sink + differential witness requirements, negative-control oracle-hit rejection) and updated gate expectations; suite green (`89 passed`).
- 2026-03-07: `DONE` - Phase 4 hardening pass: upgraded XSS witness from `xss_raw_canary` to `xss_dom_witness`, added SSRF URL-argument witness and XXE entity witness, and enforced these in deterministic class witness rules.
- 2026-03-07: `DONE` - Phase 5: added regression guaranteeing `no witness => DROPPED(V3)` for every runtime-validatable class, plus stricter witness regression set for XSS/SSRF/XXE/SQL.
- 2026-03-07: `DONE` - Full suite after gate hardening/regressions is green (`117 passed`).
- 2026-03-07: `DONE` - Fixed SCIP adapter output contract to force JSON (`scip print --json`) and extended document parsing compatibility (snake_case + camelCase keys); semantic discovery now produces real SCIP counts/hits in Docker runs.
- 2026-03-07: `DONE` - Hardened scheduler normalization for mixed candidate IDs (`cand-*`/`scip-*`) and non-canonical numeric score strings; removed hard-fail on agent-decided empty action sets (`no-actions`/`no-valid-actions`).
- 2026-03-07: `DONE` - Hardened validation-plan normalization to tolerate non-object body payloads and under-specified request counts by deterministic normalization/padding, preventing strict-run aborts from LLM formatting variance.
- 2026-03-07: `DONE` - Re-ran full suite after hardening (`121 passed`).
- 2026-03-07: `IN_PROGRESS` - Phase 6 Docker E2E now completes strict `analyze` + strict `run` without hard-fail on phpMyFAQ (`run-63b6d6d3f9`), but current run produced zero runtime bundles because skeptic/scheduler selected no candidates for execution.

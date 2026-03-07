# PRD: Agentic Exploit Discovery & Validation Cutover (Strict)

**Version:** 2.0  
**Date:** 2026-03-07  
**Status:** Active Cutover  
**Product:** `padv`

## 1. Problem Statement
The current implementation still validates some findings via heuristic string/flag matching in runtime evidence.  
This violates the required OSS-Fuzz-Gen/DeepNap-style approach where agentic loops generate, execute, and falsify exploit hypotheses with deterministic acceptance.

## 2. Goals
1. Remove non-semantic source discovery from the execution path.
2. Make SCIP+Joern the mandatory discovery backbone.
3. Enforce agentic runtime exploit generation (not plain canary reflection checks).
4. Keep final decision deterministic, but only on robust runtime witnesses.

## 3. Non-Goals
1. No reporting/advisory generation.
2. No auto-patching.
3. No external target scanning.

## 4. Mandatory Inputs for Runtime Exploits
Runtime planning must support, per target/class:
1. `GET` params
2. `POST` params
3. Headers
4. Cookies
5. JSON body
6. Multipart/file upload
7. Path parameters
8. Auth/session context transitions

## 5. Architecture Requirements
1. **LangGraph-required** for all agentic orchestration.
2. **DeepAgents-required** for proposer/skeptic/scheduler/planner.
3. **Persistent frontier state** with hypotheses, failed paths, coverage deltas.
4. **Deterministic acceptance** remains in `padv/gates/engine.py`, but may only consume class-specific exploit witnesses.
5. **Morcilla contract** stays isolated in `padv/oracle/morcilla.py`.

## 6. Cutover Plan

### Phase 0: Remove Legacy Discovery Paths
1. Remove `discover_source_candidates` from orchestrator runtime path.
2. Remove regex fallback/static regex detector from active discovery path.
3. Hard-fail if semantic discovery (`joern` + `scip`) yields zero usable candidates.
4. Update tests to reflect strict semantic-only discovery.

### Phase 1: SCIP-First Semantic Discovery
1. Treat `scip-php` output as primary semantic graph input.
2. Persist raw SCIP evidence counts and mapped sink counts in artifacts.
3. Candidate creation only from semantic symbol/callsite evidence, not line substring.

### Phase 2: Joern Dataflow Fusion
1. Fuse SCIP symbols with Joern flows into a unified evidence graph.
2. Candidate requires at least one semantic sink path (`scip` or `joern`), preferred both.
3. Persist per-candidate semantic evidence references.

### Phase 3: Agentic Runtime Exploit Loop
1. Proposer generates class-specific exploit hypotheses.
2. Scheduler picks actions by expected information gain.
3. Executor performs Playwright-driven multi-step attempts.
4. Skeptic actively refutes by counter-attempts and alternative explanations.
5. All attempts recorded with hypothesis/action/outcome deltas.

### Phase 4: Replace Heuristic Runtime Proofs
1. Remove pure reflection-based XSS acceptance.
2. Require class-specific runtime witness:
   - XSS: browser execution/DOM witness
   - SQLi: boolean/time/error differential witness
   - SSRF/XXE: controlled callback/internal target witness
   - Auth/IDOR/CSRF/session: stateful differential witness
3. Negative controls required for each witness class.

### Phase 5: Deterministic Gate Hardening
1. `VALIDATED` impossible without class witness + repro + negative controls.
2. Add regression tests: "no witness => not validated" for all runtime-validatable classes.

### Phase 6: E2E Qualification on phpMyFAQ
1. Strict `analyze` + strict `run` complete without hard-fail.
2. Evidence bundles include semantic discovery + runtime witness artifacts.
3. No heuristic-only validation accepted.

## 7. Acceptance Criteria
1. `provenance=["source"]` candidates from line-string scanning: **0 in runtime path**.
2. Semantic discovery counters available: `raw_scip_hits`, `mapped_scip_sinks`, `joern_findings`, `fused_candidates`.
3. `VALIDATED` with zero exploit witness: **0**.
4. `VALIDATED` with zero relevant runtime sink evidence for class: **0**.
5. Repeat runs are deterministic at gate decision level.

## 8. Progress Tracking
Legend: `TODO`, `IN_PROGRESS`, `DONE`, `BLOCKED`

1. Phase 0 (legacy discovery cut): `DONE`
2. Phase 1 (SCIP-first metrics/artifacts): `DONE`
3. Phase 2 (SCIP+Joern evidence graph): `DONE`
4. Phase 3 (full agentic runtime loop): `IN_PROGRESS`
5. Phase 4 (heuristic proof removal): `DONE`
6. Phase 5 (gate hardening + regressions): `DONE`
7. Phase 6 (phpMyFAQ E2E qualification): `IN_PROGRESS`

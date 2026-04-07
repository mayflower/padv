# AGENTS.md — PADV v3 Agentic Refactor Rules (No Heuristic String Matching)

You are Codex/Claude Code working in the PADV repository.

## Non-negotiable rules
1) **Test-first always.** Add failing pytest tests BEFORE changing production code.
2) Default tests: `pytest -q -m "not integration"`.
3) Keep changes PR-sized; one theme per prompt.
4) **Run-first truth:** all reads/writes bound to explicit `run_id`. No scanning “latest run”.
5) **Stable typed identities:** immutable `run_id`, `candidate_uid`, `evidence_uid`, `bundle_uid`.
6) **Typed boundaries:** planner → runtime → gates communicate via structured objects, validated by schema.
7) **No heuristic string matching in decision logic**, including:
   - no “looks like login” by keyword in HTML
   - no substring allowlists for preconditions
   - no keyword matching for coverage categories
   - no string scanning to infer witness flags (except exact canary match inside typed oracle call args)
8) **Agentic discovery is required**:
   - Candidate discovery must be LLM-driven (with tools), not a pile of procedural heuristics.
   - LLM outputs must be structured (JSON schema) and validated.
9) **Validate-only is direct and bounded** (plan → execute → gate).
10) Deterministic stopping: budgets + stagnation thresholds are enforced by orchestrator, not LLM.

## Fail-closed principle
If structured data is missing or invalid:
- mark candidate as `NEEDS_HUMAN_SETUP` / `SKIPPED_PRECONDITION` / `ERROR`
- never guess by parsing prose or HTML.

## Hotspots
- `padv/orchestrator/*`
- `padv/agents/*`
- `padv/discovery/*`
- `padv/validation/*`
- `padv/gates/*`
- `padv/dynamic/http/*`
- `padv/store/*`
- `scripts/*_integration_assess.py`

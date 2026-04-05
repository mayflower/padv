Below is a **copy/paste “test-first prompt pack”** you can feed into **OpenAI Codex (CLI)** to refactor `mayflower/padv` toward a **2026 SOTA agentic security analysis** architecture (reliable discovery/detection/validation, minimal flakiness, deterministic run isolation, typed contracts, faster validate-only replays).

It is designed explicitly around the failure modes you listed (run contamination, brittle English preconditions, unstable candidate IDs, validate-only still running the full graph, stateful executor in the wrong places, duplicated gate contracts, budget opacity, LLM-dependent control flow, fragile persistence/caching). I also anchored the pack to what’s actually in the repo today:

* gate preconditions are normalized via substring allowlists in `padv/orchestrator/runtime.py` ([GitHub][1])
* the HTTP runner is `urllib`-based and doesn’t maintain a real session / cookie learning ([GitHub][2])
* the evidence store writes plain JSON and “ignores corrupt JSON” in multiple places ([GitHub][3])
* the Mutillidae assessment script loads **global** candidates/bundles (not run-scoped) ([GitHub][4])

Also: Codex can reliably follow repo-specific guidance via `AGENTS.md` layering; that’s why the pack starts by installing a strict `AGENTS.md`. ([OpenAI Developers][5])

---

## How to use this pack (practically)

1. Start at repo root.
2. Run Codex for **one prompt at a time** (each prompt is a “PR-sized” change).
3. Enforce **test-first**: Codex must add failing tests first, then implement minimal code to pass.
4. Keep unit tests fast: `pytest -m "not integration"` (the repo already marks integration tests). ([GitHub][6])

---

## Prompt 00 — Install guardrails (AGENTS.md) + baseline test discipline

```text
You are Codex working inside the mayflower/padv repo.

TASK: Create or update a repo-root AGENTS.md that enforces a strict test-first, run-isolated, typed-contract refactor strategy.

CONSTRAINTS:
- Test-first always: for every behavioral change, add failing pytest tests BEFORE code changes.
- Default to running unit tests only: `pytest -q -m "not integration"`.
- Do not add new heavy dependencies unless absolutely required; prefer stdlib.
- No “silent ignore” of corrupt state in run-critical paths; tests should cover corruption behavior.
- Make changes PR-sized: small, reviewable, one theme per commit.

AGENTS.md must include:
- How to run unit tests and integration tests (and which are default).
- Repo hotspots to understand first: padv/orchestrator/*, padv/discovery/*, padv/dynamic/http/*, padv/store/*, scripts/mutillidae_integration_assess.py
- SOTA-2026 invariants:
  1) Run-first state: no “latest run” scanning; everything is anchored to run_id.
  2) Stable typed identities: candidates and evidence use immutable IDs.
  3) Typed boundaries: planner/runtime/gates communicate via structured objects, not free-form English strings + substring heuristics.
  4) Validate-only is a direct path (no objective selection / research).
  5) HTTP execution is session-correct and candidate-isolated.
  6) Deterministic stop rules (budgets/stagnation), not LLM “continue/stop”.

DEFINITION OF DONE:
- AGENTS.md exists and is specific enough that another engineer could follow it.
- `pytest -q -m "not integration"` runs locally (fix trivial test breakages only if necessary).
```

Why this matters: Codex will read `AGENTS.md` automatically and apply it consistently across tasks. ([OpenAI Developers][5])

---

## Prompt 01 — Fix the #1 issue: **run isolation** (run-first storage + no cross-run contamination)

```text
TASK: Eliminate run contamination by making the system “run-first”.

CURRENT PROBLEMS TO TARGET:
- The assessment harness/script reads global candidates and bundles without filtering by run_id.
- The system has patterns that pick “latest analyze-* / run-* directory” rather than binding to a specific run.
- Global-first state makes concurrency unsafe and results non-reproducible.

WHAT TO BUILD:
A minimal run-scoped storage model:
- Introduce a RunContext (or equivalent) that carries run_id and an explicit run_root directory.
- Provide a store API that can open a run-scoped view (e.g., store.for_run(run_id) or EvidenceStore(run_root)).
- Ensure analyze/run/validate pipelines write artifacts under a run directory and read only from that run directory.
- Preserve backwards compatibility only if needed, but tests must prefer the run-scoped path.

TEST-FIRST REQUIREMENTS (add tests before code):
1) Create two run directories under tmp_path with different candidates and bundles.
   Assert that loading candidates/bundles for run A never sees run B artifacts.
2) Add a regression test that simulates “latest directory scanning” being wrong:
   Ensure the code under test selects ONLY the explicit run_id, not “newest directory”.
3) Add a test for scripts/mutillidae_integration_assess.py helper logic:
   Refactor script to accept run_id explicitly (or call a shared library function that does),
   then test it loads candidates/bundles from that run only.

IMPLEMENTATION NOTES:
- Avoid changing every call site in one giant patch; do a minimal spine:
  store.run_dir(run_id) + run-scoped load/save for candidates/static_evidence/bundles + wiring from CLI.
- Any function that currently reads from global root must accept run_id/run_root explicitly.

DEFINITION OF DONE:
- New unit tests fail before changes and pass after.
- No production path uses “latest run” discovery.
- The CLI can still operate, but now produces run-scoped artifacts.
```

(Anchors: global bundle/candidate loading is visible in the Mutillidae script today. ([GitHub][4]))

---

## Prompt 02 — Replace brittle English preconditions with a **typed Gate Preconditions contract**

```text
TASK: Remove flakiness from gate preconditions by replacing free-form English strings + substring allowlists with a typed contract.

CURRENT PROBLEM TO TARGET:
- Gate preconditions are normalized using substring/prefix allowlists and heuristics; wording changes flip outcomes.

WHAT TO BUILD:
- Define a small typed model for preconditions, e.g.:
  - requires_auth
  - requires_session
  - requires_csrf_token
  - requires_upload
  - requires_specific_header
  - unknown_blockers: list[str]
- Provide a deterministic parser from existing candidate.preconditions (strings) into the typed model.
  Keep mapping conservative; unknown strings should become unknown_blockers.

TEST-FIRST REQUIREMENTS:
1) Test that multiple phrasing variants map to the same typed precondition (AUTH).
2) Test that cookie/session presence satisfies auth/session preconditions deterministically (no substring magic).
3) Test that unknown preconditions yield a stable “NEEDS_HUMAN_SETUP” decision with a typed reason.

REFACTOR REQUIREMENTS:
- Planner and runtime may still carry raw strings, but gates must use the typed preconditions object.
- Delete or bypass the substring allowlist path; it must not determine gating outcomes anymore.

DEFINITION OF DONE:
- Tests pass.
- Gate decision does not depend on the exact English phrasing beyond deterministic parsing.
```

(Anchor: the substring/prefix allowlist normalization exists in `padv/orchestrator/runtime.py` today. ([GitHub][1]))

---

## Prompt 03 — Stabilize candidate identity: **immutable candidate_uid** + evidence linking that can’t “lose” static evidence

```text
TASK: Make candidate identity stable across fusion/rank passes and prevent evidence loss.

CURRENT PROBLEM TO TARGET:
- Candidate IDs are unstable across merge/rank passes; evidence linking relies on alias heuristics.
- Fusion merges candidates on (vuln_class, file_path, line) and rewrites IDs.

WHAT TO BUILD:
- Introduce candidate_uid as an immutable ID derived from stable fields (hash).
  Example inputs: vuln_class, file_path, sink, source provenance, normalized location range.
- Preserve candidate_uid through fusion/ranking; candidate_id may remain a display field but must not be rewritten.
- Update evidence bundle schema to reference candidate_uid as the canonical anchor.
- Update evidence linking to key on candidate_uid (and only fall back to legacy keys for backwards compatibility).

TEST-FIRST REQUIREMENTS:
1) Run fusion twice on the same inputs: candidate_uid must be identical and stable.
2) Simulate a rank/merge pass: candidate_uid must remain stable.
3) Evidence linking regression: static evidence attached to a candidate must still be attached after fusion/rerank.

DEFINITION OF DONE:
- No identity “recovery through alias heuristics” needed for core flows.
- Tests pass and prove stability + no evidence loss.
```

---

## Prompt 04 — Make `validate` truly direct: **validate-only graph path** (no objective selection / research)

```text
TASK: Implement a true direct-validation execution path.

CURRENT PROBLEM TO TARGET:
- validate-only mode still runs the full LangGraph pipeline, including objective selection and agentic research.

WHAT TO BUILD:
- A minimal “ValidateGraph” (or equivalent) that takes:
  run_id/run_context,
  selected candidates,
  existing static evidence,
  and produces validation bundles + gate decisions
  WITHOUT:
  - select_objective
  - research subagents
  - hypothesis synthesis loops
- CLI: when `padv validate --candidate-id ...` is called, it should prefer this direct path.

TEST-FIRST REQUIREMENTS:
1) A unit test that monkeypatches/stubs objective-selection functions to raise if called,
   then runs validate-only and asserts no such call occurs.
2) A unit test that validate-only consumes pre-specified candidates and returns deterministic outcomes
   (even if “skipped” for missing preconditions or budget).

DEFINITION OF DONE:
- validate-only is fast and deterministic (no agentic wandering).
- Tests enforce that “research” functions are not called in validate-only.
```

---

## Prompt 05 — Fix HTTP runtime correctness: **real session**, per-candidate isolation, cookie learning

```text
TASK: Replace the current minimal HTTP runner behavior with session-correct behavior.

CURRENT PROBLEMS TO TARGET:
- Cookie jar is reused across candidates in a run OR not learned properly from Set-Cookie.
- HTTP client does not maintain a real session, does not learn from Set-Cookie, and body encoding is minimal.

WHAT TO BUILD:
- Introduce an HttpSession object that:
  - stores cookies
  - learns from Set-Cookie response headers
  - applies Cookie headers on subsequent requests
  - is instantiated per candidate (or per validation attempt) to avoid cross-candidate contamination
- Keep implementation lightweight (stdlib preferred), but behavior must be testable.

TEST-FIRST REQUIREMENTS:
1) Start a tiny local HTTP server in tests:
   - endpoint A sets a cookie
   - endpoint B asserts cookie is present; return 200 only if cookie was sent
2) Ensure session reset:
   - candidate1 acquires cookie, candidate2 must NOT inherit it by default.

DEFINITION OF DONE:
- Tests pass proving cookie learning and per-candidate isolation.
- Runner no longer behaves as a stateless one-off client.
```

(Anchor: the current runner is a small `urllib` wrapper with no session semantics. ([GitHub][2]))

---

## Prompt 06 — Unify runtime ↔ gates: **single typed WitnessContract** shared across planner/runtime/gates

```text
TASK: Eliminate duplicated/ drifting gate contracts by introducing a single typed WitnessContract.

CURRENT PROBLEM TO TARGET:
- Runtime derives witness flags heuristically.
- Gate engine separately hardcodes per-class required flags.
- There is no single typed contract object shared by planner/runtime/gates.

WHAT TO BUILD:
- Define:
  - Witness: typed structure produced by runtime execution (oracle hits, crash, diff, timing, etc.)
  - WitnessContract: typed requirements keyed by vuln_class (or a smaller set of canonical oracle classes)
- Runtime produces Witness deterministically.
- Gate evaluation consumes Witness + WitnessContract.

TEST-FIRST REQUIREMENTS:
1) Unit test per 2–3 representative vuln classes:
   - provide a Witness instance and assert gate decision is correct
2) Regression test that ensures gate required flags are not duplicated in a second table elsewhere.

DEFINITION OF DONE:
- One source of truth for “what counts as validated/refuted”.
- Tests prove runtime->gate compatibility.
```

---

## Prompt 07 — Make execution deterministic: **budget outcomes + deterministic stop rules** (LLM not in charge of “continue/stop”)

```text
TASK: Make control flow deterministic and budgeting explicit.

CURRENT PROBLEMS TO TARGET:
- validate_candidates_runtime() returns partial bundles without explicit skipped outcomes.
- Continue/stop is delegated to the root agent; bounded only by max_iterations.

WHAT TO BUILD:
- Introduce explicit per-candidate outcomes:
  VALIDATED, REFUTED, SKIPPED_BUDGET, SKIPPED_PRECONDITION, ERROR
- Make budgeting behavior explicit:
  if budget is exhausted, remaining candidates must be marked SKIPPED_BUDGET with a reason.
- Replace “LLM decides continue” with deterministic stop criteria:
  - budget exhausted
  - stagnation detected (no new evidence N rounds)
  - no runnable candidates remain

TEST-FIRST REQUIREMENTS:
1) Force a tiny budget and assert that the tail candidates become SKIPPED_BUDGET (not silent).
2) Stagnation test:
   - simulate repeated no-op iterations; verify deterministic stop triggers.

DEFINITION OF DONE:
- No ambiguous “nothing validated” result.
- Stop behavior is reproducible across runs.
```

---

## Prompt 08 — Persistence + cache correctness: atomic writes, run-scoped cache keys, TTL

```text
TASK: Harden persistence and caching so run results are trustworthy under interruption/concurrency.

CURRENT PROBLEMS TO TARGET:
- Store writes JSON directly, no atomic protocol, no locking; corrupt files are silently ignored.
- Handoff cache is shared across runs, exact-match, no TTL, no config/prompt/version in key.

WHAT TO BUILD:
1) Atomic JSON writes for store artifacts:
   - write to temp file, fsync, atomic rename
   - (optional) per-run lock to avoid concurrent writers
2) Corruption handling:
   - for run-critical artifacts, fail loudly with a typed error (don’t silently ignore)
3) Cache key scoping:
   - include config signature + code version + prompt version + run_id (where appropriate)
   - add TTL

TEST-FIRST REQUIREMENTS:
1) Atomicity regression:
   - simulate partial write and ensure next read errors deterministically (and the caller surfaces it)
2) Cache scoping:
   - same prompt but different config signature must be a cache miss
   - stale entry beyond TTL must not be used

DEFINITION OF DONE:
- Store can’t “report the wrong truth” due to state bleed or stale cache.
- Tests pass and enforce the new invariants.
```

(Anchor: today the store writes JSON directly and frequently “ignores corrupt JSON.” ([GitHub][3]))

---

## Optional Prompt 09 — Performance correctness: evidence linking indexing + defensible coverage accounting

```text
TASK: Reduce O(n^2) evidence linking hot paths and fix optimistic coverage accounting.

WHAT TO BUILD:
- Add indexing for evidence linking keyed by candidate_uid and evidence type.
- Make coverage accounting depend on explicit outcomes (VALIDATED/REFUTED/SKIPPED/ERROR), not keyword matches.

TEST-FIRST REQUIREMENTS:
1) Linker performance regression: ensure linking is linear-ish on synthetic large candidate sets.
2) Coverage correctness: categories with only “attempted but dropped” bundles must not be FULL.

DEFINITION OF DONE:
- Evidence linking is faster and coverage is defensible.
```

---

## Two small “meta-prompts” that help Codex stay on-track

These aren’t code tasks; they’re *control prompts* you can paste when Codex starts drifting.

### Meta A — “make it test-first again”

```text
Stop. Before changing any production code, write the pytest(s) that fail on main and demonstrate the bug. Only after tests fail, implement the minimal fix to make them pass. If you can’t express the behavior as a unit test, explain why and propose a different seam that can be tested.
```

### Meta B — “keep the PR small”

```text
Reduce scope: deliver the smallest change set that fixes the tests for this prompt only. Do not mix in refactors, formatting, or unrelated cleanups. If you find a second issue, create a TODO note and continue with the current prompt.
```

---

## Why this pack should move `padv` from “procedural workflow engine with LLM calls” to SOTA agentic 2026

The pack forces the key architectural shift you’re aiming for:

* **Agentic where it matters** (hypothesis generation / plan synthesis), but
* **Deterministic where trust matters** (run scoping, identity, gating, budgeting, stopping, persistence).

That is the pragmatic SOTA split in 2026: keep LLMs out of “truth accounting” and “control-plane invariants”.

If you want, I can also produce a **mapping table** from each of your 12 findings → which prompt(s) fix it, and what new tests prove the fix.

[1]: https://github.com/mayflower/padv/blob/main/padv/orchestrator/runtime.py "padv/padv/orchestrator/runtime.py at main · mayflower/padv · GitHub"
[2]: https://github.com/mayflower/padv/blob/main/padv/dynamic/http/runner.py "padv/padv/dynamic/http/runner.py at main · mayflower/padv · GitHub"
[3]: https://github.com/mayflower/padv/blob/main/padv/store/evidence_store.py "padv/padv/store/evidence_store.py at main · mayflower/padv · GitHub"
[4]: https://github.com/mayflower/padv/blob/main/scripts/mutillidae_integration_assess.py "padv/scripts/mutillidae_integration_assess.py at main · mayflower/padv · GitHub"
[5]: https://developers.openai.com/codex/guides/agents-md/ "Custom instructions with AGENTS.md – Codex | OpenAI Developers"
[6]: https://raw.githubusercontent.com/mayflower/padv/main/pyproject.toml "raw.githubusercontent.com"


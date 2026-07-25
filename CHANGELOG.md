# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Changed
- **`REFUTED` requires typed `RefutationEvidence`.** Constructing a refuting
  `GateResult` without evidence now raises `MissingRefutationEvidenceError`. The
  evidence names the failed gate, the contracted witnesses, the flags actually
  observed, and the request ids on both sides of the experiment.
- **V6 is gone.** It was appended unconditionally immediately before returning
  `VALIDATED`, so it asserted nothing. The gate set is V0-V5.
- **Analysis-only candidates no longer bypass the gate engine at runtime.**
  `_process_candidate` built a `CONFIRMED_ANALYSIS_FINDING` bundle directly for
  every non-runtime-validatable candidate, which made the A-gates unreachable in
  production regardless of what the engine enforced.
- **The XSS witness depends on where the canary landed, not on what else is on
  the page.** `xss_dom_witness` required a raw canary in the body plus the
  substring `<script` (or `onerror=`/`onload=`) anywhere in it. Nearly every page
  loads a script, so that reduced to "the canary was reflected at all". The body
  is now parsed and the flag is set only when the canary occupies an executable
  position — script text, an `on*` handler attribute, or a `javascript:` URL —
  and the flag records which one.
- **The benchmark target is pinned.** `scripts/mutillidae_e2e.sh` fetched a
  moving branch tip and `reset --hard` onto it, so two runs on different days
  measured different code. It now fetches a fixed commit
  (`MUTILLIDAE_REF`, `MUTILLIDAE_DOCKER_REF`), detaches onto it, verifies the
  resolved SHA, and writes `targets/targets.lock.json` recording what was
  actually measured, including the morcilla commit.
- Persisted bundles carry a `schema_version`, and reading an older one migrates
  it conservatively (`migrate_bundle_payload`): retired decisions degrade to
  `INCONCLUSIVE` rather than being promoted to a refutation the recorded
  evidence never established.
- **Outcome algebra separates ignorance from refutation.** The gate engine no
  longer emits the ambiguous `DROPPED`. A failed V3 (the payload was delivered
  and the class witness never appeared) is now `REFUTED`; every other gate
  failure — out-of-scope runs, missing corroboration, a dirty negative control,
  insufficient repro runs, truncated evidence — is `INCONCLUSIVE`.
  `INSUFFICIENT_EVIDENCE` is folded into `INCONCLUSIVE` and no longer degrades
  to `ERROR`. Candidate outcomes are `VALIDATED`, `REFUTED`, `ANALYSIS_FINDING`,
  `INCONCLUSIVE`, `SKIPPED_PRECONDITION`, `SKIPPED_BUDGET`, `ERROR`. Artifacts
  written by earlier runs still read back: legacy `DROPPED` and
  `INSUFFICIENT_EVIDENCE` both map to `INCONCLUSIVE`, since neither proved
  absence.
- **`CONFIRMED_ANALYSIS_FINDING` is no longer reported as `VALIDATED`.** It maps
  to its own `ANALYSIS_FINDING` outcome.
- **`analysis_only` candidates go through gates instead of around them.** They
  now run the static half of the evidence contract (A0 mode, A1 preconditions,
  A2 static multi-evidence corroboration) rather than short-circuiting before
  V0.
- **The Mutillidae benchmark matches instances, not categories.** The gap
  catalog carries explicit `instances` (file, optional sink, optional route,
  required outcome) plus optional `negative_controls`. A gap counts as `FULL`
  only when every documented instance was proven with its required outcome; a
  same-class finding in another file no longer satisfies it, and a refutation
  never counts as coverage.

### Added
- `padv.eval.metrics`: instance-level `confusion_from_matches`,
  `precision_recall_f1`, and `macro_recall`, plus `summarize_outcomes` over the
  new vocabulary. Phase B of the Mutillidae assessment now emits a `metrics`
  block with precision, recall, F1, macro recall, per-category recall,
  negative-control violations, and validated findings that matched no
  ground-truth instance.

### Removed
- The "strong refutation counts as FULL" rule in the Mutillidae assessment and
  its supporting helper.

## [0.1.0] - 2026-04-02

### Added
- CLI commands: `analyze`, `run`, `validate`, `sandbox`, `list`, `show`, `export`, `analyze-failures`
- Semantic static analysis via SCIP and Joern (CPG dataflow queries)
- Playwright-based web discovery with LLM-guided browser automation
- Multi-source candidate fusion with semantic signal filtering
- DeepAgents integration: proposer, skeptic, scheduler, experiment subagents
- Deterministic gate engine (V0-V6) for runtime validation
- Morcilla oracle integration for instrumented PHP targets
- Per-class validation contracts with witness and transport requirements
- Differential authorization testing
- Fair-share budgeting across vulnerability classes
- Persistent frontier with hypothesis/refutation tracking
- Run resume via checkpointed LangGraph state
- Docker container with Joern, SCIP, and full scanner stack
- Mutillidae end-to-end example

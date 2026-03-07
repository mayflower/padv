# PRD: padv Enhancement Suite — Research-Driven Improvements

**Version:** 1.0
**Date:** 2026-03-06
**Status:** Ready for Implementation

---

## Table of Contents

1. [Context & System Overview](#1-context--system-overview)
2. [Current Architecture Reference](#2-current-architecture-reference)
3. [Enhancement E1: LLM-Based Taint Specification Inference](#3-enhancement-e1-llm-based-taint-specification-inference)
4. [Enhancement E2: CPG-Slice → LLM Refinement Pipeline](#4-enhancement-e2-cpg-slice--llm-refinement-pipeline)
5. [Enhancement E3: State-Graph-Aware Web Discovery](#5-enhancement-e3-state-graph-aware-web-discovery)
6. [Enhancement E4: Morcilla Input-to-State Feedback](#6-enhancement-e4-morcilla-input-to-state-feedback)
7. [Enhancement E5: Morcilla-Guided Mutation Loop](#7-enhancement-e5-morcilla-guided-mutation-loop)
8. [Enhancement E6: Differential Validation for AuthZ Classes](#8-enhancement-e6-differential-validation-for-authz-classes)
9. [Enhancement E7: Failure-Pattern Learning](#9-enhancement-e7-failure-pattern-learning)
10. [Implementation Order & Dependencies](#10-implementation-order--dependencies)
11. [Configuration Schema Extensions](#11-configuration-schema-extensions)
12. [Data Model Extensions](#12-data-model-extensions)
13. [Test Strategy](#13-test-strategy)
14. [Invariants & Constraints](#14-invariants--constraints)

---

## 1. Context & System Overview

### 1.1 What padv Is

`padv` is a local CLI tool for discovery, detection, and deterministic validation of PHP security vulnerability candidates. It runs against local sandbox targets only.

### 1.2 Core Principles (Must Be Preserved)

These principles are **inviolable** — every enhancement MUST preserve them:

1. **Agents plan, Gates decide.** LLMs never make final security decisions. The deterministic Gate Engine (V0–V6) is the sole arbiter.
2. **Runtime truth comes from Morcilla.** The Morcilla PHP extension is the single source of runtime evidence, communicated via HTTP request/response headers.
3. **Evidence-first.** Every decision traces back to concrete static or runtime evidence. No textual reasoning as proof.
4. **Reproducibility over coverage.** A reproducible finding is worth more than broad but flaky coverage.
5. **Strict, safe defaults.** All configuration is explicit. No silent degradation.

### 1.3 Current CLI Commands

| Command | Description |
|---------|-------------|
| `padv run` | Full discovery + validation + gate decisions |
| `padv analyze` | Discovery + synthesis only (no validation) |
| `padv validate` | Validate existing/selected candidates |
| `padv sandbox deploy\|reset\|status\|logs` | Sandbox management |
| `padv list candidates\|bundles\|runs` | List artifacts |
| `padv show --bundle-id\|--run-id\|--candidate-id` | Show artifact details |
| `padv export --bundle-id --output` | Export bundle |

### 1.4 Current Orchestration Flow (LangGraph)

```
init → static_discovery → web_discovery → auth_setup → candidate_synthesis
  → skeptic_refine → objective_schedule → frontier_update
      ↳ (loop back to static_discovery OR proceed)
  → validation_plan → runtime_validate → deterministic_gates
  → dedup_topk → persist
```

Each stage writes a snapshot to `runs/<run-id>/stages/<seq>-<stage>.json`.

---

## 2. Current Architecture Reference

This section provides the **complete** structural context a coding agent needs. All file paths are relative to the project root.

### 2.1 Package Layout

```
padv/
├── models.py                    # Candidate, StaticEvidence, RuntimeEvidence, RuntimeCall,
│                                # GateResult, EvidenceBundle, RunSummary, ValidationPlan,
│                                # ValidationContext
├── path_scope.py                # Path normalization, vendor/test exclusion
│
├── cli/main.py                  # CLI entry (click-based). Commands: run, analyze, validate,
│                                # sandbox, list, show, export
│
├── config/schema.py             # Dataclasses: PadvConfig, TargetConfig, OracleConfig,
│                                # CanaryConfig, BudgetConfig, SandboxConfig, StoreConfig,
│                                # AuthConfig, JoernConfig, LLMConfig, AgentConfig, ScipConfig,
│                                # WebConfig. Loader: load_config(path) → PadvConfig
│
├── orchestrator/
│   ├── pipeline.py              # Public API: analyze(), run_pipeline(), validate_candidates(),
│   │                            # export_bundle()
│   ├── graphs.py                # LangGraph definition. GraphState TypedDict. Stage node
│   │                            # functions: _node_init, _node_static_discovery,
│   │                            # _node_web_discovery, _node_auth_setup,
│   │                            # _node_candidate_synthesis, _node_skeptic_refine,
│   │                            # _node_objective_schedule, _node_frontier_update,
│   │                            # _node_validation_plan, _node_runtime_validate,
│   │                            # _node_dedup_topk, _node_persist
│   └── runtime.py               # validate_candidates_runtime(): builds plans, sends HTTP,
│                                # parses Morcilla headers, evaluates gates, creates bundles
│
├── discovery/
│   ├── __init__.py              # Re-exports: discover_source_candidates,
│   │                            # discover_scip_candidates_safe, discover_web_hints,
│   │                            # establish_auth_state, fuse_candidates
│   ├── source.py                # Pattern-based sink detection. Confidence: 0.45
│   ├── scip.py                  # SCIP symbol-based discovery. Confidence: 0.5
│   ├── web.py                   # Browser-use + Playwright LLM navigation. Extracts paths,
│   │                            # parameters, web_path_hints
│   └── fusion.py                # fuse_candidates(): dedup key = (vuln_class, file_path,
│                                # line, sink). Merges provenance, evidence_refs, intercepts,
│                                # preconditions. Re-numbers to cand-XXXXX
│
├── static/joern/
│   ├── adapter.py               # discover_candidates(): Joern CPG query + result parsing.
│   │                            # Confidence: 0.6
│   ├── query_sets.py            # VulnClassSpec definitions. 25+ vuln classes with sink
│   │                            # patterns, intercepts, OWASP IDs
│   └── queries/owasp_php.sc     # Joern query script
│
├── agents/
│   ├── proposer.py              # Simple ranking fallback
│   ├── skeptic.py               # Skeptic agent role (stub)
│   └── deepagents_harness.py    # DeepAgents integration:
│                                # - ensure_agent_session()
│                                # - rank_candidates_with_deepagents()
│                                # - skeptic_refine_with_deepagents()
│                                # - schedule_actions_with_deepagents()
│                                # - make_validation_plan_with_deepagents()
│                                # Fallbacks: _default_rank(), _default_plan()
│
├── gates/engine.py              # evaluate_candidate() → GateResult
│                                # Gates: V0 (scope), V1 (preconditions), V2 (multi-evidence),
│                                # V3 (boundary proof), V4 (negative control), V5 (repro),
│                                # V6 (final)
│                                # _HTTP_SIGNAL_RULES dict per vuln_class
│                                # _has_oracle_hit(): canary in intercepted call args
│
├── oracle/morcilla.py           # build_request_headers(), parse_response_headers(),
│                                # sanitized_runtime_evidence()
│                                # Request headers: key, intercept, correlation
│                                # Response headers: status, call_count, result, overflow,
│                                # arg_truncated, result_truncated, correlation
│
├── store/evidence_store.py      # EvidenceStore: save/load candidates, static_evidence,
│                                # bundles, runs, frontier_state, stage snapshots, artifacts
│
├── dynamic/
│   ├── http/runner.py           # HTTP client for validation requests (urllib-based)
│   └── sandbox/adapter.py       # Sandbox subprocess wrapper
│
├── eval/metrics.py              # Evaluation metrics
└── logging/structured.py        # JSON log formatter
```

### 2.2 Key Data Models (padv/models.py)

```python
@dataclass(slots=True)
class Candidate:
    candidate_id: str              # "cand-00001" format after fusion
    vuln_class: str                # e.g. "sql_injection_boundary"
    title: str
    file_path: str
    line: int
    sink: str                      # e.g. "mysqli_query"
    expected_intercepts: list[str] # functions Morcilla should intercept
    entrypoint_hint: str | None    # HTTP endpoint hint
    preconditions: list[str]       # unresolved → V1 gate blocks
    notes: str
    provenance: list[str]          # ["source", "joern", "scip", "web"]
    evidence_refs: list[str]
    confidence: float              # 0.0–1.0
    auth_requirements: list[str]
    web_path_hints: list[str]

@dataclass(slots=True)
class StaticEvidence:
    candidate_id: str
    query_profile: str             # "source", "joern", "scip"
    query_id: str
    file_path: str
    line: int
    snippet: str
    hash: str

@dataclass(slots=True)
class RuntimeEvidence:
    request_id: str
    status: str                    # "active", "inactive", "auth_failed", etc.
    call_count: int
    overflow: bool
    arg_truncated: bool
    result_truncated: bool
    correlation: str | None
    calls: list[RuntimeCall]
    raw_headers: dict[str, str]
    http_status: int | None
    body_excerpt: str
    location: str
    analysis_flags: list[str]      # ["xss_raw_canary", "debug_leak", etc.]
    aux: dict[str, Any]

@dataclass(slots=True)
class RuntimeCall:
    function: str                  # intercepted function name
    file: str                      # PHP file where call occurred
    line: int
    args: list[str]                # function arguments (may contain canary)

@dataclass(slots=True)
class GateResult:
    decision: str                  # "VALIDATED" | "DROPPED" | "NEEDS_HUMAN_SETUP"
    passed_gates: list[str]        # ["V0", "V1", ...]
    failed_gate: str | None        # "V3" or None
    reason: str

@dataclass(slots=True)
class ValidationPlan:
    candidate_id: str
    intercepts: list[str]
    positive_requests: list[dict[str, Any]]   # exactly 3 HTTP request specs
    negative_requests: list[dict[str, Any]]   # at least 1 control request
    canary: str
    strategy: str                  # "default"
    negative_control_strategy: str # "canary-mismatch"
    plan_notes: list[str]

@dataclass(slots=True)
class EvidenceBundle:
    bundle_id: str
    created_at: str
    candidate: Candidate
    static_evidence: list[StaticEvidence]
    positive_runtime: list[RuntimeEvidence]
    negative_runtime: list[RuntimeEvidence]
    repro_run_ids: list[str]
    gate_result: GateResult
    limitations: list[str]
    artifact_refs: list[str]
    discovery_trace: dict[str, Any]
    planner_trace: dict[str, Any]
```

### 2.3 Gate Engine Logic (padv/gates/engine.py)

The gate sequence is strictly ordered. Failure at any gate stops evaluation:

| Gate | Check | Pass Condition | Fail Result |
|------|-------|---------------|-------------|
| V0 | Scope/Safety | No status in {auth_failed, missing_key, missing_intercept, inactive, request_failed} | DROPPED |
| V1 | Preconditions | `preconditions` list is empty | NEEDS_HUMAN_SETUP |
| V2 | Multi-Evidence | Static evidence exists AND runtime evidence exists AND ≥2 distinct evidence signals | DROPPED |
| V3 | Boundary Proof | For vuln classes with HTTP signal rules: required flags present in positive runs. For others: canary found in intercepted call args for ALL positive runs | DROPPED |
| V4 | Negative Control | For enforce_negative_clean classes: negative runs must NOT have required flags. For canary classes: negative runs must NOT contain canary in args | DROPPED |
| V5 | Reproduction | ≥3 positive runs, ≥1 negative run. No overflow/truncation in any run | DROPPED |
| V6 | Final | All above passed | VALIDATED |

HTTP signal rules per vuln class (`_HTTP_SIGNAL_RULES`):

```python
"xss_output_boundary":       required_flags={"xss_raw_canary"},           enforce_negative_clean=True
"debug_output_leak":         required_flags={"debug_leak", "verbose_error_leak", "phpinfo_marker"}, enforce_negative_clean=False
"information_disclosure":    required_flags={"info_disclosure_header", "verbose_error_leak", "phpinfo_marker"}, enforce_negative_clean=False
"broken_access_control":     required_flags={"authz_bypass_status", "authz_pair_observed"}, enforce_negative_clean=False
"idor_invariant_missing":    required_flags={"idor_bypass", "authz_bypass_status", "authz_pair_observed"}, enforce_negative_clean=False
"csrf_invariant_missing":    required_flags={"csrf_missing_token_acceptance"}, enforce_negative_clean=False
"session_fixation_invariant": required_flags={"session_id_not_rotated", "session_cookie_not_rotated"}, enforce_negative_clean=False
"auth_and_session_failures": required_flags={"auth_bypass", "authz_bypass_status", "authz_pair_observed"}, enforce_negative_clean=False
```

### 2.4 Morcilla Header Contract (padv/oracle/morcilla.py)

**Request headers** (sent by padv):

| Header (config key) | Purpose |
|---------------------|---------|
| `request_key_header` | API key for Morcilla authentication |
| `request_intercept_header` | Comma-separated list of PHP functions to intercept |
| `request_correlation_header` | Unique correlation ID for request tracing |

**Response headers** (returned by Morcilla):

| Header (config key) | Purpose | Values |
|---------------------|---------|--------|
| `response_status_header` | Instrumentation status | "active", "inactive", "auth_failed", "missing_key", "missing_intercept" |
| `response_call_count_header` | Number of intercepted calls | Integer |
| `response_result_header` | Serialized call data | JSON or base64-encoded JSON |
| `response_overflow_header` | Call list was truncated | "1" or absent |
| `response_arg_truncated_header` | Arguments were truncated | "1" or absent |
| `response_result_truncated_header` | Result payload truncated | "1" or absent |
| `response_correlation_header` | Echo of request correlation | String |

### 2.5 Configuration Schema (padv/config/schema.py)

Key config sections and their dataclasses:

```python
PadvConfig:
    target: TargetConfig           # base_url, request_timeout_seconds
    oracle: OracleConfig           # all Morcilla header names + api_key + encoding
    canary: CanaryConfig           # parameter_name, allow_casefold, allow_url_decode
    budgets: BudgetConfig          # max_candidates, max_requests, max_seconds_per_candidate, max_run_seconds
    sandbox: SandboxConfig         # deploy_cmd, reset_cmd, status_cmd, logs_cmd
    store: StoreConfig             # root path, store_raw_reports flag
    auth: AuthConfig               # enabled, login_url, username, password, profile_path
    joern: JoernConfig             # enabled (must be true), query_profile, command, timeouts, http_api
    llm: LLMConfig                 # provider ("anthropic" only), model, api_key_env, temperature, max_tokens
    agent: AgentConfig             # use_deepagents (must be true), hard_fail (must be true),
                                   # require_langgraph (must be true), max_iterations,
                                   # improvement_patience, skeptic_rounds, thread_prefix
    scip: ScipConfig               # enabled (must be true), command, hard_fail (must be true)
    web: WebConfig                 # enabled (must be true), use_browser_use (must be true),
                                   # headless, max_pages, max_actions
```

**Strict switches** (cannot be disabled in config, enforced by loader):
- `agent.use_deepagents = true`
- `agent.require_langgraph = true`
- `agent.hard_fail = true`
- `joern.enabled = true`
- `scip.enabled = true`
- `scip.hard_fail = true`
- `web.enabled = true`
- `web.use_browser_use = true`

### 2.6 Fusion Logic (padv/discovery/fusion.py)

Deduplication key: `(vuln_class, file_path, line, sink)`.
On merge: provenance, evidence_refs, intercepts, preconditions, auth_requirements, web_path_hints are union-merged. Confidence takes max. Notes concatenated. IDs renumbered to `cand-XXXXX`.

### 2.7 Existing Test Files (tests/)

```
test_source_discovery.py       test_joern_adapter.py
test_scip_adapter.py           test_web_discovery.py
test_discovery_fusion.py       test_runtime_validation.py
test_gates.py                  test_phase1_runtime_gates.py
test_graph_orchestrator.py     test_oracle.py
test_deepagents_harness.py     test_config.py
test_path_scope.py             test_taxonomy_coverage.py
test_phpmyfaq_stack_config.py
```

### 2.8 Dependencies (pyproject.toml)

Runtime: `langgraph`, `deepagents`, `langchain-core`, `langchain-anthropic`, `browser-use`, `playwright`

### 2.9 Evidence Store Layout (.padv/)

```
.padv/
├── candidates.json
├── static_evidence.json
├── frontier_state.json
├── bundles/<bundle-id>.json
├── runs/<run-id>.json
├── runs/<run-id>/stages/<seq>-<stage>.json
├── artifacts/web-discovery-*.json
├── artifacts/auth-state-*.json
└── scip/                          # SCIP artifacts
```

---

## 3. Enhancement E1: LLM-Based Taint Specification Inference

### 3.1 Problem

padv's static discovery relies on predefined sink/source lists in `query_sets.py`. PHP applications using frameworks (Laravel, Symfony, WordPress) wrap standard sinks behind custom abstractions (ORM query builders, custom `exec` wrappers, framework-specific request getters). These custom wrappers are invisible to the current pattern lists.

### 3.2 Research Basis

- **IRIS** (arXiv 2405.17238): LLM infers taint specifications (source/sink/propagator) from function signatures. Detected 55 vulnerabilities vs CodeQL's 27.
- **STaint** (ASE 2025): LLM-assisted bi-directional taint analysis for PHP. Identifies custom DB-access functions, reconstructs taint flows through database roundtrips.
- **Artemis** (arXiv 2502.21026): LLM-assisted inter-procedural path-sensitive taint analysis for PHP SSRF detection.

### 3.3 Design

Add a new **pre-discovery stage** `taint_spec_inference` that runs before `static_discovery`. This stage:

1. Scans the target codebase for function/method definitions
2. Sends batched function signatures + context to the LLM
3. LLM classifies each as: `SOURCE`, `SINK`, `PROPAGATOR`, `SANITIZER`, or `NONE`
4. Results are materialized as a `TaintSpec` object
5. The `TaintSpec` is passed into source discovery, Joern, and SCIP as supplementary sink/source lists

### 3.4 New Files

```
padv/discovery/taint_spec.py     # TaintSpec inference engine
```

### 3.5 New Data Model

```python
# In padv/models.py

@dataclass(slots=True)
class TaintSpecEntry:
    """A single inferred taint specification."""
    function_name: str                # fully qualified: "App\\DB::rawQuery"
    classification: str               # "SOURCE" | "SINK" | "PROPAGATOR" | "SANITIZER"
    vuln_classes: list[str]           # applicable vuln classes, e.g. ["sql_injection_boundary"]
    confidence: float                 # 0.0–1.0 LLM confidence
    reasoning: str                    # LLM's reasoning (stored but never used for decisions)
    file_path: str                    # where the function is defined
    line: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

@dataclass(slots=True)
class TaintSpec:
    """Collection of inferred taint specifications for a target."""
    entries: list[TaintSpecEntry]
    inferred_at: str                  # ISO timestamp
    model_used: str                   # LLM model identifier
    target_file_count: int            # number of PHP files scanned

    def sinks_for_class(self, vuln_class: str) -> list[str]:
        """Return function names classified as SINKs for given vuln class."""
        return [e.function_name for e in self.entries
                if e.classification == "SINK" and vuln_class in e.vuln_classes]

    def sources(self) -> list[str]:
        """Return all function names classified as SOURCEs."""
        return [e.function_name for e in self.entries if e.classification == "SOURCE"]

    def sanitizers_for_class(self, vuln_class: str) -> list[str]:
        """Return function names classified as SANITIZERs for given vuln class."""
        return [e.function_name for e in self.entries
                if e.classification == "SANITIZER" and vuln_class in e.vuln_classes]

    def to_dict(self) -> dict[str, Any]:
        return {
            "entries": [e.to_dict() for e in self.entries],
            "inferred_at": self.inferred_at,
            "model_used": self.model_used,
            "target_file_count": self.target_file_count,
        }
```

### 3.6 Implementation in `padv/discovery/taint_spec.py`

```python
"""
LLM-based taint specification inference.

Scans PHP files in the target, extracts function/method definitions,
and uses the LLM to classify them as sources, sinks, propagators, or sanitizers.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Callable, Awaitable

from padv.config.schema import PadvConfig
from padv.models import TaintSpec, TaintSpecEntry, utc_now_iso
from padv.path_scope import is_in_scope


# Maximum number of function signatures per LLM batch call
BATCH_SIZE = 40

# Regex to extract PHP function/method definitions with context
_FUNC_DEF_RE = re.compile(
    r'(?:public|private|protected|static|\s)*function\s+(\w+)\s*\([^)]*\)',
    re.MULTILINE,
)


def _extract_function_signatures(repo_root: str, config: PadvConfig) -> list[dict[str, Any]]:
    """
    Walk PHP files, extract function definitions with surrounding context.

    Returns list of dicts with keys: function_name, file_path, line, context.
    Context includes 3 lines before and 12 lines after the function definition.
    """
    signatures: list[dict[str, Any]] = []
    root = Path(repo_root)
    for php_file in root.rglob("*.php"):
        rel = str(php_file.relative_to(root))
        if not is_in_scope(rel, config):
            continue
        try:
            content = php_file.read_text(errors="replace")
        except OSError:
            continue
        lines = content.splitlines()
        for match in _FUNC_DEF_RE.finditer(content):
            line_no = content[:match.start()].count('\n') + 1
            context_start = max(0, line_no - 3)
            context_end = min(len(lines), line_no + 12)
            context = '\n'.join(lines[context_start:context_end])
            signatures.append({
                "function_name": match.group(1),
                "file_path": rel,
                "line": line_no,
                "context": context,
            })
    return signatures


def _build_classification_prompt(batch: list[dict[str, Any]]) -> str:
    """Build the LLM prompt for a batch of function signatures."""
    entries = []
    for i, sig in enumerate(batch):
        entries.append(
            f"### Function {i+1}: {sig['function_name']}\n"
            f"File: {sig['file_path']}:{sig['line']}\n"
            f"```php\n{sig['context']}\n```"
        )

    functions_text = '\n\n'.join(entries)

    return f"""Analyze each PHP function below and classify it for security taint analysis.

For each function, determine:
1. Classification: SOURCE (reads user input), SINK (executes dangerous operation),
   PROPAGATOR (passes taint through), SANITIZER (cleans taint), or NONE
2. Applicable vulnerability classes (if SOURCE or SINK):
   sql_injection_boundary, command_injection_boundary, code_execution_boundary,
   xss_output_boundary, file_inclusion_boundary, file_operation_boundary,
   xxe_boundary, deserialization_boundary, ssrf_boundary, ldap_injection_boundary,
   xpath_injection_boundary, debug_output_leak, information_disclosure,
   broken_access_control, idor_invariant_missing, csrf_invariant_missing,
   session_fixation_invariant, auth_and_session_failures
3. Confidence (0.0-1.0)
4. Brief reasoning (one sentence)

Focus on: custom wrappers around standard PHP functions, ORM/query-builder methods,
framework request-input helpers, custom sanitization functions.

{functions_text}

Respond as a JSON array. Each element:
{{"index": 0, "classification": "SINK", "vuln_classes": ["sql_injection_boundary"], "confidence": 0.8, "reasoning": "Wraps mysqli_query with user input"}}

Only include functions classified as SOURCE, SINK, PROPAGATOR, or SANITIZER.
Omit functions classified as NONE."""


def _parse_llm_response(response: str) -> list[dict[str, Any]]:
    """Extract JSON array from LLM response, with fallback regex extraction."""
    try:
        return json.loads(response)
    except json.JSONDecodeError:
        pass
    match = re.search(r'\[.*\]', response, re.DOTALL)
    if match:
        try:
            return json.loads(match.group())
        except json.JSONDecodeError:
            pass
    return []


async def infer_taint_specs(
    repo_root: str,
    config: PadvConfig,
    llm_call: Callable[[str], Awaitable[str]],
) -> TaintSpec:
    """
    Main entry point. Scans target, infers taint specs via LLM.

    Args:
        repo_root: Path to target source code
        config: padv configuration
        llm_call: async callable that sends a prompt to the LLM and returns the response text

    Returns:
        TaintSpec with inferred entries
    """
    signatures = _extract_function_signatures(repo_root, config)
    min_confidence = config.taint_spec.min_confidence

    entries: list[TaintSpecEntry] = []

    for i in range(0, len(signatures), BATCH_SIZE):
        batch = signatures[i:i + BATCH_SIZE]
        prompt = _build_classification_prompt(batch)
        response = await llm_call(prompt)
        parsed = _parse_llm_response(response)

        for item in parsed:
            idx = item.get("index", -1)
            if idx < 0 or idx >= len(batch):
                continue
            sig = batch[idx]
            classification = item.get("classification", "").upper()
            if classification not in {"SOURCE", "SINK", "PROPAGATOR", "SANITIZER"}:
                continue
            conf = float(item.get("confidence", 0.5))
            if conf < min_confidence:
                continue
            entries.append(TaintSpecEntry(
                function_name=sig["function_name"],
                classification=classification,
                vuln_classes=item.get("vuln_classes", []),
                confidence=conf,
                reasoning=item.get("reasoning", ""),
                file_path=sig["file_path"],
                line=sig["line"],
            ))

    return TaintSpec(
        entries=entries,
        inferred_at=utc_now_iso(),
        model_used=config.llm.model,
        target_file_count=len(set(s["file_path"] for s in signatures)),
    )
```

### 3.7 Integration Points

1. **GraphState extension**: Add `taint_spec: TaintSpec | None` field to `GraphState` in `graphs.py`
2. **New stage node**: `_node_taint_spec_inference` inserted between `init` and `static_discovery`
3. **Source discovery**: `discover_source_candidates()` in `source.py` receives `taint_spec` parameter. Appends `taint_spec.sinks_for_class(vc)` to each `VulnClassSpec`'s sink patterns
4. **Joern discovery**: `discover_candidates()` in `adapter.py` receives `taint_spec`. Generates supplementary Joern queries for custom sinks
5. **Persistence**: `TaintSpec` saved as `artifacts/taint-spec-<run-id>.json`

### 3.8 Graph Flow Change

```
init → taint_spec_inference → static_discovery → web_discovery → ...
```

### 3.9 Config Extension

```toml
[taint_spec]
enabled = true
max_functions_per_batch = 40
min_confidence = 0.6          # only use specs above this confidence
```

### 3.10 Tests

New file: `tests/test_taint_spec.py`

- Test `_extract_function_signatures` on synthetic PHP files with various function styles
- Test `_build_classification_prompt` produces valid prompt format
- Test `_parse_llm_response` with valid JSON, embedded JSON in markdown, malformed input
- Test `TaintSpec.sinks_for_class()`, `.sources()`, `.sanitizers_for_class()`
- Test `min_confidence` filtering: entries below threshold excluded
- Integration test: mock LLM call returning known JSON → verify TaintSpec output matches expected entries
- Edge case: empty codebase, no PHP files, all functions classified as NONE

---

## 4. Enhancement E2: CPG-Slice → LLM Refinement Pipeline

### 4.1 Problem

DeepAgents currently receive full candidate context including raw file content. For large codebases, this wastes tokens and dilutes the LLM's focus. Much of the code is irrelevant to the vulnerability analysis.

### 4.2 Research Basis

- **LLMxCPG** (USENIX Security 2025): CPG-based slice construction reduces code by 67–91% while preserving vulnerability-relevant context.

### 4.3 Design

After Joern discovery, extract backward slices from identified sinks through the CPG. These slices (containing only the relevant data-flow and control-flow paths) become the input context for all DeepAgent operations.

### 4.4 New Files

```
padv/static/joern/slicer.py     # CPG backward slice extraction
```

### 4.5 New Data Model

```python
# In padv/models.py

@dataclass(slots=True)
class CodeSlice:
    """A minimal code slice extracted from the CPG."""
    candidate_id: str
    sink_function: str
    sink_file: str
    sink_line: int
    slice_lines: dict[str, list[int]]    # file_path → list of relevant line numbers
    slice_code: str                       # concatenated relevant code with file/line markers
    reduction_ratio: float               # 0.0–1.0, how much code was eliminated

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
```

### 4.6 Implementation Specification

```python
"""
CPG-based backward slicing for focused LLM context.

Given a candidate's sink location, extracts the minimal code slice
that captures the data-flow and control-flow leading to the sink.

Located in: padv/static/joern/slicer.py
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from padv.config.schema import PadvConfig
from padv.models import CodeSlice


async def extract_backward_slice(
    candidate_id: str,
    sink_file: str,
    sink_line: int,
    sink_function: str,
    repo_root: str,
    config: PadvConfig,
) -> CodeSlice:
    """
    Extract backward slice from CPG for a given sink.

    Uses Joern's `reachableByFlows` query to find all data-flow predecessors
    of the sink, then extracts the corresponding source code lines.

    Steps:
    1. Query Joern for backward data-flow slice from sink location
    2. Parse returned file:line pairs
    3. Read source files and extract only relevant lines (with ±2 context lines)
    4. Format as annotated code string with "// FILE: path:line" markers
    5. Compute reduction_ratio = 1 - (slice_lines / total_lines)

    Falls back to a conservative heuristic (extract the entire function body
    containing the sink) if Joern query fails or times out.

    Args:
        candidate_id: ID of the candidate this slice belongs to
        sink_file: relative path to the file containing the sink
        sink_line: line number of the sink call
        sink_function: name of the sink function
        repo_root: path to the target source root
        config: padv configuration (uses config.joern for Joern connection)

    Returns:
        CodeSlice with the minimal relevant code
    """
    ...


def _fallback_function_body(
    sink_file: str,
    sink_line: int,
    repo_root: str,
) -> tuple[str, dict[str, list[int]]]:
    """
    Fallback: extract the entire function body containing the sink line.

    Scans backward from sink_line for 'function' keyword,
    then forward until matching closing brace.

    Returns (code_string, {file_path: [line_numbers]}).
    """
    ...


def _format_slice_code(
    file_lines: dict[str, dict[int, str]],
) -> str:
    """
    Format extracted lines as annotated code string.

    Output format:
        // FILE: src/db.php
        // LINE 42
        $result = mysqli_query($conn, $query);
        // LINE 43
        return $result;
        // FILE: src/controller.php
        // LINE 15
        $query = "SELECT * FROM users WHERE id = " . $_GET['id'];
    """
    ...
```

### 4.7 Integration Points

1. **GraphState**: Add `code_slices: dict[str, CodeSlice]` field (keyed by candidate_id)
2. **After static_discovery**: Extract slices for all candidates with Joern-provenance
3. **DeepAgents harness**: `rank_candidates_with_deepagents`, `skeptic_refine_with_deepagents`, `make_validation_plan_with_deepagents` receive `slices` dict. Prompt construction replaces raw file reads with `slice.slice_code`
4. **Persistence**: Slices saved as `artifacts/code-slices-<run-id>.json`

### 4.8 Config Extension

```toml
[joern]
# Existing config...
slice_max_depth = 10              # max backward slice depth in CPG
slice_timeout_seconds = 30        # per-candidate slice extraction timeout
```

### 4.9 Tests

New file: `tests/test_joern_slicer.py`

- Test `_fallback_function_body` extracts correct function body
- Test `_format_slice_code` output format
- Test `extract_backward_slice` with mock Joern returning known data-flow paths
- Test fallback triggers when Joern is unavailable
- Test `reduction_ratio` calculation: known file sizes → expected ratio
- Test empty slice (sink not found in CPG)

---

## 5. Enhancement E3: State-Graph-Aware Web Discovery

### 5.1 Problem

Web discovery navigates the application via LLM-guided browser interaction, but without a model of application state. This means it can miss state-dependent paths (e.g., endpoints only reachable after specific configuration, multi-step workflows).

### 5.2 Research Basis

- **Enemy of the State** (USENIX Security 2012): Black-box state-machine inference for web apps. Detects internal state changes via output differencing, builds state graph, uses it to guide further exploration.

### 5.3 Design

Augment web discovery with an explicit state graph that tracks observed application states and transitions.

### 5.4 New Files

```
padv/discovery/web_state.py      # State graph inference and management
```

### 5.5 New Data Models

```python
# In padv/models.py

@dataclass(slots=True)
class WebState:
    """An observed application state."""
    state_id: str                    # "ws-00001"
    fingerprint: str                 # hash of observable indicators
    url: str                         # URL where state was observed
    cookies: dict[str, str]          # cookie names only (values redacted)
    dom_features: list[str]          # key DOM elements present (nav items, forms, etc.)
    discovered_at: str               # ISO timestamp

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

@dataclass(slots=True)
class StateTransition:
    """An observed state transition."""
    from_state: str                  # state_id
    to_state: str                    # state_id
    action: str                      # "GET /admin/config", "POST /login", etc.
    parameters: list[str]            # parameter names used in action

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

@dataclass(slots=True)
class WebStateGraph:
    """Application state graph built during web discovery."""
    states: list[WebState]
    transitions: list[StateTransition]
    unexplored_transitions: list[dict[str, Any]]  # {from_state, candidate_action, priority}

    def reachable_from(self, state_id: str) -> set[str]:
        """Return all state IDs reachable from given state via BFS."""
        visited: set[str] = set()
        queue = [state_id]
        while queue:
            current = queue.pop(0)
            if current in visited:
                continue
            visited.add(current)
            for t in self.transitions:
                if t.from_state == current and t.to_state not in visited:
                    queue.append(t.to_state)
        return visited

    def unexplored_ratio(self) -> float:
        """Fraction of candidate transitions not yet explored."""
        total = len(self.transitions) + len(self.unexplored_transitions)
        if total == 0:
            return 0.0
        return len(self.unexplored_transitions) / total

    def to_dict(self) -> dict[str, Any]:
        return {
            "states": [s.to_dict() for s in self.states],
            "transitions": [t.to_dict() for t in self.transitions],
            "unexplored_transitions": self.unexplored_transitions,
        }
```

### 5.6 Implementation Specification

```python
"""
State-graph-aware web discovery.

Extends browser-based web discovery with explicit state tracking.
The LLM navigator receives the current state graph as context
and prioritizes actions that explore unexplored state transitions.

Located in: padv/discovery/web_state.py
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

from padv.models import WebState, StateTransition, WebStateGraph, utc_now_iso


def compute_state_fingerprint(
    url: str,
    cookies: dict[str, str],
    dom_features: list[str],
) -> str:
    """
    Compute a fingerprint representing the current application state.

    Uses URL path (not query params), sorted cookie names (not values),
    and sorted DOM feature list to create a stable SHA-256 hash.

    This ensures:
    - Same page with different query params = same state
    - Same page with different cookie values = same state (session rotation)
    - Different navigation structure = different state
    """
    from urllib.parse import urlsplit
    path = urlsplit(url).path
    cookie_names = sorted(cookies.keys())
    features = sorted(dom_features)
    raw = json.dumps({"path": path, "cookies": cookie_names, "features": features}, sort_keys=True)
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def detect_state_change(
    previous: WebState | None,
    current_url: str,
    current_cookies: dict[str, str],
    current_dom_features: list[str],
) -> tuple[bool, str]:
    """
    Detect if the application state has changed.

    Returns (changed: bool, new_fingerprint: str).
    If previous is None, always returns (True, fingerprint).
    """
    fp = compute_state_fingerprint(current_url, current_cookies, current_dom_features)
    if previous is None:
        return True, fp
    return fp != previous.fingerprint, fp


def build_navigator_context(graph: WebStateGraph, current_state_id: str) -> str:
    """
    Build LLM context string from state graph for navigation decisions.

    Format:
        ## Current State: ws-00003 (URL: /admin/dashboard)
        ## Known States: 5
        ## Explored Transitions: 8
        ## Unexplored Transitions: 3 (priority-sorted)
          1. From ws-00003: try POST /admin/config (priority: 0.9)
          2. From ws-00003: try GET /admin/users (priority: 0.7)
          3. From ws-00001: try POST /api/export (priority: 0.5)
        ## Adjacent States from current:
          - ws-00002 via GET /admin/settings
          - ws-00004 via POST /admin/config
    """
    ...


def update_graph(
    graph: WebStateGraph,
    from_state: WebState,
    to_state: WebState,
    action: str,
    parameters: list[str],
) -> WebStateGraph:
    """
    Update state graph with a newly observed transition.

    Steps:
    1. Add to_state to graph.states if fingerprint is new
    2. Add StateTransition if this from→to+action combo is new
    3. Remove matching entry from unexplored_transitions
    4. Generate new unexplored candidates from to_state (e.g., forms, links)
    5. Return updated graph
    """
    ...
```

### 5.7 Integration Points

1. **`web.py` modification**: `discover_web_hints()` creates and maintains a `WebStateGraph` during navigation. After each browser action, call `detect_state_change()` and `update_graph()`
2. **LLM navigator prompt**: Include `build_navigator_context(graph, current_state)` in each navigation decision prompt sent to the LLM
3. **Frontier integration**: `WebStateGraph.unexplored_transitions` feeds into the frontier state, enabling cross-run state exploration. In `_node_frontier_update`, check `graph.unexplored_ratio()` to decide if more web exploration is needed
4. **Persistence**: Graph saved as `artifacts/web-state-graph-<run-id>.json`
5. **GraphState**: Add `web_state_graph: WebStateGraph | None` field

### 5.8 Config Extension

```toml
[web]
# Existing config...
state_graph_enabled = true
max_states = 50                   # limit state graph size
state_fingerprint_features = ["url_path", "cookie_names", "nav_elements", "form_elements"]
```

### 5.9 Tests

New file: `tests/test_web_state.py`

- Test `compute_state_fingerprint` produces stable hashes, differentiates states
- Test `detect_state_change` with same state, different state, no previous state
- Test `update_graph` adds states/transitions, removes unexplored, generates new candidates
- Test `build_navigator_context` output format is valid and informative
- Test `reachable_from` graph traversal with cycles
- Test `unexplored_ratio` with empty graph, fully explored, partially explored
- Test `max_states` limit: new states rejected when limit reached

---

## 6. Enhancement E4: Morcilla Input-to-State Feedback

### 6.1 Problem

Morcilla currently reports which intercepted functions were called and with what arguments. But it doesn't track *how* the input (canary) was transformed on its way to the sink — what conditions it passed through, what transformations were applied. This limits the ability to understand *why* validation fails.

### 6.2 Research Basis

- **REDQUEEN** (NDSS 2019): Input-to-state correspondence. Observes that input bytes appear directly (or after simple transforms) in comparison operands. "Colorization" technique: inject random bytes, detect them in comparisons to map input→state.
- **IJON** (S&P 2020): Human-annotated state variables as fuzzer feedback.

### 6.3 Design

Extend Morcilla's response protocol with **comparison operand reporting** and **canary transformation tracking**. padv parses these into a new `InputStateMap` that the validation planner uses to generate better payloads.

> **Note**: This enhancement requires changes to the Morcilla PHP extension (in `../morcilla`). This PRD specifies the padv-side contract and parsing; the Morcilla extension changes are a separate implementation task.

### 6.4 New Morcilla Response Headers

| New Header | Purpose | Format |
|------------|---------|--------|
| `X-Morcilla-Comparisons` | Comparison operands on intercepted path | base64-json: `[{"op": "==", "left": "...", "right": "...", "file": "...", "line": 42}]` |
| `X-Morcilla-Canary-Transforms` | Detected transformations of canary value | base64-json: `[{"original": "canary123", "transformed": "CANARY123", "transform": "strtoupper", "file": "...", "line": 10}]` |
| `X-Morcilla-Branch-Trace` | Branches taken on path to sink | base64-json: `[{"file": "...", "line": 15, "taken": true, "condition_snippet": "$role === 'admin'"}]` |

### 6.5 New Data Models

```python
# In padv/models.py

@dataclass(slots=True)
class ComparisonOperand:
    """A comparison observed during execution."""
    operator: str              # "==", "===", "!=", "<", etc.
    left: str                  # left operand value
    right: str                 # right operand value
    file: str
    line: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

@dataclass(slots=True)
class CanaryTransform:
    """A detected transformation of the canary value."""
    original: str
    transformed: str
    transform: str             # "strtoupper", "urlencode", "base64_encode", "trim", etc.
    file: str
    line: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

@dataclass(slots=True)
class BranchPoint:
    """A branch taken/not-taken on the execution path."""
    file: str
    line: int
    taken: bool
    condition_snippet: str     # e.g. "$role === 'admin'"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

@dataclass(slots=True)
class InputStateMap:
    """Aggregated input-to-state correspondence for a validation run."""
    comparisons: list[ComparisonOperand]
    canary_transforms: list[CanaryTransform]
    branch_trace: list[BranchPoint]

    def blocking_conditions(self) -> list[BranchPoint]:
        """Return branches that were NOT taken (potential blockers)."""
        return [b for b in self.branch_trace if not b.taken]

    def canary_was_transformed(self) -> bool:
        """Check if canary underwent any transformation."""
        return len(self.canary_transforms) > 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "comparisons": [c.to_dict() for c in self.comparisons],
            "canary_transforms": [t.to_dict() for t in self.canary_transforms],
            "branch_trace": [b.to_dict() for b in self.branch_trace],
        }
```

### 6.6 Extension to RuntimeEvidence

```python
# Modify existing RuntimeEvidence in padv/models.py — add field:

@dataclass(slots=True)
class RuntimeEvidence:
    # ... all existing fields unchanged ...
    input_state_map: InputStateMap | None = None   # NEW — parsed from Morcilla headers
```

### 6.7 Integration Points

1. **`oracle/morcilla.py`**: Extend `parse_response_headers()` to parse new headers into `InputStateMap`. Only parse if `config.oracle.enable_input_state` is True. Gracefully handle missing headers (return `None`).
2. **`RuntimeEvidence`**: Add `input_state_map` field (default `None`)
3. **Validation planner**: `make_validation_plan_with_deepagents()` receives `InputStateMap` from previous runs in the same candidate's validation cycle → generates payloads accounting for transformations and blocking conditions
4. **Gate engine**: `InputStateMap.blocking_conditions()` included in `GateResult.reason` when V3 fails, for diagnostic purposes only (does NOT change gate logic)
5. **Serialization**: `RuntimeEvidence.to_dict()` includes `input_state_map.to_dict()` if present

### 6.8 Config Extension

```toml
[oracle]
# Existing config...
comparison_header = "X-Morcilla-Comparisons"
canary_transform_header = "X-Morcilla-Canary-Transforms"
branch_trace_header = "X-Morcilla-Branch-Trace"
enable_input_state = true          # toggle for overhead-sensitive environments
```

### 6.9 Tests

New file: `tests/test_input_state.py`

- Test parsing of each new Morcilla header (base64-json format)
- Test `InputStateMap.blocking_conditions()` returns only not-taken branches
- Test `InputStateMap.canary_was_transformed()` with/without transforms
- Test `parse_response_headers()` integration: headers present → InputStateMap populated
- Test `parse_response_headers()` with missing new headers → `input_state_map = None`
- Test `enable_input_state = false` → new headers ignored even if present
- Test `RuntimeEvidence.to_dict()` serialization with and without InputStateMap

---

## 7. Enhancement E5: Morcilla-Guided Mutation Loop

### 7.1 Problem

The current validation creates exactly 3 positive requests and ≥1 negative request per candidate. If the initial plan doesn't hit the right code path, the candidate is dropped at V3 with no recovery.

### 7.2 Research Basis

- **REDQUEEN** (NDSS 2019): Input-to-state feedback guides mutations.
- **NEUZZ** (S&P 2019): Neural network approximation of branch behavior for gradient-guided mutations.
- **VUzzer**: Application-aware evolutionary fuzzing.

### 7.3 Design

Add an optional **mutation loop** within the `runtime_validate` stage. After the initial 3 positive requests, if V3 fails but Morcilla reports partial evidence (call_count > 0 but canary not in args), generate mutated requests based on Morcilla feedback and retry.

### 7.4 New Files

```
padv/orchestrator/mutations.py   # Mutation strategy engine
```

### 7.5 Implementation Specification

```python
"""
Mutation strategies for validation request refinement.

When initial validation requests partially succeed (intercept reached but
canary not found in sink args), this module generates mutated requests
based on Morcilla feedback to improve the chance of hitting the correct path.

Located in: padv/orchestrator/mutations.py
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from padv.models import RuntimeEvidence, InputStateMap, ValidationPlan


@dataclass(slots=True)
class MutationResult:
    """Result of a mutation attempt."""
    mutated_request: dict[str, Any]  # modified HTTP request spec (same schema as ValidationPlan.positive_requests elements)
    mutation_type: str               # "canary_transform" | "encoding" | "param_position" | "path_variation"
    reasoning: str                   # why this mutation was chosen (diagnostic only)


def should_mutate(
    positive_runs: list[RuntimeEvidence],
    canary: str,
    intercepts: list[str],
) -> bool:
    """
    Decide if mutation is worthwhile.

    Returns True if ALL of these conditions hold:
    1. At least one positive run has call_count > 0 (we reached relevant code)
    2. Canary was NOT found in any intercepted call args (close but not quite)
    3. No runs had status errors (auth_failed, missing_key, etc.)

    Returns False if:
    - call_count is 0 for all runs (completely wrong path, mutation won't help)
    - Canary was already found (mutation unnecessary)
    - Status errors present (infrastructure problem, not a mutation problem)
    """
    ...


def generate_mutations(
    plan: ValidationPlan,
    positive_runs: list[RuntimeEvidence],
    input_state_map: InputStateMap | None,
    max_mutations: int,
) -> list[MutationResult]:
    """
    Generate mutated requests based on Morcilla feedback.

    Mutation strategies (applied in priority order, each may produce 0-N mutations):

    1. **canary_transform** (requires InputStateMap with canary_transforms):
       If canary was transformed (e.g., strtoupper), pre-apply the inverse transform
       to the canary in the request. E.g., if strtoupper was detected, send lowercase canary
       so it matches after transformation.

    2. **encoding** (always applicable):
       Try URL-encoding, double URL-encoding, base64-encoding, and HTML-entity-encoding
       of the canary parameter value.

    3. **param_position** (always applicable):
       Move the canary to different parameter positions in the request.
       If originally in query string, try POST body and vice versa.
       If originally in one parameter, try other parameters from web_path_hints.

    4. **path_variation** (requires web_path_hints on the candidate):
       Try alternative URL paths from the candidate's web_path_hints that weren't
       used in the original plan.

    5. **blocking_condition** (requires InputStateMap with branch_trace):
       If branch trace shows an unmet condition (e.g., missing required parameter,
       wrong HTTP method), adjust the request to satisfy it.

    Total mutations capped at max_mutations.
    """
    ...
```

### 7.6 Integration into `padv/orchestrator/runtime.py`

Within `validate_candidates_runtime()`, after initial positive runs and gate evaluation:

```python
# Pseudocode for integration point in runtime.py

# After initial 3 positive requests and gate evaluation:
gate_result = evaluate_candidate(config, static_ev, positive_runs, negative_runs, ...)

if (gate_result.failed_gate == "V3"
    and config.mutation.enabled
    and should_mutate(positive_runs, canary, intercepts)):

    # Collect InputStateMap from positive runs (if available)
    input_state_maps = [r.input_state_map for r in positive_runs if r.input_state_map]
    combined_ism = _merge_input_state_maps(input_state_maps) if input_state_maps else None

    mutations = generate_mutations(
        plan, positive_runs, combined_ism, config.mutation.max_mutations_per_candidate
    )

    for mutation in mutations:
        # Check budget before each mutation request
        if _budget_exhausted(ctx, config):
            break

        run = _execute_single_request(mutation.mutated_request, config, oracle_headers, ...)
        positive_runs.append(run)

        # Re-evaluate gates with expanded evidence
        gate_result = evaluate_candidate(
            config, static_ev, positive_runs, negative_runs, ...
        )
        if gate_result.decision == "VALIDATED":
            break  # Success — no more mutations needed
```

**Important**: mutation requests consume from the existing `budgets.max_requests` and `budgets.max_seconds_per_candidate`. No separate mutation budget.

### 7.7 Config Extension

```toml
[mutation]
enabled = true
max_mutations_per_candidate = 5    # max additional requests from mutations
strategies = ["canary_transform", "encoding", "param_position", "path_variation"]
# Note: mutations consume from budgets.max_requests — no separate budget
```

### 7.8 Tests

New file: `tests/test_mutations.py`

- Test `should_mutate()`: returns True when call_count > 0 but no canary hit
- Test `should_mutate()`: returns False when call_count = 0 (wrong path entirely)
- Test `should_mutate()`: returns False when canary already found
- Test `generate_mutations()` with no InputStateMap → only encoding + param_position strategies
- Test `generate_mutations()` with InputStateMap containing canary transforms → canary_transform strategy first
- Test mutation count capped at `max_mutations`
- Test budget exhaustion stops mutation loop
- Test that `mutation.enabled = false` prevents mutation loop entirely
- Test re-evaluation of gates after successful mutation

---

## 8. Enhancement E6: Differential Validation for AuthZ Classes

### 8.1 Problem

For access-control vulnerabilities (IDOR, broken access control, authorization bypass), the current negative control (V4) uses a different canary. But the more meaningful test is: same request, different authentication context. If an unprivileged user gets the same response as a privileged user, that's a stronger signal.

### 8.2 Research Basis

- **NDI** (CCS 2022): Non-distinguishable inconsistencies as a deterministic oracle.
- **NEZHA**: Domain-independent differential testing.

### 8.3 Design

For vuln classes in `{"broken_access_control", "idor_invariant_missing", "auth_and_session_failures"}`, extend validation with **differential auth-context requests**: same endpoint, same parameters, but with different (or no) authentication.

### 8.4 New Files

```
padv/orchestrator/differential.py   # Differential validation engine
```

### 8.5 New Data Models

```python
# In padv/models.py

@dataclass(slots=True)
class DifferentialPair:
    """A pair of requests with different auth contexts for comparison."""
    privileged_run: RuntimeEvidence     # request with full auth
    unprivileged_run: RuntimeEvidence   # request with lower/no auth
    auth_diff: str                      # description: "admin_vs_anonymous", "user_vs_anonymous"
    response_equivalent: bool           # True if responses are functionally equivalent
    equivalence_signals: list[str]      # what made them equivalent: "same_http_status",
                                        # "same_body_length", "same_morcilla_calls"

    def to_dict(self) -> dict[str, Any]:
        return {
            "privileged_run": self.privileged_run.to_dict(),
            "unprivileged_run": self.unprivileged_run.to_dict(),
            "auth_diff": self.auth_diff,
            "response_equivalent": self.response_equivalent,
            "equivalence_signals": self.equivalence_signals,
        }
```

### 8.6 Extension to EvidenceBundle

```python
# Modify existing EvidenceBundle in padv/models.py — add field:

@dataclass(slots=True)
class EvidenceBundle:
    # ... all existing fields unchanged ...
    differential_pairs: list[DifferentialPair] = field(default_factory=list)  # NEW
```

Update `EvidenceBundle.to_dict()` to include `"differential_pairs": [dp.to_dict() for dp in self.differential_pairs]`.

### 8.7 Implementation Specification

```python
"""
Differential validation for authorization vulnerability classes.

For authz-related vuln classes, sends the same request with different
auth contexts and compares responses to detect authorization bypass.

Located in: padv/orchestrator/differential.py
"""
from __future__ import annotations

from typing import Any

from padv.config.schema import PadvConfig
from padv.models import RuntimeEvidence, DifferentialPair


AUTHZ_VULN_CLASSES = frozenset({
    "broken_access_control",
    "idor_invariant_missing",
    "auth_and_session_failures",
})


def needs_differential(vuln_class: str) -> bool:
    """Check if this vuln class benefits from differential validation."""
    return vuln_class in AUTHZ_VULN_CLASSES


def build_unprivileged_request(
    privileged_request: dict[str, Any],
    auth_state: dict[str, Any] | None,
) -> dict[str, Any]:
    """
    Create an unprivileged version of a privileged request.

    Steps:
    1. Deep-copy the privileged request
    2. Remove all authentication cookies (identified by names from auth_state)
    3. Remove Authorization header if present
    4. If auth_state provides a lower-privilege credential set, use that instead of stripping entirely
    5. Keep all other request parameters identical

    Returns the modified request dict.
    """
    ...


def compare_responses(
    privileged: RuntimeEvidence,
    unprivileged: RuntimeEvidence,
    config: PadvConfig,
) -> DifferentialPair:
    """
    Compare privileged and unprivileged responses.

    Equivalence criteria (ALL must hold for response_equivalent=True):
    1. Same HTTP status code
    2. Same Morcilla call count (same code path executed)
    3. Body length within tolerance (config.differential.body_length_tolerance, default 10%)

    Each criterion that matches is added to equivalence_signals.
    """
    signals: list[str] = []

    # 1. HTTP status comparison
    if privileged.http_status == unprivileged.http_status:
        signals.append("same_http_status")

    # 2. Morcilla call count comparison
    if privileged.call_count == unprivileged.call_count:
        signals.append("same_morcilla_calls")

    # 3. Body length comparison
    priv_len = len(privileged.body_excerpt)
    unpriv_len = len(unprivileged.body_excerpt)
    if priv_len > 0:
        tolerance = config.differential.body_length_tolerance
        ratio = abs(priv_len - unpriv_len) / priv_len
        if ratio <= tolerance:
            signals.append("same_body_length")

    # Equivalent if all three criteria match
    response_equivalent = len(signals) >= 3

    return DifferentialPair(
        privileged_run=privileged,
        unprivileged_run=unprivileged,
        auth_diff=_determine_auth_diff(privileged, unprivileged),
        response_equivalent=response_equivalent,
        equivalence_signals=signals,
    )


def _determine_auth_diff(priv: RuntimeEvidence, unpriv: RuntimeEvidence) -> str:
    """Determine the auth difference description."""
    # Check if unprivileged had any auth cookies
    # Return "admin_vs_anonymous" or "authenticated_vs_anonymous" etc.
    ...
```

### 8.8 Gate Engine Extension

In `padv/gates/engine.py`, extend `evaluate_candidate()` to accept and use differential pairs:

```python
def evaluate_candidate(
    config: PadvConfig,
    static_evidence: list[StaticEvidence],
    positive_runs: list[RuntimeEvidence],
    negative_runs: list[RuntimeEvidence],
    intercepts: list[str],
    canary: str,
    preconditions: list[str],
    evidence_signals: list[str] | None = None,
    vuln_class: str | None = None,
    differential_pairs: list[DifferentialPair] | None = None,  # NEW parameter
) -> GateResult:
```

For AuthZ vuln classes, differential pairs provide **additional V3 evidence**:

```python
# Within V3 evaluation for authz classes:
# If standard required_flags are missing BUT differential pair shows equivalence,
# add "authz_bypass_status" and "authz_pair_observed" to the positive flags.
# This allows differential evidence to satisfy V3.
if rule is not None and class_key in AUTHZ_VULN_CLASSES:
    if differential_pairs:
        has_bypass = any(dp.response_equivalent for dp in differential_pairs)
        if has_bypass:
            positive_flags.add("authz_bypass_status")
            positive_flags.add("authz_pair_observed")
```

This does NOT bypass gates — it adds evidence that satisfies the existing required_flags.

### 8.9 Integration into runtime.py

Within `validate_candidates_runtime()`, after positive runs:

```python
if needs_differential(candidate.vuln_class) and config.differential.enabled:
    # Pick one positive request as the base
    base_request = plan.positive_requests[0]
    unpriv_request = build_unprivileged_request(base_request, state.get("auth_state"))
    unpriv_run = _execute_single_request(unpriv_request, config, oracle_headers, ...)
    priv_run = positive_runs[0]
    dp = compare_responses(priv_run, unpriv_run, config)
    differential_pairs.append(dp)
```

### 8.10 Config Extension

```toml
[differential]
enabled = true
auth_levels = ["anonymous"]        # which lower-privilege levels to test
body_length_tolerance = 0.10       # 10% tolerance for body length comparison
```

### 8.11 Tests

New file: `tests/test_differential.py`

- Test `needs_differential()` returns True for AuthZ classes, False for XSS, SQLi, etc.
- Test `build_unprivileged_request()` strips auth cookies and headers correctly
- Test `build_unprivileged_request()` with lower-privilege credentials from auth_state
- Test `compare_responses()` with equivalent responses → `response_equivalent=True`
- Test `compare_responses()` with different HTTP status → not equivalent
- Test `compare_responses()` with different body length beyond tolerance → not equivalent
- Test gate engine with differential pairs: bypass detected → V3 passes for authz classes
- Test gate engine: differential pairs have NO effect on non-authz vuln classes
- Test that differential requests consume from existing budget

---

## 9. Enhancement E7: Failure-Pattern Learning

### 9.1 Problem

padv persists all run data but doesn't systematically learn from failures. The same types of candidates may be repeatedly generated and fail at the same gates across runs.

### 9.2 Research Basis

- **MoonShine**: Trace-based seed selection optimization.
- **Covrig**: Code/test/coverage evolution analysis.

### 9.3 Design

Add a **failure analytics layer** that:
1. Analyzes historical runs to extract failure patterns
2. Feeds these patterns into the skeptic agent for early filtering
3. Provides a CLI command for human inspection

### 9.4 New Files

```
padv/analytics/__init__.py           # Package init
padv/analytics/failure_patterns.py   # Pattern extraction and analysis
```

### 9.5 New Data Models

```python
# In padv/models.py

@dataclass(slots=True)
class FailurePattern:
    """A recurring failure pattern across runs."""
    pattern_id: str                              # "fp-001"
    vuln_class: str
    failed_gate: str                             # "V0", "V2", "V3", etc.
    failure_reason: str                          # gate reason string
    occurrence_count: int                        # how many times seen
    example_candidate_ids: list[str]             # up to 5 examples
    provenance_correlation: dict[str, float]     # {"source": 0.8, "joern": 0.2}
    confidence_range: tuple[float, float]        # (min, max) of failed candidates
    suggestion: str                              # actionable human-readable suggestion

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

@dataclass(slots=True)
class FailureAnalysis:
    """Aggregated failure analysis across all historical runs."""
    analyzed_at: str
    total_runs_analyzed: int
    total_candidates_analyzed: int
    total_failures: int
    patterns: list[FailurePattern]
    gate_failure_distribution: dict[str, int]    # {"V0": 5, "V2": 12, "V3": 45, ...}

    def to_dict(self) -> dict[str, Any]:
        return {
            "analyzed_at": self.analyzed_at,
            "total_runs_analyzed": self.total_runs_analyzed,
            "total_candidates_analyzed": self.total_candidates_analyzed,
            "total_failures": self.total_failures,
            "patterns": [p.to_dict() for p in self.patterns],
            "gate_failure_distribution": self.gate_failure_distribution,
        }
```

### 9.6 Implementation Specification

```python
"""
Failure pattern extraction and analysis.

Scans historical bundles for recurring failure patterns,
providing actionable insights for candidate filtering.

Located in: padv/analytics/failure_patterns.py
"""
from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any

from padv.models import FailureAnalysis, FailurePattern, utc_now_iso
from padv.store.evidence_store import EvidenceStore


def analyze_failures(store: EvidenceStore, min_occurrences: int = 3) -> FailureAnalysis:
    """
    Analyze all historical bundles for failure patterns.

    Algorithm:
    1. Load all bundles from store
    2. Separate into VALIDATED vs DROPPED/NEEDS_HUMAN_SETUP
    3. Group failures by (vuln_class, failed_gate)
    4. For each group with ≥ min_occurrences:
       a. Count occurrences
       b. Collect up to 5 example candidate IDs
       c. Compute provenance correlation: fraction of failed candidates from each discovery source
       d. Compute confidence range (min, max)
       e. Generate suggestion based on pattern:
          - High V0 failure rate → infrastructure/setup problem
          - High V2 failure rate → discovery producing low-evidence candidates
          - High V3 failure rate for specific vuln_class+provenance → that source unreliable for that class
          - High V4 failure rate → negative control too sensitive
    5. Compute gate_failure_distribution across all failures
    6. Sort patterns by occurrence_count descending

    Args:
        store: EvidenceStore to read bundles from
        min_occurrences: minimum occurrences to create a pattern (default 3)

    Returns:
        FailureAnalysis with patterns and distribution
    """
    ...


def failure_penalty(
    candidate_vuln_class: str,
    candidate_provenance: list[str],
    candidate_confidence: float,
    patterns: list[FailurePattern],
) -> float:
    """
    Compute a penalty score [0.0, 1.0] based on historical failure patterns.

    High penalty = this candidate looks like historically failing candidates.

    Scoring:
    - For each matching pattern (same vuln_class):
      - base_score = min(1.0, occurrence_count / 20)  # more occurrences = higher base
      - provenance_match = average of pattern.provenance_correlation values
        for provenances present in candidate_provenance
      - confidence_match = 1.0 if candidate_confidence is within pattern.confidence_range, else 0.5
      - pattern_score = base_score * 0.5 + provenance_match * 0.3 + confidence_match * 0.2
    - Final penalty = max of all pattern_scores (worst matching pattern dominates)

    Returns 0.0 if no patterns match.
    """
    ...


def format_analysis_table(analysis: FailureAnalysis) -> str:
    """
    Format FailureAnalysis as a human-readable table string.

    Output format:
        Gate Failure Distribution:
          V0 (scope):           5  (  4%)
          V2 (multi-evidence): 12  ( 10%)
          V3 (boundary proof): 78  ( 65%)
          ...

        Top Failure Patterns:
          #1  xss_output_boundary @ V3 (47 occurrences)
              Source: 82% source, 18% joern
              Confidence: 0.35–0.55
              → Suggestion: ...
    """
    ...
```

### 9.7 Integration Points

1. **CLI**: Add `padv analyze-failures` command to `cli/main.py`:
   ```
   padv analyze-failures [--min-occurrences 3] [--format json|table]
   ```
2. **GraphState**: Add `failure_analysis: FailureAnalysis | None` field, loaded during `_node_init` by calling `analyze_failures(store)`
3. **Skeptic agent**: `skeptic_refine_with_deepagents()` receives `failure_analysis`. Include `failure_penalty()` scores in the skeptic's context. Candidates with penalty > 0.7 are flagged as "historically fragile" in the skeptic prompt
4. **Persistence**: `FailureAnalysis` saved as `artifacts/failure-analysis-<run-id>.json`
5. **No gate changes**: Failure patterns inform the skeptic (soft filter) but never affect gate decisions (hard filter)

### 9.8 Tests

New file: `tests/test_failure_patterns.py`

- Test `analyze_failures()` with mock store containing mixed VALIDATED/DROPPED bundles
- Test pattern extraction groups correctly by (vuln_class, failed_gate)
- Test `min_occurrences` threshold: groups below threshold excluded
- Test provenance correlation calculation
- Test confidence range calculation
- Test `failure_penalty()` scoring with matching and non-matching patterns
- Test `failure_penalty()` returns 0.0 with empty patterns list
- Test `format_analysis_table()` output format
- Test with empty store (no bundles) → empty analysis, no error

---

## 10. Implementation Order & Dependencies

### 10.1 Dependency Graph

```
E7 (Failure Patterns)        ← no dependencies, pure analysis layer
E6 (Differential Validation) ← uses existing auth_state
E5 (Mutation Loop)           ← standalone; benefits from E4 but works without it
E1 (Taint Spec Inference)    ← no dependencies
E2 (CPG Slicing)             ← depends on Joern being available
E4 (Input-to-State)          ← depends on Morcilla PHP extension changes (external)
E3 (State Graph)             ← depends on existing web discovery infrastructure
```

### 10.2 Recommended Implementation Phases

**Phase 1 — Quick Wins (no external dependencies, low risk):**

| Order | Enhancement | Effort | New Files | Modified Files |
|-------|-----------|--------|-----------|----------------|
| 1.1 | E7: Failure Patterns | Low | `analytics/__init__.py`, `analytics/failure_patterns.py`, `tests/test_failure_patterns.py` | `models.py`, `cli/main.py`, `graphs.py` |
| 1.2 | E6: Differential Validation | Low | `orchestrator/differential.py`, `tests/test_differential.py` | `models.py`, `runtime.py`, `gates/engine.py`, `config/schema.py` |
| 1.3 | E5: Mutation Loop | Low–Med | `orchestrator/mutations.py`, `tests/test_mutations.py` | `runtime.py`, `config/schema.py` |

**Phase 2 — Discovery Enhancement (moderate complexity):**

| Order | Enhancement | Effort | New Files | Modified Files |
|-------|-----------|--------|-----------|----------------|
| 2.1 | E1: Taint Spec Inference | Medium | `discovery/taint_spec.py`, `tests/test_taint_spec.py` | `models.py`, `graphs.py`, `source.py`, `config/schema.py` |
| 2.2 | E2: CPG Slicing | Medium | `static/joern/slicer.py`, `tests/test_joern_slicer.py` | `deepagents_harness.py`, `config/schema.py` |

**Phase 3 — Deep Integration (requires external changes or high complexity):**

| Order | Enhancement | Effort | New Files | Modified Files |
|-------|-----------|--------|-----------|----------------|
| 3.1 | E4: Input-to-State | Med–High | `tests/test_input_state.py` | `models.py`, `oracle/morcilla.py`, `runtime.py`, `config/schema.py` |
| 3.2 | E3: State Graph | High | `discovery/web_state.py`, `tests/test_web_state.py` | `web.py`, `graphs.py`, `models.py`, `config/schema.py` |

### 10.3 Per-Enhancement Implementation Checklist

For **each** enhancement, the implementing agent MUST:

1. [ ] Add new data models to `padv/models.py` with `@dataclass(slots=True)` and `to_dict()` methods
2. [ ] Add new config dataclass(es) to `padv/config/schema.py` with safe defaults
3. [ ] Update `load_config()` to parse new sections — must not fail if section is absent
4. [ ] Implement core logic in the specified new file(s)
5. [ ] Integrate into orchestrator (`graphs.py` and/or `runtime.py`) at the specified insertion points
6. [ ] Add persistence via `EvidenceStore` where specified (save as artifacts)
7. [ ] Write unit tests with mock data (no live LLM, no live Morcilla, no network)
8. [ ] Run `pytest tests/ -v` and verify ALL existing tests still pass
9. [ ] Update `padv.example.toml` with new config options (commented with defaults)
10. [ ] Ensure new stages write snapshots to `runs/<run-id>/stages/`
11. [ ] Verify no new runtime dependencies are required (or document if they are)

---

## 11. Configuration Schema Extensions

Complete summary of all new config sections and fields:

```toml
# ============================================================
# padv.toml — Enhancement Additions
# All sections below are OPTIONAL and have safe defaults.
# Existing padv.toml files continue to work without changes.
# ============================================================

# --- E1: LLM-Based Taint Specification Inference ---
[taint_spec]
enabled = true                            # set false to skip taint spec inference
max_functions_per_batch = 40              # functions sent per LLM call
min_confidence = 0.6                      # discard specs below this threshold

# --- E2: CPG Slicing (additions to existing [joern] section) ---
# [joern]
# slice_max_depth = 10                    # max CPG backward slice depth
# slice_timeout_seconds = 30              # per-candidate timeout for slice extraction

# --- E3: State Graph (additions to existing [web] section) ---
# [web]
# state_graph_enabled = true              # enable state-graph-aware navigation
# max_states = 50                         # cap on state graph size

# --- E4: Input-to-State (additions to existing [oracle] section) ---
# [oracle]
# comparison_header = "X-Morcilla-Comparisons"
# canary_transform_header = "X-Morcilla-Canary-Transforms"
# branch_trace_header = "X-Morcilla-Branch-Trace"
# enable_input_state = true               # parse extended Morcilla headers

# --- E5: Mutation Loop ---
[mutation]
enabled = true                            # enable mutation loop on V3 failure
max_mutations_per_candidate = 5           # max additional requests per candidate
strategies = ["canary_transform", "encoding", "param_position", "path_variation"]

# --- E6: Differential Validation ---
[differential]
enabled = true                            # enable differential auth-context testing
auth_levels = ["anonymous"]               # privilege levels to test against
body_length_tolerance = 0.10              # body length comparison tolerance (10%)
```

**Backward Compatibility Rule**: The `load_config()` function MUST handle missing sections by applying defaults. New config dataclasses should be constructed with defaults when the TOML section is absent:

```python
# Pattern for handling optional new config sections in load_config():
taint_spec_section = data.get("taint_spec", {})
if not isinstance(taint_spec_section, dict):
    taint_spec_section = {}

# Construct with defaults
taint_spec_config = TaintSpecConfig(
    enabled=_get_optional_bool(taint_spec_section, "enabled", True),
    max_functions_per_batch=_get_optional_int(taint_spec_section, "max_functions_per_batch", 40, min_value=1),
    min_confidence=_get_optional_float(taint_spec_section, "min_confidence", 0.6, min_value=0.0),
)
```

---

## 12. Data Model Extensions

### 12.1 New Dataclasses (all in padv/models.py unless noted)

| Dataclass | Enhancement | Fields |
|-----------|-------------|--------|
| `TaintSpecEntry` | E1 | function_name, classification, vuln_classes, confidence, reasoning, file_path, line |
| `TaintSpec` | E1 | entries, inferred_at, model_used, target_file_count |
| `CodeSlice` | E2 | candidate_id, sink_function, sink_file, sink_line, slice_lines, slice_code, reduction_ratio |
| `WebState` | E3 | state_id, fingerprint, url, cookies, dom_features, discovered_at |
| `StateTransition` | E3 | from_state, to_state, action, parameters |
| `WebStateGraph` | E3 | states, transitions, unexplored_transitions |
| `ComparisonOperand` | E4 | operator, left, right, file, line |
| `CanaryTransform` | E4 | original, transformed, transform, file, line |
| `BranchPoint` | E4 | file, line, taken, condition_snippet |
| `InputStateMap` | E4 | comparisons, canary_transforms, branch_trace |
| `MutationResult` | E5 | mutated_request, mutation_type, reasoning *(in orchestrator/mutations.py)* |
| `DifferentialPair` | E6 | privileged_run, unprivileged_run, auth_diff, response_equivalent, equivalence_signals |
| `FailurePattern` | E7 | pattern_id, vuln_class, failed_gate, failure_reason, occurrence_count, example_candidate_ids, provenance_correlation, confidence_range, suggestion |
| `FailureAnalysis` | E7 | analyzed_at, total_runs_analyzed, total_candidates_analyzed, total_failures, patterns, gate_failure_distribution |

### 12.2 Modified Dataclasses

| Dataclass | Change | Enhancement |
|-----------|--------|-------------|
| `RuntimeEvidence` | Add `input_state_map: InputStateMap \| None = None` | E4 |
| `EvidenceBundle` | Add `differential_pairs: list[DifferentialPair] = field(default_factory=list)` | E6 |

### 12.3 New Config Dataclasses (in padv/config/schema.py)

| Dataclass | Enhancement | Fields |
|-----------|-------------|--------|
| `TaintSpecConfig` | E1 | enabled, max_functions_per_batch, min_confidence |
| `MutationConfig` | E5 | enabled, max_mutations_per_candidate, strategies |
| `DifferentialConfig` | E6 | enabled, auth_levels, body_length_tolerance |

Add these as fields on `PadvConfig`:

```python
@dataclass(slots=True)
class PadvConfig:
    # ... existing fields ...
    taint_spec: TaintSpecConfig        # E1
    mutation: MutationConfig           # E5
    differential: DifferentialConfig   # E6
```

E2, E3, E4 extend existing config dataclasses (JoernConfig, WebConfig, OracleConfig) with new optional fields.

### 12.4 GraphState Extensions (in padv/orchestrator/graphs.py)

| Field | Type | Enhancement |
|-------|------|-------------|
| `taint_spec` | `TaintSpec \| None` | E1 |
| `code_slices` | `dict[str, CodeSlice]` | E2 |
| `web_state_graph` | `WebStateGraph \| None` | E3 |
| `failure_analysis` | `FailureAnalysis \| None` | E7 |

---

## 13. Test Strategy

### 13.1 Test Principles

1. **Every new module gets a dedicated test file** in `tests/`
2. **Mock all external dependencies**: LLM calls, Joern queries, Morcilla headers, filesystem I/O, HTTP requests
3. **Gate invariants preserved**: Run existing `test_gates.py` after every enhancement
4. **Backward compatibility**: Test that existing configs without new sections still load via `test_config.py`
5. **No network access in tests**: All HTTP, LLM, and Morcilla interactions must be mocked

### 13.2 New Test Files

| File | Enhancement | Key Test Cases |
|------|-------------|---------------|
| `tests/test_taint_spec.py` | E1 | Signature extraction, prompt building, LLM response parsing, TaintSpec API, min_confidence filter |
| `tests/test_joern_slicer.py` | E2 | Slice extraction, fallback heuristic, reduction ratio, format |
| `tests/test_web_state.py` | E3 | Fingerprinting, state detection, graph operations, navigator context |
| `tests/test_input_state.py` | E4 | Header parsing, blocking conditions, canary transforms, enable toggle |
| `tests/test_mutations.py` | E5 | should_mutate logic, mutation generation, budget cap, strategy selection |
| `tests/test_differential.py` | E6 | Request stripping, response comparison, gate integration, non-authz classes |
| `tests/test_failure_patterns.py` | E7 | Pattern extraction, penalty scoring, table formatting, empty store |

### 13.3 Regression Verification

After implementing each enhancement, run the full test suite:

```bash
pytest tests/ -v --tb=short
```

All pre-existing tests MUST pass. Any test failure must be investigated and fixed before proceeding to the next enhancement.

---

## 14. Invariants & Constraints

### 14.1 Inviolable Invariants

These MUST hold after implementing any or all enhancements:

1. **Gate determinism**: Given the same `static_evidence`, `positive_runs`, `negative_runs`, `intercepts`, `canary`, `preconditions`, `evidence_signals`, `vuln_class`, and `differential_pairs`, the function `evaluate_candidate()` MUST return the same `GateResult`. No LLM output, randomness, or timestamps in the decision path.

2. **Evidence traceability**: Every `VALIDATED` decision MUST trace back to concrete `StaticEvidence` + `RuntimeEvidence`. New evidence types (`InputStateMap`, `DifferentialPair`) are supplementary — they may enable validation by providing additional signals, but they do not bypass gate requirements.

3. **Budget enforcement**: Total requests per run MUST NOT exceed `budgets.max_requests`. Per-candidate time MUST NOT exceed `budgets.max_seconds_per_candidate`. Mutation requests (E5) and differential requests (E6) consume from these existing budgets.

4. **Backward compatibility**: Existing `padv.toml` files without new config sections MUST load without error. All new config sections default to safe/enabled values.

5. **Morcilla contract stability**: Existing Morcilla request/response headers MUST work unchanged. New headers (E4) are strictly additive. Absence of new headers MUST NOT cause errors.

6. **No false promotions**: No enhancement may cause a candidate to be `VALIDATED` that would have been `DROPPED` given the exact same `StaticEvidence` + `RuntimeEvidence` under the original gate logic. New evidence types may produce *additional* signals that satisfy existing gate requirements, but they cannot *remove* requirements.

7. **Snapshot integrity**: Every stage that modifies `GraphState` MUST write a snapshot to `runs/<run-id>/stages/<seq>-<stage>.json`. New stages (`taint_spec_inference`) follow this pattern.

8. **Reproducibility**: Given the same target codebase, config, and Morcilla responses, `padv run` MUST produce the same `GateResult` decisions. LLM-driven stages (ranking, planning) may vary, but gate outcomes are deterministic given their inputs.

### 14.2 Implementation Constraints

1. **Python ≥3.11** required (uses `tomllib`, `@dataclass(slots=True)`)
2. **All new dataclasses** use `@dataclass(slots=True)` and implement `to_dict() -> dict[str, Any]`
3. **All new config fields** have explicit defaults in the schema loader
4. **Async convention**: Discovery and agent functions use `async def`. Gate evaluation and store operations are synchronous.
5. **Error handling**: Follow existing pattern — errors in non-critical enhancements log warnings and continue. If `hard_fail` is set in config, errors raise and abort.
6. **No new runtime dependencies** unless documented and justified. The existing dependency set (`langgraph`, `deepagents`, `langchain-core`, `langchain-anthropic`, `browser-use`, `playwright`) must suffice.
7. **Naming conventions**: New files follow existing snake_case naming. New classes follow existing PascalCase naming. New config keys follow existing snake_case TOML convention.
8. **Type annotations**: All function signatures fully typed. Use `from __future__ import annotations` at module top.

---

*End of PRD — Enhancement Suite v1.0*

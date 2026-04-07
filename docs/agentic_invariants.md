# Agentic Invariants

## Agentic Discovery vs Deterministic Validation
PADV splits the workflow into an agent-driven discovery phase and a deterministic validation plane.
- **Agentic Discovery:** LLMs are used to intelligently mine candidates, reason about hypotheses, plan requests, and write payloads. This phase is unbounded and creative.
- **Deterministic Validation:** The runtime gates and the evaluation of outcomes are strictly typed and deterministic. Decisions are never based on LLM outputs or unstructured text.

## LLM Scope
**Where LLM is allowed to reason (candidate mining/planning):**
- Candidate generation and selection from static and dynamic analysis.
- Generating HTTP request shapes, mutations, and payloads.
- Resolving preconditions needed to reproduce vulnerabilities.

**Where LLM is forbidden (gates/outcomes/coverage):**
- Determining if a test was successful (e.g. "Did this look like a login?").
- Analyzing response bodies with unstructured string matching to determine auth or access control status.
- Interpreting success or failure coverage purely via heuristic keywords or `.lower()` matching.

All trust-plane logic must be grounded in exact matching (e.g., typed oracle reports via Morcilla/Zend headers) and explicit contracts.
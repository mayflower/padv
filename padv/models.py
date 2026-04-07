from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

from padv.identity import candidate_uid_for_fields
from padv.validation.preconditions import GatePreconditions, coerce_gate_preconditions


CandidateStatus = str
GateDecision = str

_EXPLICIT_CANDIDATE_OUTCOME_KEYS = (
    "VALIDATED",
    "REFUTED",
    "SKIPPED_BUDGET",
    "SKIPPED_PRECONDITION",
    "ERROR",
)


def explicit_candidate_outcome_for_decision(decision: str) -> str:
    normalized = str(decision or "").strip()
    if normalized in {"VALIDATED", "CONFIRMED_ANALYSIS_FINDING"}:
        return "VALIDATED"
    if normalized == "DROPPED":
        return "REFUTED"
    if normalized == "SKIPPED_BUDGET":
        return "SKIPPED_BUDGET"
    if normalized == "NEEDS_HUMAN_SETUP":
        return "SKIPPED_PRECONDITION"
    return "ERROR"


def default_candidate_outcomes() -> dict[str, int]:
    return dict.fromkeys(_EXPLICIT_CANDIDATE_OUTCOME_KEYS, 0)


def count_candidate_outcomes(bundles: list[Any]) -> dict[str, int]:
    counts = default_candidate_outcomes()
    for bundle in bundles:
        explicit = str(getattr(bundle, "candidate_outcome", "")).strip()
        if not explicit:
            gate = getattr(bundle, "gate_result", None)
            explicit = explicit_candidate_outcome_for_decision(str(getattr(gate, "decision", "")))
        counts[explicit] = counts.get(explicit, 0) + 1
    return counts


@dataclass(slots=True)
class AuthBoundaryContract:
    unauth_status_codes: list[int]
    unauth_redirect_patterns: list[str]
    expected_session_cookies: list[str]
    csrf_token_name: str | None = None

@dataclass(slots=True)
class CandidateSeed:
    seed_id: str
    vuln_class: str
    file_path: str
    symbol: str
    why: str
    requested_static_checks: list[str]
    entrypoint_hint: str | None = None

@dataclass(slots=True)
class Candidate:
    candidate_id: str
    vuln_class: str
    title: str
    file_path: str
    line: int
    sink: str
    expected_intercepts: list[str]
    entrypoint_hint: str | None = None
    preconditions: list[str] = field(default_factory=list)
    notes: str = ""
    provenance: list[str] = field(default_factory=list)
    evidence_refs: list[str] = field(default_factory=list)
    static_evidence_refs: list[str] = field(default_factory=list)
    confidence: float = 0.0
    auth_requirements: list[str] = field(default_factory=list)
    web_path_hints: list[str] = field(default_factory=list)
    gate_preconditions: GatePreconditions = field(default_factory=GatePreconditions)
    validation_mode: str = ""
    canonical_class: str = ""
    canonical_issue_id: str = ""
    candidate_uid: str = ""

    def __post_init__(self) -> None:
        self.gate_preconditions = coerce_gate_preconditions(self.gate_preconditions)
        self.candidate_uid = str(self.candidate_uid or "").strip() or candidate_uid_for_fields(
            vuln_class=self.vuln_class,
            file_path=self.file_path,
            line=self.line,
            sink=self.sink,
            expected_intercepts=self.expected_intercepts,
            entrypoint_hint=self.entrypoint_hint,
            provenance=self.provenance,
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class StaticEvidence:
    candidate_id: str
    query_profile: str
    query_id: str
    file_path: str
    line: int
    snippet: str
    hash: str
    candidate_uid: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class StaticEvidenceRequest:
    seed_id: str
    vuln_class: str
    file_path: str
    symbol: str
    requested_checks: list[str]

@dataclass(slots=True)
class StaticEvidenceResult:
    seed_id: str
    status: str
    reason: str
    evidence: list[StaticEvidence]
    expected_intercepts: list[str]


@dataclass(slots=True)
class RuntimeCall:
    function: str
    file: str
    line: int
    args: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class OracleEvidence:
    correlation_id: str
    function: str
    file: str
    line: int
    full_args: list[str] = field(default_factory=list)
    display_args: list[str] = field(default_factory=list)
    matched_canary: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class RequestEvidence:
    request_id: str
    method: str
    path: str
    transport: str
    auth_context: str
    query_keys: list[str] = field(default_factory=list)
    body_keys: list[str] = field(default_factory=list)
    header_keys: list[str] = field(default_factory=list)
    payload_placements: list[str] = field(default_factory=list)
    request_summary: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ResponseEvidence:
    status_code: int | None
    location: str = ""
    body_excerpt: str = ""
    content_type: str = ""
    elapsed_ms: int | None = None
    parsed_features: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class WitnessEvidence:
    class_name: str
    witness_flags: list[str] = field(default_factory=list)
    witness_data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class Witness:
    canonical_class: str
    positive_flags: list[str] = field(default_factory=list)
    negative_flags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class WitnessContract:
    canonical_class: str
    required_all: list[str] = field(default_factory=list)
    required_any: list[str] = field(default_factory=list)
    negative_must_not_include: list[str] = field(default_factory=list)
    enforce_negative_clean: bool = True

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class EnvironmentFacts:
    security_level: str = ""
    session_state: str = ""
    authenticated_identities: list[str] = field(default_factory=list)
    database_initialized: bool | None = None
    known_seed_data: list[str] = field(default_factory=list)
    reachable_app_paths: list[str] = field(default_factory=list)
    role_prerequisites: list[str] = field(default_factory=list)
    provenance: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ValidationClassProfile:
    canonical_class: str
    validation_mode: str
    class_contract_id: str
    required_request_shape: list[str] = field(default_factory=list)
    required_witnesses: list[str] = field(default_factory=list)
    required_negative_controls: list[str] = field(default_factory=list)
    allowed_transports: list[str] = field(default_factory=list)
    auth_handling: str = "reuse"
    min_positive_requests: int = 0
    min_negative_controls: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class RuntimeEvidence:
    request_id: str
    status: str
    call_count: int
    overflow: bool
    arg_truncated: bool
    result_truncated: bool
    correlation: str | None
    calls: list[RuntimeCall] = field(default_factory=list)
    raw_headers: dict[str, str] = field(default_factory=dict)
    http_status: int | None = None
    body_excerpt: str = ""
    location: str = ""
    analysis_flags: list[str] = field(default_factory=list)
    aux: dict[str, Any] = field(default_factory=dict)
    oracle_evidence: list[OracleEvidence] = field(default_factory=list)
    request_evidence: RequestEvidence | None = None
    response_evidence: ResponseEvidence | None = None
    witness_evidence: WitnessEvidence | None = None

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["calls"] = [c.to_dict() for c in self.calls]
        data["oracle_evidence"] = [item.to_dict() for item in self.oracle_evidence]
        data["request_evidence"] = self.request_evidence.to_dict() if self.request_evidence is not None else None
        data["response_evidence"] = self.response_evidence.to_dict() if self.response_evidence is not None else None
        data["witness_evidence"] = self.witness_evidence.to_dict() if self.witness_evidence is not None else None
        return data


@dataclass(slots=True)
class DifferentialPair:
    privileged_run: RuntimeEvidence
    unprivileged_run: RuntimeEvidence
    auth_diff: str
    response_equivalent: bool
    equivalence_signals: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "privileged_run": self.privileged_run.to_dict(),
            "unprivileged_run": self.unprivileged_run.to_dict(),
            "auth_diff": self.auth_diff,
            "response_equivalent": self.response_equivalent,
            "equivalence_signals": list(self.equivalence_signals),
        }


@dataclass(slots=True)
class GateResult:
    decision: GateDecision
    passed_gates: list[str]
    failed_gate: str | None
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


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
    differential_pairs: list[DifferentialPair] = field(default_factory=list)
    artifact_refs: list[str] = field(default_factory=list)
    discovery_trace: dict[str, Any] = field(default_factory=dict)
    planner_trace: dict[str, Any] = field(default_factory=dict)
    bundle_type: str = "validated_exploit"
    validation_contract: dict[str, Any] = field(default_factory=dict)
    environment_facts: EnvironmentFacts | None = None
    candidate_uid: str = ""
    candidate_outcome: str = ""

    def __post_init__(self) -> None:
        self.candidate_uid = str(self.candidate_uid or "").strip() or self.candidate.candidate_uid
        self.candidate_outcome = str(self.candidate_outcome or "").strip() or explicit_candidate_outcome_for_decision(
            self.gate_result.decision
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "bundle_id": self.bundle_id,
            "created_at": self.created_at,
            "candidate_uid": self.candidate_uid,
            "candidate_outcome": self.candidate_outcome,
            "candidate": self.candidate.to_dict(),
            "static_evidence": [e.to_dict() for e in self.static_evidence],
            "positive_runtime": [e.to_dict() for e in self.positive_runtime],
            "negative_runtime": [e.to_dict() for e in self.negative_runtime],
            "repro_run_ids": self.repro_run_ids,
            "gate_result": self.gate_result.to_dict(),
            "limitations": self.limitations,
            "differential_pairs": [dp.to_dict() for dp in self.differential_pairs],
            "artifact_refs": self.artifact_refs,
            "discovery_trace": self.discovery_trace,
            "planner_trace": self.planner_trace,
            "bundle_type": self.bundle_type,
            "validation_contract": self.validation_contract,
            "environment_facts": self.environment_facts.to_dict() if self.environment_facts is not None else None,
        }


@dataclass(slots=True)
class RunSummary:
    run_id: str
    mode: str
    started_at: str
    completed_at: str
    total_candidates: int
    decisions: dict[str, int]
    bundle_ids: list[str]
    discovery_trace: dict[str, Any] = field(default_factory=dict)
    planner_trace: dict[str, Any] = field(default_factory=dict)
    frontier_state: dict[str, Any] = field(default_factory=dict)
    candidate_outcomes: dict[str, int] = field(default_factory=default_candidate_outcomes)
    run_coverage: dict[str, str] = field(default_factory=dict)
    stop_rule: str = ""
    stop_reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class FailurePattern:
    pattern_id: str
    vuln_class: str
    failed_gate: str
    failure_reason: str
    occurrence_count: int
    example_candidate_ids: list[str]
    provenance_correlation: dict[str, float]
    confidence_range: tuple[float, float]
    suggestion: str

    def __post_init__(self) -> None:
        if not isinstance(self.confidence_range, tuple):
            self.confidence_range = tuple(self.confidence_range)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class FailureAnalysis:
    analyzed_at: str
    total_runs_analyzed: int
    total_candidates_analyzed: int
    total_failures: int
    patterns: list[FailurePattern]
    gate_failure_distribution: dict[str, int]

    def to_dict(self) -> dict[str, Any]:
        return {
            "analyzed_at": self.analyzed_at,
            "total_runs_analyzed": self.total_runs_analyzed,
            "total_candidates_analyzed": self.total_candidates_analyzed,
            "total_failures": self.total_failures,
            "patterns": [p.to_dict() for p in self.patterns],
            "gate_failure_distribution": self.gate_failure_distribution,
        }


def _normalize_string_list(values: Any) -> list[str]:
    if not isinstance(values, list):
        return []
    normalized: list[str] = []
    for item in values:
        text = str(item).strip()
        if text:
            normalized.append(text)
    return normalized


def _normalize_header_dict(values: Any) -> dict[str, str]:
    if not isinstance(values, dict):
        return {}
    normalized: dict[str, str] = {}
    for key, value in values.items():
        name = str(key).strip()
        if not name:
            continue
        normalized[name] = str(value)
    return normalized


def _normalize_query_dict(values: Any) -> dict[str, Any]:
    if not isinstance(values, dict):
        return {}
    normalized: dict[str, Any] = {}
    for key, value in values.items():
        name = str(key).strip()
        if not name:
            continue
        normalized[name] = value
    return normalized


def _infer_body_type(body: Any, headers: dict[str, str]) -> str:
    content_type = str(headers.get("Content-Type") or headers.get("content-type") or "").casefold()
    if "application/json" in content_type:
        return "json"
    if "multipart/form-data" in content_type:
        return "multipart"
    if "xml" in content_type:
        return "xml"
    if isinstance(body, dict):
        return "form"
    if isinstance(body, str):
        return "text"
    return "none"


@dataclass(slots=True)
class HttpExpectations:
    status_codes: list[int] = field(default_factory=list)
    body_must_contain: list[str] = field(default_factory=list)
    body_must_not_contain: list[str] = field(default_factory=list)
    header_must_include: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.status_codes = [int(value) for value in self.status_codes if isinstance(value, (int, float, str)) and str(value).strip()]
        self.body_must_contain = _normalize_string_list(self.body_must_contain)
        self.body_must_not_contain = _normalize_string_list(self.body_must_not_contain)
        self.header_must_include = _normalize_header_dict(self.header_must_include)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class HttpStep:
    method: str = "GET"
    path: str = ""
    url: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    query: dict[str, Any] = field(default_factory=dict)
    body_type: str = "none"
    body: Any = None
    body_ref: str = ""
    cookies: dict[str, str] = field(default_factory=dict)
    token_extraction_rules: dict[str, str] = field(default_factory=dict)
    expectations: HttpExpectations = field(default_factory=HttpExpectations)

    def __post_init__(self) -> None:
        self.method = str(self.method or "GET").strip().upper() or "GET"
        self.path = str(self.path or "").strip()
        self.url = str(self.url or "").strip()
        self.headers = _normalize_header_dict(self.headers)
        self.query = _normalize_query_dict(self.query)
        self.cookies = _normalize_header_dict(self.cookies)
        self.body_ref = str(self.body_ref or "").strip()
        if not isinstance(self.expectations, HttpExpectations):
            self.expectations = HttpExpectations(**dict(self.expectations or {}))
        body_type = str(self.body_type or "").strip().casefold()
        self.body_type = body_type or _infer_body_type(self.body, self.headers)

    def to_request_spec(self) -> dict[str, Any]:
        request: dict[str, Any] = {"method": self.method}
        if self.path:
            request["path"] = self.path
        if self.url:
            request["url"] = self.url
        if self.headers:
            request["headers"] = dict(self.headers)
        if self.query:
            request["query"] = dict(self.query)
        if self.cookies:
            request["cookies"] = dict(self.cookies)
        if self.body_type in {"text", "xml"}:
            request["body_text"] = "" if self.body is None else str(self.body)
        elif self.body_type != "none" and self.body is not None:
            request["body"] = self.body
        if self.token_extraction_rules:
            request["token_extraction_rules"] = dict(self.token_extraction_rules)
        return request

    def to_dict(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "path": self.path,
            "url": self.url,
            "headers": dict(self.headers),
            "query": dict(self.query),
            "body_type": self.body_type,
            "body": self.body,
            "body_ref": self.body_ref,
            "cookies": dict(self.cookies),
            "token_extraction_rules": dict(self.token_extraction_rules),
            "expectations": self.expectations.to_dict(),
        }


@dataclass(slots=True)
class CanaryMatchRule:
    location: str = "response_body"
    match_type: str = "contains"
    value: str = ""
    arg_index: int | None = None

    def __post_init__(self) -> None:
        self.location = str(self.location or "response_body").strip() or "response_body"
        self.match_type = str(self.match_type or "contains").strip() or "contains"
        self.value = str(self.value or "").strip()
        if self.arg_index is None or self.arg_index == "":
            self.arg_index = None
        else:
            self.arg_index = max(0, int(self.arg_index))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class OracleSpec:
    intercept_profile: str = "default"
    oracle_functions: list[str] = field(default_factory=list)
    canary_rules: list[CanaryMatchRule] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.intercept_profile = str(self.intercept_profile or "default").strip() or "default"
        self.oracle_functions = _normalize_string_list(self.oracle_functions)
        self.canary_rules = [
            item if isinstance(item, CanaryMatchRule) else CanaryMatchRule(**dict(item or {}))
            for item in self.canary_rules
            if isinstance(item, (CanaryMatchRule, dict))
        ]

    def to_dict(self) -> dict[str, Any]:
        return {
            "intercept_profile": self.intercept_profile,
            "oracle_functions": list(self.oracle_functions),
            "canary_rules": [item.to_dict() for item in self.canary_rules],
        }


@dataclass(slots=True)
class NegativeControl:
    label: str = ""
    step: HttpStep = field(default_factory=HttpStep)
    expect_clean: bool = True

    def __post_init__(self) -> None:
        self.label = str(self.label or "").strip()
        if not isinstance(self.step, HttpStep):
            self.step = HttpStep(**dict(self.step or {}))
        self.expect_clean = bool(self.expect_clean)

    def to_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "step": self.step.to_dict(),
            "expect_clean": self.expect_clean,
        }


@dataclass(slots=True)
class PlanBudget:
    max_requests: int = 0
    max_time_s: int = 0

    def __post_init__(self) -> None:
        self.max_requests = max(0, int(self.max_requests or 0))
        self.max_time_s = max(0, int(self.max_time_s or 0))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _coerce_http_step(value: Any) -> HttpStep | None:
    if isinstance(value, HttpStep):
        return value
    if not isinstance(value, dict):
        return None
    body = value.get("body")
    body_text = value.get("body_text")
    headers = _normalize_header_dict(value.get("headers"))
    body_type = str(value.get("body_type") or "").strip()
    if not body_type:
        body_type = _infer_body_type(body_text if isinstance(body_text, str) else body, headers)
    if body_text is not None and body is None and body_type in {"none", "text", "xml"}:
        body = body_text
    expectations = value.get("expectations")
    if isinstance(expectations, HttpExpectations):
        normalized_expectations = expectations
    elif isinstance(expectations, dict):
        normalized_expectations = HttpExpectations(**expectations)
    else:
        normalized_expectations = HttpExpectations()
    return HttpStep(
        method=value.get("method", "GET"),
        path=value.get("path", ""),
        url=value.get("url", ""),
        headers=headers,
        query=value.get("query") or {},
        body_type=body_type,
        body=body,
        body_ref=value.get("body_ref", ""),
        cookies=value.get("cookies") or {},
        expectations=normalized_expectations,
    )


def _coerce_negative_control(value: Any, *, idx: int) -> NegativeControl | None:
    if isinstance(value, NegativeControl):
        return value
    if isinstance(value, HttpStep):
        return NegativeControl(label=f"control-{idx}", step=value)
    if not isinstance(value, dict):
        return None
    if isinstance(value.get("step"), dict):
        step = _coerce_http_step(value.get("step"))
        if step is None:
            return None
        return NegativeControl(
            label=str(value.get("label", "")).strip() or f"control-{idx}",
            step=step,
            expect_clean=bool(value.get("expect_clean", True)),
        )
    step = _coerce_http_step(value)
    if step is None:
        return None
    return NegativeControl(
        label=str(value.get("label", "")).strip() or f"control-{idx}",
        step=step,
        expect_clean=bool(value.get("expect_clean", True)),
    )


@dataclass(slots=True)
class ValidationPlan:
    candidate_id: str
    intercepts: list[str]
    positive_requests: list[dict[str, Any]]
    negative_requests: list[dict[str, Any]]
    canary: str
    oracle_functions: list[str] = field(default_factory=list)
    request_expectations: list[str] = field(default_factory=list)
    response_witnesses: list[str] = field(default_factory=list)
    validation_mode: str = "runtime"
    canonical_class: str = ""
    class_contract_id: str = ""
    gate_preconditions: GatePreconditions = field(default_factory=GatePreconditions)
    environment_requirements: list[str] = field(default_factory=list)
    requests: list[dict[str, Any]] = field(default_factory=list)
    negative_controls: list[NegativeControl] = field(default_factory=list)
    strategy: str = "default"
    negative_control_strategy: str = "canary-mismatch"
    plan_notes: list[str] = field(default_factory=list)
    steps: list[HttpStep] = field(default_factory=list)
    oracle_spec: OracleSpec = field(default_factory=OracleSpec)
    budgets: PlanBudget = field(default_factory=PlanBudget)

    def __post_init__(self) -> None:
        self.gate_preconditions = coerce_gate_preconditions(self.gate_preconditions)
        self.intercepts = _normalize_string_list(self.intercepts)
        self.oracle_functions = _normalize_string_list(self.oracle_functions)
        self.request_expectations = _normalize_string_list(self.request_expectations)
        self.response_witnesses = _normalize_string_list(self.response_witnesses)
        self.environment_requirements = _normalize_string_list(self.environment_requirements)
        self.plan_notes = _normalize_string_list(self.plan_notes)
        self.strategy = str(self.strategy or "default").strip() or "default"
        self.negative_control_strategy = str(self.negative_control_strategy or "canary-mismatch").strip() or "canary-mismatch"
        self.validation_mode = str(self.validation_mode or "runtime").strip() or "runtime"
        self.canonical_class = str(self.canonical_class or "").strip()
        self.class_contract_id = str(self.class_contract_id or "").strip()
        self.canary = str(self.canary or "").strip()

        self.steps = [
            step
            for step in (_coerce_http_step(item) for item in self.steps or self.positive_requests)
            if step is not None
        ]
        self.positive_requests = [step.to_request_spec() for step in self.steps]
        self.requests = list(self.requests) if self.requests else list(self.positive_requests)

        self.negative_controls = [
            control
            for idx, item in enumerate(self.negative_controls or self.negative_requests)
            for control in [_coerce_negative_control(item, idx=idx)]
            if control is not None
        ]
        self.negative_requests = [control.step.to_request_spec() for control in self.negative_controls]

        if not isinstance(self.oracle_spec, OracleSpec):
            self.oracle_spec = OracleSpec(**dict(self.oracle_spec or {}))
        if not self.oracle_spec.oracle_functions:
            self.oracle_spec.oracle_functions = list(self.oracle_functions or self.intercepts)
        self.oracle_functions = list(self.oracle_spec.oracle_functions)
        if not self.intercepts:
            self.intercepts = list(self.oracle_spec.oracle_functions)

        if not isinstance(self.budgets, PlanBudget):
            self.budgets = PlanBudget(**dict(self.budgets or {}))


@dataclass(slots=True)
class ValidationContext:
    run_id: str
    mode: str
    max_requests: int
    started_at: datetime = field(default_factory=lambda: datetime.now(tz=timezone.utc))


@dataclass(slots=True)
class ObjectiveScore:
    objective_id: str
    title: str
    rationale: str
    expected_info_gain: float
    priority: float
    channels: list[str] = field(default_factory=list)
    related_hypothesis_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ResearchTask:
    task_id: str
    objective_id: str
    channel: str
    target_ref: str
    prompt: str
    status: str = "queued"
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ResearchFinding:
    finding_id: str
    objective_id: str
    channel: str
    title: str
    summary: str
    evidence_refs: list[str] = field(default_factory=list)
    file_refs: list[str] = field(default_factory=list)
    web_paths: list[str] = field(default_factory=list)
    params: list[str] = field(default_factory=list)
    sink_refs: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class Hypothesis:
    hypothesis_id: str
    objective_id: str
    vuln_class: str
    title: str
    rationale: str
    evidence_refs: list[str]
    candidate: Candidate
    status: str = "active"
    confidence: float = 0.0
    auth_requirements: list[str] = field(default_factory=list)
    preconditions: list[str] = field(default_factory=list)
    gate_preconditions: GatePreconditions = field(default_factory=GatePreconditions)
    web_path_hints: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.gate_preconditions = coerce_gate_preconditions(self.gate_preconditions)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["candidate"] = self.candidate.to_dict()
        return payload


@dataclass(slots=True)
class Refutation:
    refutation_id: str
    hypothesis_id: str
    title: str
    summary: str
    evidence_refs: list[str] = field(default_factory=list)
    severity: str = "medium"
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ExperimentAttempt:
    attempt_id: str
    hypothesis_id: str
    plan_id: str
    request_refs: list[str]
    witness_goal: str
    status: str
    analysis_flags: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class WitnessBundle:
    witness_id: str
    hypothesis_id: str
    bundle_id: str
    witness_type: str
    status: str
    evidence_refs: list[str] = field(default_factory=list)
    negative_control_clean: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def utc_now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()

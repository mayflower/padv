from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


CandidateStatus = str
GateDecision = str


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
    confidence: float = 0.0
    auth_requirements: list[str] = field(default_factory=list)
    web_path_hints: list[str] = field(default_factory=list)

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

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class RuntimeCall:
    function: str
    file: str
    line: int
    args: list[str]

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

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["calls"] = [c.to_dict() for c in self.calls]
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

    def to_dict(self) -> dict[str, Any]:
        return {
            "bundle_id": self.bundle_id,
            "created_at": self.created_at,
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


@dataclass(slots=True)
class ValidationPlan:
    candidate_id: str
    intercepts: list[str]
    positive_requests: list[dict[str, Any]]
    negative_requests: list[dict[str, Any]]
    canary: str
    strategy: str = "default"
    negative_control_strategy: str = "canary-mismatch"
    plan_notes: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ValidationContext:
    run_id: str
    mode: str
    max_requests: int
    started_at: datetime = field(default_factory=lambda: datetime.now(tz=timezone.utc))


def utc_now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()

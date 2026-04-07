from __future__ import annotations

import uuid
from typing import Any

from padv.config.schema import PadvConfig
from padv.models import Candidate, CandidateSeed, StaticEvidence, StaticEvidenceRequest, StaticEvidenceResult
from padv.static.joern.query_sets import VULN_CLASS_SPECS, intercepts_for_class
from padv.taxonomy import canonicalize_vuln_class
from padv.validation.preconditions import GatePreconditions

def _preconditions_for_spec(vuln_class: str, config: PadvConfig) -> GatePreconditions:
    return GatePreconditions(requires_auth=bool(config.auth.enabled))

def _run_joern_checks(request: StaticEvidenceRequest, joern_runner: Any) -> StaticEvidenceResult:
    """Mock-able runner for grounding. Uses the provided runner to query."""
    # This invokes the real/fake joern adapter and parses the results.
    # We pass the requested checks and look for hits.
    findings = joern_runner.run_checks(request.file_path, request.requested_checks)
    
    evidence = []
    intercepts = intercepts_for_class(request.vuln_class)
    
    if findings:
        for finding in findings:
            ev = StaticEvidence(
                candidate_id="", # Will be set if converted
                query_profile="grounding",
                query_id=finding.query_id,
                file_path=finding.file_path,
                line=finding.line,
                snippet=finding.snippet,
                hash="fake-hash" # Usually hashed based on snippet/line
            )
            evidence.append(ev)
        
        return StaticEvidenceResult(
            seed_id=request.seed_id,
            status="SUPPORTED",
            reason="found supporting static evidence",
            evidence=evidence,
            expected_intercepts=intercepts
        )
        
    return StaticEvidenceResult(
        seed_id=request.seed_id,
        status="UNSUPPORTED",
        reason="no supporting static evidence found",
        evidence=[],
        expected_intercepts=intercepts
    )

def ground_seeds_with_joern(
    seeds: list[CandidateSeed],
    joern_runner: Any,
    config: PadvConfig
) -> tuple[list[Candidate], list[StaticEvidence], list[CandidateSeed]]:
    """
    Takes accepted CandidateSeeds, runs Joern, and converts grounded seeds to Candidates.
    Returns:
        (grounded_candidates, all_static_evidence, rejected_seeds)
    """
    candidates = []
    all_evidence = []
    rejected = []
    
    _SPEC_BY_CLASS = {spec.vuln_class: spec for spec in VULN_CLASS_SPECS}
    
    for seed in seeds:
        req = StaticEvidenceRequest(
            seed_id=seed.seed_id,
            vuln_class=seed.vuln_class,
            file_path=seed.file_path,
            symbol=seed.symbol,
            requested_checks=seed.requested_static_checks
        )
        
        result = _run_joern_checks(req, joern_runner)
        
        if result.status == "SUPPORTED" and result.evidence:
            # Conversion to Candidate
            candidate_id = f"cand-{uuid.uuid4().hex[:10]}"
            spec = _SPEC_BY_CLASS.get(seed.vuln_class)
            title = f"Grounded {seed.vuln_class} in {seed.file_path}"
            if spec:
                title = f"{spec.owasp_id} {spec.description}"
                
            c = Candidate(
                candidate_id=candidate_id,
                vuln_class=seed.vuln_class,
                title=title,
                file_path=seed.file_path,
                line=result.evidence[0].line,
                sink=seed.symbol,
                expected_intercepts=result.expected_intercepts,
                entrypoint_hint=seed.entrypoint_hint,
                preconditions=[],
                notes="grounded from agentic discovery",
                provenance=["agentic_discovery"],
                static_evidence_refs=[
                    f"{ev.query_id}:{ev.file_path}:{ev.line}" for ev in result.evidence
                ],
                gate_preconditions=_preconditions_for_spec(seed.vuln_class, config),
                canonical_class=canonicalize_vuln_class(seed.vuln_class)
            )
            # Ensure candidate_uid is generated
            c.__post_init__()
            
            for ev in result.evidence:
                ev.candidate_id = candidate_id
                ev.candidate_uid = c.candidate_uid
                all_evidence.append(ev)
                
            candidates.append(c)
        else:
            rejected.append(seed)
            
    return candidates, all_evidence, rejected
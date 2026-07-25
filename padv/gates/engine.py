from __future__ import annotations

from padv.config.schema import PadvConfig
from padv.models import (
    Candidate,
    DifferentialPair,
    GateResult,
    RefutationEvidence,
    RuntimeEvidence,
    StaticEvidence,
    Witness,
    WitnessContract,
)
from padv.taxonomy import contains_canary, runtime_validatable_classes
from padv.validation.contracts import build_runtime_witness, witness_contract_for_vuln_class
from padv.validation.preconditions import GatePreconditions, coerce_gate_preconditions


# V6 used to be appended unconditionally right before returning VALIDATED, so it
# asserted nothing; it is gone rather than left as a label that looks like a check.
REQUIRED_GATES = ["V0", "V1", "V2", "V3", "V4", "V5"]
# Analysis-only candidates run the static half of the contract instead.
ANALYSIS_GATES = ["A0", "A1", "A2"]

_RUNTIME_VALIDATABLE_CLASSES = runtime_validatable_classes()


def _has_oracle_hit(
    evidence: RuntimeEvidence,
    intercepts: set[str],
    canary: str,
    config: PadvConfig,
) -> bool:
    intercepts_lower = {i.casefold() for i in intercepts}
    for call in evidence.calls:
        if intercepts_lower and call.function.casefold() not in intercepts_lower:
            continue
        for arg in call.args:
            if contains_canary(
                arg,
                canary,
                allow_casefold=config.canary.allow_casefold,
                allow_url_decode=config.canary.allow_url_decode,
            ):
                return True
    return False


def _request_ids(runs: list[RuntimeEvidence]) -> list[str]:
    return [str(run.request_id) for run in runs if str(run.request_id).strip()]


def _evaluate_v0_scope(
    positive_runs: list[RuntimeEvidence],
    negative_runs: list[RuntimeEvidence],
) -> tuple[list[RuntimeEvidence], list[RuntimeEvidence], GateResult | None]:
    if any(run.status == "insufficient_evidence" for run in positive_runs + negative_runs):
        return [], [], GateResult("INCONCLUSIVE", [], "V0", "oracle output truncated")
    hard_scope_failures = {"auth_failed", "missing_key", "missing_intercept", "inactive"}
    if any(run.status in hard_scope_failures for run in positive_runs):
        return [], [], GateResult("INCONCLUSIVE", [], "V0", "runtime not in valid scope")
    in_scope_positive = [run for run in positive_runs if run.status != "request_failed"]
    in_scope_negative = [run for run in negative_runs if run.status != "request_failed"]
    if not in_scope_positive or not in_scope_negative:
        return [], [], GateResult("INCONCLUSIVE", [], "V0", "runtime not in valid scope")
    return in_scope_positive, in_scope_negative, None


def _evaluate_v2_corroboration(
    static_evidence: list[StaticEvidence],
    in_scope_positive_runs: list[RuntimeEvidence],
    evidence_signals: list[str] | None,
    passed: list[str],
) -> GateResult | None:
    if not static_evidence:
        return GateResult("INCONCLUSIVE", passed, "V2", "missing static evidence")
    if not in_scope_positive_runs:
        return GateResult("INCONCLUSIVE", passed, "V2", "missing runtime evidence")
    if not _has_multi_evidence_corroboration(evidence_signals):
        return GateResult("INCONCLUSIVE", passed, "V2", "insufficient multi-evidence corroboration")
    return None


def _has_multi_evidence_corroboration(evidence_signals: list[str] | None) -> bool:
    signal_set = {s.strip().casefold() for s in (evidence_signals or []) if isinstance(s, str) and s.strip()}
    return len(signal_set) >= 2


def _evaluate_v3v4_runtime_class(
    contract: WitnessContract,
    witness: Witness,
    passed: list[str],
    positive_runs: list[RuntimeEvidence],
    negative_runs: list[RuntimeEvidence],
) -> GateResult | None:
    positive_flags = {str(x).strip().casefold() for x in witness.positive_flags if str(x).strip()}
    negative_flags = {str(x).strip().casefold() for x in witness.negative_flags if str(x).strip()}
    required_all = {str(x).strip().casefold() for x in contract.required_all if str(x).strip()}
    required_any = {str(x).strip().casefold() for x in contract.required_any if str(x).strip()}

    if (required_all and not required_all.issubset(positive_flags)) or (
        required_any and not (positive_flags & required_any)
    ):
        return GateResult(
            "REFUTED",
            passed,
            "V3",
            "runtime class witness missing",
            refutation=RefutationEvidence(
                kind="class_witness_absent",
                failed_gate="V3",
                vuln_class=contract.canonical_class,
                required_all=sorted(required_all),
                required_any=sorted(required_any),
                observed_positive_flags=sorted(positive_flags),
                positive_request_ids=_request_ids(positive_runs),
                negative_request_ids=_request_ids(negative_runs),
                detail="the payload was delivered but the contracted class witness never appeared",
            ),
        )
    passed.append("V3")

    forbidden_negative = {str(x).strip().casefold() for x in contract.negative_must_not_include if str(x).strip()}
    if contract.enforce_negative_clean and forbidden_negative and (negative_flags & forbidden_negative):
        # The control fired without the payload, so the positive witness is not
        # attributable to our input. That invalidates the experiment; it does
        # not disprove the hypothesis.
        return GateResult("INCONCLUSIVE", passed, "V4", "negative control matched class witness")
    passed.append("V4")
    return None


def _run_has_canary_hit(run: RuntimeEvidence, intercept_set: set[str], canary: str, config: PadvConfig) -> bool:
    typed_hit = any(bool(getattr(item, "matched_canary", False)) for item in getattr(run, "oracle_evidence", []) or [])
    return typed_hit or _has_oracle_hit(run, intercept_set, canary, config)


def _evaluate_v3v4_legacy(
    in_scope_positive_runs: list[RuntimeEvidence],
    in_scope_negative_runs: list[RuntimeEvidence],
    intercept_set: set[str],
    canary: str,
    config: PadvConfig,
    passed: list[str],
) -> GateResult | None:
    if not all(_run_has_canary_hit(run, intercept_set, canary, config) for run in in_scope_positive_runs):
        return GateResult(
            "REFUTED",
            passed,
            "V3",
            "canary boundary proof missing",
            refutation=RefutationEvidence(
                kind="canary_boundary_absent",
                failed_gate="V3",
                vuln_class="",
                observed_positive_flags=[],
                positive_request_ids=_request_ids(in_scope_positive_runs),
                negative_request_ids=_request_ids(in_scope_negative_runs),
                detail=(
                    "the canary was delivered but did not reach an intercepted "
                    f"call argument in every positive run (intercepts: {sorted(intercept_set)})"
                ),
            ),
        )
    passed.append("V3")

    if any(_run_has_canary_hit(run, intercept_set, canary, config) for run in in_scope_negative_runs):
        return GateResult("INCONCLUSIVE", passed, "V4", "negative control hit canary")
    passed.append("V4")
    return None


def _evaluate_v3v4(
    class_key: str,
    witness: Witness,
    in_scope_positive_runs: list[RuntimeEvidence],
    in_scope_negative_runs: list[RuntimeEvidence],
    intercept_set: set[str],
    canary: str,
    config: PadvConfig,
    passed: list[str],
    witness_contract: WitnessContract,
) -> GateResult | None:
    if class_key in _RUNTIME_VALIDATABLE_CLASSES:
        return _evaluate_v3v4_runtime_class(
            witness_contract, witness, passed, in_scope_positive_runs, in_scope_negative_runs
        )
    return _evaluate_v3v4_legacy(
        in_scope_positive_runs, in_scope_negative_runs, intercept_set, canary, config, passed,
    )


def _evaluate_v5(
    in_scope_positive_runs: list[RuntimeEvidence],
    in_scope_negative_runs: list[RuntimeEvidence],
    passed: list[str],
) -> GateResult | None:
    if len(in_scope_positive_runs) < 2 or len(in_scope_negative_runs) < 1:
        return GateResult("INCONCLUSIVE", passed, "V5", "insufficient repro runs")
    if any(run.overflow or run.arg_truncated or run.result_truncated for run in in_scope_positive_runs + in_scope_negative_runs):
        return GateResult("INCONCLUSIVE", passed, "V5", "runtime evidence truncated")
    return None


def _evaluate_analysis_only(
    typed_preconditions: GatePreconditions,
    static_evidence: list[StaticEvidence],
    evidence_signals: list[str] | None,
) -> GateResult:
    """Gate analysis-only candidates on the static half of the evidence contract.

    These candidates carry no runtime proof, so the runtime gates cannot apply.
    They still have to clear preconditions and multi-evidence corroboration, and
    they are reported as ANALYSIS_FINDING rather than VALIDATED.
    """
    passed = ["A0"]
    if typed_preconditions.has_unresolved():
        return GateResult("NEEDS_HUMAN_SETUP", passed, "A1", typed_preconditions.reason())
    passed.append("A1")

    if not static_evidence:
        return GateResult("INCONCLUSIVE", passed, "A2", "missing static evidence")
    if not _has_multi_evidence_corroboration(evidence_signals):
        return GateResult("INCONCLUSIVE", passed, "A2", "insufficient multi-evidence corroboration")
    passed.append("A2")

    return GateResult(
        "CONFIRMED_ANALYSIS_FINDING",
        passed,
        None,
        "analysis-only candidate corroborated by static multi-evidence; no runtime proof",
    )


def evaluate_candidate(
    config: PadvConfig,
    static_evidence: list[StaticEvidence],
    positive_runs: list[RuntimeEvidence],
    negative_runs: list[RuntimeEvidence],
    intercepts: list[str],
    canary: str,
    preconditions: GatePreconditions | None,
    evidence_signals: list[str] | None = None,
    vuln_class: str | None = None,
    differential_pairs: list[DifferentialPair] | None = None,
    candidate: Candidate | None = None,
    witness: Witness | None = None,
    witness_contract: WitnessContract | None = None,
) -> GateResult:
    passed: list[str] = []
    typed_preconditions = coerce_gate_preconditions(preconditions)
    if candidate is not None and str(getattr(candidate, "validation_mode", "")).strip() == "analysis_only":
        return _evaluate_analysis_only(typed_preconditions, static_evidence, evidence_signals)

    in_scope_positive_runs, in_scope_negative_runs, v0_fail = _evaluate_v0_scope(positive_runs, negative_runs)
    if v0_fail is not None:
        return v0_fail
    passed.append("V0")

    if typed_preconditions.has_unresolved():
        return GateResult("NEEDS_HUMAN_SETUP", passed, "V1", typed_preconditions.reason())
    passed.append("V1")

    v2_fail = _evaluate_v2_corroboration(static_evidence, in_scope_positive_runs, evidence_signals, passed)
    if v2_fail is not None:
        return v2_fail
    passed.append("V2")

    class_key = str(getattr(candidate, "canonical_class", "") or vuln_class or getattr(candidate, "vuln_class", "")).strip()
    shared_contract = witness_contract or witness_contract_for_vuln_class(class_key)
    shared_witness = witness or build_runtime_witness(
        config=config,
        vuln_class=class_key,
        positive_runs=in_scope_positive_runs,
        negative_runs=in_scope_negative_runs,
        intercepts=intercepts,
        canary=canary,
        differential_pairs=differential_pairs,
    )
    intercept_set = {str(x).strip() for x in intercepts if str(x).strip()}

    v3v4_fail = _evaluate_v3v4(
        shared_contract.canonical_class,
        shared_witness,
        in_scope_positive_runs,
        in_scope_negative_runs,
        intercept_set,
        canary,
        config,
        passed,
        shared_contract,
    )
    if v3v4_fail is not None:
        return v3v4_fail

    v5_fail = _evaluate_v5(in_scope_positive_runs, in_scope_negative_runs, passed)
    if v5_fail is not None:
        return v5_fail
    passed.append("V5")

    return GateResult("VALIDATED", passed, None, "all required gates passed")

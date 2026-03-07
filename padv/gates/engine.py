from __future__ import annotations

import urllib.parse

from padv.config.schema import PadvConfig
from padv.models import DifferentialPair, GateResult, RuntimeEvidence, StaticEvidence


REQUIRED_GATES = ["V0", "V1", "V2", "V3", "V4", "V5", "V6"]
AUTHZ_VULN_CLASSES = frozenset(
    {
        "broken_access_control",
        "idor_invariant_missing",
        "auth_and_session_failures",
    }
)

_HTTP_SIGNAL_RULES: dict[str, dict[str, object]] = {
    "xss_output_boundary": {
        "required_flags": {"xss_raw_canary"},
        "enforce_negative_clean": True,
    },
    "debug_output_leak": {
        "required_flags": {"debug_leak", "verbose_error_leak", "phpinfo_marker"},
        "enforce_negative_clean": False,
    },
    "information_disclosure": {
        "required_flags": {"info_disclosure_header", "verbose_error_leak", "phpinfo_marker"},
        "enforce_negative_clean": False,
    },
    "broken_access_control": {
        "required_flags": {"authz_bypass_status", "authz_pair_observed"},
        "enforce_negative_clean": False,
    },
    "idor_invariant_missing": {
        "required_flags": {"idor_bypass", "authz_bypass_status", "authz_pair_observed"},
        "enforce_negative_clean": False,
    },
    "csrf_invariant_missing": {
        "required_flags": {"csrf_missing_token_acceptance"},
        "enforce_negative_clean": False,
    },
    "session_fixation_invariant": {
        "required_flags": {"session_id_not_rotated", "session_cookie_not_rotated"},
        "enforce_negative_clean": False,
    },
    "auth_and_session_failures": {
        "required_flags": {"auth_bypass", "authz_bypass_status", "authz_pair_observed"},
        "enforce_negative_clean": False,
    },
}


def _contains_canary(arg: str, canary: str, allow_casefold: bool, allow_url_decode: bool) -> bool:
    candidates = [arg]
    if allow_url_decode:
        candidates.append(urllib.parse.unquote(arg))

    if allow_casefold:
        folded = canary.casefold()
        return any(folded in c.casefold() for c in candidates)
    return any(canary in c for c in candidates)


def _has_oracle_hit(
    evidence: RuntimeEvidence,
    intercepts: set[str],
    canary: str,
    config: PadvConfig,
) -> bool:
    intercepts_lower = {i.lower() for i in intercepts}
    for call in evidence.calls:
        if intercepts_lower and call.function.lower() not in intercepts_lower:
            continue
        for arg in call.args:
            if _contains_canary(
                arg,
                canary,
                allow_casefold=config.canary.allow_casefold,
                allow_url_decode=config.canary.allow_url_decode,
            ):
                return True
    return False


def _flag_set(runs: list[RuntimeEvidence]) -> set[str]:
    out: set[str] = set()
    for run in runs:
        for flag in run.analysis_flags:
            if isinstance(flag, str) and flag.strip():
                out.add(flag.strip().casefold())
    return out


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
    differential_pairs: list[DifferentialPair] | None = None,
) -> GateResult:
    passed: list[str] = []

    if any(run.status in {"auth_failed", "missing_key", "missing_intercept", "inactive", "request_failed"} for run in positive_runs):
        return GateResult("DROPPED", passed, "V0", "runtime not in valid scope")
    passed.append("V0")

    if preconditions:
        return GateResult("NEEDS_HUMAN_SETUP", passed, "V1", "preconditions unresolved")
    passed.append("V1")

    if not static_evidence:
        return GateResult("DROPPED", passed, "V2", "missing static evidence")
    if not positive_runs:
        return GateResult("DROPPED", passed, "V2", "missing runtime evidence")
    signal_set = {s.strip().lower() for s in (evidence_signals or []) if isinstance(s, str) and s.strip()}
    if len(signal_set) < 2:
        return GateResult("DROPPED", passed, "V2", "insufficient multi-evidence corroboration")
    passed.append("V2")

    class_key = (vuln_class or "").strip().casefold()
    rule = _HTTP_SIGNAL_RULES.get(class_key)
    if rule is not None:
        required_flags = {str(x).strip().casefold() for x in rule.get("required_flags", set()) if str(x).strip()}
        positive_flags = _flag_set(positive_runs)
        if class_key in AUTHZ_VULN_CLASSES and differential_pairs:
            if any(pair.response_equivalent for pair in differential_pairs):
                positive_flags.add("authz_bypass_status")
                positive_flags.add("authz_pair_observed")
        if required_flags and not required_flags.issubset(positive_flags):
            return GateResult("DROPPED", passed, "V3", "runtime class signal missing")
        passed.append("V3")

        enforce_negative_clean = bool(rule.get("enforce_negative_clean", False))
        if enforce_negative_clean:
            negative_flags = _flag_set(negative_runs)
            if required_flags and (negative_flags & required_flags):
                return GateResult("DROPPED", passed, "V4", "negative control matched class signal")
        passed.append("V4")
    else:
        intercept_set = set(intercepts)
        positive_hits = [
            _has_oracle_hit(run, intercept_set, canary, config)
            for run in positive_runs
        ]
        if not all(positive_hits):
            return GateResult("DROPPED", passed, "V3", "canary boundary proof missing")
        passed.append("V3")

        negative_hits = [
            _has_oracle_hit(run, intercept_set, canary, config)
            for run in negative_runs
        ]
        if any(negative_hits):
            return GateResult("DROPPED", passed, "V4", "negative control hit canary")
        passed.append("V4")

    if len(positive_runs) < 3 or len(negative_runs) < 1:
        return GateResult("DROPPED", passed, "V5", "insufficient repro runs")
    if any(run.overflow or run.result_truncated for run in positive_runs + negative_runs):
        return GateResult("DROPPED", passed, "V5", "runtime evidence truncated")
    passed.append("V5")

    passed.append("V6")
    return GateResult("VALIDATED", passed, None, "all required gates passed")

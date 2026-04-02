from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any

from padv.models import FailureAnalysis, FailurePattern, utc_now_iso
from padv.store.evidence_store import EvidenceStore


def _as_float(value: Any, default: float = 0.0) -> float:
    if isinstance(value, bool):
        return default
    if isinstance(value, (int, float)):
        return float(value)
    return default


def _as_str(value: Any, default: str = "") -> str:
    if isinstance(value, str):
        return value
    return default


def _suggestion_for_pattern(failed_gate: str, vuln_class: str, top_sources: list[str]) -> str:
    if failed_gate == "V0":
        return "Check runtime scope/auth/oracle setup before candidate validation."
    if failed_gate == "V1":
        return "Resolve preconditions earlier (auth/session/setup) to avoid human-setup drops."
    if failed_gate == "V2":
        return "Increase multi-evidence corroboration for this class before scheduling validation."
    if failed_gate == "V3":
        if top_sources:
            src = ", ".join(top_sources[:2])
            return f"Boundary proof is weak for {vuln_class}; reassess source reliability ({src})."
        return f"Boundary proof is weak for {vuln_class}; improve exploit-path realism."
    if failed_gate == "V4":
        return "Negative controls are too sensitive; tighten canary separation and control requests."
    if failed_gate == "V5":
        return "Repro quality is unstable; reduce truncation/overflow and enforce deterministic requests."
    return "Investigate recurring gate failures and adjust candidate synthesis quality."


def _accumulate_bundle_failure(
    bundle: dict[str, Any],
    bundle_id: str,
    groups: dict[tuple[str, str], dict[str, Any]],
    gate_distribution: Counter[str],
) -> bool:
    """Process one bundle for failure analysis.  Returns True if the bundle was a failure."""
    gate_result = bundle.get("gate_result", {})
    if not isinstance(gate_result, dict):
        return False
    decision = _as_str(gate_result.get("decision"))
    if decision in {"VALIDATED", "CONFIRMED_ANALYSIS_FINDING"}:
        return False

    failed_gate = _as_str(gate_result.get("failed_gate"), "unknown")
    reason = _as_str(gate_result.get("reason"), "unknown")
    gate_distribution[failed_gate] += 1

    candidate = bundle.get("candidate", {})
    if not isinstance(candidate, dict):
        return True

    vuln_class = _as_str(candidate.get("vuln_class"), "unknown")
    candidate_id = _as_str(candidate.get("candidate_id"), bundle_id)
    confidence = _as_float(candidate.get("confidence"), 0.0)
    provenance = candidate.get("provenance", [])
    if not isinstance(provenance, list):
        provenance = []
    normalized_provenance = sorted(
        {_as_str(p).strip().lower() for p in provenance if _as_str(p).strip()}
    )

    key = (vuln_class, failed_gate)
    entry = groups[key]
    entry["count"] += 1
    entry["reason_counter"][reason] += 1
    entry["candidate_ids"].append(candidate_id)
    entry["confidences"].append(confidence)
    for source in normalized_provenance:
        entry["provenance_counter"][source] += 1
    return True


def _build_pattern(vuln_class: str, failed_gate: str, entry: dict[str, Any]) -> FailurePattern:
    count = int(entry["count"])
    reason_counter: Counter[str] = entry["reason_counter"]
    reason = reason_counter.most_common(1)[0][0] if reason_counter else "unknown"

    confidences: list[float] = entry["confidences"] or [0.0]
    min_conf = min(confidences)
    max_conf = max(confidences)

    provenance_counter: Counter[str] = entry["provenance_counter"]
    provenance_correlation = {
        source: round(src_count / count, 4)
        for source, src_count in provenance_counter.items()
    }
    top_sources = [source for source, _ in provenance_counter.most_common(2)]
    suggestion = _suggestion_for_pattern(failed_gate, vuln_class, top_sources)

    return FailurePattern(
        pattern_id="",
        vuln_class=vuln_class,
        failed_gate=failed_gate,
        failure_reason=reason,
        occurrence_count=count,
        example_candidate_ids=entry["candidate_ids"][:5],
        provenance_correlation=provenance_correlation,
        confidence_range=(round(min_conf, 4), round(max_conf, 4)),
        suggestion=suggestion,
    )


def analyze_failures(store: EvidenceStore, min_occurrences: int = 3) -> FailureAnalysis:
    bundle_ids = store.list_bundle_ids()
    run_ids = store.list_run_ids()

    total_candidates = 0
    total_failures = 0
    gate_distribution: Counter[str] = Counter()

    groups: dict[tuple[str, str], dict[str, Any]] = defaultdict(
        lambda: {
            "count": 0,
            "reason_counter": Counter(),
            "candidate_ids": [],
            "provenance_counter": Counter(),
            "confidences": [],
        }
    )

    for bundle_id in bundle_ids:
        bundle = store.load_bundle(bundle_id)
        if not isinstance(bundle, dict):
            continue
        total_candidates += 1
        if _accumulate_bundle_failure(bundle, bundle_id, groups, gate_distribution):
            total_failures += 1

    patterns: list[FailurePattern] = []
    for (vuln_class, failed_gate), entry in groups.items():
        if int(entry["count"]) < min_occurrences:
            continue
        patterns.append(_build_pattern(vuln_class, failed_gate, entry))

    patterns.sort(key=lambda p: (-p.occurrence_count, p.vuln_class, p.failed_gate))
    for idx, pattern in enumerate(patterns, start=1):
        pattern.pattern_id = f"fp-{idx:03d}"

    return FailureAnalysis(
        analyzed_at=utc_now_iso(),
        total_runs_analyzed=len(run_ids),
        total_candidates_analyzed=total_candidates,
        total_failures=total_failures,
        patterns=patterns,
        gate_failure_distribution=dict(sorted(gate_distribution.items())),
    )


def failure_penalty(
    candidate_vuln_class: str,
    candidate_provenance: list[str],
    candidate_confidence: float,
    patterns: list[FailurePattern],
) -> float:
    if not patterns:
        return 0.0

    normalized_provenance = sorted({str(p).strip().lower() for p in candidate_provenance if str(p).strip()})
    scores: list[float] = []
    for pattern in patterns:
        if pattern.vuln_class != candidate_vuln_class:
            continue

        base_score = min(1.0, float(pattern.occurrence_count) / 20.0)
        if normalized_provenance:
            provenance_match = sum(
                float(pattern.provenance_correlation.get(source, 0.0))
                for source in normalized_provenance
            ) / len(normalized_provenance)
        else:
            provenance_match = 0.0

        conf_min, conf_max = pattern.confidence_range
        confidence_match = 1.0 if conf_min <= candidate_confidence <= conf_max else 0.5
        score = base_score * 0.5 + provenance_match * 0.3 + confidence_match * 0.2
        scores.append(max(0.0, min(1.0, score)))

    if not scores:
        return 0.0
    return max(scores)


def format_analysis_table(analysis: FailureAnalysis) -> str:
    lines: list[str] = []
    lines.append("Gate Failure Distribution:")
    total = max(1, analysis.total_failures)
    if not analysis.gate_failure_distribution:
        lines.append("  (no failures observed)")
    else:
        for gate, count in sorted(
            analysis.gate_failure_distribution.items(),
            key=lambda item: (-item[1], item[0]),
        ):
            pct = int(round((count / total) * 100.0))
            lines.append(f"  {gate:<4}: {count:>4} ({pct:>3}%)")

    lines.append("")
    lines.append("Top Failure Patterns:")
    if not analysis.patterns:
        lines.append("  (no recurring patterns)")
        return "\n".join(lines)

    for idx, pattern in enumerate(analysis.patterns, start=1):
        lines.append(f"  #{idx}  {pattern.vuln_class} @ {pattern.failed_gate} ({pattern.occurrence_count} occurrences)")
        if pattern.provenance_correlation:
            src_fragments = [
                f"{int(round(score * 100.0)):>2}% {source}"
                for source, score in sorted(
                    pattern.provenance_correlation.items(),
                    key=lambda item: (-item[1], item[0]),
                )
            ]
            lines.append(f"      Source: {', '.join(src_fragments)}")
        else:
            lines.append("      Source: (none)")
        lines.append(
            f"      Confidence: {pattern.confidence_range[0]:.2f}–{pattern.confidence_range[1]:.2f}"
        )
        lines.append(f"      → Suggestion: {pattern.suggestion}")

    return "\n".join(lines)

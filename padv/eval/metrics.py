from __future__ import annotations

from collections.abc import Iterable, Mapping

from padv.models import CANDIDATE_OUTCOMES, explicit_candidate_outcome_for_decision


def _ratio_key(outcome: str) -> str:
    return f"{outcome.casefold()}_ratio"


def summarize_outcomes(outcomes: Mapping[str, int]) -> dict[str, float]:
    """Share of each candidate outcome across a run.

    These are process ratios, not effectiveness. Precision and recall need
    ground truth and live in :func:`confusion_from_matches`.
    """
    counts = {outcome: int(outcomes.get(outcome, 0)) for outcome in CANDIDATE_OUTCOMES}
    total = sum(counts.values())
    if total <= 0:
        return {_ratio_key(outcome): 0.0 for outcome in CANDIDATE_OUTCOMES}
    return {_ratio_key(outcome): counts[outcome] / total for outcome in CANDIDATE_OUTCOMES}


def summarize_decisions(decisions: Mapping[str, int]) -> dict[str, float]:
    """Same as :func:`summarize_outcomes`, keyed by raw gate decision."""
    outcomes: dict[str, int] = dict.fromkeys(CANDIDATE_OUTCOMES, 0)
    for decision, count in decisions.items():
        outcome = explicit_candidate_outcome_for_decision(decision)
        outcomes[outcome] = outcomes.get(outcome, 0) + int(count)
    return summarize_outcomes(outcomes)


def confusion_from_matches(
    expected_ids: Iterable[str],
    validated_ids: Iterable[str],
    negative_control_ids: Iterable[str] = (),
) -> dict[str, int]:
    """Instance-level confusion counts.

    ``expected_ids`` are the ground-truth instances that must be found,
    ``validated_ids`` the instances a run actually proved, and
    ``negative_control_ids`` the patched or benign near-misses that must never
    be proved. Controls are reported separately but also count as false
    positives, as does any validated instance that matches no ground-truth
    entry: an unmatched claim is unproven by definition of the benchmark.
    """
    expected = {str(x).strip() for x in expected_ids if str(x).strip()}
    validated = {str(x).strip() for x in validated_ids if str(x).strip()}
    controls = {str(x).strip() for x in negative_control_ids if str(x).strip()}
    return {
        "true_positives": len(validated & expected),
        "false_positives": len(validated - expected),
        "false_negatives": len(expected - validated),
        "control_violations": len(validated & controls),
    }


def precision_recall_f1(
    true_positives: int,
    false_positives: int,
    false_negatives: int,
) -> dict[str, float]:
    tp = max(0, int(true_positives))
    fp = max(0, int(false_positives))
    fn = max(0, int(false_negatives))
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    return {"precision": precision, "recall": recall, "f1": f1}


def macro_recall(per_class: Mapping[str, tuple[int, int]]) -> float:
    """Unweighted mean recall over classes, given ``{class: (found, expected)}``.

    Macro rather than micro so a class with many instances cannot mask a class
    the run never detects at all.
    """
    recalls = [
        (found / expected) if expected > 0 else 0.0
        for found, expected in per_class.values()
    ]
    if not recalls:
        return 0.0
    return sum(recalls) / len(recalls)

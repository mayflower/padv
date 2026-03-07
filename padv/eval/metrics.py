from __future__ import annotations


def summarize_decisions(decisions: dict[str, int]) -> dict[str, float]:
    total = sum(decisions.values())
    if total <= 0:
        return {"validated_ratio": 0.0, "drop_ratio": 0.0, "needs_setup_ratio": 0.0}
    return {
        "validated_ratio": decisions.get("VALIDATED", 0) / total,
        "drop_ratio": decisions.get("DROPPED", 0) / total,
        "needs_setup_ratio": decisions.get("NEEDS_HUMAN_SETUP", 0) / total,
    }

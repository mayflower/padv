from __future__ import annotations

from importlib import import_module
from typing import Any


__all__ = [
    "apply_validation_profile",
    "canonical_issue_id",
    "coerce_gate_preconditions",
    "ensure_no_legacy_preconditions",
    "GatePreconditions",
    "InvalidGatePreconditionsError",
    "is_runtime_validatable",
    "profile_for_vuln_class",
    "resolve_gate_preconditions",
]

_PRECONDITION_EXPORTS = {
    "GatePreconditions",
    "coerce_gate_preconditions",
    "ensure_no_legacy_preconditions",
    "InvalidGatePreconditionsError",
    "resolve_gate_preconditions",
}

_CONTRACT_EXPORTS = {
    "apply_validation_profile",
    "canonical_issue_id",
    "is_runtime_validatable",
    "profile_for_vuln_class",
}


def __getattr__(name: str) -> Any:
    if name in _PRECONDITION_EXPORTS:
        module = import_module(".preconditions", __name__)
        return getattr(module, name)
    if name in _CONTRACT_EXPORTS:
        module = import_module(".contracts", __name__)
        return getattr(module, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(__all__))

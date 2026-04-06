from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any


class InvalidGatePreconditionsError(TypeError):
    """Raised when decision-plane code receives legacy or malformed preconditions."""


def _normalized_strings(values: Sequence[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        if not isinstance(value, str):
            raise InvalidGatePreconditionsError("gate precondition string fields must contain strings")
        text = value.strip()
        if not text or text in seen:
            continue
        seen.add(text)
        out.append(text)
    return out


@dataclass(slots=True)
class GatePreconditions:
    requires_auth: bool = False
    requires_session: bool = False
    requires_csrf_token: bool = False
    requires_upload: bool = False
    requires_seed: bool = False
    requires_specific_header: list[str] = field(default_factory=list)
    unknown_blockers: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.requires_specific_header = _normalized_strings(self.requires_specific_header)
        self.unknown_blockers = _normalized_strings(self.unknown_blockers)

    def is_empty(self) -> bool:
        return not any(
            [
                self.requires_auth,
                self.requires_session,
                self.requires_csrf_token,
                self.requires_upload,
                self.requires_seed,
                bool(self.requires_specific_header),
                bool(self.unknown_blockers),
            ]
        )

    def has_unresolved(self) -> bool:
        return not self.is_empty()

    def reason(self) -> str:
        parts: list[str] = []
        if self.requires_auth:
            parts.append("requires_auth")
        if self.requires_session:
            parts.append("requires_session")
        if self.requires_csrf_token:
            parts.append("requires_csrf_token")
        if self.requires_upload:
            parts.append("requires_upload")
        if self.requires_seed:
            parts.append("requires_seed")
        if self.requires_specific_header:
            parts.append(f"requires_specific_header={','.join(self.requires_specific_header)}")
        if self.unknown_blockers:
            parts.append(f"unknown_blockers={'; '.join(self.unknown_blockers)}")
        if not parts:
            return "typed_preconditions_unresolved: none"
        return f"typed_preconditions_unresolved: {', '.join(parts)}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "requires_auth": self.requires_auth,
            "requires_session": self.requires_session,
            "requires_csrf_token": self.requires_csrf_token,
            "requires_upload": self.requires_upload,
            "requires_seed": self.requires_seed,
            "requires_specific_header": list(self.requires_specific_header),
            "unknown_blockers": list(self.unknown_blockers),
        }


def _mapping_bool(
    value: Mapping[str, object],
    *,
    key: str,
    aliases: Sequence[str] = (),
) -> bool:
    for candidate in (key, *aliases):
        if candidate not in value:
            continue
        raw = value[candidate]
        if not isinstance(raw, bool):
            raise InvalidGatePreconditionsError(f"gate preconditions field {key!r} must be a boolean")
        return raw
    return False


def _mapping_string_list(
    value: Mapping[str, object],
    *,
    key: str,
    aliases: Sequence[str] = (),
) -> list[str]:
    for candidate in (key, *aliases):
        if candidate not in value:
            continue
        raw = value[candidate]
        if raw is None:
            return []
        if not isinstance(raw, list):
            raise InvalidGatePreconditionsError(f"gate preconditions field {key!r} must be a list of strings")
        return _normalized_strings(raw)
    return []


def coerce_gate_preconditions(
    value: GatePreconditions | Mapping[str, object] | None,
) -> GatePreconditions:
    if isinstance(value, GatePreconditions):
        return GatePreconditions(
            requires_auth=bool(value.requires_auth),
            requires_session=bool(value.requires_session),
            requires_csrf_token=bool(value.requires_csrf_token),
            requires_upload=bool(value.requires_upload),
            requires_seed=bool(value.requires_seed),
            requires_specific_header=list(value.requires_specific_header),
            unknown_blockers=list(value.unknown_blockers),
        )
    if value is None:
        return GatePreconditions()
    if isinstance(value, Mapping):
        return GatePreconditions(
            requires_auth=_mapping_bool(value, key="requires_auth"),
            requires_session=_mapping_bool(value, key="requires_session"),
            requires_csrf_token=_mapping_bool(value, key="requires_csrf_token", aliases=("requires_csrf",)),
            requires_upload=_mapping_bool(value, key="requires_upload"),
            requires_seed=_mapping_bool(value, key="requires_seed"),
            requires_specific_header=_mapping_string_list(
                value,
                key="requires_specific_header",
                aliases=("required_headers",),
            ),
            unknown_blockers=_mapping_string_list(value, key="unknown_blockers"),
        )
    raise InvalidGatePreconditionsError(
        "gate preconditions must be a GatePreconditions object or structured mapping"
    )


def merge_gate_preconditions(
    *values: GatePreconditions | Mapping[str, object] | None,
) -> GatePreconditions:
    merged = GatePreconditions()
    for value in values:
        item = coerce_gate_preconditions(value)
        merged.requires_auth = merged.requires_auth or item.requires_auth
        merged.requires_session = merged.requires_session or item.requires_session
        merged.requires_csrf_token = merged.requires_csrf_token or item.requires_csrf_token
        merged.requires_upload = merged.requires_upload or item.requires_upload
        merged.requires_seed = merged.requires_seed or item.requires_seed
        merged.requires_specific_header = _normalized_strings(
            [*merged.requires_specific_header, *item.requires_specific_header]
        )
        merged.unknown_blockers = _normalized_strings([*merged.unknown_blockers, *item.unknown_blockers])
    return merged


def ensure_no_legacy_preconditions(
    *,
    preconditions: Sequence[str] | None = None,
    auth_requirements: Sequence[str] | None = None,
) -> None:
    has_preconditions = bool(_normalized_strings(preconditions or []))
    has_auth_requirements = bool(_normalized_strings(auth_requirements or []))
    if not has_preconditions and not has_auth_requirements:
        return
    raise InvalidGatePreconditionsError(
        "legacy candidate.preconditions/auth_requirements are not allowed in decision-plane APIs; "
        "use gate_preconditions"
    )


def resolve_gate_preconditions(
    parsed: GatePreconditions | Mapping[str, object] | None,
    *,
    cookie_jar: dict[str, str] | None = None,
) -> GatePreconditions:
    resolved = coerce_gate_preconditions(parsed)
    if cookie_jar:
        resolved.requires_auth = False
        resolved.requires_session = False
    return resolved

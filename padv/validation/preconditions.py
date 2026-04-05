from __future__ import annotations

import re
from dataclasses import dataclass, field


def _unique_append(items: list[str], value: str) -> None:
    if value not in items:
        items.append(value)


def _normalize_text(value: str) -> str:
    return " ".join(str(value).strip().split())


_AUTH_REQUIRED_PATTERNS = (
    re.compile(r"\blogin required\b"),
    re.compile(r"\bauthenticated user\b"),
    re.compile(r"\bauthenticated session\b"),
    re.compile(r"\bauthenticated\b"),
    re.compile(r"\badmin session\b"),
    re.compile(r"\badmin role\b"),
    re.compile(r"\bprivileged\b"),
    re.compile(r"\bauthori[sz]ed\b"),
)

_SESSION_REQUIRED_PATTERNS = (
    re.compile(r"\bsession required\b"),
    re.compile(r"\bauthenticated session\b"),
    re.compile(r"\badmin session\b"),
    re.compile(r"\bvalid session\b"),
    re.compile(r"\bcookie\b"),
    re.compile(r"\bphpsessid\b"),
)

_AUTH_NEGATION_PATTERNS = (
    re.compile(r"\bunauthenticated access allowed\b"),
    re.compile(r"\baccessible without authentication\b"),
    re.compile(r"\bno authentication check\b"),
    re.compile(r"\bno username/password required\b"),
    re.compile(r"\bno jwt token required\b"),
    re.compile(r"\banonymous access\b"),
    re.compile(r"\bno special permissions\b"),
    re.compile(r"\bno credentials required\b"),
)

_REQUEST_SHAPE_MARKERS = (
    "for level",
    "content-type:",
    "http post request",
    "http get request",
    "post request",
    "get request",
    "post or get",
    "soap request",
    "soap envelope",
    "soap 1.1",
    "soapaction",
    "json body",
    "valid json",
    "xml",
    "multipart/form-data",
    "parameter",
    "query string",
    "query must return",
    "response",
    "base query returns",
    "matching 5 columns",
    "match 5-column structure",
    "union-based",
    "boolean-blind",
    "error-based",
    "time-based",
    "special uuid",
)

_ENVIRONMENT_MARKERS = (
    "security level",
    "security-level",
    "security_level",
    "satisfying precondition",
    "$lprotectagainst",
    "shell_exec()",
    "shell_exec",
    "mysql",
    "public endpoint",
    "database must be accessible",
    "database accessible",
    "error reporting",
    "unix/linux system",
    "web server",
    "allowoverride",
    "mod_mime",
    "webroot path",
    "write permissions",
    "writable by",
    "file_exists()",
    "require_once()",
    "session_start()",
    "session must be initiated",
    "automatically created",
    "automatically happens on first request",
    "standard php behavior",
    "standard linux permission",
    "populated with",
)

_UPLOAD_MARKERS = (
    "file upload",
    "upload webshell",
    "upload_directory",
    "multipart/form-data",
    "uploaded_file_path",
    "uploaded file",
)

_HEADER_REQUIREMENT_PATTERNS = (
    (re.compile(r"\bx-csrf-token\b"), "x-csrf-token"),
    (re.compile(r"\bcsrf-token\b"), "csrf-token"),
    (re.compile(r"\bauthorization header\b"), "authorization"),
    (re.compile(r"\bx-api-key\b"), "x-api-key"),
)


@dataclass(slots=True)
class GatePreconditions:
    requires_auth: bool = False
    requires_session: bool = False
    requires_csrf_token: bool = False
    requires_upload: bool = False
    requires_specific_header: list[str] = field(default_factory=list)
    unknown_blockers: list[str] = field(default_factory=list)

    def has_unresolved(self) -> bool:
        return any(
            [
                self.requires_auth,
                self.requires_session,
                self.requires_csrf_token,
                self.requires_upload,
                bool(self.requires_specific_header),
                bool(self.unknown_blockers),
            ]
        )

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
        if self.requires_specific_header:
            parts.append(f"requires_specific_header={','.join(self.requires_specific_header)}")
        if self.unknown_blockers:
            parts.append(f"unknown_blockers={'; '.join(self.unknown_blockers)}")
        if not parts:
            return "typed_preconditions_unresolved: none"
        return f"typed_preconditions_unresolved: {', '.join(parts)}"


def parse_gate_preconditions(raw_values: list[str]) -> GatePreconditions:
    parsed = GatePreconditions()
    for raw in raw_values:
        text = _normalize_text(raw)
        if not text:
            continue
        lowered = text.casefold()

        if lowered == "runtime-oracle-not-applicable":
            continue
        if lowered == "auth-state-known":
            parsed.requires_auth = True
            continue

        if any(pattern.search(lowered) for pattern in _AUTH_NEGATION_PATTERNS):
            continue

        matched = False
        for pattern, header_name in _HEADER_REQUIREMENT_PATTERNS:
            if pattern.search(lowered):
                _unique_append(parsed.requires_specific_header, header_name)
                matched = True

        if "csrf" in lowered and "token" in lowered:
            parsed.requires_csrf_token = True
            matched = True

        if any(marker in lowered for marker in _UPLOAD_MARKERS):
            parsed.requires_upload = True
            matched = True

        if any(pattern.search(lowered) for pattern in _AUTH_REQUIRED_PATTERNS):
            parsed.requires_auth = True
            matched = True

        if any(pattern.search(lowered) for pattern in _SESSION_REQUIRED_PATTERNS):
            parsed.requires_session = True
            matched = True

        if matched:
            continue

        if any(marker in lowered for marker in _REQUEST_SHAPE_MARKERS):
            continue
        if any(marker in lowered for marker in _ENVIRONMENT_MARKERS):
            continue

        _unique_append(parsed.unknown_blockers, text)
    return parsed


def resolve_gate_preconditions(
    parsed: GatePreconditions,
    *,
    cookie_jar: dict[str, str] | None = None,
) -> GatePreconditions:
    resolved = GatePreconditions(
        requires_auth=parsed.requires_auth,
        requires_session=parsed.requires_session,
        requires_csrf_token=parsed.requires_csrf_token,
        requires_upload=parsed.requires_upload,
        requires_specific_header=list(parsed.requires_specific_header),
        unknown_blockers=list(parsed.unknown_blockers),
    )
    if cookie_jar:
        resolved.requires_auth = False
        resolved.requires_session = False
    return resolved


def coerce_gate_preconditions(value: GatePreconditions | list[str] | None) -> GatePreconditions:
    if isinstance(value, GatePreconditions):
        return value
    if not value:
        return GatePreconditions()
    return parse_gate_preconditions([str(item) for item in value])

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from typing import Any

from padv.config.schema import OracleConfig
from padv.models import OracleEvidence, RuntimeCall, RuntimeEvidence


class OracleParseError(ValueError):
    pass


@dataclass(slots=True)
class MorcillaRequestHeaders:
    key_header: str
    intercept_header: str
    correlation_header: str


def build_request_headers(
    oracle: OracleConfig,
    intercepts: list[str],
    correlation_id: str,
) -> MorcillaRequestHeaders:
    intercept_value = ", ".join(sorted({i for i in intercepts if i}))
    return MorcillaRequestHeaders(
        key_header=f"{oracle.request_key_header}: {oracle.api_key}",
        intercept_header=f"{oracle.request_intercept_header}: {intercept_value}",
        correlation_header=f"{oracle.request_correlation_header}: {correlation_id}",
    )


def _as_bool(value: str | None) -> bool:
    if value is None:
        return False
    return value.strip().lower() in {"1", "true", "yes", "y"}


def _parse_calls(payload: str, encoding: str) -> list[RuntimeCall]:
    if not payload:
        return []

    if encoding == "base64-json":
        try:
            decoded = base64.b64decode(payload, validate=True)
        except Exception as exc:  # pragma: no cover
            raise OracleParseError(f"invalid base64 payload: {exc}") from exc
        raw = decoded.decode("utf-8", errors="replace")
    elif encoding == "json":
        raw = payload
    else:  # pragma: no cover
        raise OracleParseError(f"unsupported encoding: {encoding}")

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise OracleParseError(f"invalid json payload: {exc}") from exc

    if not isinstance(data, list):
        raise OracleParseError("payload json must be an array")

    calls: list[RuntimeCall] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        function = str(item.get("function", ""))
        file_path = str(item.get("file", ""))
        line_value = item.get("line", 0)
        line = int(line_value) if isinstance(line_value, int) else 0
        args_raw = item.get("args", [])
        args = [str(a) for a in args_raw] if isinstance(args_raw, list) else []
        calls.append(RuntimeCall(function=function, file=file_path, line=line, args=args))

    return calls


def parse_response_headers(
    request_id: str,
    headers: dict[str, str],
    oracle: OracleConfig,
) -> RuntimeEvidence:
    normalized = {k.lower(): v for k, v in headers.items()}

    def get_header(name: str) -> str | None:
        return normalized.get(name.lower())

    status = get_header(oracle.response_status_header) or "inactive"
    call_count_raw = get_header(oracle.response_call_count_header) or "0"
    try:
        call_count = int(call_count_raw)
    except ValueError:
        call_count = 0

    overflow = _as_bool(get_header(oracle.response_overflow_header))
    arg_truncated = _as_bool(get_header(oracle.response_arg_truncated_header))
    result_truncated = _as_bool(get_header(oracle.response_result_truncated_header))
    correlation = get_header(oracle.response_correlation_header)
    payload = get_header(oracle.response_result_header) or ""

    calls: list[RuntimeCall] = []
    if payload:
        calls = _parse_calls(payload, oracle.result_encoding)

    if payload and oracle.result_encoding == "base64-json" and len(payload) > oracle.max_result_b64_len:
        result_truncated = True

    return RuntimeEvidence(
        request_id=request_id,
        status=status,
        call_count=call_count,
        overflow=overflow,
        arg_truncated=arg_truncated,
        result_truncated=result_truncated,
        correlation=correlation,
        calls=calls,
        raw_headers=headers,
        http_status=None,
        body_excerpt="",
        location="",
        analysis_flags=[],
        aux={},
    )


def sanitized_runtime_evidence(evidence: RuntimeEvidence) -> RuntimeEvidence:
    redacted_calls = []
    for call in evidence.calls:
        redacted_args = []
        for arg in call.args:
            if len(arg) <= 64:
                redacted_args.append(arg)
            else:
                redacted_args.append(arg[:24] + "..." + arg[-12:])
        redacted_calls.append(
            RuntimeCall(function=call.function, file=call.file, line=call.line, args=redacted_args)
        )

    return RuntimeEvidence(
        request_id=evidence.request_id,
        status=evidence.status,
        call_count=evidence.call_count,
        overflow=evidence.overflow,
        arg_truncated=evidence.arg_truncated,
        result_truncated=evidence.result_truncated,
        correlation=evidence.correlation,
        calls=redacted_calls,
        raw_headers={},
        http_status=evidence.http_status,
        body_excerpt=evidence.body_excerpt,
        location=evidence.location,
        analysis_flags=list(evidence.analysis_flags),
        aux=dict(evidence.aux),
        oracle_evidence=[
            OracleEvidence(
                correlation_id=item.correlation_id,
                function=item.function,
                file=item.file,
                line=item.line,
                full_args=list(item.full_args),
                display_args=list(item.display_args),
                matched_canary=bool(item.matched_canary),
            )
            for item in evidence.oracle_evidence
        ],
        request_evidence=evidence.request_evidence,
        response_evidence=evidence.response_evidence,
        witness_evidence=evidence.witness_evidence,
    )

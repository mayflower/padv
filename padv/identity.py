from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable


def _normalize_text(value: object) -> str:
    return " ".join(str(value).strip().casefold().split())


def _normalize_path(value: object) -> str:
    return str(value).strip().replace("\\", "/")


def _stable_tokens(values: Iterable[object]) -> list[str]:
    return sorted({_normalize_text(value) for value in values if _normalize_text(value)})


def candidate_uid_for_fields(
    *,
    vuln_class: str,
    file_path: str,
    line: int,
    sink: str,
    provenance: Iterable[object] = (),
) -> str:
    payload = {
        "vuln_class": _normalize_text(vuln_class),
        "file_path": _normalize_path(file_path),
        "location": f"{int(line)}-{int(line)}",
        "sink": _normalize_text(sink),
        "provenance": _stable_tokens(provenance),
    }
    digest = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    ).hexdigest()[:20]
    return f"cuid-{digest}"

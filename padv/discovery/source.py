from __future__ import annotations

import hashlib
import re
from pathlib import Path

from padv.config.schema import PadvConfig
from padv.models import Candidate, StaticEvidence
from padv.path_scope import is_app_candidate_path, normalize_repo_path
from padv.static.joern.query_sets import VULN_CLASS_SPECS, VulnClassSpec


_SPEC_BY_CLASS = {spec.vuln_class: spec for spec in VULN_CLASS_SPECS}
_FUNC_DEF_RE = re.compile(r"^\s*function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(")


def _hash_for(file_path: str, line: int, text: str) -> str:
    payload = f"source:{file_path}:{line}:{text}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()[:16]


def _looks_like_php(path: Path) -> bool:
    return path.suffix.lower() in {
        ".php",
        ".phtml",
        ".inc",
        ".php3",
        ".php4",
        ".php5",
        ".php7",
        ".php8",
        ".module",
        ".install",
        ".theme",
    }


def _preconditions_for_spec(spec: VulnClassSpec, config: PadvConfig) -> list[str]:
    preconditions: list[str] = []
    if config.auth.enabled:
        preconditions.append("auth-state-known")
    if not spec.runtime_validatable:
        preconditions.append("runtime-oracle-not-applicable")
    return preconditions


def _find_entrypoint_hint(lines: list[str], line_no: int) -> str | None:
    idx = max(0, line_no - 1)
    for cursor in range(idx, -1, -1):
        match = _FUNC_DEF_RE.match(lines[cursor])
        if match:
            return match.group(1)
    return None


def discover_source_candidates(repo_root: str, config: PadvConfig) -> tuple[list[Candidate], list[StaticEvidence]]:
    root = Path(repo_root)
    if not root.exists():
        raise FileNotFoundError(f"repo root does not exist: {repo_root}")

    candidates: list[Candidate] = []
    static_evidence: list[StaticEvidence] = []
    next_idx = 1

    for path in root.rglob("*"):
        if len(candidates) >= config.budgets.max_candidates:
            break
        if not path.is_file() or not _looks_like_php(path):
            continue

        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        lines = text.splitlines()
        rel_path = normalize_repo_path(str(path.relative_to(root)))
        if not is_app_candidate_path(rel_path):
            continue
        for line_no, line in enumerate(lines, start=1):
            line_lower = line.casefold()
            for spec in VULN_CLASS_SPECS:
                if len(candidates) >= config.budgets.max_candidates:
                    break
                pattern = next((p for p in spec.sink_patterns if p.casefold() in line_lower), None)
                if not pattern:
                    continue

                candidate_id = f"source-{next_idx:05d}"
                next_idx += 1
                snippet = line.strip()[:240]
                evidence_id = f"source::{spec.vuln_class}:{rel_path}:{line_no}"
                entrypoint = _find_entrypoint_hint(lines, line_no)

                candidate = Candidate(
                    candidate_id=candidate_id,
                    vuln_class=spec.vuln_class,
                    title=f"{spec.owasp_id} {spec.description}",
                    file_path=rel_path,
                    line=line_no,
                    sink=pattern,
                    expected_intercepts=list(spec.intercepts),
                    entrypoint_hint=entrypoint,
                    preconditions=_preconditions_for_spec(spec, config),
                    notes="source research detector",
                    provenance=["source"],
                    evidence_refs=[evidence_id],
                    confidence=0.45,
                    auth_requirements=(["login"] if config.auth.enabled else []),
                    web_path_hints=[],
                )

                evidence = StaticEvidence(
                    candidate_id=candidate_id,
                    query_profile=config.joern.query_profile,
                    query_id=f"source::{spec.vuln_class}",
                    file_path=rel_path,
                    line=line_no,
                    snippet=snippet,
                    hash=_hash_for(rel_path, line_no, snippet),
                )

                candidates.append(candidate)
                static_evidence.append(evidence)
                break

    return candidates, static_evidence

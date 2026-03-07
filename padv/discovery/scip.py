from __future__ import annotations

import hashlib
import json
import re
import shlex
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from time import time

from padv.config.schema import PadvConfig
from padv.models import Candidate, StaticEvidence
from padv.path_scope import is_app_candidate_path, normalize_repo_path
from padv.static.joern.query_sets import VULN_CLASS_SPECS, VulnClassSpec


class ScipExecutionError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class ScipSymbolHit:
    file_path: str
    line: int
    symbol: str
    vuln_class: str


_SPEC_BY_CLASS = {spec.vuln_class: spec for spec in VULN_CLASS_SPECS}


def _hash_for(file_path: str, line: int, text: str) -> str:
    payload = f"scip:{file_path}:{line}:{text}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()[:16]


def _preconditions_for_spec(spec: VulnClassSpec, config: PadvConfig) -> list[str]:
    preconditions: list[str] = []
    if config.auth.enabled:
        preconditions.append("auth-state-known")
    if not spec.runtime_validatable:
        preconditions.append("runtime-oracle-not-applicable")
    return preconditions


def _collect_created_scip_files(base_dir: Path, started_at: float) -> list[Path]:
    files: list[Path] = []
    for path in base_dir.rglob("*.scip"):
        try:
            if path.stat().st_mtime >= started_at:
                files.append(path)
        except OSError:
            continue
    return sorted(files)


def _run_command(cmd: str, cwd: Path, timeout_seconds: int) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            shlex.split(cmd),
            cwd=str(cwd),
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout_seconds,
        )
    except OSError as exc:
        raise ScipExecutionError(f"unable to execute command '{cmd}': {exc}") from exc
    except subprocess.TimeoutExpired as exc:
        raise ScipExecutionError(f"command timed out ({timeout_seconds}s): {cmd}") from exc


def _run_scip_generate(repo_root: Path, config: PadvConfig, artifact_dir: Path) -> Path:
    artifact_dir.mkdir(parents=True, exist_ok=True)

    started_at = time()
    proc = _run_command(config.scip.command, repo_root, config.scip.timeout_seconds)
    if proc.returncode != 0:
        stderr = (proc.stderr or "").strip()
        stdout = (proc.stdout or "").strip()
        msg = stderr or stdout or "scip command failed"
        raise ScipExecutionError(f"scip indexing failed ({proc.returncode}): {msg}")

    candidates = _collect_created_scip_files(repo_root, started_at)
    if not candidates:
        candidates = sorted(repo_root.rglob("*.scip"))
    if not candidates:
        raise ScipExecutionError("scip command completed but no .scip artifact was produced")

    source = candidates[-1]
    target = artifact_dir / source.name
    if source.resolve() != target.resolve():
        shutil.copy2(source, target)
    return target


def _run_scip_print(scip_file: Path, config: PadvConfig, repo_root: Path) -> str:
    if not config.scip.print_command.strip():
        return ""
    print_cmd = f"{config.scip.print_command} {shlex.quote(str(scip_file))}"
    proc = _run_command(print_cmd, repo_root, config.scip.timeout_seconds)
    if proc.returncode != 0:
        stderr = (proc.stderr or "").strip()
        stdout = (proc.stdout or "").strip()
        msg = stderr or stdout or "scip print failed"
        raise ScipExecutionError(f"scip print failed ({proc.returncode}): {msg}")
    return proc.stdout or ""


def _match_vuln_class(symbol: str) -> str | None:
    normalized = symbol.casefold()
    compact_symbol = re.sub(r"[^a-z0-9_$]", "", normalized)
    best_class: str | None = None
    best_score = -1
    for spec in VULN_CLASS_SPECS:
        for pattern in spec.sink_patterns:
            raw = pattern.replace("(", "").replace(")", "").replace("->", "::").casefold().strip()
            if not raw:
                continue

            candidates = {raw}
            candidates.add(raw.replace(" ", ""))
            candidates.add(re.sub(r"[^a-z0-9_$]", "", raw))
            if "::" in raw:
                candidates.add(raw.split("::", 1)[1])
            if raw.startswith("$_get") or raw.startswith("$_post") or raw.startswith("$_session"):
                candidates.add(raw.split("[", 1)[0])
            if raw.startswith("echo"):
                candidates.add("echo")

            for token in sorted(c for c in candidates if c):
                compact_token = re.sub(r"[^a-z0-9_$]", "", token)
                matched = False
                if token in normalized:
                    matched = True
                elif compact_token and compact_token in compact_symbol:
                    matched = True
                elif compact_token and compact_symbol.startswith(compact_token):
                    matched = True
                if not matched:
                    continue

                score = len(compact_token or token)
                if score > best_score:
                    best_score = score
                    best_class = spec.vuln_class
    return best_class


def _iter_documents(payload: object) -> list[tuple[str, list[dict[str, object]]]]:
    if isinstance(payload, dict) and isinstance(payload.get("documents"), list):
        docs = payload["documents"]
    elif isinstance(payload, list):
        docs = payload
    else:
        return []

    out: list[tuple[str, list[dict[str, object]]]] = []
    for doc in docs:
        if not isinstance(doc, dict):
            continue
        path = str(doc.get("relative_path", "")).strip() or str(doc.get("path", "")).strip()
        occurrences = doc.get("occurrences")
        if not path or not isinstance(occurrences, list):
            continue
        filtered: list[dict[str, object]] = [o for o in occurrences if isinstance(o, dict)]
        out.append((path, filtered))
    return out


def _extract_hits(print_stdout: str) -> list[ScipSymbolHit]:
    if isinstance(print_stdout, tuple) and len(print_stdout) == 1 and isinstance(print_stdout[0], str):
        print_stdout = print_stdout[0]
    payload: object
    try:
        payload = json.loads(print_stdout)
    except json.JSONDecodeError:
        rows: list[object] = []
        for raw_line in print_stdout.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        payload = rows

    hits: list[ScipSymbolHit] = []
    seen: set[tuple[str, int, str, str]] = set()
    for file_path, occurrences in _iter_documents(payload):
        for occ in occurrences:
            symbol = str(occ.get("symbol", "")).strip()
            vuln_class = _match_vuln_class(symbol)
            if not vuln_class:
                continue

            line_no = 1
            range_value = occ.get("range")
            if isinstance(range_value, list) and range_value:
                first = range_value[0]
                if isinstance(first, int):
                    line_no = first + 1

            key = (file_path, line_no, symbol, vuln_class)
            if key in seen:
                continue
            seen.add(key)
            hits.append(
                ScipSymbolHit(
                    file_path=file_path,
                    line=line_no,
                    symbol=symbol,
                    vuln_class=vuln_class,
                )
            )
    return hits


def discover_scip_candidates(
    repo_root: str,
    config: PadvConfig,
) -> tuple[list[Candidate], list[StaticEvidence], list[str]]:
    if not config.scip.enabled:
        return [], [], []

    root = Path(repo_root)
    if not root.exists():
        raise FileNotFoundError(f"repo root does not exist: {repo_root}")

    artifact_root = Path(config.scip.artifact_dir)
    if not artifact_root.is_absolute():
        artifact_root = root / artifact_root
    artifact_root.mkdir(parents=True, exist_ok=True)

    artifact_refs: list[str] = []
    scip_file = _run_scip_generate(root, config, artifact_root)
    artifact_refs.append(str(scip_file))

    print_stdout = _run_scip_print(scip_file, config, root)
    hits = _extract_hits(print_stdout)

    candidates: list[Candidate] = []
    evidence: list[StaticEvidence] = []
    for idx, hit in enumerate(hits, start=1):
        if len(candidates) >= config.budgets.max_candidates:
            break
        spec = _SPEC_BY_CLASS.get(hit.vuln_class)
        if spec is None:
            continue
        rel_path = normalize_repo_path(hit.file_path, repo_root=root)
        if not rel_path or not is_app_candidate_path(rel_path):
            continue

        candidate_id = f"scip-{idx:05d}"
        evidence_id = f"scip::{hit.vuln_class}:{rel_path}:{hit.line}"
        snippet = hit.symbol[:240]
        candidates.append(
            Candidate(
                candidate_id=candidate_id,
                vuln_class=spec.vuln_class,
                title=f"{spec.owasp_id} {spec.description}",
                file_path=rel_path,
                line=hit.line,
                sink=hit.symbol or "scip-symbol",
                expected_intercepts=list(spec.intercepts),
                entrypoint_hint=None,
                preconditions=_preconditions_for_spec(spec, config),
                notes="scip semantic detector",
                provenance=["scip"],
                evidence_refs=[evidence_id],
                confidence=0.55,
                auth_requirements=(["login"] if config.auth.enabled else []),
                web_path_hints=[],
            )
        )
        evidence.append(
            StaticEvidence(
                candidate_id=candidate_id,
                query_profile=config.joern.query_profile,
                query_id=f"scip::{spec.vuln_class}",
                file_path=rel_path,
                line=hit.line,
                snippet=snippet,
                hash=_hash_for(rel_path, hit.line, snippet),
            )
        )

    return candidates, evidence, artifact_refs


def discover_scip_candidates_safe(
    repo_root: str,
    config: PadvConfig,
) -> tuple[list[Candidate], list[StaticEvidence], list[str], str | None]:
    try:
        candidates, evidence, refs = discover_scip_candidates(repo_root, config)
        return candidates, evidence, refs, None
    except Exception as exc:
        raise ScipExecutionError(str(exc)) from exc

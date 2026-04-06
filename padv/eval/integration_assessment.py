from __future__ import annotations

from dataclasses import dataclass
from typing import Any


VALID_STATUSES = {"FULL", "PARTIAL", "NONE", "FAIL"}


@dataclass(slots=True)
class RequirementResult:
    requirement_id: str
    scenario: str
    observed_result: str
    evidence_path: str
    status: str
    root_cause: str
    next_fix: str

    def to_dict(self) -> dict[str, Any]:
        status = self.status.strip().upper()
        if status not in VALID_STATUSES:
            status = "FAIL"
        return {
            "requirement_id": self.requirement_id,
            "scenario": self.scenario,
            "observed_result": self.observed_result,
            "evidence_path": self.evidence_path,
            "status": status,
            "root_cause": self.root_cause,
            "next_fix": self.next_fix,
        }


def classify_failure(message: str) -> str:
    text = (message or "").casefold()
    if not text.strip():
        return "unknown"
    if "deepagents" in text or "langgraph" in text or "agent" in text:
        return "agent"
    if "config" in text or "toml" in text or "missing or invalid section" in text:
        return "config"
    if "permission denied" in text or "no such file" in text or "traceback" in text or "ioerror" in text or "input/output error" in text:
        return "io"
    if "joern" in text or "scip" in text or "web discovery failed" in text or "playwright" in text:
        return "discovery_channel"
    if "timeout" in text or "connection" in text or "network" in text or "dns" in text or "refused" in text:
        return "network"
    return "unknown"


def prioritize_gap(requirement_id: str, status: str) -> str:
    norm_id = requirement_id.strip().upper()
    norm_status = status.strip().upper()
    if norm_status == "FULL":
        return ""

    if norm_id in {"CORE-INFRA", "CORE-ANALYZE", "CORE-RUN"}:
        return "P1"
    if norm_id.startswith("CORE-") and norm_status == "FAIL":
        return "P1"
    if norm_id.startswith("CORE-"):
        return "P2"
    if norm_id.startswith("E"):
        return "P2"
    return "P3"


def matrix_to_gap_list(matrix: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for row in matrix:
        rid = str(row.get("requirement_id", "")).strip()
        status = str(row.get("status", "FAIL")).strip().upper()
        if not rid or status == "FULL":
            continue
        out.append(
            {
                "priority": prioritize_gap(rid, status),
                "requirement_id": rid,
                "status": status,
                "root_cause": str(row.get("root_cause", "")),
                "next_fix": str(row.get("next_fix", "")),
            }
        )
    priority_rank = {"P1": 1, "P2": 2, "P3": 3, "": 9}
    out.sort(key=lambda item: (priority_rank.get(item["priority"], 9), item["requirement_id"]))
    return out

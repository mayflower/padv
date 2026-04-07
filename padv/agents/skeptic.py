from __future__ import annotations

import json
import re
from dataclasses import asdict
from typing import Any

from padv.models import CandidateSeed
from padv.store.evidence_store import EvidenceStore
from padv.agents.proposer import propose_candidates_from_index


class SkepticError(Exception):
    pass


def review_candidates(
    llm: Any,
    seeds: list[CandidateSeed],
    repo_index: dict[str, Any],
    store: EvidenceStore,
    run_id: str,
) -> list[CandidateSeed]:
    if not seeds:
        return []
        
    prompt = f"""
    Review these CandidateSeeds based on the RepoIndex.
    Return ONLY a JSON array of objects conforming to this schema:
    [
        {{
            "seed_id": "string (must match input)",
            "decision": "ACCEPT" | "REJECT",
            "reason": "string (typed reason, e.g. 'valid_hypothesis', 'no_sink', 'unreachable')",
            "vuln_class_override": "string (optional)",
            "add_static_checks": ["string"]
        }}
    ]
    
    Candidates:
    {json.dumps([asdict(s) for s in seeds], indent=2)}
    
    RepoIndex:
    {json.dumps(repo_index)[:2000]}
    """
    
    response = llm.invoke([("user", prompt)])
    content = response.content
    
    match = re.search(r'```(?:json)?\s*(\[\s*\{.*?\}\s*\])\s*```', content, re.DOTALL)
    if match:
        json_str = match.group(1)
    else:
        json_str = content
        
    try:
        data = json.loads(json_str)
    except json.JSONDecodeError as e:
        raise SkepticError(f"Failed to parse JSON: {e}")
        
    if not isinstance(data, list):
        raise SkepticError("Schema validation failed: root must be a list")
        
    seed_map = {s.seed_id: s for s in seeds}
    accepted = []
    
    for item in data:
        if not isinstance(item, dict):
            raise SkepticError("Schema validation failed: items must be dicts")
            
        required = ["seed_id", "decision", "reason"]
        for req in required:
            if req not in item:
                raise SkepticError(f"Schema validation failed: missing required field '{req}'")
                
        if item["decision"] not in ("ACCEPT", "REJECT"):
            raise SkepticError("Schema validation failed: decision must be ACCEPT or REJECT")
            
        seed_id = item["seed_id"]
        if seed_id not in seed_map:
            continue
            
        if item["decision"] == "ACCEPT":
            seed = seed_map[seed_id]
            
            override = item.get("vuln_class_override")
            if override:
                seed.vuln_class = override
                
            added_checks = item.get("add_static_checks", [])
            if isinstance(added_checks, list):
                for check in added_checks:
                    if check not in seed.requested_static_checks:
                        seed.requested_static_checks.append(check)
                        
            accepted.append(seed)
            
    run_store = store.for_run(run_id)
    run_store.save_json_artifact("skeptic_decisions.json", data)
    return accepted


def _seed_signature(seed: CandidateSeed) -> str:
    return f"{seed.vuln_class}:{seed.file_path}:{seed.symbol}"


def multi_trajectory_discovery(
    llm: Any,
    repo_index: dict[str, Any],
    store: EvidenceStore,
    run_id: str,
    max_rounds: int = 3,
    max_stagnation: int = 1,
) -> dict[str, Any]:
    accepted_signatures = set()
    accepted_seeds = []
    
    rounds_executed = 0
    stagnant_rounds = 0
    stop_reason = "max_rounds_reached"
    
    for round_idx in range(max_rounds):
        rounds_executed += 1
        
        # Propose
        proposed = propose_candidates_from_index(llm, repo_index, store, run_id)
        
        # Deduplicate proposed before Skeptic (save LLM calls)
        novel_proposed = []
        for p in proposed:
            sig = _seed_signature(p)
            if sig not in accepted_signatures:
                novel_proposed.append(p)
                
        # Skeptic
        reviewed = review_candidates(llm, novel_proposed, repo_index, store, run_id)
        
        round_novel = 0
        for r in reviewed:
            sig = _seed_signature(r)
            if sig not in accepted_signatures:
                accepted_signatures.add(sig)
                accepted_seeds.append(r)
                round_novel += 1
                
        if round_novel == 0:
            stagnant_rounds += 1
        else:
            stagnant_rounds = 0
            
        if stagnant_rounds >= max_stagnation:
            stop_reason = "stagnation"
            break
            
    return {
        "accepted_seeds": accepted_seeds,
        "rounds_executed": rounds_executed,
        "stop_reason": stop_reason,
    }

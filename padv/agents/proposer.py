from __future__ import annotations

import json
import re
from dataclasses import asdict
from typing import Any
from uuid import uuid4

from padv.models import CandidateSeed
from padv.store.evidence_store import EvidenceStore


class ProposerError(Exception):
    pass


def propose_candidates_from_index(
    llm: Any,
    repo_index: dict[str, Any],
    store: EvidenceStore,
    run_id: str,
) -> list[CandidateSeed]:
    prompt = f"""
    Given this repository index, identify potential vulnerabilities.
    Return ONLY a JSON array of objects conforming to this schema:
    [
        {{
            "vuln_class": "string",
            "file_path": "string",
            "symbol": "string",
            "entrypoint_hint": "string (optional)",
            "why": "string",
            "requested_static_checks": ["string"]
        }}
    ]
    
    Index summary:
    {json.dumps(repo_index)[:2000]} # Truncated for this test example
    """
    
    response = llm.invoke([("user", prompt)])
    content = response.content
    
    # Extract json block if present
    match = re.search(r'```(?:json)?\s*(\[\s*\{.*?\}\s*\])\s*```', content, re.DOTALL)
    if match:
        json_str = match.group(1)
    else:
        json_str = content
        
    try:
        data = json.loads(json_str)
    except json.JSONDecodeError as e:
        raise ProposerError(f"Failed to parse JSON: {e}")
        
    if not isinstance(data, list):
        raise ProposerError("Schema validation failed: root must be a list")
        
    seeds = []
    for item in data:
        if not isinstance(item, dict):
            raise ProposerError("Schema validation failed: items must be dicts")
            
        # Check required fields
        required = ["vuln_class", "file_path", "symbol", "why", "requested_static_checks"]
        for req in required:
            if req not in item:
                raise ProposerError(f"Schema validation failed: missing required field '{req}'")
                
        seed_id = f"seed-{uuid4().hex[:10]}"
        seeds.append(CandidateSeed(
            seed_id=seed_id,
            vuln_class=item["vuln_class"],
            file_path=item["file_path"],
            symbol=item["symbol"],
            entrypoint_hint=item.get("entrypoint_hint"),
            why=item["why"],
            requested_static_checks=item["requested_static_checks"]
        ))
        
    run_store = store.for_run(run_id)
    run_store.save_json_artifact("candidate_seeds.json", [asdict(s) for s in seeds])
    return seeds

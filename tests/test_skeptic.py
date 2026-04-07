from __future__ import annotations

import json
from pathlib import Path
import pytest

from padv.models import CandidateSeed
from padv.agents.skeptic import review_candidates, SkepticError, multi_trajectory_discovery
from padv.store.evidence_store import EvidenceStore

class FakeLLM:
    def __init__(self, responses: list[str]):
        self.responses = responses
        self.calls = 0

    def invoke(self, messages, **kwargs):
        if self.calls >= len(self.responses):
            response_text = self.responses[-1]
        else:
            response_text = self.responses[self.calls]
        self.calls += 1
        class FakeResponse:
            content = response_text
        return FakeResponse()

def test_skeptic_parses_valid_json_decisions(tmp_path: Path):
    store = EvidenceStore(tmp_path / ".padv")
    run_id = "test-run"
    repo_index = {"files": [], "symbols": [], "sink_callsites": []}
    
    seeds = [
        CandidateSeed(
            seed_id="seed-1",
            vuln_class="sql_injection",
            file_path="a.php",
            symbol="a",
            why="test",
            requested_static_checks=[]
        )
    ]
    
    valid_json = """
    ```json
    [
      {
        "seed_id": "seed-1",
        "decision": "ACCEPT",
        "reason": "valid_hypothesis",
        "add_static_checks": ["owasp_php.sc"]
      }
    ]
    ```
    """
    
    llm = FakeLLM([valid_json])
    
    reviewed = review_candidates(llm, seeds, repo_index, store, run_id)
    assert len(reviewed) == 1
    assert "owasp_php.sc" in reviewed[0].requested_static_checks

def test_skeptic_fails_closed_on_invalid_schema(tmp_path: Path):
    store = EvidenceStore(tmp_path / ".padv")
    run_id = "test-run"
    seeds = [
        CandidateSeed("seed-1", "sql", "a.php", "a", "test", [])
    ]
    
    invalid_schema = """
    [
      {
        "seed_id": "seed-1",
        "decision": "MAYBE"
      }
    ]
    """
    llm = FakeLLM([invalid_schema])
    
    with pytest.raises(SkepticError, match="Schema validation"):
        review_candidates(llm, seeds, {}, store, run_id)

def test_deterministic_merge_and_stagnation(tmp_path: Path):
    store = EvidenceStore(tmp_path / ".padv")
    run_id = "test-run"
    repo_index = {"files": [], "symbols": [], "sink_callsites": []}
    
    # Round 1: Proposer returns seed A. Skeptic accepts A.
    # Round 2: Proposer returns seed A again. Skeptic accepts A. -> Stagnation!
    
    proposer_json = """
    ```json
    [
      {
        "vuln_class": "sql_injection",
        "file_path": "a.php",
        "symbol": "a",
        "why": "test",
        "requested_static_checks": []
      }
    ]
    ```
    """
    
    # Skeptic will just receive the proposed seeds and must output decisions matching their IDs.
    # We can fake the skeptic output dynamically or just use a catch-all fake that accepts everything.
    class SmartFakeLLM:
        def invoke(self, messages, **kwargs):
            prompt = str(messages[0][1])
            if "identify potential vulnerabilities" in prompt:
                # Proposer
                class FakeR: content = proposer_json
                return FakeR()
            else:
                # Skeptic
                # Extract seed IDs from the prompt to accept them
                import re
                ids = re.findall(r'"seed_id": "(seed-[a-f0-9]+)"', prompt)
                decisions = []
                for sid in ids:
                    decisions.append({
                        "seed_id": sid,
                        "decision": "ACCEPT",
                        "reason": "valid_hypothesis",
                        "add_static_checks": []
                    })
                class FakeR: content = json.dumps(decisions)
                return FakeR()
                
    llm = SmartFakeLLM()
    
    result = multi_trajectory_discovery(llm, repo_index, store, run_id, max_rounds=5, max_stagnation=1)
    
    assert len(result["accepted_seeds"]) == 1
    assert result["rounds_executed"] == 2
    assert result["stop_reason"] == "stagnation"

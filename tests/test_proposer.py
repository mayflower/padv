from __future__ import annotations

import json
from pathlib import Path
import pytest

from padv.models import CandidateSeed
from padv.agents.proposer import propose_candidates_from_index, ProposerError
from padv.store.evidence_store import EvidenceStore

class FakeLLM:
    def __init__(self, response_text: str):
        self.response_text = response_text
        self.calls = []

    def invoke(self, messages, **kwargs):
        self.calls.append((messages, kwargs))
        class FakeResponse:
            content = self.response_text
        return FakeResponse()

def test_proposer_parses_valid_json_seeds(tmp_path: Path):
    store = EvidenceStore(tmp_path / ".padv")
    run_id = "test-run"
    repo_index = {"files": [], "symbols": [], "sink_callsites": []}
    
    valid_json = """
    ```json
    [
      {
        "vuln_class": "sql_injection_boundary",
        "file_path": "login.php",
        "symbol": "authenticate",
        "entrypoint_hint": "POST /login.php",
        "why": "Looks like user input goes to DB",
        "requested_static_checks": ["owasp_php.sc"]
      }
    ]
    ```
    """
    
    llm = FakeLLM(valid_json)
    
    seeds = propose_candidates_from_index(llm, repo_index, store, run_id)
    assert len(seeds) == 1
    assert seeds[0].vuln_class == "sql_injection_boundary"
    assert seeds[0].file_path == "login.php"
    assert seeds[0].symbol == "authenticate"
    assert "owasp_php.sc" in seeds[0].requested_static_checks

def test_proposer_fails_closed_on_invalid_json(tmp_path: Path):
    store = EvidenceStore(tmp_path / ".padv")
    run_id = "test-run"
    repo_index = {"files": [], "symbols": [], "sink_callsites": []}
    
    invalid_json = "This is not json."
    llm = FakeLLM(invalid_json)
    
    with pytest.raises(ProposerError, match="Failed to parse JSON"):
        propose_candidates_from_index(llm, repo_index, store, run_id)

def test_proposer_fails_closed_on_invalid_schema(tmp_path: Path):
    store = EvidenceStore(tmp_path / ".padv")
    run_id = "test-run"
    repo_index = {"files": [], "symbols": [], "sink_callsites": []}
    
    # Missing required 'file_path'
    invalid_schema = """
    [
      {
        "vuln_class": "sql_injection_boundary",
        "symbol": "authenticate",
        "why": "Missing file_path",
        "requested_static_checks": []
      }
    ]
    """
    llm = FakeLLM(invalid_schema)
    
    with pytest.raises(ProposerError, match="Schema validation"):
        propose_candidates_from_index(llm, repo_index, store, run_id)

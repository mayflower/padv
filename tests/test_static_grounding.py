from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from padv.config.schema import load_config
from padv.models import CandidateSeed
from padv.discovery.static_grounding import ground_seeds_with_joern

@dataclass
class FakeFinding:
    query_id: str
    file_path: str
    line: int
    snippet: str

class FakeJoernRunner:
    def __init__(self, findings_by_file: dict[str, list[FakeFinding]]):
        self.findings = findings_by_file
        
    def run_checks(self, file_path: str, checks: list[str]) -> list[FakeFinding]:
        return self.findings.get(file_path, [])

def test_unsupported_seed_is_rejected():
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    seeds = [
        CandidateSeed(
            seed_id="seed-1",
            vuln_class="sql_injection_boundary",
            file_path="login.php",
            symbol="auth",
            why="test",
            requested_static_checks=["owasp_php.sc"]
        )
    ]
    
    # Returns no findings
    runner = FakeJoernRunner({})
    
    candidates, evidence, rejected = ground_seeds_with_joern(seeds, runner, config)
    
    assert len(candidates) == 0
    assert len(evidence) == 0
    assert len(rejected) == 1
    assert rejected[0].seed_id == "seed-1"

def test_supported_seed_becomes_candidate():
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    seeds = [
        CandidateSeed(
            seed_id="seed-2",
            vuln_class="command_injection_boundary",
            file_path="exec.php",
            symbol="do_exec",
            why="test",
            requested_static_checks=["owasp_php.sc"]
        )
    ]
    
    runner = FakeJoernRunner({
        "exec.php": [
            FakeFinding("joern::cmd_boundary", "exec.php", 10, "exec($cmd)")
        ]
    })
    
    candidates, evidence, rejected = ground_seeds_with_joern(seeds, runner, config)
    
    assert len(rejected) == 0
    assert len(candidates) == 1
    assert len(evidence) == 1
    
    c = candidates[0]
    assert c.vuln_class == "command_injection_boundary"
    assert c.file_path == "exec.php"
    assert c.candidate_uid != ""
    assert "joern::cmd_boundary:exec.php:10" in c.static_evidence_refs
    assert evidence[0].candidate_uid == c.candidate_uid

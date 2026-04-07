from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from threading import Thread
import pytest

from padv.config.schema import load_config
from padv.discovery.repo_index import build_repo_index
from padv.agents.proposer import propose_candidates_from_index
from padv.discovery.static_grounding import ground_seeds_with_joern
from padv.store.evidence_store import EvidenceStore
from padv.models import CandidateSeed, ValidationPlan, HttpStep, HttpExpectations
from padv.orchestrator.runtime import validate_candidates_runtime
from padv.eval.coverage import evaluate_run_coverage


class MockTargetServer(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/login":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"login page")
            return
            
        cookie = self.headers.get("Cookie", "")
        if "session=valid" not in cookie:
            self.send_response(302)
            self.send_header("Location", "/login")
            self.end_headers()
            return
            
        if self.path.startswith("/api/data"):
            # If authenticated and parameter id has canary, we fire a mock oracle hit
            from urllib.parse import urlparse, parse_qs
            parsed = urlparse(self.path)
            qs = parse_qs(parsed.query)
            q_id = qs.get("id", [""])[0]
            print(f"DEBUG: Server received q_id={q_id}")
            
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            
            # Fire an oracle intercept report for mysqli_query if canary is present
            if q_id:
                # We format the headers exactly as Morcilla would send them
                self.send_header("X-Morcilla-Status", "active")
                self.send_header("X-Morcilla-Call-Count", "1")
                # Base64 encoded JSON of the intercept report
                # InterceptReport schema: [{correlation_id, function, file, line, args: [arg]}]
                report = [{
                    "correlation_id": "c1",
                    "function": "mysqli_query",
                    "file": "/var/www/html/api.php",
                    "line": 42,
                    "args": [f"SELECT * FROM data WHERE id='{q_id}'"]
                }]
                import base64
                encoded = base64.b64encode(json.dumps(report).encode("utf-8")).decode("utf-8")
                self.send_header("X-Morcilla-Result", encoded)
            
            self.end_headers()
            if q_id == "padv_canary":
                self.wfile.write(b'{"status":"error"}')
            else:
                self.wfile.write(b'{"status":"ok"}')
            return
            
        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        if self.path == "/login":
            self.send_response(302)
            self.send_header("Set-Cookie", "session=valid; HttpOnly")
            self.send_header("Location", "/dashboard")
            self.end_headers()
        else:
            self.send_response(403)
            self.end_headers()


@pytest.fixture(scope="module")
def mock_server():
    server = HTTPServer(("localhost", 0), MockTargetServer)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://localhost:{server.server_port}"
    server.shutdown()


class FakeLLM:
    def __init__(self, response_text: str):
        self.response_text = response_text
    def invoke(self, messages, **kwargs):
        class FakeResponse:
            content = self.response_text
            model_name = "fake-model"
        return FakeResponse()


class FakeJoernRunner:
    def run_checks(self, file_path: str, checks: list[str]):
        class FakeFinding:
            query_id = "joern::sql_injection"
            file_path = "/var/www/html/api.php"
            line = 42
            snippet = "mysqli_query($conn, $sql);"
        return [FakeFinding()]


@pytest.mark.integration
def test_agentic_discovery_to_validate_only(tmp_path: Path, mock_server: str, monkeypatch):
    store = EvidenceStore(tmp_path / ".padv")
    run_id = "test-run-agentic"
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    config.target.base_url = mock_server
    
    # Disable cache for tests to be deterministic
    config.agent.deterministic_mode = True

    # 1. Build RepoIndex (we fake the repo_root contents)
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    (repo_root / "api.php").write_text("<?php\nfunction get_data() {\n  mysqli_query('SELECT * FROM data WHERE id=' . $_GET['id']);\n}\n")
    
    # Mock joern_is_available so it doesn't fail
    import padv.discovery.repo_index
    monkeypatch.setattr(padv.discovery.repo_index, "joern_is_available", lambda: True)
    repo_index = build_repo_index(run_id, "sha", config, str(repo_root), store)
    assert any(f["path"] == "api.php" for f in repo_index["files"])

    # 2. Propose Candidates
    valid_json = """
    ```json
    [
      {
        "vuln_class": "sql_injection_boundary",
        "file_path": "api.php",
        "symbol": "get_data",
        "entrypoint_hint": "/api/data",
        "why": "SQLi in api.php",
        "requested_static_checks": ["owasp_php.sc"]
      }
    ]
    ```
    """
    llm = FakeLLM(valid_json)
    seeds = propose_candidates_from_index(llm, repo_index, store, run_id)
    assert len(seeds) == 1
    
    # 3. Grounding via static stub
    joern_runner = FakeJoernRunner()
    candidates, static_evidence, rejected = ground_seeds_with_joern(seeds, joern_runner, config)
    assert len(candidates) == 1
    assert len(rejected) == 0
    candidate = candidates[0]
    
    # 4. Validate-only path (no research loops)
    # We craft a plan to trigger the SQLi via the discovered entrypoint
    plan = ValidationPlan(
        candidate_id=candidate.candidate_id,
        intercepts=["mysqli_query"],
        positive_requests=[
            {
                "method": "GET",
                "path": "/api/data",
                "query": {"id": config.canary.parameter_name}
            },
            {
                "method": "GET",
                "path": "/api/data",
                "query": {"id": config.canary.parameter_name}
            }
        ],
        negative_requests=[{
            "method": "GET",
            "path": "/api/data",
            "query": {"id": "benign_id"}
        }],
        canary=config.canary.parameter_name
    )    
    auth_state = {
        "context": "authenticated",
        "cookies": {"session": "valid"}
    }
    
    bundles, decisions = validate_candidates_runtime(
        config=config,
        store=store,
        static_evidence=static_evidence,
        candidates=candidates,
        run_id=run_id,
        plans_by_candidate={candidate.candidate_id: plan},
        auth_state=auth_state,
        planner_trace={"proposer": {"hypotheses": []}} # Just empty struct
    )
    
    assert len(bundles) == 1
    bundle = bundles[0]
    print(f"Gate result: {bundle.gate_result}, limitations: {bundle.limitations}")
    assert bundle.gate_result.decision == "VALIDATED"
    assert bundle.candidate_outcome == "VALIDATED"
    
    # Coverage test integration
    coverage = evaluate_run_coverage(bundles)
    assert coverage["sql_injection_boundary"] == "FULL"

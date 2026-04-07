from __future__ import annotations

import json
from pathlib import Path

from padv.config.schema import load_config
from padv.discovery.repo_index import build_repo_index
from padv.store.evidence_store import EvidenceStore

def test_build_repo_index_determinism(tmp_path: Path):
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    store = EvidenceStore(tmp_path / ".padv")
    run_id = "test-run"
    repo_root = str(tmp_path / "fixtures")
    (tmp_path / "fixtures").mkdir()
    (tmp_path / "fixtures" / "test.php").write_text("<?php function a() {}")
    
    index1 = build_repo_index(run_id, "test-sha", config, repo_root, store)
    index2 = build_repo_index(run_id, "test-sha", config, repo_root, store)
    
    assert json.dumps(index1, sort_keys=True) == json.dumps(index2, sort_keys=True)

def test_build_repo_index_minimal_content(tmp_path: Path):
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    store = EvidenceStore(tmp_path / ".padv")
    run_id = "test-run"
    fixture_repo = tmp_path / "tiny_repo"
    fixture_repo.mkdir()
    (fixture_repo / "test.php").write_text("<?php\nfunction hello() {}\n", encoding="utf-8")
    
    index = build_repo_index(run_id, "test-sha", config, str(fixture_repo), store)
    assert any(f["path"] == "test.php" for f in index["files"])
    assert any(s["name"] == "hello" for s in index["symbols"])

def test_build_repo_index_joern_seam(tmp_path: Path, monkeypatch):
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    store = EvidenceStore(tmp_path / ".padv")
    run_id = "test-run"
    fixture_repo = tmp_path / "tiny_repo"
    fixture_repo.mkdir(exist_ok=True)
    
    import padv.discovery.repo_index
    monkeypatch.setattr(padv.discovery.repo_index, "joern_is_available", lambda: False)
    
    index = build_repo_index(run_id, "test-sha", config, str(fixture_repo), store)
    assert index["sink_callsites_available"] is False
    assert index["sink_callsites"] == []
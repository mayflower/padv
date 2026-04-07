from __future__ import annotations

import pytest
from pathlib import Path
import json

from padv.config.schema import load_config
from padv.agents.cache import with_agent_cache, _cache_key, _config_signature

class FakeLLM:
    def __init__(self, response: str, model_name: str = "fake-model"):
        self.response = response
        self.model_name = model_name
        self.calls = 0

    def invoke(self, messages, **kwargs):
        self.calls += 1
        class FakeResp:
            content = self.response
        return FakeResp()

def test_cache_miss_on_prompt_version_change(tmp_path: Path):
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    config.agent.deterministic_mode = False
    store_path = tmp_path / ".padv"

    @with_agent_cache(stage="test", prompt_version="v1")
    def run_v1(llm, config, store_path, prompt):
        return llm.invoke([("user", prompt)]).content

    @with_agent_cache(stage="test", prompt_version="v2")
    def run_v2(llm, config, store_path, prompt):
        return llm.invoke([("user", prompt)]).content

    llm = FakeLLM("ok")
    
    run_v1(llm, config, store_path, "hello")
    assert llm.calls == 1

    # Should hit cache
    run_v1(llm, config, store_path, "hello")
    assert llm.calls == 1

    # Should miss because version changed
    run_v2(llm, config, store_path, "hello")
    assert llm.calls == 2

def test_cache_miss_on_config_change(tmp_path: Path):
    config1 = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    config1.agent.deterministic_mode = False
    
    config2 = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    config2.agent.deterministic_mode = False
    config2.budgets.max_requests = 999  # Change config

    store_path = tmp_path / ".padv"

    @with_agent_cache(stage="test", prompt_version="v1")
    def run(llm, config, store_path, prompt):
        return llm.invoke([("user", prompt)]).content

    llm = FakeLLM("ok")
    
    run(llm, config1, store_path, "hello")
    assert llm.calls == 1

    # Should miss because config signature changed
    run(llm, config2, store_path, "hello")
    assert llm.calls == 2

def test_ttl_expiry_invalidates_cache(tmp_path: Path):
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    config.agent.deterministic_mode = False
    store_path = tmp_path / ".padv"

    # Set TTL to negative to force expiry
    @with_agent_cache(stage="test", prompt_version="v1", ttl_seconds=-1)
    def run(llm, config, store_path, prompt):
        return llm.invoke([("user", prompt)]).content

    llm = FakeLLM("ok")
    
    run(llm, config, store_path, "hello")
    assert llm.calls == 1

    # Should miss because TTL expired
    run(llm, config, store_path, "hello")
    assert llm.calls == 2

def test_deterministic_mode_always_misses(tmp_path: Path):
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    config.agent.deterministic_mode = True
    store_path = tmp_path / ".padv"

    @with_agent_cache(stage="test", prompt_version="v1")
    def run(llm, config, store_path, prompt):
        return llm.invoke([("user", prompt)]).content

    llm = FakeLLM("ok")
    
    run(llm, config, store_path, "hello")
    assert llm.calls == 1

    # Should miss because deterministic_mode is True
    run(llm, config, store_path, "hello")
    assert llm.calls == 2

from __future__ import annotations

import ast
from pathlib import Path

import pytest
from padv.orchestrator.runtime import (
    _check_authz_bypass_status,
    _derive_authz_probe_flags,
    _derive_session_fixation_flags,
    _collect_analysis_flags,
    _annotate_runtime_evidence,
)


def test_no_login_markers_heuristic():
    """Ensure _LOGIN_MARKERS and _looks_like_login are not used in orchestrator runtime."""
    runtime_py = Path("padv/orchestrator/runtime.py")
    if runtime_py.exists():
        content = runtime_py.read_text(encoding="utf-8")
        assert "_LOGIN_MARKERS" not in content, "Found banned heuristic _LOGIN_MARKERS in runtime.py"
        assert "def _looks_like_login" not in content, "Found banned heuristic _looks_like_login in runtime.py"

def test_no_lower_coverage_matching():
    """Ensure .lower() is not used for heuristic string matching in gates."""
    gates_py = Path("padv/gates/engine.py")
    if gates_py.exists():
        content = gates_py.read_text(encoding="utf-8")
        # Parse the AST and look for Call nodes calling `.lower`
        tree = ast.parse(content)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr == "lower":
                    # Only exact canary matching is allowed
                    raise AssertionError("Found banned .lower() call in gates/engine.py. Gates must be deterministic and typed.")

def test_no_regex_preconditions():
    """Ensure natural language parsing with regex is not used for preconditions."""
    for path in Path("padv/validation").glob("**/*.py"):
        content = path.read_text(encoding="utf-8")
        tree = ast.parse(content)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for name in node.names:
                    assert name.name != "re", f"Found banned regex import in {path}"
            elif isinstance(node, ast.ImportFrom):
                assert node.module != "re", f"Found banned regex import in {path}"

def test_typed_decision_plane_apis_reject_strings():
    """Ensure decision-plane APIs enforce strict types (HttpResponse) over str/Any."""
    
    with pytest.raises(TypeError, match="Expected HttpResponse"):
        _check_authz_bypass_status("string_response", "string_probe") # type: ignore
        
    with pytest.raises(TypeError, match="Expected HttpResponse"):
        _derive_authz_probe_flags(None, "string_response", "string_probe", {}) # type: ignore
        
    with pytest.raises(TypeError, match="Expected HttpResponse"):
        _derive_session_fixation_flags("string_response", {}, None) # type: ignore
        
    with pytest.raises(TypeError, match="Expected HttpResponse"):
        _collect_analysis_flags(None, "string_response", None, None, None, {}, {}, None) # type: ignore
        
    with pytest.raises(TypeError, match="Expected HttpResponse"):
        _annotate_runtime_evidence(None, "string_response", None, None, None, {}, {}, None) # type: ignore

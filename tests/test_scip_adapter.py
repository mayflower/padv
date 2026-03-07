from __future__ import annotations

from pathlib import Path

import pytest

from padv.config.schema import load_config
from padv.discovery import scip as scip_module
from padv.discovery.scip import ScipExecutionError, discover_scip_candidates, discover_scip_candidates_safe


def test_scip_discovery_success(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    (repo_root / "a.php").write_text("<?php mysqli_query($db, $q);", encoding="utf-8")
    scip_file = tmp_path / "index.scip"
    scip_file.write_bytes(b"fake")

    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    config.scip.enabled = True
    config.scip.hard_fail = True
    config.scip.artifact_dir = str(tmp_path / "artifacts")

    monkeypatch.setattr("padv.discovery.scip._run_scip_generate", lambda *args, **kwargs: scip_file)
    monkeypatch.setattr(
        "padv.discovery.scip._run_scip_print",
        lambda *args, **kwargs: '{"documents":[{"relative_path":"a.php","occurrences":[{"symbol":"mysqli_query","range":[2,1,2,10]}]}]}',
    )

    candidates, evidence, refs = discover_scip_candidates(str(repo_root), config)
    assert len(candidates) == 1
    assert candidates[0].vuln_class == "sql_injection_boundary"
    assert evidence[0].query_id == "scip::sql_injection_boundary"
    assert refs


def test_scip_discovery_hard_fail(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    repo_root = tmp_path / "repo"
    repo_root.mkdir()

    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    config.scip.enabled = True
    config.scip.hard_fail = True
    monkeypatch.setattr(
        "padv.discovery.scip._run_scip_generate",
        lambda *args, **kwargs: (_ for _ in ()).throw(ScipExecutionError("missing scip")),
    )

    with pytest.raises(ScipExecutionError):
        discover_scip_candidates_safe(str(repo_root), config)


def test_scip_discovery_safe_wrapper_raises(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    repo_root = tmp_path / "repo"
    repo_root.mkdir()

    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    config.scip.enabled = True
    monkeypatch.setattr(
        "padv.discovery.scip._run_scip_generate",
        lambda *args, **kwargs: (_ for _ in ()).throw(ScipExecutionError("missing scip")),
    )

    with pytest.raises(ScipExecutionError, match="missing scip"):
        discover_scip_candidates_safe(str(repo_root), config)


def test_scip_discovery_excludes_test_paths(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    scip_file = tmp_path / "index.scip"
    scip_file.write_bytes(b"fake")

    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    config.scip.enabled = True
    config.scip.hard_fail = True
    config.scip.artifact_dir = str(tmp_path / "artifacts")

    monkeypatch.setattr("padv.discovery.scip._run_scip_generate", lambda *args, **kwargs: scip_file)
    monkeypatch.setattr(
        "padv.discovery.scip._run_scip_print",
        lambda *args, **kwargs: (
            '{"documents":['
            '{"relative_path":"tests/a.php","occurrences":[{"symbol":"mysqli_query","range":[1,1,1,12]}]},'
            '{"relative_path":"src/a.php","occurrences":[{"symbol":"mysqli_query","range":[2,1,2,12]}]}'
            "]}",
        ),
    )

    candidates, evidence, refs = discover_scip_candidates(str(repo_root), config)
    assert len(candidates) == 1
    assert candidates[0].file_path == "src/a.php"
    assert evidence[0].file_path == "src/a.php"
    assert refs


def test_scip_matcher_handles_symbol_name_variants() -> None:
    payload = (
        '{"documents":['
        '{"relative_path":"src/x.php","occurrences":[{"symbol":"echo","range":[1,0,1,4]}]},'
        '{"relative_path":"src/y.php","occurrences":[{"symbol":"$_GET[\'id\']","range":[2,0,2,5]}]}'
        "]}"
    )
    hits = scip_module._extract_hits(payload)  # type: ignore[attr-defined]
    classes = {h.vuln_class for h in hits}
    assert "xss_output_boundary" in classes
    assert "idor_invariant_missing" in classes

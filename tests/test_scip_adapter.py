from __future__ import annotations

from pathlib import Path
import subprocess

import pytest

from padv.config.schema import load_config
from padv.discovery import scip as scip_module
from padv.discovery.scip import (
    ScipExecutionError,
    discover_scip_candidates,
    discover_scip_candidates_safe,
    discover_scip_candidates_with_meta,
)


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


def test_scip_discovery_meta_counts(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
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
            '{"relative_path":"src/a.php","occurrences":[{"symbol":"mysqli_query","range":[2,1,2,12]}]},'
            '{"relative_path":"src/a.php","occurrences":[{"symbol":"unrelated_call","range":[3,1,3,12]}]}'
            "]}",
        ),
    )

    candidates, evidence, refs, meta = discover_scip_candidates_with_meta(str(repo_root), config)
    assert len(candidates) == 1
    assert len(evidence) == 1
    assert refs
    assert meta.raw_scip_hits == 3
    assert meta.mapped_scip_sinks == 2
    assert meta.app_scoped_sinks == 1
    assert meta.dropped_non_app_sinks == 1
    assert meta.candidate_count == 1


def test_scip_discovery_fairly_preserves_minority_classes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    scip_file = tmp_path / "index.scip"
    scip_file.write_bytes(b"fake")

    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    config.scip.enabled = True
    config.scip.hard_fail = True
    config.scip.artifact_dir = str(tmp_path / "artifacts")
    config.budgets.max_candidates = 2

    monkeypatch.setattr("padv.discovery.scip._run_scip_generate", lambda *args, **kwargs: scip_file)
    monkeypatch.setattr(
        "padv.discovery.scip._run_scip_print",
        lambda *args, **kwargs: (
            '{"documents":['
            '{"relative_path":"src/a.php","occurrences":['
            '{"symbol":"echo","range":[1,1,1,4]},'
            '{"symbol":"print","range":[2,1,2,5]}'
            "]},"
            '{"relative_path":"src/b.php","occurrences":['
            '{"symbol":"mysqli_query","range":[3,1,3,12]}'
            "]}"
            "]}",
        ),
    )

    candidates, _evidence, _refs, meta = discover_scip_candidates_with_meta(str(repo_root), config)
    assert [candidate.vuln_class for candidate in candidates] == [
        "xss_output_boundary",
        "sql_injection_boundary",
    ]
    assert meta.app_scoped_sinks == 3
    assert meta.candidate_count == 2


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


def test_scip_print_enforces_json_flag(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    config.scip.print_command = "scip print"

    seen: dict[str, str] = {}

    def fake_run_command(cmd: str, cwd: Path, timeout_seconds: int) -> subprocess.CompletedProcess[str]:
        seen["cmd"] = cmd
        seen["cwd"] = str(cwd)
        seen["timeout"] = str(timeout_seconds)
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout='{"documents":[]}', stderr="")

    monkeypatch.setattr(scip_module, "_run_command", fake_run_command)

    out = scip_module._run_scip_print(tmp_path / "index.scip", config, tmp_path)  # type: ignore[attr-defined]
    assert out == '{"documents":[]}'
    assert "--json" in seen["cmd"]
    assert "index.scip" in seen["cmd"]


def test_scip_extract_supports_camel_case_document_keys() -> None:
    payload = (
        '{"documents":['
        '{"relativePath":"src/a.php","occurrences":[{"symbol":"mysqli_query","range":[1,0,1,12]}]}'
        "]}"
    )
    hits = scip_module._extract_hits(payload)  # type: ignore[attr-defined]
    assert len(hits) == 1
    assert hits[0].file_path == "src/a.php"
    assert hits[0].vuln_class == "sql_injection_boundary"


def test_scip_workspace_generates_synthetic_composer_for_plain_php_repo(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    (repo_root / "src").mkdir()
    (repo_root / "src" / "a.php").write_text("<?php echo $_GET['x'];", encoding="utf-8")

    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    config.scip.enabled = True

    seen: dict[str, str] = {}

    def fake_run_command(cmd: str, cwd: Path, timeout_seconds: int) -> subprocess.CompletedProcess[str]:
        seen["cmd"] = cmd
        seen["cwd"] = str(cwd)
        vendor = cwd / "vendor"
        vendor.mkdir(parents=True, exist_ok=True)
        (vendor / "autoload.php").write_text("<?php", encoding="utf-8")
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(scip_module, "_run_command", fake_run_command)

    workspace = scip_module._build_scip_workspace(  # type: ignore[attr-defined]
        repo_root, tmp_path / "workspace", config
    )

    composer_json = workspace / "composer.json"
    payload = composer_json.read_text(encoding="utf-8")
    assert '"classmap": [' in payload
    assert seen["cmd"].startswith("composer install ")
    assert seen["cwd"] == str(workspace)
    assert (workspace / "src" / "a.php").exists()


def test_scip_discovery_indexes_from_staged_workspace(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    (repo_root / "src").mkdir()
    (repo_root / "src" / "a.php").write_text("<?php mysqli_query($db, $q);", encoding="utf-8")

    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    config.scip.enabled = True
    config.scip.hard_fail = True
    config.scip.artifact_dir = str(tmp_path / "artifacts")

    seen: dict[str, str] = {}
    scip_file = tmp_path / "artifacts" / "index.scip"
    scip_file.parent.mkdir(parents=True, exist_ok=True)
    scip_file.write_bytes(b"fake")

    def fake_run_command(cmd: str, cwd: Path, timeout_seconds: int) -> subprocess.CompletedProcess[str]:
        vendor = cwd / "vendor"
        vendor.mkdir(parents=True, exist_ok=True)
        (vendor / "autoload.php").write_text("<?php", encoding="utf-8")
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

    def fake_generate(repo_root_arg: Path, _config, _artifact_dir: Path) -> Path:
        seen["generate_cwd"] = str(repo_root_arg)
        assert repo_root_arg != repo_root
        assert (repo_root_arg / "composer.json").exists()
        return scip_file

    monkeypatch.setattr(scip_module, "_run_command", fake_run_command)
    monkeypatch.setattr(scip_module, "_run_scip_generate", fake_generate)
    monkeypatch.setattr(
        scip_module,
        "_run_scip_print",
        lambda *args, **kwargs: '{"documents":[{"relative_path":"src/a.php","occurrences":[{"symbol":"mysqli_query","range":[2,1,2,10]}]}]}',
    )

    candidates, evidence, refs = discover_scip_candidates(str(repo_root), config)
    assert len(candidates) == 1
    assert candidates[0].file_path == "src/a.php"
    assert evidence[0].file_path == "src/a.php"
    assert refs == [str(scip_file)]
    assert seen["generate_cwd"] != str(repo_root)

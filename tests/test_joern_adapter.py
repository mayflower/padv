from __future__ import annotations

from pathlib import Path

import pytest

from padv.config.schema import load_config
from padv.static.joern import adapter
from padv.static.joern.adapter import JoernExecutionError, JoernFinding


def _write_php(tmp_path: Path, rel_path: str, content: str) -> None:
    path = tmp_path / rel_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def test_parse_joern_jsonl(tmp_path: Path) -> None:
    file_path = tmp_path / "hits.jsonl"
    file_path.write_text(
        "\n".join(
            [
                '{"vuln_class":"sql_injection_boundary","query_id":"joern::sql","file_path":"src/a.php","line":12,"sink":"mysqli_query","snippet":"mysqli_query($db,$q);"}',
                "not-json",
                '{"vuln_class":"","file_path":"src/b.php","line":2}',
            ]
        ),
        encoding="utf-8",
    )

    findings = adapter._parse_joern_jsonl(file_path)
    assert len(findings) == 1
    assert findings[0].vuln_class == "sql_injection_boundary"
    assert findings[0].line == 12


def test_discover_candidates_prefers_joern(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _write_php(tmp_path, "src/a.php", "<?php mysqli_query($db, $q); ?>")

    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    config.joern.enabled = True
    config.joern.fallback_to_regex = False

    def fake_run(_repo_root: Path, _config):
        return [
            JoernFinding(
                vuln_class="sql_injection_boundary",
                query_id="joern::sql_boundary",
                file_path="src/a.php",
                line=1,
                sink="mysqli_query",
                snippet="mysqli_query($db, $q)",
            )
        ]

    monkeypatch.setattr(adapter, "_run_joern_findings", fake_run)

    candidates, static_evidence = adapter.discover_candidates(str(tmp_path), config)
    assert len(candidates) == 1
    assert candidates[0].notes == "joern script detector"
    assert static_evidence[0].query_id == "joern::sql_boundary"


def test_discover_candidates_does_not_fallback_to_regex(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _write_php(tmp_path, "src/a.php", "<?php exec($cmd); ?>")

    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    config.joern.enabled = True
    config.joern.fallback_to_regex = True

    def fake_run(_repo_root: Path, _config):
        raise JoernExecutionError("joern unavailable")

    monkeypatch.setattr(adapter, "_run_joern_findings", fake_run)

    with pytest.raises(JoernExecutionError):
        adapter.discover_candidates(str(tmp_path), config)


def test_discover_candidates_raises_without_fallback(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _write_php(tmp_path, "src/a.php", "<?php exec($cmd); ?>")

    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    config.joern.enabled = True
    config.joern.fallback_to_regex = False

    def fake_run(_repo_root: Path, _config):
        raise JoernExecutionError("joern unavailable")

    monkeypatch.setattr(adapter, "_run_joern_findings", fake_run)

    with pytest.raises(JoernExecutionError):
        adapter.discover_candidates(str(tmp_path), config)


def test_parse_joern_stdout_marker_json() -> None:
    stdout = (
        "noise\n"
        '<padv_result>[{"vuln_class":"ssrf","query_id":"joern::ssrf","file_path":"src/x.php","line":9,"sink":"curl_exec","snippet":"curl_exec($ch)"}]</padv_result>\n'
        "done"
    )
    findings = adapter._parse_joern_stdout_json(stdout)
    assert len(findings) == 1
    assert findings[0].vuln_class == "ssrf"
    assert findings[0].line == 9


def test_discover_candidates_detects_insecure_design_regex(tmp_path: Path) -> None:
    _write_php(tmp_path, "src/design.php", "<?php allow_all_access($user); ?>")

    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    config.joern.enabled = False

    candidates, static_evidence = adapter.discover_candidates(str(tmp_path), config)
    assert any(c.vuln_class == "insecure_design" for c in candidates)
    assert any(e.query_id == "regex::insecure_design" for e in static_evidence)


def test_discover_candidates_regex_excludes_test_paths(tmp_path: Path) -> None:
    _write_php(tmp_path, "tests/a.php", "<?php exec($cmd); ?>")
    _write_php(tmp_path, "src/a.php", "<?php exec($cmd); ?>")

    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    config.joern.enabled = False

    candidates, _ = adapter.discover_candidates(str(tmp_path), config)
    assert any(c.file_path == "src/a.php" for c in candidates)
    assert all(not c.file_path.startswith("tests/") for c in candidates)


def test_discover_candidates_detects_vulnerable_components_manifest(tmp_path: Path) -> None:
    composer = tmp_path / "composer.json"
    composer.write_text(
        '{"require":{"symfony/http-foundation":"5.4.0","guzzlehttp/guzzle":"7.0.0"}}',
        encoding="utf-8",
    )

    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    config.joern.enabled = False

    candidates, static_evidence = adapter.discover_candidates(str(tmp_path), config)
    assert any(c.vuln_class == "vulnerable_components" for c in candidates)
    assert any(e.query_id == "manifest::vulnerable_components" for e in static_evidence)


def test_http_mode_allows_server_side_import_without_local_parse(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _write_php(tmp_path, "src/a.php", "<?php curl_exec($ch); ?>")

    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    config.joern.enabled = True
    config.joern.use_http_api = True
    config.joern.parse_command = ""

    def fake_parse(*args, **kwargs):
        raise AssertionError("local parse should not be called when parse_command is empty")

    def fake_post(query: str, config):
        assert 'importCode("' in query
        return (
            '<padv_result>[{"vuln_class":"ssrf","query_id":"joern::ssrf","file_path":"src/a.php","line":1,'
            '"sink":"curl_exec","snippet":"curl_exec($ch)"}]</padv_result>'
        )

    monkeypatch.setattr(adapter, "_run_joern_parse", fake_parse)
    monkeypatch.setattr(adapter, "_post_joern_http_query", fake_post)

    findings = adapter._run_joern_findings_http(tmp_path, config)
    assert len(findings) == 1
    assert findings[0].vuln_class == "ssrf"

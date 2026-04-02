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


def test_discover_candidates_with_meta_reports_joern_findings(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _write_php(tmp_path, "src/a.php", "<?php mysqli_query($db, $q); ?>")

    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    config.joern.enabled = True

    monkeypatch.setattr(
        adapter,
        "_run_joern_findings",
        lambda *_args, **_kwargs: [
            JoernFinding(
                vuln_class="sql_injection_boundary",
                query_id="joern::sql_boundary",
                file_path="src/a.php",
                line=1,
                sink="mysqli_query",
                snippet="mysqli_query($db, $q)",
            ),
            JoernFinding(
                vuln_class="sql_injection_boundary",
                query_id="joern::sql_boundary",
                file_path="tests/a.php",
                line=1,
                sink="mysqli_query",
                snippet="mysqli_query($db, $q)",
            ),
        ],
    )

    candidates, static_evidence, meta = adapter.discover_candidates_with_meta(str(tmp_path), config)
    assert len(candidates) == 1
    assert len(static_evidence) == 1
    assert meta.joern_findings == 2
    assert meta.joern_app_findings == 1
    assert meta.joern_candidate_count == 1


def test_discover_candidates_with_meta_fairly_preserves_minority_classes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _write_php(tmp_path, "src/a.php", "<?php echo $_GET['x'];")
    _write_php(tmp_path, "src/b.php", "<?php mysqli_query($db, $q);")

    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    config.joern.enabled = True
    config.budgets.max_candidates = 2

    monkeypatch.setattr(
        adapter,
        "_run_joern_findings",
        lambda *_args, **_kwargs: [
            JoernFinding(
                vuln_class="xss_output_boundary",
                query_id="joern::xss",
                file_path="src/a.php",
                line=1,
                sink="echo",
                snippet="echo $_GET['x']",
            ),
            JoernFinding(
                vuln_class="xss_output_boundary",
                query_id="joern::xss",
                file_path="src/a.php",
                line=2,
                sink="print",
                snippet="print $_GET['x']",
            ),
            JoernFinding(
                vuln_class="sql_injection_boundary",
                query_id="joern::sql_boundary",
                file_path="src/b.php",
                line=1,
                sink="mysqli_query",
                snippet="mysqli_query($db, $q)",
            ),
        ],
    )

    candidates, _evidence, meta = adapter.discover_candidates_with_meta(str(tmp_path), config)
    assert [candidate.vuln_class for candidate in candidates] == [
        "xss_output_boundary",
        "sql_injection_boundary",
    ]
    assert meta.joern_app_findings == 3
    assert meta.joern_candidate_count == 2


def test_discover_candidates_does_not_fallback_to_regex(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _write_php(tmp_path, "src/a.php", "<?php exec($cmd); ?>")

    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    config.joern.enabled = True

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


def test_parse_joern_stdout_from_repl_base64_list() -> None:
    payload = (
        '{"vuln_class":"xss_output_boundary","query_id":"joern::xss","file_path":"src/index.php","line":40,"sink":"exit","snippet":"exit(1)"}'
    ).encode("utf-8")
    import base64

    encoded = base64.b64encode(payload).decode("ascii")
    stdout = f'val res9: List[String] = List("{encoded}")'
    findings = adapter._parse_joern_stdout_json(stdout)
    assert len(findings) == 1
    assert findings[0].file_path == "src/index.php"
    assert findings[0].line == 40


def test_parse_joern_stdout_from_last_repl_base64_list_only() -> None:
    import base64

    bad = base64.b64encode(b'{"not":"a finding"}').decode("ascii")
    good = base64.b64encode(
        b'{"vuln_class":"sql_injection_boundary","query_id":"joern::sql","file_path":"src/db.php","line":23,"sink":"query","snippet":"$db->query($sql)"}'
    ).decode("ascii")
    stdout = (
        f'val res4: List[String] = List("{bad}")\n'
        f'val res5: List[String] = List("{good}")'
    )
    findings = adapter._parse_joern_stdout_json(stdout)
    assert len(findings) == 1
    assert findings[0].file_path == "src/db.php"
    assert findings[0].sink == "query"


def test_discover_candidates_rejects_disabled_joern(tmp_path: Path) -> None:
    _write_php(tmp_path, "src/a.php", "<?php exec($cmd); ?>")
    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    config.joern.enabled = False
    with pytest.raises(JoernExecutionError, match="joern.enabled must remain true"):
        adapter.discover_candidates(str(tmp_path), config)


def test_discover_candidates_detects_vulnerable_components_manifest(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    composer = tmp_path / "composer.json"
    composer.write_text(
        '{"require":{"symfony/http-foundation":"5.4.0","guzzlehttp/guzzle":"7.0.0"}}',
        encoding="utf-8",
    )

    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    config.joern.enabled = True
    monkeypatch.setattr(adapter, "_run_joern_findings", lambda *_args, **_kwargs: [])

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


def test_http_mode_with_parse_command_uses_imported_cpg(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _write_php(tmp_path, "src/a.php", "<?php mysqli_query($db, $q); ?>")

    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    config.joern.enabled = True
    config.joern.use_http_api = True
    config.joern.parse_command = "joern-parse"
    shared_dir = tmp_path / "shared"
    monkeypatch.setenv("PADV_JOERN_SHARED_DIR", str(shared_dir))

    seen: dict[str, str] = {}

    def fake_parse(*, repo_root: Path, cpg_path: Path, config) -> None:
        seen["repo_root"] = str(repo_root)
        seen["cpg_path"] = str(cpg_path)
        seen["parse_command"] = config.joern.parse_command
        cpg_path.write_text("fake-cpg", encoding="utf-8")

    def fake_post(*, query: str, config):
        seen["query"] = query
        seen["server_url"] = config.joern.server_url
        return (
            '<padv_result>[{"vuln_class":"sql_injection_boundary","query_id":"joern::sql_boundary",'
            '"file_path":"src/a.php","line":1,"sink":"mysqli_query","snippet":"mysqli_query($db, $q)"}]</padv_result>'
        )

    monkeypatch.setattr(adapter, "_run_joern_parse", fake_parse)
    monkeypatch.setattr(adapter, "_post_joern_http_query", fake_post)

    findings = adapter._run_joern_findings_http(tmp_path, config)
    assert len(findings) == 1
    assert findings[0].vuln_class == "sql_injection_boundary"
    assert 'importCpg("' in seen["query"]
    assert seen["repo_root"] != str(tmp_path)
    assert seen["repo_root"].endswith("/source")
    assert seen["cpg_path"].startswith(str(shared_dir))


def test_build_joern_parse_scope_excludes_vendor_dir_and_tests(tmp_path: Path) -> None:
    _write_php(
        tmp_path,
        "composer.json",
        '{"config":{"vendor-dir":"vendor"},"autoload":{"psr-4":{"Mutillidae\\\\":"./src/classes"}}}',
    )
    _write_php(tmp_path, "src/classes/Controller.php", "<?php echo 'ok';")
    _write_php(tmp_path, "src/includes/bootstrap.php", "<?php echo 'bootstrap';")
    _write_php(tmp_path, "documentation/language_en.php", "<?php echo 'translation';")
    _write_php(tmp_path, "vendor/aws/Foo.php", "<?php echo 'vendor';")
    _write_php(tmp_path, "tests/TestCase.php", "<?php echo 'test';")

    scoped = adapter._build_joern_parse_scope(tmp_path, tmp_path / ".scope")
    scoped_files = sorted(path.relative_to(scoped).as_posix() for path in scoped.rglob("*.php"))
    assert scoped_files == [
        "src/classes/Controller.php",
    ]


def test_remap_findings_to_repo_root_maps_staged_paths(tmp_path: Path) -> None:
    parse_root = tmp_path / "stage" / "source"
    parse_root.mkdir(parents=True)
    finding = JoernFinding(
        vuln_class="xss_output_boundary",
        query_id="joern::xss_boundary",
        file_path=str((parse_root / "src/index.php").resolve()),
        line=12,
        sink="echo",
        snippet="echo $payload;",
    )

    remapped = adapter._remap_findings_to_repo_root([finding], parse_root=parse_root, repo_root=tmp_path / "repo")
    assert remapped[0].file_path.endswith("repo/src/index.php")


def test_http_query_template_keeps_scala_escape_sequences() -> None:
    query = adapter._joern_http_query_for_php(Path("/tmp/repo.cpg.bin"))
    esc_line = next(line for line in query.splitlines() if "value.replace" in line)
    assert 'replace("\\\\", "\\\\\\\\")' in esc_line
    assert 'replace("\\"", "\\\\\\"")' in esc_line
    assert "Base64.getEncoder.encodeToString" in query

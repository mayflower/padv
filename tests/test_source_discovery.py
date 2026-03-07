from __future__ import annotations

from pathlib import Path

from padv.config.schema import load_config
from padv.discovery.source import discover_source_candidates


def _write_php(tmp_path: Path, rel_path: str, content: str) -> None:
    path = tmp_path / rel_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def test_source_discovery_excludes_tests_but_includes_scripts(tmp_path: Path) -> None:
    _write_php(tmp_path, "tests/a.php", "<?php exec($cmd); ?>")
    _write_php(tmp_path, "scripts/a.php", "<?php exec($cmd); ?>")
    _write_php(tmp_path, "src/a.php", "<?php exec($cmd); ?>")
    _write_php(tmp_path, "modules/custom.feature.module", "<?php exec($cmd); ?>")

    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    config.budgets.max_candidates = 20

    candidates, evidence = discover_source_candidates(str(tmp_path), config)
    paths = {c.file_path for c in candidates}
    assert "src/a.php" in paths
    assert "scripts/a.php" in paths
    assert "modules/custom.feature.module" in paths
    assert all(not c.file_path.startswith("tests/") for c in candidates)
    assert {e.file_path for e in evidence} == paths


def test_source_discovery_detects_extended_php_security_markers(tmp_path: Path) -> None:
    _write_php(
        tmp_path,
        "src/extended.php",
        "\n".join(
            [
                "<?php",
                "popen($cmd, 'r');",
                "ldap_search($conn, $base, $filter);",
                "echo $_GET['x'];",
                "include_once($_GET['page']);",
                "DOMDocument::loadXML($xml);",
                "header('Location: ' . $_GET['next']);",
                "preg_match($pattern, $input);",
                "session_regenerate_id(true);",
                "phpinfo();",
            ]
        ),
    )

    config = load_config(Path(__file__).resolve().parents[1] / "padv.toml")
    config.budgets.max_candidates = 200

    candidates, _ = discover_source_candidates(str(tmp_path), config)
    classes = {c.vuln_class for c in candidates}
    expected = {
        "command_injection_boundary",
        "ldap_injection_boundary",
        "xss_output_boundary",
        "file_boundary_influence",
        "xxe_influence",
        "header_injection_boundary",
        "regex_dos_boundary",
        "session_fixation_invariant",
        "debug_output_leak",
    }
    assert expected.issubset(classes)

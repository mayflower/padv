from __future__ import annotations

import json
from pathlib import Path


REQUIRED_CATEGORIES = {
    "sql_injection",
    "cross_site_scripting",
    "command_injection",
    "authn_authz_failures",
    "session_misuse",
    "csrf",
    "file_inclusion_path_traversal",
    "ldap_injection",
    "xxe_xml_injection",
    "unrestricted_file_upload",
    "open_redirect_header_cookie_manipulation",
    "information_disclosure_misconfiguration",
}



def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")



def test_mutillidae_compose_uses_required_services_only() -> None:
    root = Path(__file__).resolve().parents[1]
    compose = _read(root / "docker-compose.mutillidae.yml")
    assert "www:" in compose
    assert "database:" in compose
    assert "directory:" in compose
    assert "database_admin" not in compose
    assert "directory_admin" not in compose
    assert '"18080:80"' in compose



def test_mutillidae_web_image_uses_morcilla_and_official_runtime_assets() -> None:
    root = Path(__file__).resolve().parents[1]
    dockerfile = _read(root / "docker" / "mutillidae" / "www-morcilla.Dockerfile")
    assert "docker-php-ext-install morcilla" in dockerfile
    assert "morcilla.key=test-key" in dockerfile
    assert "targets/mutillidae/src" in dockerfile
    assert "targets/mutillidae-docker/.build/www/configuration" in dockerfile



def test_mutillidae_e2e_script_bootstraps_database_and_ldap() -> None:
    root = Path(__file__).resolve().parents[1]
    script = _read(root / "scripts" / "mutillidae_e2e.sh")
    assert "bootstrap_database()" in script
    assert "seed_ldap_directory()" in script
    assert "ensure_scanner_image()" in script
    assert 'docker image inspect "${SCANNER_IMAGE}"' in script
    assert "set-up-database.php" in script
    assert "ldapadd" in script
    assert "contains_text()" in script
    assert "/workspace/targets/mutillidae" in script
    assert "padv.mutillidae.strict.toml" in script



def test_mutillidae_assessment_targets_runtime_and_scanner_paths() -> None:
    root = Path(__file__).resolve().parents[1]
    script = _read(root / "scripts" / "mutillidae_integration_assess.py")
    assert "docker-compose.mutillidae.yml" in script
    assert "padv.mutillidae.strict.toml" in script
    assert "/workspace/targets/mutillidae" in script
    assert "http://127.0.0.1:18080/" in script
    assert "dc=mutillidae,dc=localhost" in script



def test_mutillidae_strict_config_points_to_mutillidae_runtime() -> None:
    root = Path(__file__).resolve().parents[1]
    config = _read(root / "padv.mutillidae.strict.toml")
    assert 'base_url = "http://host.docker.internal:18080/"' in config
    assert 'query_profile = "mutillidae-strict"' in config
    assert '[web]' in config
    assert 'enabled = true' in config



def test_mutillidae_gap_catalog_covers_documented_categories() -> None:
    root = Path(__file__).resolve().parents[1]
    data = json.loads(_read(Path(__file__).resolve().parent / "fixtures" / "mutillidae-gap-catalog.json"))
    categories = {item["category"] for item in data}
    assert categories == REQUIRED_CATEGORIES
    for item in data:
        assert set(item) == {
            "gap_id",
            "category",
            "documented_source",
            "expected_channels",
            "runtime_validatable",
            "minimum_evidence_expectation",
            "target_expectation",
        }
        assert item["target_expectation"] in {"must_find", "should_find", "static_only_ok"}
        assert set(item["expected_channels"]) == {"source", "joern/scip", "web", "runtime"}



def test_readme_uses_mutillidae_e2e_flow() -> None:
    root = Path(__file__).resolve().parents[1]
    readme = _read(root / "README.md")
    assert "Mutillidae Example" in readme
    assert "scripts/mutillidae_e2e.sh" in readme
    assert "phpMyFAQ E2E Flow" not in readme


def test_scanner_dockerfile_uses_dependency_layer_not_editable_install() -> None:
    root = Path(__file__).resolve().parents[1]
    dockerfile = _read(root / "Dockerfile")
    assert "COPY pyproject.toml README.md /workspace/haxor/" in dockerfile
    assert "COPY docker /workspace/haxor/docker" in dockerfile
    assert "pip install -r /tmp/requirements.txt" in dockerfile
    assert "pip install -e ." not in dockerfile
    assert 'ENTRYPOINT ["python", "-m", "padv.cli.main"]' in dockerfile

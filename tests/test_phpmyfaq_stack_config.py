from __future__ import annotations

from pathlib import Path


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_phpmyfaq_compose_uses_entrypoint_disable_htaccess_var() -> None:
    root = Path(__file__).resolve().parents[1]
    compose = _read(root / "docker-compose.phpmyfaq.yml")
    assert "DISABLE_HTACCESS: \"\"" in compose
    assert "PMF_DISABLE_HTACCESS" not in compose


def test_phpmyfaq_apache_image_uses_entrypoint_disable_htaccess_var() -> None:
    root = Path(__file__).resolve().parents[1]
    dockerfile = _read(root / "docker" / "phpmyfaq" / "apache-morcilla.Dockerfile")
    assert "DISABLE_HTACCESS" in dockerfile
    assert "PMF_DISABLE_HTACCESS" not in dockerfile


def test_phpmyfaq_compose_error_reporting_is_not_deprecated_only() -> None:
    root = Path(__file__).resolve().parents[1]
    compose = _read(root / "docker-compose.phpmyfaq.yml")
    assert "PHP_ERROR_REPORTING: \"E_ALL & ~E_DEPRECATED\"" in compose


def test_phpmyfaq_setup_enforces_reference_url_with_port() -> None:
    root = Path(__file__).resolve().parents[1]
    script = _read(root / "scripts/phpmyfaq_e2e.sh")
    assert "ensure_phpmyfaq_runtime_config()" in script
    assert "main.referenceURL" in script
    assert "http://127.0.0.1:18080" in script
    assert "ensure_phpmyfaq_runtime_config" in script.split("cmd_setup()", 1)[1]
    assert "ensure_phpmyfaq_runtime_config" in script.split("cmd_test()", 1)[1]

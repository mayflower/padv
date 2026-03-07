from __future__ import annotations

from padv.path_scope import is_app_candidate_path


def test_path_scope_keeps_scripts_and_docker_paths() -> None:
    assert is_app_candidate_path("scripts/bootstrap.php")
    assert is_app_candidate_path(".docker/frankenphp/worker.php")
    assert is_app_candidate_path("docker/setup.php")


def test_path_scope_still_excludes_test_and_vendor() -> None:
    assert not is_app_candidate_path("tests/a.php")
    assert not is_app_candidate_path("vendor/pkg/a.php")

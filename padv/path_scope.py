from __future__ import annotations

from pathlib import Path, PurePosixPath


_EXCLUDED_SEGMENTS = frozenset(
    {
        "test",
        "tests",
        "testing",
        "spec",
        "specs",
        "fixture",
        "fixtures",
        "mock",
        "mocks",
        "stub",
        "stubs",
        "vendor",
        "node_modules",
        ".git",
    }
)


def normalize_repo_path(path: str, repo_root: Path | None = None) -> str:
    raw = path.replace("\\", "/").strip()
    if not raw:
        return ""

    path_obj = Path(raw)
    if repo_root and path_obj.is_absolute():
        try:
            raw = path_obj.resolve().relative_to(repo_root.resolve()).as_posix()
        except ValueError:
            return ""
    else:
        raw = path_obj.as_posix()

    while raw.startswith("./"):
        raw = raw[2:]
    if raw.startswith("/"):
        return ""
    return raw


def is_app_candidate_path(path: str) -> bool:
    normalized = path.replace("\\", "/").strip()
    if not normalized:
        return False

    parts = [part.casefold() for part in PurePosixPath(normalized).parts]
    return not any(part in _EXCLUDED_SEGMENTS for part in parts)
